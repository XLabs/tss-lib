package main

import (
	"context"
	"io"
	"net"
	"sync"

	common "github.com/xlabs/tss-common"
	"github.com/xlabs/tss-common/service/signer"
	"github.com/xlabs/tss-lib/v2/tss"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type Server struct {
	signer.UnimplementedSignerServer
	ctx    context.Context
	cancel context.CancelFunc
	logger *zap.Logger

	*grpc.Server
	tss.Signer
	listener net.Listener

	waitersLock  sync.Mutex
	waiters      map[uint64]chan<- *signer.SignResponse
	nextWaiterID uint64
}

// addSubscriber creates a channel for a new subscriber, adds it to the waiters map,
// and returns the subscriber's ID and channel.
func (s *Server) addSubscriber() (uint64, chan *signer.SignResponse) {
	ch := make(chan *signer.SignResponse)

	s.waitersLock.Lock()
	defer s.waitersLock.Unlock()

	waiterID := s.nextWaiterID
	s.nextWaiterID++
	s.waiters[waiterID] = ch

	return waiterID, ch
}

// removeSubscriber removes a subscriber from the waiters map and closes their channel.
func (s *Server) removeSubscriber(id uint64) {
	s.waitersLock.Lock()
	defer s.waitersLock.Unlock()

	if ch, ok := s.waiters[id]; ok {
		delete(s.waiters, id)
		close(ch)
	}
}

// SignMessage implements signer.SignerServer.
func (s *Server) SignMessage(stream signer.Signer_SignMessageServer) error {
	waiterID, ch := s.addSubscriber()
	defer s.removeSubscriber(waiterID)

	errChan := make(chan error, 2)

	// Goroutine to handle receiving messages from the client
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				if err != io.EOF { // If the client closes the stream, io.EOF will be received.
					s.logger.Error("Error receiving from stream", zap.Error(err))
				}
				errChan <- err
				return
			}

			if err := s.Signer.BeginAsyncThresholdSigningProtocol(req); err != nil {
				select {
				case ch <- &signer.SignResponse{
					Response: &signer.SignResponse_Status{
						Status: &signer.SignStatus{
							Code:    int32(codes.FailedPrecondition),
							Message: err.Error(),
							Details: &anypb.Any{},
						}},
				}:
				default:
					s.logger.Warn("Couldn't inform subscriber about signing error, channel full")
				}
			}
		}
	}()

	go func() { errChan <- s.streamSignatures(stream, ch) }()

	// Wait for the first error from either sending or receiving.
	return <-errChan
}

// fanOutSignatures listens for produced signatures and forwards them to all registered waiters.
func (s *Server) fanOutSignatures() {
	for sig := range s.Signer.ProducedSignature() {
		s.waitersLock.Lock()

		for _, waiter := range s.waiters {
			select {
			case waiter <- wrapsig(sig):
			default: // If the channel is full, skip sending to avoid blocking.
				s.logger.Warn("Couldn't inform subscriber about new signature, channel full")
			}
		}

		s.waitersLock.Unlock()
	}
}

func wrapsig(sig *common.SignatureData) *signer.SignResponse {
	return &signer.SignResponse{
		Response: &signer.SignResponse_Signature{
			Signature: proto.CloneOf(sig), // ensures a deep copy
		},
	}
}

// streamSignatures listens for signatures on a channel and sends them to the client stream.
// It returns when the client's context is done or when sending fails.
func (s *Server) streamSignatures(stream signer.Signer_SignMessageServer, ch <-chan *signer.SignResponse) error {
	for {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-stream.Context().Done():
			return stream.Context().Err()
		case sig, ok := <-ch:
			if !ok {
				// Channel is closed.
				return nil
			}

			if err := stream.Send(sig); err != nil {
				return err
			}
		}
	}
}

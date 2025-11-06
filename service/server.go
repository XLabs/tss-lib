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
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const bufferSize = 100

type server struct {
	signer.UnimplementedSignerServer
	ctx    context.Context
	cancel context.CancelFunc
	logger *zap.Logger

	*grpc.Server
	tss.Signer
	listener net.Listener

	mtx           sync.Mutex
	hasSubscriber bool
}

// SignMessage implements signer.SignerServer. Ensures we have two goroutines:
// one for reading requests from the client stream and initializing the signing process,
// and one for sending responses (signatures or status updates) to the client stream
func (s *server) SignMessage(stream signer.Signer_SignMessageServer) error {
	if err := s.setSubscriber(); err != nil {
		return err
	}
	defer s.removeSubscriber()

	ch := make(chan *signer.SignResponse, bufferSize) // Buffered channel for sending status updates
	errChan := make(chan error, 2)                    // Buffer size 2 to avoid blocking

	// Goroutine to handle receiving messages from the client
	go s.requestReader(stream, errChan, ch)

	// Goroutine to handle sending responses to the client, including signatures or
	// status updates received on `ch`.
	go func() { errChan <- s.responseSender(stream, ch) }()

	// Wait for the first error from either sending or receiving.
	return <-errChan
}

func (s *server) removeSubscriber() {
	s.mtx.Lock()
	s.hasSubscriber = false
	s.mtx.Unlock()
}

func (s *server) setSubscriber() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.hasSubscriber {
		return status.Error(codes.ResourceExhausted, "only one subscriber allowed at a time")
	}

	s.hasSubscriber = true

	return nil
}

// requestReader listens for incoming requests from the client stream.
// runs until an error occurs or the stream is closed.
// reports errors to errChan and signing issues to issues channel.
func (s *server) requestReader(stream signer.Signer_SignMessageServer, errChan chan error, issues chan *signer.SignResponse) {
	for {
		req, err := stream.Recv()
		if err != nil {
			if err != io.EOF { // If the client closes the stream, io.EOF will be received.
				s.logger.Error("Error receiving from stream", zap.Error(err))
			}
			errChan <- err

			return
		}

		// TODO: support warning and async error reports to client?
		err = s.Signer.BeginAsyncThresholdSigningProtocol(req) // start the signing protocol
		if err == nil {
			continue
		}

		select {
		case issues <- &signer.SignResponse{
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

func wrapsig(sig *common.SignatureData) *signer.SignResponse {
	return &signer.SignResponse{
		Response: &signer.SignResponse_Signature{
			Signature: proto.CloneOf(sig), // ensures a deep copy
		},
	}
}

// responseSender listens for signatures on the channel and sends them to the client stream.
// It returns when the client's context is done or when sending fails.
func (s *server) responseSender(stream signer.Signer_SignMessageServer, ch <-chan *signer.SignResponse) error {
	for {
		var SignResponse *signer.SignResponse
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-stream.Context().Done():
			return stream.Context().Err()
		case sig := <-s.Signer.Responses():
			SignResponse = sig
		case sig, ok := <-ch:
			if !ok {
				// Channel is closed.
				return nil
			}
			SignResponse = sig
		}

		// SignResponse is either set from ProducedSignature or from ch.
		if err := stream.Send(SignResponse); err != nil {
			return err
		}
	}
}

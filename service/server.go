package main

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/protocols/cmp"
	"github.com/xlabs/multi-party-sig/protocols/frost"
	common "github.com/xlabs/tss-common"
	"github.com/xlabs/tss-common/service/signer"
	"github.com/xlabs/tss-lib/v2/tss"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	pubData *signer.PublicData

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

	s.logger.Info("Client subscribed to signing stream")

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

func (s *server) GetPublicData(ctx context.Context, _ *signer.PublicDataRequest) (*signer.PublicData, error) {
	if s.pubData == nil {
		return nil, status.Error(codes.Internal, "public data not initialized")
	}

	return s.pubData, nil
}

func genPubData(s tss.Signer) (*signer.PublicData, error) {
	frostPubBytes, err := getPubkey(s, common.ProtocolFROSTSign)
	if err != nil {
		return nil, err
	}

	ecdsaPubBytes, err := getPubkey(s, common.ProtocolECDSASign)
	if err != nil {
		return nil, err
	}

	return &signer.PublicData{
		FrostPublicData: frostPubBytes,
		EcdsaPublicData: ecdsaPubBytes,
	}, nil
}

func getPubkey(s tss.Signer, prot common.ProtocolType) ([]byte, error) {
	key, err := s.GetPublicKey(prot)
	if err != nil {
		return nil, err
	}

	return key.Curve().MarshalPoint(key)
}

func (s *server) VerifySignature(ctx context.Context, req *signer.VerifySignatureRequest) (*signer.VerifySignatureResponse, error) {
	if req == nil || req.Signature == nil || req.Signature.TrackingId == nil || req.PublicData == nil {
		return nil, status.Error(codes.InvalidArgument, "request, signature, public data, or tracking ID is missing")
	}

	// inspect that req has the same public key as ours for the given protocol
	protocol, err := req.GetSignature().GetTrackingId().GetProtocolType()
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid protocol type in tracking ID")
	}

	var pkeyBytes []byte
	switch protocol {
	case common.ProtocolFROSTSign:
		pkeyBytes = req.GetPublicData().GetFrostPublicData()
	case common.ProtocolECDSASign:
		pkeyBytes = req.GetPublicData().GetEcdsaPublicData()
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported protocol type: %s", protocol.ToString())
	}

	// we currently support only a single curve: secp256k1
	pubkey, err := (&curve.Secp256k1{}).UnmarshalPoint(pkeyBytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid public key")
	}

	var isValid bool
	msg := req.GetSignature().GetM()

	switch protocol {
	case common.ProtocolFROSTSign:
		sig, err := frost.Secp256k1SignatureTranslate(req.GetSignature())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid signature")
		}

		isValid = sig.Verify(pubkey, msg) == nil
	case common.ProtocolECDSASign:
		sig, err := cmp.Secp256k1SignatureTranslate(req.GetSignature())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid signature")
		}

		isValid = sig.Verify(pubkey, msg)
	}

	return &signer.VerifySignatureResponse{IsValid: isValid}, nil
}

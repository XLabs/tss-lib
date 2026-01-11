package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"path"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	common "github.com/xlabs/tss-common"
	"github.com/xlabs/tss-common/service/signer"
	"github.com/xlabs/tss-lib/v2/tss"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

// ensures that a secure connection is made by checking the peer certificate from the gRPC stream
func TestSecureConn(t *testing.T) {
	a := require.New(t)

	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	secretsDir := path.Join(getProjectRootDir(), "tss", "internal", "testutils", "testdata", "tss5")

	serverSecrets, err := tss.LoadGuardianStorage(tss.StorageLoader{Path: path.Join(secretsDir, "guardian0.json")})
	a.NoError(err)
	invalidSecrets, err := tss.LoadGuardianStorage(tss.StorageLoader{Path: path.Join(secretsDir, "guardian1.json")})
	a.NoError(err)

	pool := x509.NewCertPool()
	pool.AddCert(serverSecrets.GetCertificate().Leaf) // only accepting the server's cert.

	l, err := net.Listen("tcp", "localhost:0")
	a.NoError(err)
	defer l.Close()

	// socket specifies to the clients the address of the server.
	socket := l.Addr().String()
	t.Log("Socket address chosen by OS: " + socket)

	serverOpts := []grpc.ServerOption{makeCreds(serverSecrets)}
	grpcServer := grpc.NewServer(serverOpts...)

	// Mock tss.Signer
	mockSigner := &mockTssSigner{
		responses: make(chan *signer.SignResponse),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvr := &server{
		UnimplementedSignerServer: signer.UnimplementedSignerServer{},
		ctx:                       ctx,
		cancel:                    cancel,
		logger:                    logger,
		Signer:                    mockSigner,
		listener:                  l,
		Server:                    grpcServer,
		mtx:                       sync.Mutex{},
	}

	signer.RegisterSignerServer(srvr.Server, srvr)

	go func() {
		if err := srvr.Serve(l); err != nil {
			logger.Error("gRPC server stopped with error", zap.Error(err))
		}
	}()
	defer srvr.Stop()

	validClientCreds := credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*serverSecrets.GetCertificate()},
		RootCAs:      pool,
		ServerName:   "localhost", // This should match a SAN in the server's certificate if it has one
	})

	t.Run("ValidClientCert", func(t *testing.T) {
		a := require.New(t)

		conn, err := grpc.NewClient(socket, grpc.WithTransportCredentials(validClientCreds))
		a.NoError(err)
		defer conn.Close()

		client := signer.NewSignerClient(conn)
		stream, err := client.SignMessage(ctx)
		a.NoError(err)

		// ensuring connection is valid by sending a sign request
		a.NoError(stream.Send(&signer.SignRequest{
			Digest:    []byte{1, 2, 3, 4, 5},
			Protocol:  common.ProtocolFROSTSign.ToString(),
			Committee: []*signer.TypedKey{}, // no committee for this test
		}))

		mockSigner.responses <- &signer.SignResponse{}

		msg, err := stream.Recv()
		a.NoError(err)
		a.NotNil(msg)

		a.NoError(stream.CloseSend())
	})

	t.Run("TestErrorOnSigRequest", func(t *testing.T) {
		conn, err := grpc.NewClient(socket, grpc.WithTransportCredentials(validClientCreds))
		a.NoError(err)
		defer conn.Close()

		client := signer.NewSignerClient(conn)
		stream, err := client.SignMessage(ctx)
		a.NoError(err)

		mockSigner.returnErrOnSignRequest = true
		defer func() { mockSigner.returnErrOnSignRequest = false }()

		// ensuring connection is valid by sending a sign request
		a.NoError(stream.Send(&signer.SignRequest{
			Digest:    []byte{1, 2, 3, 4, 5},
			Protocol:  common.ProtocolFROSTSign.ToString(),
			Committee: []*signer.TypedKey{}, // no committee for this test
		}))

		msg, err := stream.Recv()
		a.NoError(err)
		a.Equal(codes.FailedPrecondition, codes.Code(msg.Response.(*signer.SignResponse_Status).Status.Code))

		a.NoError(stream.CloseSend())
	})
	t.Run("InvalidClientCert", func(t *testing.T) {
		a := require.New(t)

		conn, err := grpc.NewClient(socket,
			grpc.WithTransportCredentials(
				credentials.NewTLS(&tls.Config{
					Certificates: []tls.Certificate{*invalidSecrets.GetCertificate()},
					RootCAs:      pool, // accepting server's cert.
					ServerName:   "localhost",
				}),
			),
		)
		a.NoError(err)
		defer conn.Close()

		client := signer.NewSignerClient(conn)
		_, err = client.SignMessage(ctx) // This will actually establish the connection.
		a.Error(err)
	})

}

type mockTssSigner struct {
	tss.Signer
	responses              chan *signer.SignResponse
	returnErrOnSignRequest bool
}

var errMockSignRequest = errors.New("mock sign request error")

func (m *mockTssSigner) BeginAsyncThresholdSigningProtocol(*signer.SignRequest) error {
	if m.returnErrOnSignRequest {
		return errMockSignRequest
	}
	return nil
}
func (m *mockTssSigner) Responses() <-chan *signer.SignResponse { return m.responses }

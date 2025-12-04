package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net"
	"sync"

	"github.com/xlabs/tss-common/service/signer"
	"github.com/xlabs/tss-lib/v2/tss"
	"github.com/xlabs/tss-lib/v2/tss/comm"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	socket  = flag.String("socket", "localhost:50051", "The server's socket address")
	secrets = flag.String("s", "", "the path to the signer secrets file (must be provided)")
	unsafe  = flag.Bool("unsafe", false, "if set, disables safety checks")
)

func main() {
	flag.Parse()

	runMain(*socket, *secrets, *unsafe)
}

func runMain(socket, secrets string, unsafe bool) bool {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	if len(secrets) == 0 {
		flag.Usage()
		return true
	}

	logger.Info("Loading secrets...")

	st, err := tss.NewGuardianStorageFromFile(secrets)
	if err != nil {
		logger.Fatal("failed to load secrets file", zap.Error(err))
	}

	logger.Info("starting TSS engine...")
	engine, err := tss.NewReliableTSS(st)
	if err != nil {
		logger.Fatal("failed to create TSS signer", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := engine.Start(ctx, logger); err != nil {
		logger.Fatal("failed to start TSS signer", zap.Error(err))
	}

	logger.Info("Starting peer-to-peer communication layer...")
	comms, err := comm.NewServer(logger, engine)
	if err != nil {
		logger.Fatal("failed to create peer-to-peer communication layer", zap.Error(err))
	}

	go func() {
		if err := comms.Run(ctx); err != nil {
			cancel()

			logger.Fatal("peer-to-peer communication layer closing, shutting down.", zap.Error(err))
		}
	}()

	logger.Info("Starting gRPC server...", zap.String("socket", socket))

	l, err := net.Listen("tcp", socket)
	if err != nil {
		panic(err)
	}

	// set up gRPC server options
	serverOpts := []grpc.ServerOption{}

	// add TLS credentials if not disabled
	if unsafe {
		logger.Warn("running in unsafe mode, TLS disabled!")
	} else {
		serverOpts = append(serverOpts, makeCreds(logger, st))
	}

	grpcServer := grpc.NewServer(serverOpts...)

	srvr := &server{
		UnimplementedSignerServer: signer.UnimplementedSignerServer{}, // grpc requirement
		unsafe:                    unsafe,
		ctx:                       ctx,
		cancel:                    cancel,
		logger:                    logger,
		Signer:                    engine,
		listener:                  l,
		Server:                    grpcServer,
		mtx:                       sync.Mutex{},
		hasSubscriber:             false,
	}

	signer.RegisterSignerServer(srvr.Server, srvr)

	go func() {
		if err := srvr.Serve(l); err != nil {
			logger.Error("gRPC server stopped with error", zap.Error(err))
		}

		cancel()
	}()

	logger.Info("Server is running and accepting requests.\nNotice: signature requests demand peers to be online.")

	<-ctx.Done()

	logger.Info("Shutting down gRPC server...")
	srvr.GracefulStop()
	return false
}

func makeCreds(lg *zap.Logger, st *tss.GuardianStorage) grpc.ServerOption {
	clientAcceptedCerts := x509.NewCertPool()

	// We only accept connections from clients that pesent the same cert as we use for ourselves.
	clientAcceptedCerts.AddCert(st.GetCertificate().Leaf)

	return grpc.Creds(credentials.NewTLS(
		&tls.Config{
			MinVersion:   tls.VersionTLS13, // version 1.3
			Certificates: []tls.Certificate{*st.GetCertificate()},

			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  clientAcceptedCerts, // treating each peer as its own CA, will use the given cert as the ID of the peer.
		},
	))
}

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net"
	"sync"

	common "github.com/xlabs/tss-common"
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

type runParams struct {
	ctx    context.Context // set as parameter to allow test injection
	logger *zap.Logger     // set as parameter to allow test injection

	socket  string
	secrets string
	unsafe  bool
}

func main() {
	flag.Parse()

	if *secrets == "" {
		flag.Usage()
		return
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	runMain(runParams{
		ctx:    context.Background(),
		logger: logger,

		socket:  *socket,
		secrets: *secrets,
		unsafe:  *unsafe,
	})
}

// separated to allow test injection
func runMain(p runParams) {
	if p.logger == nil {
		panic("logger must be provided")
	}
	if p.ctx == nil {
		p.logger.Fatal("main context must be provided")
	}
	if p.secrets == "" {
		p.logger.Fatal("secrets file path must be provided")
	}

	p.logger.Info("Loading secrets...")

	st, err := tss.LoadGuardianStorage(tss.StorageLoader{
		Path: p.secrets,
	})
	if err != nil {
		p.logger.Fatal("failed to load secrets file", zap.Error(err))
	}

	if !st.HasEthKeyMappings() {
		p.logger.Warn("no Ethereum key mappings found in secrets file! Leader mechanism will not work without them.")
	}

	supportedProtocols := st.ExistingSecretsForSigning()

	p.logger.Info(
		"Loaded secrets, starting server...",
		zap.Strings("loaded_schemes", protocolsToString(supportedProtocols...)),
	)

	p.logger.Info("starting TSS engine...")
	engine, err := tss.NewReliableTSS(st)
	if err != nil {
		p.logger.Fatal("failed to create TSS signer", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()

	if err := engine.Start(ctx, p.logger); err != nil {
		p.logger.Fatal("failed to start TSS signer", zap.Error(err))
	}

	pubData, err := genPubData(engine, supportedProtocols)
	if err != nil {
		p.logger.Fatal("failed to generate public data", zap.Error(err))
	}

	p.logger.Info("Starting peer-to-peer communication layer...")
	comms, err := comm.NewServer(p.logger, engine)
	if err != nil {
		p.logger.Fatal("failed to create peer-to-peer communication layer", zap.Error(err))
	}

	go func() {
		if err := comms.Run(ctx); err != nil {
			cancel()

			if err == context.Canceled {
				p.logger.Info("peer-to-peer communication layer closed")

				return
			}

			p.logger.Fatal("peer-to-peer communication layer closing, shutting down.", zap.Error(err))
		}
	}()

	p.logger.Info("Starting gRPC server...", zap.String("socket", p.socket))

	l, err := net.Listen("tcp", p.socket)
	if err != nil {
		p.logger.Fatal("failed to listen on socket", zap.String("socket", p.socket), zap.Error(err))
	}

	// set up gRPC server options
	serverOpts := []grpc.ServerOption{}

	// add TLS credentials if not disabled
	if p.unsafe {
		p.logger.Warn("running in unsafe mode, TLS disabled!")
	} else {
		serverOpts = append(serverOpts, makeCreds(st))
	}

	grpcServer := grpc.NewServer(serverOpts...)

	srvr := &server{
		UnimplementedSignerServer: signer.UnimplementedSignerServer{}, // grpc requirement

		secretsPath: p.secrets,
		ctx:         ctx,
		cancel:      cancel,
		logger:      p.logger,
		Signer:      engine,
		listener:    l,
		Server:      grpcServer,
		pubData:     pubData,

		mtx:           sync.Mutex{},
		hasSubscriber: false,
	}

	signer.RegisterSignerServer(srvr.Server, srvr)

	go func() {
		if err := srvr.Serve(l); err != nil {
			p.logger.Error("gRPC server stopped with error", zap.Error(err))
		}

		cancel()
	}()

	p.logger.Info("Server is running and accepting requests.\nNotice: signature requests demand peers to be online.")

	<-ctx.Done()

	p.logger.Info("Shutting down gRPC server...")
	srvr.GracefulStop()
}

// protocolsToString converts a list of ProtocolType to their string representations.
// Used for logging purposes.
func protocolsToString(prot ...common.ProtocolType) []string {
	typesAsString := make([]string, 0, len(prot))
	for _, t := range prot {
		typesAsString = append(typesAsString, t.ToString())
	}

	return typesAsString
}

func makeCreds(st *tss.GuardianStorage) grpc.ServerOption {
	clientAcceptedCerts := x509.NewCertPool()

	// We only accept connections from clients that present the same cert as we use for ourselves.
	// That is, only the entity that has the authority to request signatures can connect.
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

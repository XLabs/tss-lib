package main

import (
	"context"
	"flag"
	"net"
	"strconv"
	"sync"

	"github.com/xlabs/tss-common/service/signer"
	"github.com/xlabs/tss-lib/v2/tss"
	"github.com/xlabs/tss-lib/v2/tss/comm"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

var (
	port    = flag.Int("p", 50052, "The server's port")
	secrets = flag.String("s", "", "the path to the signer secrets file (must be provided)")
)

func main() {
	flag.Parse()

	prt := *port

	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	if *secrets == "" {
		flag.Usage()

		return
	}

	logger.Info("Loading secrets...")

	st, err := tss.NewGuardianStorageFromFile(*secrets)
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

	logger.Info("Starting gRPC server...", zap.Int("port", prt))

	l, err := net.Listen("tcp", "[::]:"+strconv.Itoa(prt))
	if err != nil {
		panic(err)
	}

	srvr := &Server{
		UnimplementedSignerServer: signer.UnimplementedSignerServer{}, // grpc requirement

		ctx:    ctx,
		cancel: cancel,

		logger: logger,
		Signer: engine,

		listener: l,
		Server:   grpc.NewServer(),

		waitersLock:  sync.Mutex{},
		waiters:      map[uint64]chan<- *signer.SignResponse{},
		nextWaiterID: 0,
	}

	signer.RegisterSignerServer(srvr.Server, srvr)

	go srvr.fanOutSignatures()

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
}

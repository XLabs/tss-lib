package main

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func getProjectRootDir() string {
	_, b, _, _ := runtime.Caller(0)
	basepath := filepath.Dir(b)

	for {
		if !strings.Contains(basepath, "tss-lib") {
			break
		}
		basepath = filepath.Dir(basepath)
	}
	return path.Join(basepath, "tss-lib")
}

var testSecretsPath = filepath.Join(getProjectRootDir(), "tss", "internal", "testutils", "testdata", "tss5", "guardian0.json")

func TestRunMain(t *testing.T) {
	a := require.New(t)

	// Create a logger that panics on fatal errors, which we can recover from.
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		os.Stdout,
		zapcore.DebugLevel,
	)
	testLogger := zap.New(core, zap.WithFatalHook(zapcore.WriteThenPanic))

	secretsPath := testSecretsPath

	a.Panics(func() {
		runMain(runParams{
			ctx:     context.Background(),
			logger:  testLogger,
			secrets: "",
		})
	})

	t.Run("should start and stop gracefully", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			runMain(runParams{
				ctx:     ctx,
				logger:  testLogger,
				socket:  "localhost:0",
				secrets: secretsPath,
				unsafe:  false,
			})
		}()

		cancel()
		wg.Wait()
	})

	t.Run("unsafe should start and stop gracefully", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			runMain(runParams{
				ctx:     ctx,
				logger:  testLogger,
				socket:  "localhost:0",
				secrets: secretsPath,
				unsafe:  true,
			})
		}()

		cancel()
		wg.Wait()
	})
	a.PanicsWithValue("failed to listen on socket", func() {
		runMain(runParams{
			ctx:     context.Background(),
			logger:  testLogger,
			socket:  "sck",
			secrets: secretsPath,
			unsafe:  true,
		})
	})

	a.PanicsWithValue("failed to load secrets file", func() {
		runMain(runParams{
			ctx:     context.Background(),
			logger:  testLogger,
			socket:  "localhost:0",
			secrets: "nonexistent.json",
			unsafe:  true,
		})
	})
}

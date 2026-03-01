package testutils

import (
	"errors"
	"fmt"
	"path"
	"runtime"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// MustGetMockGuardianTssStorage returns the path to a mock guardian storage file.
func MustGetMockGuardianTssStorage() string {
	str, err := GetMockGuardianTssStorage(0)
	if err != nil {
		panic(err)
	}
	return str
}

// GetGuardianStorageDir returns a directory to store guardian TSS data.
// guardianTssStorageSet should be somthing like tss<NumServers> If not provided, it defaults to "tss5".
func GetGuardianStorageDir(guardianTssStorageSet ...string) (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("could not get runtime.Caller(0)")
	}

	setFolder := "tss5"
	if len(guardianTssStorageSet) > 0 {
		setFolder = guardianTssStorageSet[0]
	}

	return path.Join(path.Dir(file), "testdata", setFolder), nil
}
func GetMockGuardianTssStorage(guardianIndex int, guardianTssStorageSet ...string) (string, error) {
	dir, err := GetGuardianStorageDir(guardianTssStorageSet...)
	if err != nil {
		return "", err
	}

	guardianStorageFname := path.Join(dir, fmt.Sprintf("guardian%d.json", guardianIndex))
	return guardianStorageFname, nil
}

func NewTestLogger(t testing.TB) *zap.Logger {
	logger := zaptest.NewLogger(t)
	t.Cleanup(func() {
		_ = logger.Sync()
	})
	return logger
}

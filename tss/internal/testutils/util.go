package testutils

import (
	"errors"
	"fmt"
	"path"
	"runtime"
	"testing"

	"go.uber.org/zap"
)

// MustGetMockGuardianTssStorage returns the path to a mock guardian storage file.
func MustGetMockGuardianTssStorage() string {
	str, err := GetMockGuardianTssStorage(0)
	if err != nil {
		panic(err)
	}
	return str
}

func GetMockGuardianTssStorage(guardianIndex int, guardianTssStorageSet ...string) (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("could not get runtime.Caller(0)")
	}

	setFolder := "tss5"
	if len(guardianTssStorageSet) > 0 {
		setFolder = guardianTssStorageSet[0]
	}
	guardianStorageFname := path.Join(path.Dir(file), "testdata", setFolder, fmt.Sprintf("guardian%d.json", guardianIndex))
	return guardianStorageFname, nil
}

func NewTestLogger(t testing.TB) *zap.Logger {
	lg, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create test logger: %v", err)
	}
	return lg
}

package testutils

import (
	"errors"
	"fmt"
	"path"
	"runtime"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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
	core, recorded := observer.New(zap.DebugLevel)
	t.Cleanup(func() {
		logs := recorded.All()
		for _, log := range logs {
			t.Logf("TSS LOG [%s]: %s\n", log.Level.String(), log.Message)
			for _, field := range log.Context {
				t.Logf("    %s: %v\n", field.Key, field.Interface)
			}
		}
	})

	return zap.New(core)
}

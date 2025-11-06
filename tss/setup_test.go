package tss

import (
	"testing"

	"github.com/xlabs/tss-lib/v2/tss/internal/testutils"
)

const (
	Participants = 5
	Threshold    = 2 // not including, meaning 3 guardians are needed to sign.
)

func TestGuardianStorageUnmarshal(t *testing.T) {
	var st GuardianStorage
	err := st.load(testutils.MustGetMockGuardianTssStorage())
	if err != nil {
		t.Error(err)
	}
}

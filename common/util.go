package common

import (
	"bytes"
	"fmt"
)

func ConvertBoolArrayToByteArray(bools []bool) []byte {
	byteArray := make([]byte, (len(bools)+7)/8) // Each byte can hold up to 8 bools, so we round up

	for i, b := range bools {
		if b {
			byteArray[i/8] |= 1 << (i % 8) // Set the bit in the correct position
		}
	}

	return byteArray
}

func (t *TrackingID) BitLen() int {
	return len(t.PartiesState) * 8
}

// Will panic if i is out of bounds
func (t *TrackingID) PartyStateOk(i int) bool {
	// Find the index of the byte containing the bit
	byteIndex := i / 8
	// Find the position of the bit within the byte
	bitPosition := uint(i % 8)

	// Use bitwise AND to check if the specific bit is set
	// we check for != 0 since it can be different byte values (depending on the bit position)
	return t.PartiesState[byteIndex]&(1<<bitPosition) != 0
}

// ConvertByteArrayToBoolArray converts a packed []byte back to a []bool.
func ConvertByteArrayToBoolArray(byteArray []byte, numBools int) []bool {
	bools := make([]bool, numBools)

	for i := 0; i < numBools; i++ {
		bools[i] = (byteArray[i/8] & (1 << (i % 8))) != 0 // Check if the bit is set
	}

	return bools
}

const nilTrackID = "nilTrackID"

func (t *TrackingID) ToString() string {
	if t == nil {
		return nilTrackID
	}

	return fmt.Sprintf("%x-%x-%x", t.Digest, t.PartiesState, t.AuxilaryData)
}

func (x *TrackingID) ToByteString() []byte {
	return []byte(x.ToString())
}

var errNilTrackID = fmt.Errorf("nil TrackingID")

func (t *TrackingID) FromString(s string) error {
	if t == nil {
		return errNilTrackID
	}

	if s == nilTrackID {
		return errNilTrackID
	}

	// i need to handle cases where there are no auxilary data or parties state
	// i.e. "010203--" or "010203-040506-"

	// Split the string into parts
	parts := bytes.Split([]byte(s), []byte{'-'})
	if len(parts) != 3 {
		return fmt.Errorf("invalid TrackingID format: %s", s)
	}
	// Parse the first part (Digest)
	if len(parts[0]) == 0 {
		return fmt.Errorf("invalid TrackingID format: %s", s)
	}
	t.Digest = make([]byte, len(parts[0]))
	if _, err := fmt.Sscanf(string(parts[0]), "%x", &t.Digest); err != nil {
		return fmt.Errorf("failed to parse TrackingID from string: %w", err)
	}
	// Parse the second part (PartiesState)

	t.PartiesState = nil
	if len(parts[1]) > 0 {
		t.PartiesState = make([]byte, len(parts[1]))

		if _, err := fmt.Sscanf(string(parts[1]), "%x", &t.PartiesState); err != nil {
			return fmt.Errorf("failed to parse TrackingID from string: %w", err)
		}
	}

	// Parse the third part (AuxilaryData)
	t.AuxilaryData = nil
	if len(parts[2]) > 0 {
		t.AuxilaryData = make([]byte, len(parts[2]))
		if _, err := fmt.Sscanf(string(parts[2]), "%x", &t.AuxilaryData); err != nil {
			return fmt.Errorf("failed to parse TrackingID from string: %w", err)
		}
	}

	return nil
}

func (t *TrackingID) Equals(other *TrackingID) bool {
	if t == nil && other == nil {
		return true
	}

	if t == nil || other == nil {
		return false
	}

	return bytes.Equal(t.Digest, other.Digest) &&
		bytes.Equal(t.PartiesState, other.PartiesState) &&
		bytes.Equal(t.AuxilaryData, other.AuxilaryData)
}

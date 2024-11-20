package common

import "fmt"

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

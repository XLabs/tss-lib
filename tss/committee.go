package tss

import (
	"errors"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"
)

var errRepeatingCommitteeMembers = errors.New("couldn't map all committee members")
var errCommitteeTooSmall = errors.New("committee is too small")

func (st *GuardianStorage) translateEthCommitteeMembers(committee [][]byte) (map[SenderIndex]*Identity, error) {
	signersID := make(map[SenderIndex]*Identity, len(committee))

	for _, member := range committee {
		if len(member) != ethcommon.AddressLength {
			return nil, fmt.Errorf("invalid committee member length: %d", len(member))
		}

		memberAddress := ethcommon.BytesToAddress(member)
		id, err := st.fetchIdentityFromVaav1Pubkey(memberAddress)
		if err != nil {
			return nil, fmt.Errorf("couldn't map committee member %s to guardian identity: %w", memberAddress.String(), err)
		}

		signersID[id.CommunicationIndex] = id
	}

	if len(signersID) != len(committee) {
		return nil, errRepeatingCommitteeMembers
	}

	if st.Threshold > len(signersID) {
		return nil, errCommitteeTooSmall
	}

	return signersID, nil
}

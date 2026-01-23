package tss

import (
	"errors"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"
	common "github.com/xlabs/tss-common"
	"github.com/xlabs/tss-common/service/signer"
)

var errMappingCommitteeMembers = errors.New("couldn't map all committee members")
var errCommitteeTooSmall = errors.New("committee is too small")

func (st *GuardianStorage) translateEthCommitteeMembers(committee []*signer.TypedKey) (map[SenderIndex]*Identity, error) {
	signersID := make(map[SenderIndex]*Identity, len(committee))

	for _, member := range committee {
		if member == nil {
			return nil, fmt.Errorf("nil committee member")
		}

		if member.Type != signer.TypedKey_EthKey {
			return nil, fmt.Errorf("unsupported committee member type: %s", member.Type.Descriptor().FullName())
		}

		if len(member.Key) != ethcommon.AddressLength {
			return nil, fmt.Errorf("invalid committee member length: %d", len(member.Key))
		}

		memberAddress := ethcommon.BytesToAddress(member.Key)
		id, err := st.fetchIdentityFromEthAddress(memberAddress)
		if err != nil {
			return nil, fmt.Errorf("couldn't map committee member %s to guardian identity: %w", memberAddress.String(), err)
		}

		signersID[id.CommunicationIndex] = id
	}

	if len(signersID) != len(committee) {
		return nil, errMappingCommitteeMembers // either duplicate members or some members couldn't be mapped.
	}

	if st.Threshold > len(signersID) {
		return nil, errCommitteeTooSmall
	}

	return signersID, nil
}

func (t *Engine) findExcludeesFromCommittee(members map[SenderIndex]*Identity) []*common.PartyID {
	if len(members) == 0 {
		return nil
	}

	if len(members) < t.GuardianStorage.Threshold {
		return nil // not enough guardians to form a committee.
	}

	// grab everyone that is not in the committee
	var excludedSigners []*common.PartyID
	for _, id := range t.GuardianStorage.Identities {
		if _, ok := members[id.CommunicationIndex]; !ok {
			excludedSigners = append(excludedSigners, id.Pid)
		}
	}

	return excludedSigners
}

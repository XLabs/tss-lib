package sign

import (
	"fmt"

	"github.com/xlabs/tss-lib/v2/common"
	"github.com/xlabs/tss-lib/v2/frost/keygen"
	"github.com/xlabs/tss-lib/v2/internal/party"
	"github.com/xlabs/tss-lib/v2/internal/protocol"
	"github.com/xlabs/tss-lib/v2/internal/round"
)

const (
	// Frost Sign with Threshold.
	protocolID        = "frost/sign-threshold"
	protocolIDTaproot = "frost/sign-threshold-taproot"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

func StartSignCommon(taproot bool, result *keygen.Config, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			FinalRoundNumber: protocolRounds,
			SelfID:           result.ID,
			PartyIDs:         signers,
			Threshold:        result.Threshold,
			Group:            result.PublicKey.Curve(),
			ProtocolID:       protocolID,
			TrackingID:       &common.TrackingID{},
		}

		if err := info.TrackingID.FromString(string(sessionID)); err != nil {
			return nil, fmt.Errorf("sign.StartSign: %w", err)
		}

		if taproot {
			info.ProtocolID = protocolIDTaproot
		} else {
			info.ProtocolID = protocolID
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("sign.StartSign: %w", err)
		}
		return &round1{
			Helper:  helper,
			taproot: taproot,
			M:       messageHash,
			Y:       result.PublicKey,
			YShares: result.VerificationShares.Points,
			s_i:     result.PrivateShare,
		}, nil
	}
}

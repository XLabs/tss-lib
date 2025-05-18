package keygen

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/xlabs/tss-lib/v2/frost/internal/hash"
	"github.com/xlabs/tss-lib/v2/frost/internal/math/curve"
	"github.com/xlabs/tss-lib/v2/frost/internal/math/polynomial"
	"github.com/xlabs/tss-lib/v2/frost/internal/round"
	"github.com/xlabs/tss-lib/v2/frost/internal/types"
	zksch "github.com/xlabs/tss-lib/v2/frost/internal/zk/sch"
)

func NewBroadcast2(Phi_i *polynomial.Exponent, Sigma_i *zksch.Proof, Commitment []byte) (*Broadcast2, error) {
	phii, err := Phi_i.MarshalBinary()
	if err != nil {
		return nil, err
	}

	sigmai, err := cbor.Marshal(Sigma_i)
	if err != nil {
		return nil, err
	}

	return &Broadcast2{
		Phii:       phii,
		Sigmai:     sigmai,
		Commitment: Commitment,
	}, nil
}

// Reliable implements round.ReliableBroadcastContent.
func (b *Broadcast2) Reliable() bool {
	return true
}

// RoundNumber implements round.Content.
func (x *Broadcast2) RoundNumber() round.Number {
	return 2
}

// ValidateBasic implements round.Content.
func (x *Broadcast2) ValidateBasic() bool {
	if x == nil {
		return false
	}

	return len(x.Phii) > 0 && len(x.Sigmai) > 0 && len(x.Commitment) > 0
}

func NewBroadcast3(c_l types.RID, decommitment hash.Decommitment) *Broadcast3 {
	return &Broadcast3{
		Cl:           c_l,
		Decommitment: decommitment,
		sizeCache:    0,
	}
}

// Reliable implements round.BroadcastRoundContent.
func (b *Broadcast3) Reliable() bool {
	return true
}

// RoundNumber implements round.Content.
func (x *Broadcast3) RoundNumber() round.Number {
	return 3
}

// ValidateBasic implements round.Content.
func (x *Broadcast3) ValidateBasic() bool {
	if x == nil {
		return false
	}

	return len(x.Decommitment) > 0 && len(x.Cl) > 0
}

func NewMessage3(f_li curve.Scalar) (*Message3, error) {
	scalarbits, err := f_li.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &Message3{
		FLi: scalarbits,
	}, nil
}

// RoundNumber implements round.Content.
func (x *Message3) RoundNumber() round.Number {
	return 3
}

// ValidateBasic implements round.Content.
func (x *Message3) ValidateBasic() bool {
	if x == nil {
		return false
	}

	return len(x.FLi) > 0
}

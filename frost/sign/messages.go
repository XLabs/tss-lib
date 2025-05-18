package sign

import (
	"github.com/xlabs/tss-lib/v2/frost/internal/math/curve"
	"github.com/xlabs/tss-lib/v2/frost/internal/round"
)

func NewBroadcast2(Di, Ei curve.Point) (round.Content, error) {
	DiBinary, err := Di.MarshalBinary()
	if err != nil {
		return nil, err
	}
	EiBinary, err := Ei.MarshalBinary()
	if err != nil {
		return nil, err
	}

	content := &Broadcast2{
		Di: DiBinary,
		Ei: EiBinary,
	}

	return content, nil
}

func (b *Broadcast2) RoundNumber() int {
	return 2
}

func (b *Broadcast2) ValidateBasic() bool {
	if b == nil {
		return false
	}

	if len(b.Di) == 0 || len(b.Di) > 33 {
		return false
	}

	if len(b.Ei) == 0 || len(b.Ei) > 33 {
		return false
	}

	return true
}

func (b *Broadcast2) Reliable() bool {
	return true
}

// Broadcast3:
func NewBroadcast3(z_i curve.Scalar) (*Broadcast3, error) {
	z_iBinary, err := z_i.MarshalBinary()
	if err != nil {
		return nil, err
	}

	content := &Broadcast3{
		Zi: z_iBinary,
	}

	return content, nil
}

func (b *Broadcast3) RoundNumber() int {
	return 3
}

func (b *Broadcast3) ValidateBasic() bool {
	if b == nil {
		return false
	}

	if len(b.Zi) == 0 {
		return false
	}

	return true
}

// This message should be broadcast, but not reliably.
// TODO: Check why they set it to false in the original code.
// perhaps this is a mistake.
func (b *Broadcast3) Reliable() bool {
	return false
}

package sign

import (
	"fmt"

	"github.com/xlabs/tss-lib/v2/internal/math/curve"
	"github.com/xlabs/tss-lib/v2/internal/party"
	"github.com/xlabs/tss-lib/v2/internal/round"
	"github.com/xlabs/tss-lib/v2/internal/taproot"
	"github.com/xlabs/tss-lib/v2/tss"
)

// This corresponds with step 7 of Figure 3 in the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
//
// The big difference, once again, stems from their being no signing authority.
// Instead, each participant calculates the signature on their own.
type round3 struct {
	*round2
	// R is the group commitment, and the first part of the consortium signature
	R curve.Point
	// RShares is the fraction each participant contributes to the group commitment
	//
	// This corresponds to R_i in the Frost paper
	RShares map[party.ID]curve.Point
	// c is the challenge, computed as H(R, Y, m).
	c curve.Scalar
	// z contains the response from each participant
	//
	// z[i] corresponds to zᵢ in the Frost paper
	z map[party.ID]curve.Scalar

	// Lambda contains all Lagrange coefficients of the parties participating in this session.
	// Lambda[l] = λₗ
	Lambda map[party.ID]curve.Scalar
}

type broadcast3 struct {
	round.NormalBroadcastContent
	// Z_i is the response scalar computed by the sender of this message.
	Z_i curve.Scalar
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*Broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !body.ValidateBasic() {
		return round.ErrInvalidContent
	}

	Zi := r.Group().NewScalar()
	if err := Zi.UnmarshalBinary(body.Zi); err != nil {
		return fmt.Errorf("failed to unmarshal zᵢ: %w", err)
	}

	var expected, actual curve.Point
	if r.taproot {
		// These steps come from Figure 3 of the Frost paper.

		// 7.b "Verify the validity of each response by checking
		//
		//    zᵢ • G = Rᵢ + c * λᵢ * Yᵢ
		//
		// for each share zᵢ, i in S. If the equality does not hold, identify and report the
		// misbehaving participant, and then abort. Otherwise, continue."
		//
		// Note that step 7.a is an artifact of having a signing authority. In our case,
		// we've already computed everything that step computes.
		expected = r.c.Act(r.Lambda[from].Act(r.YShares[from])).Add(r.RShares[from])

		actual = Zi.ActOnBase()

	} else {
		left := r.c.Act(r.Lambda[from].Act(r.YShares[from]))
		right := r.RShares[from]
		expected = left.Sub(right)

		// z_i = (λᵢ sᵢ c) - [dᵢ + (eᵢ ρᵢ)] here.
		actual = Zi.ActOnBase() // z_i*G = [ C * λᵢ *si  - (di +ei*rhoi)]G=
		// 							 (C * λᵢ *si)G  - (di +ei*rhoi)G =
		// 							 (C * λᵢ)Yᵢ - (di +ei*rhoi)G=
		// 							 (C * λᵢ)Yᵢ - Rshares[i]
	}

	if !actual.Equal(expected) {
		return fmt.Errorf("round3: failed to verify response from %v", from)
	}

	r.z[from] = Zi

	return nil
}

// VerifyMessage implements round.Round.
func (round3) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round3) StoreMessage(round.Message) error { return nil }

func (r *round3) CanFinalize() bool {
	// Rshares, z lambda:
	t := r.Threshold() + 1

	if len(r.RShares) < t || len(r.z) < t || len(r.Lambda) < t {
		return false
	}

	// check we received from all participants:
	for _, l := range r.OtherPartyIDs() {
		if _, ok := r.RShares[l]; !ok {
			return false
		}

		if _, ok := r.z[l]; !ok {
			return false
		}

		if _, ok := r.Lambda[l]; !ok {
			return false
		}
	}

	return true
}

// Finalize implements round.Round.
func (r *round3) Finalize(chan<- tss.ParsedMessage) (round.Session, error) {
	// These steps come from Figure 3 of the Frost paper.

	// 7.c "Compute the group's response z = ∑ᵢ zᵢ"
	z := r.Group().NewScalar()
	for _, z_l := range r.z {
		z.Add(z_l)
	}

	if !r.taproot {
		// in non-taproot mode, we need to negate the response, so
		// we receive a response where z corresponds to the eth-contract signature value s = k - x*challenge.
		z = z.Negate()
	}

	// The format of our signature depends on using taproot, naturally
	if r.taproot {
		sig := taproot.Signature(make([]byte, 0, taproot.SignatureLen))
		sig = append(sig, r.R.(*curve.Secp256k1Point).XBytes()...)
		zBytes, err := z.MarshalBinary()
		if err != nil {
			return r, err
		}
		sig = append(sig, zBytes[:]...)

		taprootPub := taproot.PublicKey(r.Y.(*curve.Secp256k1Point).XBytes())

		if !taprootPub.Verify(sig, r.M) {
			return r.AbortRound(fmt.Errorf("generated signature failed to verify")), nil
		}

		return r.ResultRound(sig), nil
	} else {
		sig := Signature{
			R: r.R,
			Z: z,
		}

		if err := sig.Verify(r.Y, r.M); err != nil {
			return r.AbortRound(fmt.Errorf("generated signature failed to verify: %w", err)), nil
		}

		return r.ResultRound(sig), nil
	}
}

// MessageContent implements round.Round.
func (round3) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	s, _ := r.Group().NewScalar().MarshalBinary()

	return &Broadcast3{
		Zi: s,
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }

package keygen

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/xlabs/tss-lib/v2/frost/internal/hash"
	"github.com/xlabs/tss-lib/v2/frost/internal/math/curve"
	"github.com/xlabs/tss-lib/v2/frost/internal/math/polynomial"
	"github.com/xlabs/tss-lib/v2/frost/internal/party"
	"github.com/xlabs/tss-lib/v2/frost/internal/round"
	"github.com/xlabs/tss-lib/v2/frost/internal/types"
	sch "github.com/xlabs/tss-lib/v2/frost/internal/zk/sch"
	"github.com/xlabs/tss-lib/v2/tss"
)

// This round corresponds with steps 5 of Round 1, 1 of Round 2, Figure 1 in the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
type round2 struct {
	*round1
	// f_i is the polynomial this participant uses to share their contribution to
	// the secret
	f_i *polynomial.Polynomial
	// Phi contains the polynomial commitment for each participant, ourselves included.
	//
	// Phi[l][k] corresponds to ϕₗₖ in the Frost paper.
	Phi map[party.ID]*polynomial.Exponent
	// ChainKeyDecommitment will be used to decommit our contribution to the chain key
	ChainKeyDecommitment hash.Decommitment

	// ChainKey will be the final bit of randomness everybody contributes to.
	//
	// This is an addition to FROST, which we include for key derivation
	ChainKeys map[party.ID]types.RID
	// ChainKeyCommitments holds the commitments for the chain key contributions
	ChainKeyCommitments map[party.ID]hash.Commitment
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// Phi_i is the commitment to the polynomial that this participant generated.
	Phi_i *polynomial.Exponent
	// Sigma_i is the Schnorr proof of knowledge of the participant's secret
	Sigma_i *sch.Proof
	// Commitment = H(cᵢ, uᵢ)
	Commitment hash.Commitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	tmp, ok := msg.Content.(*Broadcast2)
	if !ok || !tmp.ValidateBasic() {
		return round.ErrInvalidContent
	}

	phii := polynomial.EmptyExponent(r.Group())
	if err := phii.UnmarshalBinary(tmp.Phii); err != nil {
		return fmt.Errorf("failed to unmarshal Phi_i: %w", err)
	}

	sigmai := sch.EmptyProof(r.Group())
	if err := cbor.Unmarshal(tmp.Sigmai, sigmai); err != nil {
		return fmt.Errorf("failed to unmarshal Sigma_i: %w", err)
	}

	body := &broadcast2{
		Phi_i:      phii,
		Sigma_i:    sigmai,
		Commitment: tmp.Commitment,
	}

	// check nil
	if (!r.refresh && !body.Sigma_i.IsValid()) || body.Phi_i == nil {
		return round.ErrNilFields
	}

	if err := body.Commitment.Validate(); err != nil {
		return fmt.Errorf("commitment: %w", err)
	}

	// These steps come from Figure 1, Round 1 of the Frost paper

	// 5. "Upon receiving ϕₗ, σₗ from participants 1 ⩽ l ⩽ n, participant
	// Pᵢ verifies σₗ = (Rₗ, μₗ), aborting on failure, by checking
	// Rₗ = μₗ * G - cₗ * ϕₗ₀, where cₗ = H(l, ctx, ϕₗ₀, Rₗ).
	//
	// Upon success, participants delete { σₗ | 1 ⩽ l ⩽ n }"
	//
	// Note: I've renamed Cₗ to Φₗ, as in the previous round.
	// R_l = Rₗ, mu_l = μₗ
	//
	// To see why this is correct, compare this verification with the proof we
	// produced in the previous round. Note how we do the same hash cloning,
	// but this time with the ID of the message sender.

	// Refresh: There's no proof to verify, but instead check that the constant is identity
	if r.refresh {
		if !body.Phi_i.Constant().IsIdentity() {
			return fmt.Errorf("party %s sent a non-zero constant while refreshing", from)
		}
	} else {
		if !body.Sigma_i.Verify(r.Helper.HashForID(from), body.Phi_i.Constant(), nil) {
			return fmt.Errorf("failed to verify Schnorr proof for party %s", from)
		}
	}

	r.Phi[from] = body.Phi_i
	r.ChainKeyCommitments[from] = body.Commitment
	return nil
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

func (r *round2) Finalize(out chan<- tss.ParsedMessage) (round.Session, error) {
	// These steps come from Figure 1, Round 2 of the Frost paper

	// 1. "Each P_i securely sends to each other participant Pₗ a secret share
	// (l, fᵢ(l)), deleting f_i and each share afterward except for (i, fᵢ(i)),
	// which they keep for themselves."

	if err := r.BroadcastMessage(out, NewBroadcast3(r.ChainKeys[r.SelfID()], r.ChainKeyDecommitment)); err != nil {
		return r, err
	}

	for _, l := range r.OtherPartyIDs() {
		msg, err := NewMessage3(r.f_i.Evaluate(l.Scalar(r.Group())))
		if err != nil {
			return r, err
		}

		if err := r.SendMessage(out, msg, l); err != nil {
			return r, err
		}
	}

	selfShare := r.f_i.Evaluate(r.SelfID().Scalar(r.Group()))
	return &round3{
		round2:    r,
		shareFrom: map[party.ID]curve.Scalar{r.SelfID(): selfShare},
	}, nil
}

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (r *round2) BroadcastContent() round.BroadcastContent {
	b, _ := NewBroadcast2(polynomial.EmptyExponent(r.Group()), sch.EmptyProof(r.Group()), hash.Commitment{})
	return b
}

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }

package sign

import (
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/xlabs/tss-lib/v2/frost/internal/hash"
	"github.com/xlabs/tss-lib/v2/frost/internal/math/curve"
	"github.com/xlabs/tss-lib/v2/frost/internal/math/polynomial"
	"github.com/xlabs/tss-lib/v2/frost/internal/math/sample"
	"github.com/xlabs/tss-lib/v2/frost/internal/party"
	"github.com/xlabs/tss-lib/v2/frost/internal/round"
	"github.com/xlabs/tss-lib/v2/frost/internal/taproot"
)

// This round roughly corresponds with steps 3-6 of Figure 3 in the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
//
// The main differences stem from the lack of a signature authority.
//
// This means that instead of receiving a bundle of all the commitments, instead
// each participant sends us their commitment directly.
//
// Then, instead of sending our scalar response to the authority, we broadcast it
// to everyone instead.
type round2 struct {
	*round1
	// d_i = dᵢ is the first nonce we've created.
	d_i curve.Scalar
	// e_i = eᵢ is the second nonce we've created.
	e_i curve.Scalar
	// D[i] = Dᵢ will contain all of the commitments created by each party, ourself included.
	D map[party.ID]curve.Point
	// E[i] = Eᵢ will contain all of the commitments created by each party, ourself included.
	E map[party.ID]curve.Point
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*Broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	Di := r.Group().NewPoint()
	Ei := r.Group().NewPoint()

	if err := Di.UnmarshalBinary(body.Di); err != nil {
		return fmt.Errorf("failed to unmarshal Dᵢ: %w", err)
	}

	if err := Ei.UnmarshalBinary(body.Ei); err != nil {
		return fmt.Errorf("failed to unmarshal Eᵢ: %w", err)
	}

	// This section roughly follows Figure 3.

	// 3. "After receiving (m, B), each Pᵢ first validates the message m,
	// and then checks Dₗ, Eₗ in Gˣ for each commitment in B, aborting if
	// either check fails."
	//
	// We make a few departures.
	//
	// We implicitly assume that the message validation has happened before
	// calling this protocol.
	//
	// We also receive each Dₗ, Eₗ from the participant l directly, instead of
	// an entire bundle from a signing authority.
	if Di.IsIdentity() || Ei.IsIdentity() {
		return fmt.Errorf("nonce commitment is the identity point")
	}

	r.D[msg.From] = Di
	r.E[msg.From] = Ei

	return nil
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// This essentially follows parts of Figure 3.

	// 4. "Each Pᵢ then computes the set of binding values ρₗ = H₁(l, m, B). // l is related to the ID of the players.
	// Each Pᵢ then derives the group commitment R = ∑ₗ Dₗ + ρₗ * Eₗ and //  R = kG
	// the challenge c = H₂(Address(R), Y, m)." // Y should be the public key?
	//
	// It's easier to calculate H(m, B, l), that way we can simply clone the hash
	// state after H(m, B), instead of rehashing them each time.
	//
	// We also use a hash of the message, instead of the message directly.

	rho := make(map[party.ID]curve.Scalar)
	// This calculates H(m, B), allowing us to avoid re-hashing this data for
	// each extra party l.
	rhoPreHash := hash.New()
	_ = rhoPreHash.WriteAny(r.M)
	for _, l := range r.PartyIDs() {
		_ = rhoPreHash.WriteAny(r.D[l], r.E[l])
	}
	for _, l := range r.PartyIDs() {
		rhoHash := rhoPreHash.Clone()
		_ = rhoHash.WriteAny(l)
		rho[l] = sample.Scalar(rhoHash.Digest(), r.Group())
	}

	R := r.Group().NewPoint()
	RShares := make(map[party.ID]curve.Point)
	for _, l := range r.PartyIDs() {
		RShares[l] = rho[l].Act(r.E[l])
		RShares[l] = RShares[l].Add(r.D[l])
		R = R.Add(RShares[l])
	}
	var c curve.Scalar
	if r.taproot {
		// BIP-340 adjustment: We need R to have an even y coordinate. This means
		// conditionally negating k = ∑ᵢ (dᵢ + (eᵢ ρᵢ)), which we can accomplish
		// by negating our dᵢ, eᵢ, if necessary. This entails negating the RShares
		// as well.
		RSecp := R.(*curve.Secp256k1Point)
		if !RSecp.HasEvenY() {
			r.d_i.Negate()
			r.e_i.Negate()
			for _, l := range r.PartyIDs() {
				RShares[l] = RShares[l].Negate()
			}
		}

		// BIP-340 adjustment: we need to calculate our hash as specified in:
		// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing
		RBytes := RSecp.XBytes()
		PBytes := r.Y.(*curve.Secp256k1Point).XBytes()
		cHash := taproot.TaggedHash("BIP0340/challenge", RBytes, PBytes, r.M)
		c = r.Group().NewScalar().SetNat(new(saferith.Nat).SetBytes(cHash))
	} else {
		var err error
		c, err = makeEthChallenge(R, r.Y, r.M)
		if err != nil {
			return r, err
		}
	}

	// Lambdas[i] = λᵢ
	Lambdas := polynomial.Lagrange(r.Group(), r.PartyIDs())

	var z_i curve.Scalar
	// S in schnorr: s = k + x*C
	// 5. "Each Pᵢ computes their response using their long-lived secret share sᵢ
	// by computing zᵢ = [dᵢ + (eᵢ ρᵢ)] + λᵢ sᵢ c, using S to determine // Should be minus siC (z_i) = (di +ei*rhoi) - \lambdai si C
	// the ith lagrange coefficient λᵢ"
	if r.taproot {
		z_i = r.Group().NewScalar().Set(Lambdas[r.SelfID()]).Mul(r.s_i).Mul(c)
		z_i.Add(r.d_i)
		ed := r.Group().NewScalar().Set(rho[r.SelfID()]).Mul(r.e_i)
		z_i.Add(ed)
	} else {
		z_i = r.Group().NewScalar().Set(Lambdas[r.SelfID()]).Mul(r.s_i).Mul(c)

		// ed == dᵢ + eᵢ ρᵢ
		ed := r.Group().NewScalar().Set(rho[r.SelfID()]).Mul(r.e_i)
		ed.Add(r.d_i)

		z_i.Sub(ed)
	}

	// 6. "Each Pᵢ securely deletes ((dᵢ, Dᵢ), (eᵢ, Eᵢ)) from their local storage,
	// and returns zᵢ to SA."
	//
	// Since we don't have a signing authority, we instead broadcast zᵢ.

	// TODO: Securely delete the nonces.

	// Broadcast our response
	b, err := NewBroadcast3(z_i)
	if err != nil {
		return r, err
	}

	if err := r.BroadcastMessage(out, b); err != nil {
		return r, err
	}

	return &round3{
		round2:  r,
		R:       R,
		RShares: RShares,
		c:       c,
		z:       map[party.ID]curve.Scalar{r.SelfID(): z_i},
		Lambda:  Lambdas,
	}, nil
}

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// BroadcastContent implements round.BroadcastRound.
func (r *round2) BroadcastContent() round.BroadcastContent {
	b, _ := NewBroadcast2(r.Group().NewPoint(), r.Group().NewPoint())
	return b
}

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }

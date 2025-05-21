package sign

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/cronokirby/saferith"
	"github.com/xlabs/tss-lib/v2/internal/eth"
	"github.com/xlabs/tss-lib/v2/internal/math/curve"
	"github.com/xlabs/tss-lib/v2/internal/math/sample"
	"golang.org/x/crypto/sha3"
)

// messageHash is a wrapper around bytes to provide some domain separation.
type messageHash []byte

// WriteTo makes messageHash implement the io.WriterTo interface.
func (m messageHash) WriteTo(w io.Writer) (int64, error) {
	if m == nil {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write(m)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (messageHash) Domain() string {
	return "messageHash"
}

// Signature represents the result of a Schnorr signature.
//
// This signature claims to satisfy:
//
//	z * G = R + H(R, Y, m) * Y
//
// for a public key Y.
type Signature struct {
	// R is the commitment point.
	R curve.Point
	// z is the response scalar.
	Z curve.Scalar
}

func Sign(secret curve.Scalar, m []byte) Signature {
	group := secret.Curve()

	// k is the first nonce
	k := sample.Scalar(rand.Reader, group)

	R := k.ActOnBase() // R == kG.

	// Hash the message and the public key
	challenge, err := makeEthChallenge(R, secret.ActOnBase(), messageHash(m))
	if err != nil {
		panic(err)
	}

	// z = k - s_i * c
	z := k.Sub(secret.Mul(challenge))

	return Signature{
		R: R,
		Z: z,
	}
}

// Verify checks if a signature equation actually holds.
//
// Note that m is the hash of a message, and not the message itself.
func (sig Signature) Verify(public curve.Point, m []byte) error {
	r, err := eth.PointToAddress(sig.R)
	if err != nil {
		return err
	}

	// challengeHash := hash.New()
	// _ = challengeHash.WriteAny(r, public, messageHash(m))
	// challenge := sample.Scalar(challengeHash.Digest(), group)
	challenge, err := makeEthChallenge(sig.R, public, messageHash(m))
	if err != nil {
		return err
	}

	// expected := challenge.Act(public) // ePK = -exG?
	ePK := challenge.Act(public)
	// expected = expected.Add(sig.R)    // R + exG =? kG + exG == sG
	sG := sig.Z.ActOnBase() // sG = zG

	actual := ePK.Add(sG) // where  s = k-s_iC.
	// ePK + sG = e(xG) + (k+xe)G

	actualAddress, err := eth.PointToAddress(actual)
	if err != nil {
		return err
	}

	if r != actualAddress {
		return fmt.Errorf("signature verification failed: %x != %x", r, actualAddress)
	}

	return nil //actual.Equal(sig.R)
}

func VerifyContract(ContractSig) {}

// Verify checks if a signature equation actually holds.
//
// Note that m is the hash of a message, and not the message itself.
// func (sig Signature) VerifyOldstyle(public curve.Point, m []byte) bool {
// 	group := public.Curve()

// 	r, err := eth.PointToAddress(sig.R)
// 	if err != nil {
// 		return false
// 	}

// 	challengeHash := hash.New()
// 	_ = challengeHash.WriteAny(r, public, messageHash(m))
// 	challenge := sample.Scalar(challengeHash.Digest(), group)

// 	expected := challenge.Act(public) // ePK = -exG?
// 	expected = expected.Add(sig.R)    // exG + sG

// 	actual := sig.z.ActOnBase()

// 	return expected.Equal(actual)
// }

func marshalPointForContract(p curve.Point) ([]byte, error) {
	bts, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}

	chainlinkStyle := make([]byte, len(bts))
	copy(chainlinkStyle, bts[1:])
	chainlinkStyle[len(bts)-1] = bts[0] - 2

	return chainlinkStyle, nil
}

func makeEthChallenge(R, pk curve.Point, msgHash []byte) (curve.Scalar, error) {
	sumhash, err := challengeHash(R, pk, msgHash)
	if err != nil {
		return nil, err
	}

	nat := new(saferith.Nat).SetBytes(sumhash)
	c := pk.Curve().NewScalar().SetNat(nat)

	return c, nil
}

func challengeHash(R curve.Point, pk curve.Point, msgHash []byte) ([]byte, error) {
	hsh := sha3.NewLegacyKeccak256()

	pkbts, err := marshalPointForContract(pk)
	if err != nil {
		return nil, err
	}

	if _, err := hsh.Write(pkbts); err != nil {
		return nil, err
	}

	if _, err := hsh.Write(msgHash); err != nil {
		return nil, err
	}

	addressR, err := eth.PointToAddress(R)
	if err != nil {
		return nil, err
	}

	if _, err := hsh.Write(addressR[:]); err != nil {
		return nil, err
	}

	return hsh.Sum(nil), nil
}

func (s Signature) ToContractSig(pk curve.Point, msg []byte) (ContractSig, error) {
	sigBin, err := s.Z.MarshalBinary()
	if err != nil {
		return ContractSig{}, err
	}

	rAddress, err := eth.PointToAddress(s.R)
	if err != nil {
		return ContractSig{}, err
	}

	pkBin, err := marshalPointForContract(pk)
	if err != nil {
		return ContractSig{}, err
	}

	consig := ContractSig{
		PkX:       [32]byte(pkBin[:32]),
		PkYParity: pkBin[32],
		S:         (&big.Int{}).SetBytes(sigBin),
		M:         (&big.Int{}).SetBytes(msg),
		R:         s.R,
		Address:   rAddress,
	}

	return consig, nil
}

type ContractSig struct {
	PkX       [32]byte
	PkYParity uint8
	M         *big.Int // Message Hash

	S       *big.Int
	R       curve.Point
	Address eth.EthAddress
}

func Bytes2Hex(d []byte) string {
	return hex.EncodeToString(d)
}

func LeftPadBytes(slice []byte, l int) []byte {
	if l <= len(slice) {
		return slice
	}

	padded := make([]byte, l)
	copy(padded[l-len(slice):], slice)

	return padded
}

func (s ContractSig) String() string {
	b := strings.Builder{}

	b.WriteString("ContractSig{\n")
	b.WriteString("  pkX                : 0x" + Bytes2Hex(s.PkX[:]) + "\n")
	b.WriteString("  pkyparity          : " + strconv.FormatUint(uint64(s.PkYParity), 10) + "\n")
	b.WriteString("  msghash            : 0x" + Bytes2Hex(LeftPadBytes(s.M.Bytes(), 32)) + "\n")
	b.WriteString("  s                  : 0x" + Bytes2Hex(LeftPadBytes(s.S.Bytes(), 32)) + "\n")
	b.WriteString("  nonceTimesGAddress : 0x" + Bytes2Hex(s.Address[:]) + "\n")
	b.WriteString("}\n")

	return b.String()
}

func PublicKeyValidForContract(pk curve.Point) bool {
	return !pk.XScalar().IsOverHalfOrder()
}

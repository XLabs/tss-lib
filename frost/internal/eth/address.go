package eth

import (
	"fmt"

	"github.com/xlabs/tss-lib/v2/frost/internal/math/curve"
	"golang.org/x/crypto/sha3"
)

type EthAddress [20]byte

var (
	ErrPointIsIdentity = fmt.Errorf("point is identity")
	ErrLongMarshal     = fmt.Errorf("couldn't marshal point to 64 bytes")
)

func PointToAddress(p curve.Point) (EthAddress, error) {
	if p.IsIdentity() {
		return EthAddress{}, ErrPointIsIdentity
	}

	x := p.XScalar()
	y := p.YScalar()

	if x == nil || y == nil {
		return EthAddress{}, ErrLongMarshal
	}

	xbts, err := x.MarshalBinary()
	if err != nil {
		return EthAddress{}, err
	}
	ybts, err := y.MarshalBinary()
	if err != nil {
		return EthAddress{}, err
	}

	if len(xbts) != 32 || len(ybts) != 32 {
		return EthAddress{}, ErrLongMarshal
	}

	pBytes := make([]byte, 64)
	copy(pBytes[:32], xbts)
	copy(pBytes[32:], ybts)

	h := sha3.NewLegacyKeccak256()
	if _, err := h.Write(pBytes); err != nil {
		return EthAddress{}, err // shouldn't happen.
	}

	var addr EthAddress
	copy(addr[:], h.Sum(nil)[12:])

	return addr, nil
}

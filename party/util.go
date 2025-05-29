package party

import (
	"encoding/binary"

	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/protocols/frost/sign"
	common "github.com/xlabs/tss-common"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

type protocolType int

const (
	unknownProtocolType protocolType = iota
	keygenProtocolType
	signingProtocolType
)

func findProtocolType(message common.ParsedMessage) protocolType {
	switch message.Content().(type) {
	case *sign.Broadcast2, *sign.Broadcast3:
		return signingProtocolType
	// case :
	// 	return keygenProtocolType
	default: // unrecognised message, just ignore!
		return unknownProtocolType
	}
}

type prng struct {
	shake sha3.ShakeHash
	buf   [8]byte
}

func newPrng(seed []byte) (*prng, error) {
	shk := sha3.NewShake256()
	_, err := shk.Write(seed)
	if err != nil {
		return nil, err
	}
	return &prng{shake: shk}, nil
}

func (p *prng) genUint64() (uint64, error) {
	if _, err := p.shake.Read(p.buf[:]); err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint64(p.buf[:]), nil
}

func (p *prng) modint(i uint64) (int, error) {
	n, err := p.genUint64()
	if err != nil {
		return 0, err
	}
	// since n is relatively small (compared to uint64), we can ignore the modulo bias.
	return int(n % i), nil
}

func randomShuffle[T any](seed []byte, arr []T) error {
	rng, err := newPrng(seed)
	if err != nil {
		return err
	}

	n := len(arr)
	// Fisher–Yates shuffle
	for i := n - 1; i >= 0; i-- {
		j, err := rng.modint(uint64(i + 1))
		if err != nil {
			return err
		}

		arr[i], arr[j] = arr[j], arr[i]
	}

	return nil
}

func shuffleParties(seed []byte, parties []*common.PartyID) ([]*common.PartyID, error) {
	cpy := make([]*common.PartyID, len(parties))
	// deep copy:
	for i, p := range parties {
		pid := proto.Clone(p.MessageWrapper_PartyID).(*common.MessageWrapper_PartyID)
		cpy[i] = &common.PartyID{
			MessageWrapper_PartyID: pid,
			Index:                  p.Index,
		}
	}

	if err := randomShuffle(seed, cpy); err != nil {
		return nil, err
	}

	return cpy, nil
}

func pids2IDs(pids []*common.PartyID) []party.ID {
	ids := make([]party.ID, len(pids))
	for i, pid := range pids {
		ids[i] = party.ID(pid.GetId())
	}

	return ids
}

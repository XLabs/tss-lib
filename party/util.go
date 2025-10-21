package party

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/xlabs/multi-party-sig/pkg/ecdsa"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/protocols/frost"
	common "github.com/xlabs/tss-common"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

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

func shuffle[T any](seed []byte, arr []T) error {
	rng, err := newPrng(seed)
	if err != nil {
		return err
	}

	n := len(arr)
	// Fisher–Yates shuffle
	for i := n - 1; i > 0; i-- {
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
		cpy[i] = proto.CloneOf(p)
	}

	if err := shuffle(seed, cpy); err != nil {
		return nil, err
	}

	return cpy, nil
}

func pids2IDs(pids []*common.PartyID) []party.ID {
	ids := make([]party.ID, len(pids))
	for i, pid := range pids {
		ids[i] = party.ID(pid.GetID())
	}

	return ids
}

// sessionMap is a wrapper around a syncMap, specified
// to store and load singleSessions.
type sessionMap struct {
	sync.Map
}

func (s *sessionMap) cleanup(maxTTL time.Duration) {
	currentTime := time.Now()

	keysToDelete := make([]any, 0)

	s.Range(func(key, value any) bool {
		signer, ok := value.(*singleSession)
		if !ok {
			// since this is not a signer, it should be removed.
			keysToDelete = append(keysToDelete, key)

			return true
		}

		if currentTime.Sub(signer.getInitTime()) >= maxTTL {
			keysToDelete = append(keysToDelete, key)
		}

		return true // true to continue the iteration
	})

	for _, key := range keysToDelete {
		s.Delete(key)
	}
}

func (s *sessionMap) LoadOrStore(key string, toload *singleSession) (*singleSession, bool) {
	_signer, loaded := s.Map.LoadOrStore(key, toload)
	return _signer.(*singleSession), loaded
}

func (s *sessionMap) deleteSession(session *singleSession) {
	s.Map.Delete(session.trackingId.ToString())
}
func rsToCommonSig(R curve.Point, S curve.Scalar, self *common.PartyID, tid *common.TrackingID) (*common.SignatureData, *common.Error) {
	rbits, err := R.Curve().MarshalPoint(R)
	if err != nil {
		return nil, common.NewTrackableError(
			err,
			"rsToCommonSig",
			unknownRound,
			self,
			tid,
		)
	}

	sbits, err := S.Curve().MarshalScalar(S)
	if err != nil {
		return nil, common.NewTrackableError(
			err,
			"rsToCommonSig",
			unknownRound,
			self,
			tid,
		)
	}

	dgst := Digest{}
	copy(dgst[:], tid.Digest)

	return &common.SignatureData{
		R:          rbits,
		S:          sbits,
		M:          dgst[:],
		TrackingId: tid,
	}, nil
}

func frostSigToCommonSig(sig *frost.Signature, self *common.PartyID, tid *common.TrackingID) (*common.SignatureData, *common.Error) {
	return rsToCommonSig(sig.R, sig.Z, self, tid)
}

func ecdsaSigToCommonSig(res *ecdsa.Signature, partyID *common.PartyID, trackingID *common.TrackingID) (*common.SignatureData, *common.Error) {
	return rsToCommonSig(res.R, res.S, partyID, trackingID)
}

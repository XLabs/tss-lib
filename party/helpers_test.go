package party

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/math/polynomial"
	"github.com/xlabs/multi-party-sig/pkg/math/sample"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/protocols/cmp/config/configgen"
	"github.com/xlabs/multi-party-sig/protocols/frost"
	"github.com/xlabs/multi-party-sig/protocols/frost/sign"
	common "github.com/xlabs/tss-common"
)

type prmKey struct{ N, T int }

var cachedParams = map[prmKey][]Parameters{}

type saferng struct {
	sync.Mutex
	prng *prng
}

func (p *saferng) Read(b []byte) (n int, err error) {
	p.Lock()
	defer p.Unlock()

	return p.prng.shake.Read(b)
}

func makeTestParameters(a *assert.Assertions, participants, threshold int) []Parameters {
	if params, ok := cachedParams[prmKey{N: participants, T: threshold}]; ok {
		fmt.Println("using cached params for", participants, threshold)
		return params
	}

	ps := make([]Parameters, participants)
	partyIDs := make([]*common.PartyID, len(ps))

	for i := range partyIDs {
		partyIDs[i] = &common.PartyID{
			ID: strconv.Itoa(i),
		}
	}
	group := curve.Secp256k1{}

	f, pk := DKGShares(group, threshold)

	privateShares := make(map[party.ID]curve.Scalar, len(partyIDs))
	for _, pid := range partyIDs {
		id := party.ID(pid.GetID())

		privateShares[id] = f.Evaluate(id.Scalar(group))
	}

	verificationShares := make(map[party.ID]curve.Point, len(partyIDs))

	for _, pid := range partyIDs {
		id := party.ID(pid.GetID())
		point := privateShares[id].ActOnBase()
		verificationShares[id] = point
	}

	prng, err := newPrng([]byte{1, 2, 3, 4})
	a.NoError(err)

	cmpCnfgs := configgen.GenerateCmpTestConfig(group, pids2IDs(partyIDs), threshold, &saferng{prng: prng})
	for i, pid := range partyIDs {
		id := party.ID(pid.GetID())

		ecdsaCnfg, ok := cmpCnfgs[id]
		a.True(ok)

		ps[i] = Parameters{
			FrostSecrets: &frost.Config{
				ID:                 id,
				Threshold:          threshold,
				PrivateShare:       privateShares[id],
				PublicKey:          pk,
				ChainKey:           []byte{1, 2, 3, 4},
				VerificationShares: party.NewPointMap(verificationShares),
			},
			EcdsaSecrets: ecdsaCnfg,

			PartyIDs: partyIDs,
			Self:     pid,

			MaxSignerTTL:         0, // letting it pick default.
			LoadDistributionSeed: []byte{5, 6, 7, 8},
		}
	}

	cachedParams[prmKey{N: participants, T: threshold}] = ps
	return ps
}

func DKGShares(group curve.Secp256k1, threshold int) (*polynomial.Polynomial, curve.Point) {
	for range 128 {
		secret := sample.Scalar(rand.Reader, group)
		publicKey := secret.ActOnBase()

		if sign.PublicKeyValidForContract(publicKey) {
			f := polynomial.NewPolynomial(group, threshold, secret)
			return f, publicKey
		}
	}
	panic("could not find valid DKG shares")
}

func createFullParties(a *assert.Assertions, participants, threshold int) ([]FullParty, []Parameters) {
	params := makeTestParameters(a, participants, threshold)
	parties := make([]FullParty, len(params))

	for i := range params {
		p, err := NewFullParty(&params[i])
		a.NoError(err)
		parties[i] = p
	}

	return parties, params
}

func pidToDigest(pid *common.PartyID) Digest {
	bf := bytes.NewBuffer(nil)

	bf.WriteString(pid.GetID())

	return hash(bf.Bytes())
}

func createSingleDigest() (map[Digest]bool, Digest) {
	digestSet := make(map[Digest]bool)
	d := crypto.Keccak256([]byte("hello, world"))
	hash := Digest{}
	copy(hash[:], d)
	digestSet[hash] = false
	return digestSet, hash
}

func getLen(m *sync.Map) int {
	l := 0
	m.Range(func(_, _ interface{}) bool {
		l++
		return true
	})

	return l
}

func (r *rateLimiter) lenDigestMap() int {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	return len(r.digestToPeer)
}

func fpSign(a *assert.Assertions, p FullParty, st SigningTask) *SigningInfo {
	// TODO
	info, err := p.AsyncRequestNewSignature(st)
	a.NoError(err)

	return info
}

func waitforDKG(parties []FullParty, a *assert.Assertions) bool {
	timeout := time.After(time.Second * 10)
	for _, p := range parties {
		select {

		case cnfg := <-p.(*Impl).outputChannels.KeygenOutputChannel:
			if cnfg == nil {
				a.FailNow("received nil config from keygen")
			}
		case <-timeout:
			a.FailNow("timeout waiting for keygen to finish")

			return true
		}
	}
	return false
}

func goStartDKG(p FullParty, threshold int, seed Digest) {
	go func() {
		if err := p.StartDKG(DkgTask{
			Threshold: threshold,
			Seed:      seed,
		}); err != nil {
			panic(err)
		}
	}()
}

func createDigests(numDigests int) map[Digest]bool {
	digestSet := make(map[Digest]bool)
	for i := 0; i < numDigests; i++ {
		d := crypto.Keccak256([]byte("hello, world" + strconv.Itoa(i)))
		hash := Digest{}
		copy(hash[:], d)
		digestSet[hash] = false
	}
	return digestSet
}

// ------------ Network simulator ------------

type networkSimulator struct {
	chans           OutputChannels
	idToFullParty   map[string]FullParty
	digestsToVerify map[Digest]bool // states whether it was checked or not yet.
	numSigsReceived map[Digest]int

	Timeout time.Duration // 0 means no timeout
	// used to wait for errors
	expectErr bool
	protocol  common.ProtocolType
}

func newNetworkSimulator(parties []FullParty) networkSimulator {
	return networkSimulator{
		chans:           newOutChannels(),
		idToFullParty:   idToParty(parties),
		digestsToVerify: map[Digest]bool{},
		numSigsReceived: map[Digest]int{},

		Timeout:   0,                        // no timeout
		expectErr: false,                    // no error expected
		protocol:  common.ProtocolFROSTSign, // default
	}
}

// numSigsExpected is set when we wish to check that each guardian has signed.
func (n *networkSimulator) verifiedAllSignatures(numSigsExpected ...int) bool {
	for _, b := range n.digestsToVerify {
		if b {
			continue
		}
		return false
	}

	if len(numSigsExpected) == 0 {
		return true
	}
	numExpected := numSigsExpected[0]

	for dgst, _ := range n.digestsToVerify {
		v, ok := n.numSigsReceived[dgst]
		if !ok {
			return false
		}
		if v < numExpected {
			return false
		}

	}

	return true

}

func (n *networkSimulator) run(a *assert.Assertions, donechan ...chan struct{}) {
	var dnchn chan struct{} = nil
	if len(donechan) > 0 {
		dnchn = donechan[0]
	}
	after := time.After(n.Timeout)
	if n.Timeout == 0 {
		after = nil
	}

	var anyParty FullParty
	for _, p := range n.idToFullParty {
		anyParty = p
		break
	}
	a.NotNil(anyParty)

	numSigsExpected := anyParty.(*Impl).committeeSize()

	for {
		select {
		case err := <-n.chans.ErrChannel:
			if n.expectErr {
				fmt.Println("Received expected error:", err)
				return
			}

			a.NoErrorf(err, "unexpected error: %v, digest %v", err.Cause(), err.TrackingId())
			a.FailNow("unexpected error")

		// simulating the network:
		case newMsg := <-n.chans.OutChannel:
			passMsg(a, newMsg, n.idToFullParty, n.expectErr)

		case <-dnchn:
			return
		case m := <-n.chans.SignatureOutputChannel:
			d := Digest{}
			copy(d[:], m.M)
			verified, ok := n.digestsToVerify[d]
			a.True(ok)

			if !verified {
				pk, err := anyParty.GetPublic(n.protocol)
				a.NoError(err, "failed to get public key for signature validation")

				a.True(validateSignature(pk, m, d[:]))
				n.digestsToVerify[d] = true
				fmt.Println("Signature validated correctly.", m.TrackingId)
			}

			n.numSigsReceived[d] = n.numSigsReceived[d] + 1

			if n.verifiedAllSignatures(numSigsExpected) {
				fmt.Println("All signatures validated correctly.")
				return
			}

		case <-after:
			fmt.Println("network timeout")
			return
		}
	}
}

func validateSignature(pk curve.Point, m *common.SignatureData, digest []byte) bool {
	sg, err := frost.Secp256k1SignatureTranslate(m)
	if err != nil {
		fmt.Println("failed to translate signature:", err)
		return false
	}

	if err := sg.Verify(pk, digest); err != nil {
		fmt.Println("failed to verify signature:", err)
		return false
	}

	return true
}

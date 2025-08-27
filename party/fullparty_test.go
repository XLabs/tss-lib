package party

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/xlabs/multi-party-sig/protocols/frost"
	"github.com/xlabs/multi-party-sig/protocols/frost/sign"
	common "github.com/xlabs/tss-common"

	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/math/polynomial"
	"github.com/xlabs/multi-party-sig/pkg/math/sample"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/round"

	"github.com/xlabs/tss-lib/v2/test"
	"google.golang.org/protobuf/proto"
)

func init() {

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Set the logger as the default logger
	slog.SetDefault(logger)
}

func TestSigning(t *testing.T) {
	st := signerTester{
		participants:             1,
		threshold:                0,
		numSignatures:            1,
		maxNetworkSimulationTime: time.Second * 3,
	}
	t.Run("one-out-of-one signer", st.run)

	st = signerTester{
		participants:             test.TestParticipants,
		threshold:                test.TestThreshold,
		numSignatures:            1,
		maxNetworkSimulationTime: time.Second * 200,
	}
	t.Run("one signature", st.run)

	st.numSignatures = 5
	st.maxNetworkSimulationTime = time.Second * 200
	t.Run("five signatures ", st.run)

	st2 := signerTester{
		participants:             5,
		threshold:                3,
		numSignatures:            50,
		maxNetworkSimulationTime: time.Minute,
	}
	t.Run("3 threshold 20 signatures", st2.run)
}

type signerTester struct {
	participants, threshold, numSignatures int
	maxNetworkSimulationTime               time.Duration
}

func (st *signerTester) run(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, st.participants, st.threshold)

	digestSet := createDigests(st.numSignatures)

	n := networkSimulator{
		outchan:         make(chan common.ParsedMessage, len(parties)*1000),
		sigchan:         make(chan *common.SignatureData, st.numSignatures*len(parties)),
		errchan:         make(chan *common.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         st.maxNetworkSimulationTime,
	}

	for _, p := range parties {
		a.NoError(
			p.Start(OutputChannels{
				OutChannel:             n.outchan,
				SignatureOutputChannel: n.sigchan,
				KeygenOutputChannel:    make(chan *TSSSecrets),
				ErrChannel:             n.errchan,
			}),
		)
	}

	for digest := range digestSet {
		for _, party := range parties {
			fpSign(a, party, SigningTask{
				Digest:       digest,
				Faulties:     nil,
				AuxilaryData: nil,
			})
		}
	}

	fmt.Println("Setup done. waiting for test to run.")

	time.Sleep(time.Second * 1)
	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	fmt.Println("ngoroutines:", runtime.NumGoroutine())
	<-donechan
	a.True(n.verifiedAllSignatures())

	for _, party := range parties {
		party.Stop()
	}
}

/*
Test to ensure that a Part will not attempt to sign a digest, even if received messages to sign from others.
*/
func TestPartyDoesntFollowRouge(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	digestSet, hash := createSingleDigest()

	n := networkSimulator{
		outchan:         make(chan common.ParsedMessage, len(parties)*20),
		sigchan:         make(chan *common.SignatureData, test.TestParticipants),
		errchan:         make(chan *common.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 3,
	}

	for _, p := range parties {
		a.NoError(p.Start(OutputChannels{
			OutChannel:             n.outchan,
			SignatureOutputChannel: n.sigchan,
			KeygenOutputChannel:    make(chan *TSSSecrets),
			ErrChannel:             n.errchan,
		}))
	}

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	var trackingId *common.TrackingID
	for i := 0; i < len(parties)-1; i++ {
		info := fpSign(a, parties[i], SigningTask{
			Digest: hash,
		})
		trackingId = info.TrackingID
	}

	<-donechan
	impl := parties[len(parties)-1].(*Impl)

	// test:
	v, ok := impl.sessionMap.Load(trackingId.ToString())
	a.True(ok)

	singleSigner, ok := v.(*singleSession)
	a.True(ok)

	// unless request to sign something, LocalParty should remain nil.
	singleSigner.mtx.Lock()
	a.Nil(singleSigner.session)
	a.Greater(len(singleSigner.messages[2]), 1) // in frost, 2 is the first round which receives messages from others.
	singleSigner.mtx.Unlock()
	// a.GreaterOrEqual(len(singleSigner.messageBuffer), 1) // ensures this party received at least one message from others

	for _, party := range parties {
		party.Stop()
	}

}

func fpSign(a *assert.Assertions, p FullParty, st SigningTask) *SigningInfo {
	// TODO
	info, err := p.AsyncRequestNewSignature(st)
	a.NoError(err)

	return info
}
func TestMultipleRequestToSignSameThing(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, 5, 3)

	digestSet, _ := createSingleDigest()

	n := networkSimulator{
		outchan:         make(chan common.ParsedMessage, len(parties)*1000),
		sigchan:         make(chan *common.SignatureData, 5),
		errchan:         make(chan *common.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 30 * time.Duration(len(digestSet)),
	}

	for _, p := range parties {
		a.NoError(p.Start(OutputChannels{
			OutChannel:             n.outchan,
			SignatureOutputChannel: n.sigchan,
			KeygenOutputChannel:    make(chan *TSSSecrets),
			ErrChannel:             n.errchan,
		}))
	}

	for digest := range digestSet {
		for i := 0; i < 10; i++ {
			go func(digest Digest) {
				for _, party := range parties {
					fpSign(a, party, SigningTask{
						Digest: digest,
					})
				}
			}(digest)
		}
	}

	time.Sleep(time.Second)

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	fmt.Println("Setup done. test starting.")

	fmt.Println("ngoroutines:", runtime.NumGoroutine())
	<-donechan
	a.True(n.verifiedAllSignatures())

	for _, party := range parties {
		party.Stop()
	}
}

func TestLateParties(t *testing.T) {
	t.Run("single late party", func(t *testing.T) { testLateParties(t, 1) })
	t.Run("multiple late parties", func(t *testing.T) { testLateParties(t, 5) })
}

func testLateParties(t *testing.T, numLate int) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	digestSet, hash := createSingleDigest()

	n := networkSimulator{
		outchan:         make(chan common.ParsedMessage, len(parties)*20),
		sigchan:         make(chan *common.SignatureData, test.TestParticipants),
		errchan:         make(chan *common.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 3,
	}

	for _, p := range parties {
		a.NoError(p.Start(OutputChannels{
			OutChannel:             n.outchan,
			SignatureOutputChannel: n.sigchan,
			KeygenOutputChannel:    make(chan *TSSSecrets),
			ErrChannel:             n.errchan,
		}))
	}

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	for i := 0; i < len(parties)-numLate; i++ {
		fpSign(a, parties[i], SigningTask{
			Digest: hash,
		})
	}

	<-donechan
	a.False(n.verifiedAllSignatures())

	for i := len(parties) - numLate; i < len(parties); i++ {
		fpSign(a, parties[i], SigningTask{
			Digest: hash,
		})
	}

	n.Timeout = time.Second * 20
	donechan2 := make(chan struct{})
	go func() {
		defer close(donechan2)
		n.run(a)
	}()

	<-donechan2
	a.True(n.verifiedAllSignatures())

	for _, party := range parties {
		party.Stop()
	}
}

func createSingleDigest() (map[Digest]bool, Digest) {
	digestSet := make(map[Digest]bool)
	d := crypto.Keccak256([]byte("hello, world"))
	hash := Digest{}
	copy(hash[:], d)
	digestSet[hash] = false
	return digestSet, hash
}

func TestCleanup(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)
	maxTTL := time.Second * 1
	for _, impl := range parties {
		impl.(*Impl).maxTTl = maxTTL
	}
	n := networkSimulator{
		outchan: make(chan common.ParsedMessage, len(parties)*20),
		sigchan: make(chan *common.SignatureData, test.TestParticipants),
		errchan: make(chan *common.Error, 1),
	}

	for _, p := range parties {
		a.NoError(p.Start(OutputChannels{
			OutChannel:             n.outchan,
			SignatureOutputChannel: n.sigchan,
			KeygenOutputChannel:    make(chan *TSSSecrets),
			ErrChannel:             n.errchan,
		}))
	}
	p1 := parties[0].(*Impl)
	digest := Digest{}
	fpSign(a, p1, SigningTask{
		Digest: digest,
	})

	a.Equal(getLen(&p1.sessionMap.Map), 1, "expected 1 signer ")

	<-time.After(maxTTL * 2)

	a.Equal(getLen(&p1.sessionMap.Map), 0, "expected 0 signers ")

	for _, party := range parties {
		party.Stop()
	}
}

func getLen(m *sync.Map) int {
	l := 0
	m.Range(func(_, _ interface{}) bool {
		l++
		return true
	})

	return l
}

type networkSimulator struct {
	outchan chan common.ParsedMessage
	sigchan chan *common.SignatureData

	errchan         chan *common.Error
	idToFullParty   map[string]FullParty
	digestsToVerify map[Digest]bool // states whether it was checked or not yet.

	Timeout time.Duration // 0 means no timeout
	// used to wait for errors
	expectErr bool
}

func (n *networkSimulator) verifiedAllSignatures() bool {
	for _, b := range n.digestsToVerify {
		if b {
			continue
		}
		return false
	}
	return true

}

func idToParty(parties []FullParty) map[string]FullParty {
	idToFullParty := map[string]FullParty{}
	for _, p := range parties {
		idToFullParty[p.(*Impl).self.GetID()] = p
	}
	return idToFullParty
}

func (n *networkSimulator) run(a *assert.Assertions, donechan ...chan struct{}) {
	var anyParty FullParty
	for _, p := range n.idToFullParty {
		anyParty = p
		break
	}
	var dnchn chan struct{} = nil
	if len(donechan) > 0 {
		dnchn = donechan[0]
	}

	a.NotNil(anyParty)

	after := time.After(n.Timeout)
	if n.Timeout == 0 {
		after = nil
	}

	for {
		select {
		case err := <-n.errchan:
			if n.expectErr {
				fmt.Println("Received expected error:", err)
				return
			}

			a.NoErrorf(err, "unexpected error: %v, digest %v", err.Cause(), err.TrackingId())
			a.FailNow("unexpected error")

		// simulating the network:
		case newMsg := <-n.outchan:
			passMsg(a, newMsg, n.idToFullParty, n.expectErr)

		case <-dnchn:
			return
		case m := <-n.sigchan:
			d := Digest{}
			copy(d[:], m.M)
			verified, ok := n.digestsToVerify[d]
			a.True(ok)

			if !verified {
				pk, err := anyParty.GetPublic()
				a.NoError(err, "failed to get public key for signature validation")

				a.True(validateSignature(pk, m, d[:]))
				n.digestsToVerify[d] = true
				fmt.Println("Signature validated correctly.", m.TrackingId)
				continue
			}

			if n.verifiedAllSignatures() {
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

func passMsg(a *assert.Assertions, newMsg common.ParsedMessage, idToParty map[string]FullParty, expectErr bool) {
	if !newMsg.ValidateBasic() {
		panic("invalid message received, can't store it, or process it further")
	}

	bz, routing, err := newMsg.WireBytes()
	if expectErr && err != nil {
		return
	}
	a.NoError(err)

	if routing.IsBroadcast() {
		slog.Info("Broadcasting message", "from", routing.From.GetID(), "type", newMsg.Type())
		for pID, p := range idToParty {
			parsedMsg, done := copyParsedMessage(a, bz, routing, expectErr)
			if done {
				return
			}
			if routing.From.GetID() == pID {
				continue
			}

			err = p.Update(parsedMsg)
			if expectErr && err != nil {
				continue
			}
			a.NoError(err)
		}

		return
	}

	parsedMsg, done := copyParsedMessage(a, bz, routing, expectErr)
	if done {
		return
	}

	to := routing.To

	err = idToParty[to.GetID()].Update(parsedMsg)
	if expectErr && err != nil {
		return
	}

	a.NoError(err)

}

func copyParsedMessage(a *assert.Assertions, bz []byte, routing *common.MessageRouting, expectErr bool) (common.ParsedMessage, bool) {
	from := proto.CloneOf(routing.From)

	bts := make([]byte, len(bz))
	copy(bts, bz)

	parsedMsg, err := common.ParseWireMessage(bts, from, routing.To)
	if expectErr && err != nil {
		return nil, true
	}
	a.NoError(err)

	return parsedMsg, false
}

func makeTestParameters(a *assert.Assertions, participants, threshold int) []Parameters {
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

	for i, pid := range partyIDs {
		id := party.ID(pid.GetID())

		ps[i] = Parameters{
			FrostSecrets: &frost.Config{
				ID:                 id,
				Threshold:          threshold,
				PrivateShare:       privateShares[id],
				PublicKey:          pk,
				ChainKey:           []byte{1, 2, 3, 4},
				VerificationShares: party.NewPointMap(verificationShares),
			},

			PartyIDs: partyIDs,
			Self:     pid,

			MaxSignerTTL:         0, // letting it pick default.
			LoadDistributionSeed: []byte{5, 6, 7, 8},
		}
	}

	return ps
}

func DKGShares(group curve.Secp256k1, threshold int) (*polynomial.Polynomial, curve.Point) {

	secret := sample.Scalar(rand.Reader, group)
	f := polynomial.NewPolynomial(group, threshold, secret)
	publicKey := secret.ActOnBase()

	return f, publicKey

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

func TestClosingThreadpoolMidRun(t *testing.T) {
	// t.Skip()
	// This test Fails when not run in isolation.
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	digestSet := createDigests(200) // 200 digests to sign

	n := networkSimulator{
		outchan:         make(chan common.ParsedMessage, len(parties)*20),
		sigchan:         make(chan *common.SignatureData, test.TestParticipants),
		errchan:         make(chan *common.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 5,
		expectErr:       true,
	}

	goroutinesstart := runtime.NumGoroutine()

	for _, p := range parties {
		a.NoError(p.Start(OutputChannels{
			OutChannel:             n.outchan,
			SignatureOutputChannel: n.sigchan,
			KeygenOutputChannel:    make(chan *TSSSecrets),
			ErrChannel:             n.errchan,
		}))
	}

	a.Equal(
		len(parties)*(numHandlerWorkers+1)+goroutinesstart,
		runtime.NumGoroutine(),
		"expected each party to add 2*numcpu workers and 1 cleanup gorotuines",
	)

	for i := 0; i < len(parties); i++ {
		for dgst := range digestSet {
			fpSign(a, parties[i], SigningTask{
				Digest: dgst,
			})
		}
	}

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	// stopping everyone to close the threadpools.
	for _, party := range parties {
		party.(*Impl).cancelFunc()
	}

	<-donechan

	for _, party := range parties {
		party.Stop()
	}

	for _, fp := range parties {
		p := fp.(*Impl)
		<-p.ctx.Done()
	}

	a.Equal(goroutinesstart, runtime.NumGoroutine(), "expected same number of goroutines at the end")
}

func TestTrailingZerosInDigests(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, 5, 3)

	digestSet := make(map[Digest]bool)

	hash1 := Digest{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	digestSet[hash1] = false

	hash2 := Digest{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	digestSet[hash2] = false

	n := networkSimulator{
		outchan:         make(chan common.ParsedMessage, len(parties)*1000),
		sigchan:         make(chan *common.SignatureData, 5),
		errchan:         make(chan *common.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 20 * time.Duration(len(digestSet)),
	}

	for _, p := range parties {
		a.NoError(p.Start(OutputChannels{
			OutChannel:             n.outchan,
			SignatureOutputChannel: n.sigchan,
			KeygenOutputChannel:    make(chan *TSSSecrets),
			ErrChannel:             n.errchan,
		}))
	}

	for digest := range digestSet {
		go func(digest Digest) {
			for _, party := range parties {
				fpSign(a, party, SigningTask{
					Digest: digest,
				})
			}
		}(digest)
	}

	time.Sleep(time.Second)

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	<-donechan
	a.True(n.verifiedAllSignatures())

	for _, party := range parties {
		party.Stop()
	}
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

func pidToDigest(pid *common.PartyID) Digest {
	bf := bytes.NewBuffer(nil)

	bf.WriteString(pid.GetID())

	return hash(bf.Bytes())
}

func TestChangingCommittee(t *testing.T) {
	// NOTICE: This test is extremly slow due to the amount of processing done on a single machine.
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold) // threshold =2 means we need 3 in comittee to sign

	digestSet, hash := createSingleDigest()
	fmt.Println("old digest:", hash)

	n := networkSimulator{
		outchan:         make(chan common.ParsedMessage, len(parties)*10000), // 10k messages per party should be enough.
		sigchan:         make(chan *common.SignatureData, len(parties)),
		errchan:         make(chan *common.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 120 * time.Duration(len(digestSet)),
	}

	for _, p := range parties {
		a.NoError(p.Start(OutputChannels{
			OutChannel:             n.outchan,
			SignatureOutputChannel: n.sigchan,
			KeygenOutputChannel:    make(chan *TSSSecrets),
			ErrChannel:             n.errchan,
		}))
	}

	threadsWait := sync.WaitGroup{}
	threadsWait.Add(2)

	barrier := make(chan struct{})
	go func() {
		defer threadsWait.Done()
		wg := sync.WaitGroup{}
		for _, party := range parties {
			wg.Add(1)
			p := party
			go func() {
				defer wg.Done()
				fpSign(a, p, SigningTask{
					Digest: hash,
				})
			}()
		}
		wg.Wait()
		close(barrier)
	}()

	go func() {
		defer threadsWait.Done()

		<-barrier
		for nremoved := 1; nremoved < 5; nremoved++ {
			fmt.Println("changing comittee, starting signing process again.")

			faulties := make([]*common.PartyID, nremoved)
			for i := 0; i < nremoved; i++ {
				faulties[i] = parties[i].(*Impl).self
			}
			faultiesMap := map[Digest]bool{}
			for _, pid := range faulties {
				faultiesMap[pidToDigest(pid)] = true
			}

			var prevFaulties []*common.PartyID
			if len(faulties)-1 > 0 {
				prevFaulties = faulties[:len(faulties)-1]
			}
			for _, p_ := range parties {
				p := p_.(*Impl)

				// Dropping ongoing sig to ensure the state of prev sig is `unset`.
				trackid := p.createTrackingID(SigningTask{
					Digest:   hash,
					Faulties: prevFaulties, // prev round faulties.
				})
				p.sessionMap.Map.Delete(trackid.ToString()) // ensures signature is not created.

				// shuffle the order of the parties when telling them to replace the comittee.
				// (Ensures different ordered faulties array does not affect the signprotocol)
				seedPerParty := pidToDigest(p.self)

				shuffledFaulties, err := shuffleParties(seedPerParty[:], faulties)
				a.NoError(err)

				info, err := p.AsyncRequestNewSignature(SigningTask{
					Digest:       hash,
					Faulties:     shuffledFaulties,
					AuxilaryData: []byte{},
				})
				a.NoError(err)

				if err != nil {
					p.AsyncRequestNewSignature(SigningTask{
						Digest:       hash,
						Faulties:     shuffledFaulties,
						AuxilaryData: []byte{},
					})
					return
				}
				for _, pid := range info.SigningCommittee {
					a.NotContains(faultiesMap, pidToDigest(pid))
				}
			}
		}
	}()

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	<-donechan
	a.True(n.verifiedAllSignatures())
	for _, party := range parties {
		party.Stop()
	}

	threadsWait.Wait()
}

func getProjectRootDir() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	abs, err := filepath.Abs(wd)
	if err != nil {
		panic(err)
	}

	for {
		cur := filepath.Dir(abs)
		if cur == "" {
			panic("could not find project root")
		}

		if !strings.Contains(cur, "tss-lib") {
			break
		}
		abs = cur

	}

	return abs
}

func TestErrorsInUpdate(t *testing.T) {
	a := assert.New(t)
	parties, _ := createFullParties(a, 5, 4)

	outchan := make(chan common.ParsedMessage, len(parties)*20)
	sigchan := make(chan *common.SignatureData, test.TestParticipants)
	errchan := make(chan *common.Error, 1)

	for _, v := range parties {
		v.Start(OutputChannels{
			OutChannel:             outchan,
			SignatureOutputChannel: sigchan,
			KeygenOutputChannel:    make(chan *TSSSecrets),
			ErrChannel:             errchan,
		})
	}

	_, hash := createSingleDigest()

	for _, party := range parties {
		go fpSign(a, party, SigningTask{
			Digest: hash,
		})
	}

	success := atomic.Bool{}
	success.Store(false)

	donechn := time.After(time.Second * 5)
	for {
		select {
		case <-donechn:
			if !success.Load() {
				t.Fail()
			}
			return

		case m := <-outchan:
			if m.GetFrom().GetID() == parties[0].(*Impl).self.GetID() {
				// this is the party that will send rubbish.
				switch msg := m.Content().(type) {
				case *sign.Broadcast3:
					msg.Zi = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
				case *sign.Broadcast2:
					msg.Ei[10] += 1
				}
			}

			for _, p := range parties {
				p := p
				m := m
				go func() {
					if err := p.Update(m); err != nil {
						return
					}
				}()
			}

		case err := <-errchan:
			fmt.Println("sucess, received error:", err)
			// this is a sucess.
			return
		}
	}
}

func TestKeygen(t *testing.T) {
	t.Run("keygen", testKeygen)

	t.Run("keygen with nil config", testNilConfigKeyGen)

	t.Run("keygen with one late party", testKeygenWithOneLateParty)
}
func testKeygen(t *testing.T) {
	a := assert.New(t)

	participants := 5
	threshold := 3

	parties, _ := createFullParties(a, participants, threshold)

	maxTTL := time.Minute * 1
	for _, impl := range parties {
		impl.(*Impl).maxTTl = maxTTL
	}

	n := networkSimulator{
		outchan: make(chan common.ParsedMessage, len(parties)*20),
		sigchan: make(chan *common.SignatureData),
		errchan: make(chan *common.Error, len(parties)),

		idToFullParty:   idToParty(parties),
		digestsToVerify: map[Digest]bool{},

		Timeout:   0,
		expectErr: false,
	}

	for _, p := range parties {
		a.NoError(p.Start(OutputChannels{
			OutChannel:             n.outchan,
			SignatureOutputChannel: n.sigchan,
			KeygenOutputChannel:    make(chan *TSSSecrets, 100),
			ErrChannel:             n.errchan,
		}))
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	donechn := make(chan struct{})
	go func() {
		defer wg.Done()
		n.run(a, donechn)
	}()

	for _, p := range parties {
		if err := p.StartDKG(DkgTask{
			Threshold: threshold,
			Seed:      Digest{1, 2, 3, 4},
		}); err != nil {
			panic(err)
		}
	}

	waitforDKG(parties, a)
	close(donechn)
	wg.Wait()

}

func testNilConfigKeyGen(t *testing.T) {
	a := assert.New(t)

	participants := 5
	threshold := 3

	parties, _ := createFullParties(a, participants, threshold)

	for _, p := range parties {
		p.(*Impl).config = nil

	}
	maxTTL := time.Minute * 1
	for _, impl := range parties {
		impl.(*Impl).maxTTl = maxTTL
	}

	n := networkSimulator{
		outchan: make(chan common.ParsedMessage, len(parties)*20),
		sigchan: make(chan *common.SignatureData),
		errchan: make(chan *common.Error, len(parties)),

		idToFullParty:   idToParty(parties),
		digestsToVerify: map[Digest]bool{},

		Timeout:   0,
		expectErr: false,
	}

	for _, p := range parties {
		a.NoError(p.Start(OutputChannels{
			OutChannel:             n.outchan,
			SignatureOutputChannel: n.sigchan,
			KeygenOutputChannel:    make(chan *TSSSecrets, 100),
			ErrChannel:             n.errchan,
		}))
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	donechn := make(chan struct{})
	go func() {
		defer wg.Done()
		n.run(a, donechn)
	}()

	for _, p := range parties {
		if err := p.StartDKG(DkgTask{
			Threshold: threshold,
			Seed:      Digest{1, 2, 3, 4},
		}); err != nil {
			panic(err)
		}
	}

	waitforDKG(parties, a)
	close(donechn)
	wg.Wait()
}

func testKeygenWithOneLateParty(t *testing.T) {

	a := assert.New(t)

	participants := 5
	threshold := 2

	parties, _ := createFullParties(a, participants, threshold)

	maxTTL := time.Minute * 5
	for _, impl := range parties {
		impl.(*Impl).maxTTl = maxTTL
	}

	n := networkSimulator{
		outchan: make(chan common.ParsedMessage, len(parties)*20),
		sigchan: make(chan *common.SignatureData),

		errchan: make(chan *common.Error, len(parties)),

		idToFullParty:   idToParty(parties),
		digestsToVerify: map[Digest]bool{},

		Timeout:   0, // no timeout on network.
		expectErr: false,
	}

	for _, p := range parties {
		a.NoError(p.Start(OutputChannels{
			OutChannel:             n.outchan,
			SignatureOutputChannel: n.sigchan,
			KeygenOutputChannel:    make(chan *TSSSecrets, 100),
			ErrChannel:             n.errchan,
		}))
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	donechn := make(chan struct{})
	go func() {
		defer wg.Done()

		n.run(a, donechn)
	}()

	for _, p := range parties[:participants-1] {
		if err := p.StartDKG(DkgTask{
			Threshold: threshold,
			Seed:      Digest{1, 2, 3, 4},
		}); err != nil {
			panic(err)
		}
	}

	time.Sleep(time.Second * 5)
	for _, p := range parties[participants-1:] {
		if err := p.StartDKG(DkgTask{
			Threshold: threshold,
			Seed:      Digest{1, 2, 3, 4},
		}); err != nil {
			panic(err)
		}
	}
	fmt.Println("Waiting for DKG to finish...")

	waitforDKG(parties, a)
	close(donechn)
	wg.Wait()
}

func waitforDKG(parties []FullParty, a *assert.Assertions) bool {
	timeout := time.After(time.Second * 10)
	for _, p := range parties {
		select {

		case cnfg := <-p.(*Impl).keygenout:
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

type safeBuffer struct {
	buffer bytes.Buffer
	mu     sync.Mutex
}

func (sb *safeBuffer) Write(p []byte) (n int, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	return sb.buffer.Write(p)
}

func (sb *safeBuffer) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	return sb.buffer.String()
}

func TestMessageFromNonCommitteeIsReported(t *testing.T) {
	a := assert.New(t)

	// preparing to capture slog output in a buffer (so we can read from it later).
	var buf safeBuffer // need safe buffer to ensure race doesn't happen.

	old := slog.Default()
	slog.SetDefault(slog.New(
		slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}),
	))
	defer slog.SetDefault(old)

	// actual test:
	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	_, hash := createSingleDigest()

	outchan := make(chan common.ParsedMessage, len(parties)*20)
	sigchan := make(chan *common.SignatureData, test.TestParticipants)
	errchan := make(chan *common.Error, 1)

	for _, p := range parties {
		a.NoError(p.Start(OutputChannels{
			OutChannel:             outchan,
			SignatureOutputChannel: sigchan,
			KeygenOutputChannel:    nil,
			ErrChannel:             errchan,
		}))
	}

	info := fpSign(a, parties[0], SigningTask{
		Digest:   hash,
		Faulties: []*common.PartyID{parties[1].(*Impl).self},
	})

	p := (&round.Message{
		From:      party.ID(parties[1].(*Impl).self.ID),
		To:        party.ID(parties[0].(*Impl).self.ID),
		Broadcast: true,
		Content: &sign.Broadcast2{
			Di: make([]byte, 32),
			Ei: make([]byte, 32),
		},
		TrackingID: info.TrackingID,
	}).ToParsed()

	// Trigger the code path that should warn
	go parties[0].Update(p)

	//  Assert the warning appears
	a.Eventually(func() bool {
		return strings.Contains(buf.String(), "message from non-committee member dropped")
	}, 4*time.Second, 10*time.Millisecond, "expected slog warning not observed")
}

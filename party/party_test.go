package party

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/xlabs/multi-party-sig/protocols/frost/sign"
	common "github.com/xlabs/tss-common"

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

func newOutChannels() OutputChannels {
	return OutputChannels{
		OutChannel:             make(chan common.ParsedMessage, 1000*1000),
		SignatureOutputChannel: make(chan *common.SignatureData, 1000*1000),
		KeygenOutputChannel:    make(chan *TSSSecrets, 1),
		ErrChannel:             make(chan *common.Error, 1),
		WarningChannel:         make(chan *Warning, 1),
	}

}

func TestSigning(t *testing.T) {
	st := signerTester{
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

	for _, protocol := range []common.ProtocolType{common.ProtocolECDSASign} {
		parties, _ := createFullParties(a, st.participants, st.threshold)

		digestSet := createDigests(st.numSignatures)

		n := newNetworkSimulator(parties)
		// n.protocol = protocol // TODO: use it,.
		n.digestsToVerify = digestSet
		n.Timeout = st.maxNetworkSimulationTime

		for _, p := range parties {
			a.NoError(
				p.Start(n.chans),
			)
		}

		for digest := range digestSet {
			for _, party := range parties {
				fpSign(a, party, SigningTask{
					Digest:        digest,
					Faulties:      nil,
					AuxiliaryData: nil,
					ProtocolType:  protocol,
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

		time.Sleep(time.Second * 1)
		for _, party := range parties {
			party.Stop()

			p := party.(*Impl)
			l := p.rateLimiter.lenDigestMap()

			p.rateLimiter.mtx.Lock()
			for key := range p.rateLimiter.digestToPeer {
				_, ok := p.sessionMap.Load(string(key))
				a.False(ok, "expected session to be removed from session map")
			}
			p.rateLimiter.mtx.Unlock()

			a.Equal(0, l, "expected 0 digests in rate limiter, got %d", l)
		}
	}
}

/*
Test to ensure that a Part will not attempt to sign a digest, even if received messages to sign from others.
*/
func TestPartyDoesntFollowRouge(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	digestSet, hash := createSingleDigest()

	n := newNetworkSimulator(parties)
	n.digestsToVerify = digestSet
	n.Timeout = time.Second * 3

	for _, p := range parties {
		a.NoError(p.Start(n.chans))
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

func TestMultipleRequestToSignSameThing(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, 5, 3)

	digestSet, _ := createSingleDigest()

	n := newNetworkSimulator(parties)
	n.digestsToVerify = digestSet
	n.Timeout = time.Second * 30 * time.Duration(len(digestSet))

	for _, p := range parties {
		a.NoError(p.Start(n.chans))
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

	n := newNetworkSimulator(parties)
	n.digestsToVerify = digestSet
	n.Timeout = time.Second * 3

	for _, p := range parties {
		a.NoError(p.Start(n.chans))
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

func TestCleanup(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)
	maxTTL := time.Second * 1
	for _, impl := range parties {
		impl.(*Impl).maxTTl = maxTTL
	}

	n := newNetworkSimulator(parties)

	for _, p := range parties {
		a.NoError(p.Start(n.chans))
	}
	p1 := parties[0].(*Impl)
	digest := Digest{}
	info := fpSign(a, p1, SigningTask{
		Digest: digest,
	})
	p1.rateLimiter.add(info.TrackingID, p1.self) // manually adding to rate limiter, as fpSign doesn't do it.

	a.Equal(getLen(&p1.sessionMap.Map), 1, "expected 1 signer ")
	a.Equal(1, p1.rateLimiter.lenDigestMap(), "expected 1 digest in rate limiter")

	<-time.After(maxTTL * 3)

	a.Equal(getLen(&p1.sessionMap.Map), 0, "expected 0 signers ")
	a.Equal(0, p1.rateLimiter.lenDigestMap(), "expected 0 digest in rate limiter")

	for _, party := range parties {
		party.Stop()
	}
}

func idToParty(parties []FullParty) map[string]FullParty {
	idToFullParty := map[string]FullParty{}
	for _, p := range parties {
		idToFullParty[p.(*Impl).self.GetID()] = p
	}
	return idToFullParty
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

func TestClosingThreadpoolMidRun(t *testing.T) {
	// t.Skip()
	// This test Fails when not run in isolation.
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	digestSet := createDigests(200) // 200 digests to sign

	n := newNetworkSimulator(parties)
	n.digestsToVerify = digestSet
	n.Timeout = time.Second * 2
	n.expectErr = true

	goroutinesstart := runtime.NumGoroutine()

	for _, p := range parties {
		a.NoError(p.Start(n.chans))
	}

	a.Equal(
		len(parties)*(2*numHandlerWorkers+1)+goroutinesstart,
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

	time.Sleep(time.Second * 2) // waiting for goroutines to finish

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

	n := newNetworkSimulator(parties)
	n.digestsToVerify = digestSet
	n.Timeout = time.Second * 20 * time.Duration(len(digestSet))

	for _, p := range parties {
		a.NoError(p.Start(n.chans))
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

func TestChangingCommittee(t *testing.T) {
	// NOTICE: This test is extremly slow due to the amount of processing done on a single machine.
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold) // threshold =2 means we need 3 in comittee to sign

	digestSet, hash := createSingleDigest()
	fmt.Println("old digest:", hash)

	n := newNetworkSimulator(parties)
	n.digestsToVerify = digestSet
	n.Timeout = time.Second * 120 * time.Duration(len(digestSet))

	for _, p := range parties {
		a.NoError(p.Start(n.chans))
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
					Digest:        hash,
					Faulties:      shuffledFaulties,
					AuxiliaryData: []byte{},
				})
				a.NoError(err)

				if err != nil {
					p.AsyncRequestNewSignature(SigningTask{
						Digest:        hash,
						Faulties:      shuffledFaulties,
						AuxiliaryData: []byte{},
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

	chans := newOutChannels()
	for _, v := range parties {
		v.Start(chans)
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

		case m := <-chans.OutChannel:
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

		case err := <-chans.ErrChannel:
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

	n := newNetworkSimulator(parties)

	for _, p := range parties {
		a.NoError(p.Start(n.chans))
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	donechn := make(chan struct{})
	go func() {
		defer wg.Done()
		n.run(a, donechn)
	}()

	for _, p := range parties {
		goStartDKG(p, threshold, Digest{1, 2, 3, 4})
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
		p.(*Impl).frostConfig = nil

	}
	maxTTL := time.Minute * 1
	for _, impl := range parties {
		impl.(*Impl).maxTTl = maxTTL
	}

	n := newNetworkSimulator(parties)

	for _, p := range parties {
		a.NoError(p.Start(n.chans))
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	donechn := make(chan struct{})
	go func() {
		defer wg.Done()
		n.run(a, donechn)
	}()

	for _, p := range parties {
		goStartDKG(p, threshold, Digest{1, 2, 3, 4})
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

	n := newNetworkSimulator(parties)

	for _, p := range parties {
		a.NoError(p.Start(n.chans))
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	donechn := make(chan struct{})
	go func() {
		defer wg.Done()

		n.run(a, donechn)
	}()

	for _, p := range parties[:participants-1] {
		goStartDKG(p, threshold, Digest{1, 2, 3, 4})
	}

	time.Sleep(time.Second * 5)
	for _, p := range parties[participants-1:] {
		goStartDKG(p, threshold, Digest{1, 2, 3, 4})
	}
	fmt.Println("Waiting for DKG to finish...")

	waitforDKG(parties, a)
	close(donechn)
	wg.Wait()
}

func TestMessageFromNonCommitteeIsReported(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	_, hash := createSingleDigest()

	for _, p := range parties {
		a.NoError(p.Start(newOutChannels()))
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

	select {
	case <-parties[0].(*Impl).outputChannels.WarningChannel:
		return
	case <-time.After(5 * time.Second):
		a.FailNow("timeout waiting for warning to be sent")
	}
}

func TestSessionRejectsMessageSentTwice(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	_, hash := createSingleDigest()

	for _, p := range parties {
		a.NoError(p.Start(newOutChannels()))
	}

	info := fpSign(a, parties[0], SigningTask{
		Digest:   hash,
		Faulties: []*common.PartyID{parties[1].(*Impl).self, parties[2].(*Impl).self},
	})

	p := (&round.Message{
		From:      party.ID(parties[3].(*Impl).self.ID), // party 3 is in committee
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

	// check no warning yet
	select {
	case <-parties[0].(*Impl).outputChannels.WarningChannel:
		a.FailNow("did not expect a warning the first time")
	case <-time.After(200 * time.Millisecond):
	}

	//  Assert the warning appears after sending similar message type for the same session and round again
	go parties[0].Update(p) // sending the same message again.
	select {
	case <-parties[0].(*Impl).outputChannels.WarningChannel:
		return
	case <-time.After(1 * time.Second):
		a.FailNow("timeout waiting for warning to be sent")
	}
}

func TestRateLimiting(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	// Changing parameters before starting the parties.
	for _, p := range parties {
		p.(*Impl).rateLimiter.maxActiveSessions = 1
		p.(*Impl).maxTTl = time.Second * 1
	}

	_, hash := createSingleDigest()

	for _, p := range parties {
		a.NoError(p.Start(newOutChannels()))
	}

	info := fpSign(a, parties[0], SigningTask{
		Digest:   hash,
		Faulties: []*common.PartyID{parties[1].(*Impl).self, parties[2].(*Impl).self},
	})

	p := (&round.Message{
		From:      party.ID(parties[3].(*Impl).self.ID), // party 3 is in committee
		To:        party.ID(parties[0].(*Impl).self.ID),
		Broadcast: true,
		Content: &sign.Broadcast2{
			Di: make([]byte, 32),
			Ei: make([]byte, 32),
		},
		TrackingID: info.TrackingID,
	}).ToParsed()

	// Trigger the code path that should warn
	a.NoError(parties[0].Update(p))

	tid := proto.CloneOf(info.TrackingID)
	tid.Digest[0] += 1 // changing the digest to make a new session.
	p = (&round.Message{
		From:      party.ID(parties[3].(*Impl).self.ID), // party 3 is in committee
		To:        party.ID(parties[0].(*Impl).self.ID),
		Broadcast: true,
		Content: &sign.Broadcast2{
			Di: make([]byte, 32),
			Ei: make([]byte, 32),
		},
		TrackingID: tid,
	}).ToParsed()
	a.ErrorContains(parties[0].Update(p), "reached the maximum")

	// waiting for the rate limiter to cleanup.
	time.Sleep(parties[0].(*Impl).maxTTl * 3)
	a.NoError(parties[0].Update(p))
}

func TestUpdateChecks(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	for _, p := range parties {
		a.NoError(p.Start(newOutChannels()))
	}

	a.ErrorIs(parties[0].Update(nil), errNilMessage)

	p := &round.Message{
		From:      party.ID("UNKNOWN"),
		To:        party.ID(parties[0].(*Impl).self.ID),
		Broadcast: true,
		Content: &sign.Broadcast2{
			Di: make([]byte, 32),
			Ei: make([]byte, 32),
		},
		TrackingID: nil,
	}
	a.ErrorIs(parties[0].Update(p.ToParsed()), errInvalidTrackingID)

	_, hash := createSingleDigest()
	info := fpSign(a, parties[0], SigningTask{
		Digest:   hash,
		Faulties: []*common.PartyID{parties[1].(*Impl).self, parties[2].(*Impl).self},
	})
	p.TrackingID = info.TrackingID
	a.ErrorContains(parties[0].Update(p.ToParsed()), "unknown sender")

	tmp := p.ToParsed()
	tmp.WireMsg().From = nil
	a.ErrorContains(parties[0].Update(tmp), "mismatch")
	tmp.(*common.MessageImpl).From = nil
	a.ErrorIs(parties[0].Update(tmp), errNilSender)
}

func TestMessageKeep(t *testing.T) {

	msg := &round.Message{
		From:      party.ID("UNKNOWN"),
		To:        party.ID("UNKNOWN"),
		Broadcast: true,
		Content: &sign.Broadcast2{
			Di: make([]byte, 32),
			Ei: make([]byte, 32),
		},
		TrackingID: nil,
	}

	broadcast := msg.ToParsed()

	msg.Broadcast = false
	direct := msg.ToParsed()

	t.Run("keep blocks adding to full cell", func(t *testing.T) {
		a := assert.New(t)

		keep := messageKeep{}

		a.NoError(keep.addMessage(broadcast))
		a.Error(keep.addMessage(broadcast))

		a.NoError(keep.addMessage(direct))
		a.Error(keep.addMessage(direct))

		// shouldn't do anything as cells are not full yet.
		keep.clearDeliveredMessages(true)
		a.Error(keep.addMessage(direct))
		a.Error(keep.addMessage(broadcast))

		for _, v := range keep.cells {
			a.NotNil(v)
		}

		// filling the cells

		keep.getMessages(true) // changing the stage for the cells

		a.Error(keep.addMessage(msg.ToParsed()))
		msg.Broadcast = true
		a.Error(keep.addMessage(msg.ToParsed()))

		// Now clearing the cells
		keep.clearDeliveredMessages(true)
		for _, v := range keep.cells {
			a.Nil(v)
		}

		// not allowing adding messages, even though the cells are empty, as they are in delivered state.
		a.Error(keep.addMessage(direct))
		a.Error(keep.addMessage(broadcast))
	})

	t.Run("order of messages", func(t *testing.T) {
		a := assert.New(t)

		keep := messageKeep{}

		// Test direct message not returned before a broadcast message is added.
		keep.addMessage(direct)
		a.Len(keep.getMessages(true), 0, "expected no message to be returned, since we inspect a broadcast round")

		keep.addMessage(broadcast)
		a.Len(keep.getMessages(true), 2, "expected both messages to be returned, since we inspect a broadcast round")

		// Test that broadcast is returned on demand for broadcast round.
		keep = messageKeep{}
		msg.Broadcast = true
		keep.addMessage(broadcast)
		msgs := keep.getMessages(true)
		a.Len(msgs, 1)

		a.True(msgs[0].IsBroadcast())

		// check that we don't return the broadcast message again. Just the direct one.
		keep.addMessage(direct)
		msgs = keep.getMessages(true)
		a.Len(msgs, 1)
		a.False(msgs[0].IsBroadcast(), "expected direct message to be returned.")

		// Check broadcast message is not returned in a direct round.
		keep = messageKeep{}
		msg.Broadcast = true
		keep.addMessage(broadcast)
		msgs = keep.getMessages(false)
		a.Len(msgs, 0, "expected no message to be returned, since we inspect a direct round")

		keep.addMessage(direct)
		msgs = keep.getMessages(false)
		a.Len(msgs, 1, "expected only direct message to be returned.")
		a.False(msgs[0].IsBroadcast())
	})

	t.Run("clear messages logic", func(t *testing.T) {
		a := assert.New(t)

		// broadcast case, check delivery
		keep := messageKeep{}
		keep.addMessage(broadcast)
		keep.addMessage(direct)

		keep.clearDeliveredMessages(true)
		for _, v := range keep.cells {
			a.NotNil(v) // not delivered yet, so should not be cleared.
		}

		keep.getMessages(true) // changing the stage for the cells
		keep.clearDeliveredMessages(true)
		for _, v := range keep.cells {
			a.Nil(v)
		}

		// inspect direct round drops broadcast messages always.
		keep = messageKeep{}
		keep.addMessage(broadcast)
		keep.addMessage(direct)

		keep.clearDeliveredMessages(false)
		a.Nil(keep.cells[broadcastMessagePos])
		a.NotNil(keep.cells[directMessagePos])

		a.Len(keep.getMessages(false), 1)
	})
}

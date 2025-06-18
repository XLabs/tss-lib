package party

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/party"

	"github.com/xlabs/multi-party-sig/protocols/frost"
	common "github.com/xlabs/tss-common"
	"golang.org/x/crypto/sha3"
)

// Impl handles multiple signers
type Impl struct {
	ctx        context.Context
	cancelFunc context.CancelFunc

	config   *frost.Config
	peers    []*common.PartyID
	peersmap map[party.ID]*common.PartyID
	peerIDs  []party.ID

	self *common.PartyID

	sessionMap *sessionMap

	incomingMessagesChannel chan feedMessageTask
	startSignerTaskChan     chan *singleSession

	errorChannel           chan<- *common.Error
	outChan                chan common.ParsedMessage
	signatureOutputChannel chan *common.SignatureData

	maxTTl               time.Duration
	loadDistributionSeed []byte

	workersWg sync.WaitGroup
}

func hash(msg []byte) Digest {
	return sha3.Sum256(msg)
}

func (p *Impl) cleanupWorker() {
	defer p.workersWg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return

		case <-time.After(p.maxTTl):
			p.sessionMap.cleanup(p.maxTTl)
		}
	}
}

func (p *Impl) GetPublic() curve.Point {
	return p.config.PublicKey
}

// The worker serves as messages courier to all singelSession instances.
func (p *Impl) worker() {
	defer p.workersWg.Done()

	for {
		select {
		case task := <-p.incomingMessagesChannel:
			switch findProtocolType(task.message) {
			case signingProtocolType:
				p.handleIncomingSigningMessage(task)
			default:
				p.errorChannel <- common.NewError(errors.New("received unknown message type"), "incomingMessage", 0, p.self, task.message.GetFrom())
			}

		case signer := <-p.startSignerTaskChan:
			p.startSigner(signer)

		case <-p.ctx.Done():
			return
		}
	}
}

var (
	numHandlerWorkers = runtime.NumCPU() * 2
)

func (p *Impl) Start(outChannel chan common.ParsedMessage, signatureOutputChannel chan *common.SignatureData, errChannel chan<- *common.Error) error {
	if outChannel == nil || signatureOutputChannel == nil || errChannel == nil {
		return errors.New("nil channel passed to Start()")
	}

	p.errorChannel = errChannel
	p.signatureOutputChannel = signatureOutputChannel
	p.outChan = outChannel

	p.workersWg.Add(numHandlerWorkers + 1) // +1 for cleanup worker.

	// since the worker needs to contend for locks, we can add more than the number of CPUs.
	for i := 0; i < numHandlerWorkers; i++ {
		go p.worker()
	}

	go p.cleanupWorker()

	return nil
}

func (p *Impl) Stop() {
	p.cancelFunc()

	p.workersWg.Wait()
}

func (p *Impl) AsyncRequestNewSignature(s SigningTask) (*SigningInfo, error) {
	trackid := p.createTrackingID(s)

	// fast lock.
	signer, err := p.getOrCreateSingleSession(trackid)
	if err != nil {
		return nil, err
	}

	info, err := p.GetSigningInfo(s)
	if err != nil {
		return nil, err
	}

	select {
	case <-p.ctx.Done():
		return nil, p.ctx.Err()

	case p.startSignerTaskChan <- signer:
	}

	return info, nil
}

func (p *Impl) startSigner(signer *singleSession) {
	if signer == nil {
		return
	}

	config := p.config

	// The following method initiates the singleSession (if it’s a committee
	// member). Depending on the protocol, this function might be
	// compute intensive (frost is cheap, gg18 is not).
	if err := p.setSession(config, signer); err != nil {
		p.reportError(common.NewTrackableError(
			err,
			"startSigner",
			-1,
			nil,
			signer.trackingId,
		))

		return
	}

	if signer.getState() != set {
		return // not in committee, or, any other reason
	}

	// the first round doesn't have to wait for messages, so we can advance it right away.
	p.sessionAdvance(signer)
}

// session advance will consume messages, and attempt to finalize the session.
func (p *Impl) sessionAdvance(signer *singleSession) UpdateMeta {
	var err *common.Error
	var report finalizeReport

	// do while loop:
	// if advanced one round -> see if there is more to advance.
	for ok := true; ok; ok = report.advancedRound {
		if report, err = signer.advanceOnce(); err != nil {
			return UpdateMeta{Error: err}
		}

		if report.isSessionComplete {
			break // session is complete, no need to advance further.
		}
	}

	if !report.isSessionComplete {
		return UpdateMeta{
			AdvancedRound:      report.advancedRound,
			CurrentRoundNumber: int(report.currentRound),
			SignerState:        set.String(),
		}
	}

	sig, err := signer.extractSignature()
	if err != nil {
		return UpdateMeta{Error: err}
	}

	if err := p.outputSig(sig, signer); err != nil {
		return UpdateMeta{Error: err}
	}

	return UpdateMeta{
		AdvancedRound:      report.advancedRound,
		CurrentRoundNumber: int(signer.getRound()),
		SignerState:        set.String(),
	}
}

var (
	errNilSigner              = errors.New("nil signer")
	errShouldBeBroadcastRound = errors.New("frost sessions should be of type BroadcastRound")
)

func pidToDigest(pid *common.PartyID) Digest {
	bf := bytes.NewBuffer(nil)

	bf.WriteString(pid.GetID())

	return hash(bf.Bytes())
}

// assumes locked by the caller.
// This is the only method that changes the session state.
func (p *Impl) setSession(config *frost.Config, signer *singleSession) error {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	if signer.getState() != unset {
		return nil
	}

	if !common.UnSortedPartyIDs(signer.committee).IsInCommittee(p.self) {
		signer.state.Store(int64(notInCommittee))

		return nil
	}

	// set the state to "set" (in committee).
	signer.state.Store(int64(set))

	sessionCreator := frost.Sign(config, pids2IDs(signer.committee), signer.digest[:])

	session, err := sessionCreator(signer.trackingId.ToByteString())
	if err != nil {
		return err
	}

	signer.session = session

	return nil
}

// getOrCreateSingleSession returns the signer for the given digest, or creates a new one if it doesn't exist.
func (p *Impl) getOrCreateSingleSession(trackingId *common.TrackingID) (*singleSession, error) {
	s := p.sessionMap

	dgst := Digest{}
	copy(dgst[:], trackingId.Digest)

	signer, loaded := s.LoadOrStore(trackingId.ToString(), &singleSession{
		startTime: time.Now(),
		state:     atomic.Int64{},

		self:       p.self,
		digest:     dgst,
		trackingId: trackingId,
		mtx:        sync.Mutex{},

		// set after store or load of the singleSession.
		committee: nil,
		// session is once allowed to sign (AsyncRequestNewSignature).
		session: nil,

		// first round doesn't receive messages (only round number 2,3)
		messages: make([]map[Digest]common.ParsedMessage, frost.NumRounds-1),

		outputchan: p.outChan,
		peersmap:   p.peersmap,
	})

	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	// Only a single concurrent run of this method will pass this point (due to the syncMap output).
	if !loaded {
		committee, err := p.computeCommittee(signer.trackingId)
		if err != nil {
			return nil, err
		}

		signer.committee = committee
	}

	return signer, nil
}

func (p *Impl) computeCommittee(trackid *common.TrackingID) (common.SortedPartyIDs, error) {
	validParties, err := p.getValidCommitteeMembers(trackid)
	if err != nil {
		return nil, err
	}

	if len(validParties) < p.committeeSize() {
		return nil, fmt.Errorf("not enough valid parties in signer committee: %d < %d",
			len(validParties),
			p.committeeSize(),
		)
	}

	parties, err := shuffleParties(p.makeShuffleSeed(trackid), validParties)
	if err != nil {
		return nil, err
	}

	return common.SortPartyIDs(parties[:p.committeeSize()]), nil
}

func (p *Impl) committeeSize() int {
	return p.config.Threshold + 1
}

func (p *Impl) makeShuffleSeed(trackid *common.TrackingID) []byte {
	seed := append(p.loadDistributionSeed, []byte(trackid.ToString())...)
	return seed
}

type feedMessageTask struct {
	message common.ParsedMessage
	result  chan UpdateMeta
}

func (p *Impl) Update(message common.ParsedMessage) (<-chan UpdateMeta, error) {
	answerChan := make(chan UpdateMeta, 1)

	select {
	case p.incomingMessagesChannel <- feedMessageTask{message: message, result: answerChan}:
		return answerChan, nil
	case <-p.ctx.Done():
		close(answerChan) // ensures no one will block waiting on the channel.

		return answerChan, p.ctx.Err()
	}
}

func (p *Impl) handleIncomingSigningMessage(task feedMessageTask) {
	// assumes the message has a tracking ID.
	message := task.message
	signer, err := p.getOrCreateSingleSession(message.WireMsg().GetTrackingID())
	if err != nil {
		task.result <- UpdateMeta{
			Error: common.NewTrackableError(
				err,
				"handleIncomingSigningMessage",
				-1,
				message.GetFrom(),
				message.WireMsg().GetTrackingID(),
			),
		}

		return
	}

	state := signer.getState()
	if state == notInCommittee {
		// no need to store the message since the signer is not in the committee.

		task.result <- UpdateMeta{ // updating the task result.
			AdvancedRound:      false,
			CurrentRoundNumber: 0,
			SignerState:        unset.String(),
		}

		return
	}

	signer.storeMessage(message)

	if state != set {
		// not allowed to consume/ finalize messages.

		task.result <- UpdateMeta{
			AdvancedRound:      false,
			CurrentRoundNumber: 0,
			SignerState:        state.String(),
		}

		return
	}

	task.result <- p.sessionAdvance(signer)

}

func (p *Impl) reportError(newError *common.Error) {
	select {
	case p.errorChannel <- newError:
	default: // no one is waiting on error reporting channel/ no buffer.
	}
}

func (p *Impl) createTrackingID(s SigningTask) *common.TrackingID {
	offlineMap := map[string]bool{}
	for _, v := range s.Faulties {
		offlineMap[string(v.GetID())] = true
	}

	pids := make([]bool, len(p.peers))

	for i, v := range p.peers {
		if !offlineMap[string(v.GetID())] {
			pids[i] = true
		}
	}

	dgst := Digest{}
	copy(dgst[:], s.Digest[:])

	// TODO: Discuss what happens upon config change. maybe trackID should contain the hash of config? (sessions with the tracking ID but unmatching configs will fail.)
	tid := &common.TrackingID{
		Digest:       dgst[:],
		PartiesState: common.ConvertBoolArrayToByteArray(pids),
		AuxilaryData: s.AuxilaryData,
	}

	return tid
}

var errInvalidTrackingID = errors.New("invalid tracking id")

// returns the parties that can still be part of the committee.
func (p *Impl) getValidCommitteeMembers(trackingId *common.TrackingID) (common.UnSortedPartyIDs, error) {
	pids := p.peers

	ValidCommitteeMembers := make([]*common.PartyID, 0, len(pids))

	if len(trackingId.PartiesState) < (len(pids)+7)/8 {
		return nil, errInvalidTrackingID
	}

	for i, pid := range pids {
		if trackingId.PartyStateOk(i) {
			ValidCommitteeMembers = append(ValidCommitteeMembers, pid)
		}
	}

	return common.UnSortedPartyIDs(ValidCommitteeMembers), nil
}

func (p *Impl) GetSigningInfo(s SigningTask) (*SigningInfo, error) {

	trackingId := p.createTrackingID(s)

	sortedCommittee, err := p.computeCommittee(trackingId)
	if err != nil {
		return nil, err
	}

	return &SigningInfo{
		SigningCommittee: sortedCommittee,
		TrackingID:       trackingId,
		IsSigner:         common.UnSortedPartyIDs(sortedCommittee).IsInCommittee(p.self),
	}, nil
}

func (p *Impl) outputSig(sig frost.Signature, signer *singleSession) *common.Error {
	rbits, err := sig.R.MarshalBinary()
	if err != nil {
		return common.NewTrackableError(
			err,
			"outputSig",
			-1,
			signer.self,
			signer.trackingId,
		)
	}

	sbits, err := sig.Z.MarshalBinary()
	if err != nil {
		return common.NewTrackableError(
			err,
			"outputSig",
			-1,
			signer.self,
			signer.trackingId,
		)
	}

	select {
	case p.signatureOutputChannel <- &common.SignatureData{
		R:          rbits,
		S:          sbits,
		M:          signer.digest[:],
		TrackingId: signer.trackingId,
	}:
	case <-p.ctx.Done():
		// nothing to report.
	}

	return nil
}

package party

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/round"

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

	self *common.PartyID

	sessionMap *sessionMap

	incomingMessagesChannel chan feedMessageTask
	startSignerTaskChan     chan *singleSession

	errorChannel           chan<- *common.Error
	outChan                chan common.ParsedMessage
	signatureOutputChannel chan *common.SignatureData
	keygenout              chan *frost.Config

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
	return p.config.PublicKey.Clone()
}

// The worker serves as messages courier to all singelSession instances.
func (p *Impl) worker() {
	defer p.workersWg.Done()

	for {
		select {
		case task := <-p.incomingMessagesChannel:
			switch task.message.Content().GetProtocol() {
			case common.ProtocolFROST:
				p.handleFrostMessage(task)
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

func (p *Impl) Start(params OutputChannels) error {
	if params.OutChannel == nil ||
		params.SignatureOutputChannel == nil ||
		params.ErrChannel == nil {
		return errors.New("nil channel passed to Start()")
	}

	p.errorChannel = params.ErrChannel
	p.signatureOutputChannel = params.SignatureOutputChannel
	p.outChan = params.OutChannel
	p.keygenout = params.KeygenOutputChannel

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

var errNoConfig = errors.New("signing protocol not configured")

func (p *Impl) AsyncRequestNewSignature(s SigningTask) (*SigningInfo, error) {
	if p.config == nil {
		return nil, errNoConfig
	}

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
	if err := p.setSigningSession(config, signer); err != nil {
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
	p.advanceSession(signer)
}

// advanceSession will consume messages, and attempt to finalize the session.
func (p *Impl) advanceSession(session *singleSession) *common.Error {
	var err *common.Error
	var report finalizeReport

	// do while loop:
	// if advanced one round -> attempt to do so again(unless session is completed).
	for ok := true; ok; ok = report.advancedRound && !report.isSessionComplete {
		if report, err = session.advanceOnce(); err != nil {
			return err
		}

		p.logReport(session, report)
	}

	if !report.isSessionComplete {
		return nil
	}

	// after session end, either with success or error, we remove it from the session map.
	p.sessionMap.deleteSession(session)

	// Finalizing the session.
	out, err := session.extractOutput()
	if err != nil {
		return err
	}

	switch res := out.(type) {
	case *frost.Config:
		p.outputKeygen(res)

	case frost.Signature:
		err = p.outputSig(res, session)
	default:
		err = common.NewTrackableError(
			fmt.Errorf("unknown output type: %T", out),
			"advanceSession:output",
			-1,
			session.self,
			session.trackingId,
		)
	}

	return err
}

func (p *Impl) outputKeygen(res *frost.Config) {
	select {
	case p.keygenout <- res:
	case <-p.ctx.Done():
		// nothing to report.
	}
}

// assumes locked by the caller.
// This is the only method that changes the session state.
func (p *Impl) setSigningSession(config *frost.Config, signer *singleSession) error {
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
		messages: make(map[round.Number]map[strPartyID]*messageKeep, frost.NumRounds-1),

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
}

func (p *Impl) Update(message common.ParsedMessage) error {
	select {
	case p.incomingMessagesChannel <- feedMessageTask{message: message}:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

func (p *Impl) handleFrostMessage(task feedMessageTask) {
	// assumes the message has a tracking ID.
	message := task.message

	signer, err := p.getOrCreateSingleSession(message.WireMsg().GetTrackingID())
	if err != nil {
		p.outputErr(common.NewTrackableError(
			err,
			"handleFrostMessage",
			-1,
			message.GetFrom(),
			message.WireMsg().GetTrackingID(),
		))

		return
	}

	state := signer.getState()
	if state == notInCommittee {
		// no need to store the message since the signer is not in the committee.

		return // no issues, and nothing to report.
	}

	if err := signer.storeMessage(message); err != nil {
		p.outputErr(err)

		return
	}

	if state != set {
		// not allowed to consume/ finalize messages.
		return
	}

	if err := p.advanceSession(signer); err != nil {
		p.reportError(err)

		return
	}
}

func (p *Impl) logReport(signer *singleSession, report finalizeReport) {
	if report.isSessionComplete {
		slog.Debug("session completed",
			slog.String("trackingID", signer.trackingId.ToString()),
		)
	} else if report.advancedRound {
		slog.Debug("session advanced",
			slog.String("trackingID", signer.trackingId.ToString()),
			slog.Int64("round", int64(signer.getRound())),
		)
	}
}

func (p *Impl) outputErr(err *common.Error) {
	if err == nil {
		return // nothing to report.
	}

	select {
	case p.errorChannel <- err:
	case <-p.ctx.Done():
	}
}

func (p *Impl) reportError(newError *common.Error) {
	select {
	case p.errorChannel <- newError:
	default: // no one is waiting on error reporting channel/ no buffer.
	}
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

var errDKGIssue = errors.New("FullParty has bad configurations. Cannot start DKG protocol")

func (p *Impl) StartDKG(task DkgTask) error {
	if p.keygenout == nil {
		return errDKGIssue
	}

	if len(p.peers) < task.Threshold {
		return fmt.Errorf("not enough parties to start DKG. Need at least: %d", task.Threshold+1)
	}

	tid := p.createTrackingID(task)

	s, err := p.getOrCreateSingleSession(tid)
	if err != nil {
		return common.NewError(
			err,
			"StartDKG",
			-1,
			p.self,
		)
	}

	if err := p.setKeygenSession(s, task.Threshold); err != nil {
		return err
	}

	// checking for nil since returning a nil *common.Error via error interface isn't treated
	// as nil by go interface semantics.
	if err := p.advanceSession(s); err != nil {
		return err
	}

	return nil
}

// ensures the session can advance. An unset session doesn't consume messages.
func (p *Impl) setKeygenSession(s *singleSession, threshold int) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.isKeygenSession = true

	s.committee = common.SortPartyIDs(p.peers)

	sessionCreator := frost.Keygen(curve.Secp256k1{}, party.FromTssID(s.self), pids2IDs(s.committee), threshold)

	session, err := sessionCreator(s.trackingId.ToByteString())
	if err != nil {
		return err
	}

	s.session = session

	s.state.Store(int64(set))

	return nil
}

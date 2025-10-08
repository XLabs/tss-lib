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
	"github.com/xlabs/multi-party-sig/pkg/pool"
	"github.com/xlabs/multi-party-sig/pkg/protocol"
	"github.com/xlabs/multi-party-sig/pkg/round"

	"github.com/xlabs/multi-party-sig/protocols/cmp"
	"github.com/xlabs/multi-party-sig/protocols/frost"
	common "github.com/xlabs/tss-common"
	"golang.org/x/crypto/sha3"
)

// Impl handles multiple signers
type Impl struct {
	ctx        context.Context
	cancelFunc context.CancelFunc

	frostConfig *frost.Config

	ecdsaConfig       *cmp.Config
	ecdsaCachedPublic curve.Point

	peers    []*common.PartyID
	peersmap map[party.ID]*common.PartyID

	self *common.PartyID

	sessionMap *sessionMap

	incomingMessagesChannel chan feedMessageTask
	startSignerTaskChan     chan *singleSession

	outputChannels OutputChannels

	maxTTl               time.Duration
	loadDistributionSeed []byte

	workersWg sync.WaitGroup

	rateLimiter rateLimiter

	pool *pool.Pool
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
			p.rateLimiter.cleanSelf(p.maxTTl)
		}
	}
}

// The worker serves as messages courier to all singelSession instances.
func (p *Impl) worker() {
	defer p.workersWg.Done()

	for {
		select {
		case task := <-p.incomingMessagesChannel:
			switch task.message.Content().GetProtocol() {
			case common.ProtocolFROSTSign, common.ProtocolFROSTDKG,
				common.ProtocolECDSADKG, common.ProtocolECDSASign:
				p.handleMessage(task)
			default:
				p.outputChannels.ErrChannel <- common.NewError(errors.New("received unknown message type"), "incomingMessage", 0, p.self, task.message.GetFrom())
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

func (p *Impl) Start(out OutputChannels) error {
	if out.OutChannel == nil ||
		out.SignatureOutputChannel == nil ||
		out.ErrChannel == nil ||
		out.WarningChannel == nil {
		return errors.New("nil channel passed to Start()")
	}

	p.outputChannels = out

	p.workersWg.Add(numHandlerWorkers + 1) // +1 for cleanup worker.

	// since the worker needs to contend for locks, we can add more than the number of CPUs.
	for i := 0; i < numHandlerWorkers; i++ {
		go p.worker()
	}

	go p.cleanupWorker()

	p.pool = pool.NewPool(numHandlerWorkers)

	return nil
}

func (p *Impl) Stop() {
	p.cancelFunc()
	p.workersWg.Wait()

	// stopped passing messages to sessions, we can now safely
	// tear down the pool used by the sessions.
	p.pool.TearDown()
}

var ErrNoConfig = errors.New("signing protocol not configured")

func (p *Impl) GetPublic(t common.ProtocolType) (curve.Point, error) {
	switch t {
	case common.ProtocolECDSASign, common.ProtocolECDSADKG:
		if p.ecdsaConfig == nil || p.ecdsaCachedPublic == nil {
			return nil, ErrNoConfig
		}

		return p.ecdsaCachedPublic.Clone(), nil
	case common.ProtocolFROSTSign, common.ProtocolFROSTDKG:
		if p.frostConfig == nil {
			return nil, ErrNoConfig
		}

		return p.frostConfig.PublicKey.Clone(), nil
	default:
		return nil, fmt.Errorf("public not found for: %s", t.ToString())
	}
}

func (p *Impl) AsyncRequestNewSignature(s SigningTask) (*SigningInfo, error) {
	if err := p.canSatisfyTask(s); err != nil {
		return nil, err
	}
	if s.ProtocolType != common.ProtocolFROSTSign && s.ProtocolType != common.ProtocolECDSASign {
		return nil, fmt.Errorf("not a valid signing protocol: %s", s.ProtocolType.ToString())
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

var errNotConfiguredToRunDKG = errors.New("not configured to run DKG. missing KeygenOutputChannel")

func (p *Impl) canSatisfyTask(s task) error {
	protoType := s.GetProtocolType()
	switch protoType {
	case common.ProtocolFROSTSign:
		if p.frostConfig == nil {
			return ErrNoConfig
		}
	case common.ProtocolFROSTDKG:
		if p.outputChannels.KeygenOutputChannel == nil {
			return errNotConfiguredToRunDKG
		}
	case common.ProtocolECDSASign:
		if p.ecdsaConfig == nil {
			return ErrNoConfig
		}
	case common.ProtocolECDSADKG:
		return fmt.Errorf("ECDSA DKG protocol not supported") // TODO: implement ECDSA DKG
	default:
		return fmt.Errorf("unknown signing protocol: %s", protoType.ToString())
	}

	return nil
}

func (p *Impl) startSigner(signer *singleSession) {
	if signer == nil {
		return
	}

	// The following method initiates the singleSession (if it’s a committee
	// member). Depending on the protocol, this function might be
	// compute intensive (frost is cheap, gg18 is not).
	if err := p.setSigningSession(signer); err != nil {
		p.outputErr(common.NewTrackableError(
			err,
			"startSigner",
			-1,
			nil,
			signer.trackingId,
		))

		return
	}

	if signer.getState() != activated {
		return // not in committee, or, any other reason
	}

	// the first round doesn't have to wait for messages, so we can advance it right away.
	if err := p.advanceSession(signer); err != nil {
		p.outputErr(common.NewTrackableError(
			err,
			"startSigner:advanceSession",
			-1,
			nil,
			signer.trackingId,
		))
	}
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

	// also remove it from the rate limiter.
	p.rateLimiter.remove(session.trackingId)

	// Finalizing the session.
	conf, sig, err := session.extractOutput()
	if err != nil {
		return err
	}

	if conf != nil {
		p.outputKeygen(conf)
	}

	if sig != nil {
		return p.outputSig(*sig, session)
	}

	return nil
}

func (p *Impl) outputKeygen(res *TSSSecrets) {
	select {
	case p.outputChannels.KeygenOutputChannel <- res:
	case <-p.ctx.Done():
		// nothing to report.
	}
}

// This is the only method that changes the session state.
func (p *Impl) setSigningSession(signer *singleSession) error {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	// this function sets the state. once set, it cannot be changed.
	if signer.getState() != awaitingActivation {
		return nil
	}

	// compute committee, then check if the signer is in the committee.
	committee, err := p.computeCommittee(signer.trackingId)
	if err != nil {
		return err
	}

	signer.committee = committee

	if !common.UnSortedPartyIDs(signer.committee).IsInCommittee(p.self) {
		signer.state.Store(int64(notInCommittee))

		// not in committee, so we can remove it from the rate limiter.
		// we will not store any messages for this session anymore.
		p.rateLimiter.remove(signer.trackingId)

		return nil
	}

	// set the state to "set" (in committee).
	signer.state.Store(int64(activated))

	var sessionCreator protocol.StartFunc
	switch signer.protocol {
	case common.ProtocolFROSTSign:
		sessionCreator = frost.Sign(p.frostConfig, pids2IDs(signer.committee), signer.digest[:])
	case common.ProtocolECDSASign:
		sessionCreator = cmp.Sign(p.ecdsaConfig, pids2IDs(signer.committee), signer.digest[:], p.pool)
	default:
		return fmt.Errorf("unsupported signing protocol: %s", signer.protocol.ToString())
	}

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

	protocol, err := trackingId.GetProtocolType()
	if err != nil {
		return nil, err
	}

	signer, _ := s.LoadOrStore(trackingId.ToString(), &singleSession{
		startTime: time.Now(),
		state:     atomic.Int64{},

		self:       p.self,
		digest:     dgst,
		trackingId: trackingId,
		mtx:        sync.Mutex{},

		protocol: protocol,
		// A SingleSession may be created in response to a message from a peer whose honesty
		// cannot be assumed. Therefore, any data provided alongside the trackingID
		// (the identifier for this new session) must be considered untrusted.
		// In particular, we cannot rely on it to determine the session type or committee.
		// To establish these safely, we wait for the operator/user to explicitly request
		// a new signing or DKG via AsyncRequestNewSignature/StartDKG, which updates both
		// the session type and the committee.
		committee: nil,
		session:   nil,
		// first round doesn't receive messages (only round number 2,3)
		messages: make(map[round.Number]map[strPartyID]*messageKeep, frost.NumRounds-1),

		outputChannels: &p.outputChannels,
	})

	return signer, nil
}

func (p *Impl) computeCommittee(trackid *common.TrackingID) (common.SortedPartyIDs, error) {
	validParties, err := p.getValidCommitteeMembers(trackid)
	if err != nil {
		return nil, err
	}

	committeeSize := p.committeeSize()

	if len(validParties) < committeeSize {
		return nil, fmt.Errorf("not enough valid parties in signer committee: %d < %d",
			len(validParties),
			committeeSize,
		)
	}

	parties, err := shuffleParties(p.makeShuffleSeed(trackid), validParties)
	if err != nil {
		return nil, err
	}

	return common.SortPartyIDs(parties[:p.committeeSize()]), nil
}

func (p *Impl) committeeSize() int {
	if p.frostConfig == nil {
		return len(p.peers) // default to all peers.
	}

	return p.frostConfig.Threshold + 1
}

func (p *Impl) makeShuffleSeed(trackid *common.TrackingID) []byte {
	seed := append(p.loadDistributionSeed, []byte(trackid.ToString())...)
	return seed
}

type feedMessageTask struct {
	message common.ParsedMessage
}

var (
	errNilMessage = errors.New("nil message")
	errNilSender  = errors.New("nil sender in message")
)

func (p *Impl) Update(message common.ParsedMessage) error {
	if message == nil {
		return errNilMessage
	}

	wiremsg := message.WireMsg()
	if wiremsg == nil {
		return errNilMessage
	}

	trackid := wiremsg.GetTrackingID()
	if trackid == nil {
		return errInvalidTrackingID
	}

	peer := message.GetFrom()
	if peer == nil {
		return errNilSender
	}
	if !wiremsg.GetFrom().Equals(peer) {
		return fmt.Errorf("mismatched sender in message: %s != %s", wiremsg.GetFrom().ToString(), peer.ToString())
	}

	peerID := party.ID(peer.GetID())

	// ensure known sender.
	if _, ok := p.peersmap[peerID]; !ok {
		return fmt.Errorf("unknown sender: %s", message.GetFrom().ToString())
	}

	canFeed := p.rateLimiter.add(message.WireMsg().GetTrackingID(), peer)
	if !canFeed {
		return fmt.Errorf("peer %v has reached the maximum number of simultaneous sessions", peerID)
	}

	select {
	case p.incomingMessagesChannel <- feedMessageTask{message: message}:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

func (p *Impl) handleMessage(task feedMessageTask) {
	// assumes the message has a tracking ID.
	message := task.message

	signer, err := p.getOrCreateSingleSession(message.WireMsg().GetTrackingID())
	if err != nil {
		p.outputErr(common.NewTrackableError(
			err,
			"handleMessage",
			unknownRound,
			message.GetFrom(),
			message.WireMsg().GetTrackingID(),
		))

		return
	}

	state := signer.getState()
	if state == notInCommittee {
		// no need to store the message since the signer is not in the committee.

		// ensuring we remove this trackid from the rate limiter.
		p.rateLimiter.remove(signer.trackingId)

		return
	}

	if err := signer.storeMessage(message); err != nil {
		p.outputErr(err)

		return
	}

	if state != activated {
		// not allowed to consume/ finalize messages.
		return
	}

	if err := p.advanceSession(signer); err != nil {
		p.outputErr(err)

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
	case p.outputChannels.ErrChannel <- err:
	case <-p.ctx.Done():
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
	rbits, err := sig.R.Curve().MarshalPoint(sig.R)
	if err != nil {
		return common.NewTrackableError(
			err,
			"outputSig",
			unknownRound,
			signer.self,
			signer.trackingId,
		)
	}

	sbits, err := sig.Z.Curve().MarshalScalar(sig.Z)
	if err != nil {
		return common.NewTrackableError(
			err,
			"outputSig",
			unknownRound,
			signer.self,
			signer.trackingId,
		)
	}

	select {
	case p.outputChannels.SignatureOutputChannel <- &common.SignatureData{
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

func (p *Impl) StartDKG(task DkgTask) error {
	if err := p.canSatisfyTask(task); err != nil {
		return err
	}

	if len(p.peers) <= task.Threshold {
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

	s.state.Store(int64(activated))

	return nil
}

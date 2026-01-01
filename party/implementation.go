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
	ecdsaConfig *cmp.Config

	peers    []*common.PartyID
	peersmap map[party.ID]*common.PartyID

	self *common.PartyID

	sessionMap *sessionMap

	frostWorkerChans workerChans
	ecdsaWorkerChans workerChans

	outputChannels OutputChannels

	maxTTl               time.Duration
	loadDistributionSeed []byte

	workersWg sync.WaitGroup

	rateLimiter RateLimiter

	pool *pool.Pool
}

type workerChans struct {
	incomingMessages chan feedMessageTask // used to feed incoming messages to the worker
	startSigner      chan *singleSession  // used to start a signer on the worker
}

func hash(msg []byte) Digest {
	return sha3.Sum256(msg)
}

var ErrTimeout = errors.New("timed out")

func (p *Impl) cleanupWorker() {
	defer p.workersWg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return

		case <-time.After(p.maxTTl):
			ttlSigs := p.sessionMap.cleanup(p.maxTTl)
			p.rateLimiter.CleanSelf(p.maxTTl)

			for _, tid := range ttlSigs {
				p.outputErr(common.NewTrackableError(ErrTimeout, "signature timed out", -1, p.self, tid))
			}
		}
	}
}

// The worker serves as messages courier to all singelSession instances.
func (p *Impl) worker(chns workerChans) {
	defer p.workersWg.Done()

	for {
		select {
		case task := <-chns.incomingMessages:
			p.handleMessage(task)
		case signer := <-chns.startSigner:
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
	for i := 0; i < numHandlerWorkers/2; i++ {
		go p.worker(p.frostWorkerChans)
	}
	for i := 0; i < numHandlerWorkers/2; i++ {
		go p.worker(p.ecdsaWorkerChans)
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

var (
	ErrNoConfig          = errors.New("signing protocol not configured")
	ErrDkgHasNoPublicKey = errors.New("dkg protocols have no public key to use")
)

func (p *Impl) GetPublic(t common.ProtocolType) (curve.Point, error) {
	switch t {
	case common.ProtocolECDSASign:
		if p.ecdsaConfig == nil {
			return nil, ErrNoConfig
		}

		return p.ecdsaConfig.PublicPoint().Clone(), nil
	case common.ProtocolFROSTSign:
		if p.frostConfig == nil {
			return nil, ErrNoConfig
		}

		return p.frostConfig.PublicKey.Clone(), nil
	case common.ProtocolFROSTDKG, common.ProtocolECDSADKG:
		return nil, ErrDkgHasNoPublicKey
	default:
		return nil, fmt.Errorf("public not found for: %s", t.ToString())
	}
}

func (p *Impl) AsyncRequestNewSignature(s SigningTask) (*SigningInfo, error) {
	if err := p.validateTaskConfiguration(s); err != nil {
		return nil, err
	}
	if s.ProtocolType != common.ProtocolFROSTSign && s.ProtocolType != common.ProtocolECDSASign {
		return nil, fmt.Errorf("not a valid signing protocol: %s", s.ProtocolType.ToString())
	}

	trackid := p.createTrackingID(s)

	info, err := p.GetSigningInfo(s)
	if err != nil {
		return nil, err
	}

	// fast lock.
	signer, err := p.getOrCreateSingleSession(trackid)
	if err != nil {
		if errors.Is(err, ErrNotInCommittee) {
			return info, nil // not an error for the client.
		}
		return nil, err
	}

	wrkrchan := p.frostWorkerChans
	if s.ProtocolType == common.ProtocolECDSASign {
		wrkrchan = p.ecdsaWorkerChans
	}

	select {
	case <-p.ctx.Done():
		return nil, p.ctx.Err()

	case wrkrchan.startSigner <- signer:
	}

	return info, nil
}

var errNotConfiguredToRunDKG = errors.New("not configured to run DKG. missing KeygenOutputChannel")

// ensures we have the right configuration to run the given task.
// For instance, if the task is FROST signing, we need to have the frost config set.
// If the task is DKG, we need to have the KeygenOutputChannel set.
func (p *Impl) validateTaskConfiguration(s task) error {
	protoType := s.GetProtocolType()
	switch protoType {
	case common.ProtocolFROSTSign:
		if p.frostConfig == nil {
			return ErrNoConfig
		}
	case common.ProtocolECDSASign:
		if p.ecdsaConfig == nil {
			return ErrNoConfig
		}
	case common.ProtocolECDSADKG, common.ProtocolFROSTDKG:
		if p.outputChannels.KeygenOutputChannel == nil {
			return errNotConfiguredToRunDKG
		}
	default:
		return fmt.Errorf("unknown protocol: %s", protoType.ToString())
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
	p.rateLimiter.Remove(session.trackingId)

	// Finalizing the session.
	conf, sig, err := session.extractOutput()
	if err != nil {
		return err
	}

	if conf != nil {
		p.outputKeygen(conf)
	}

	if sig != nil {
		return p.outputSig(sig)
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

	// once state changes from awaitingActivation, the signer is fully initialized.
	if signer.getState() != awaitingActivation {
		return nil
	}

	// set the state to "activated" (in committee).
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

var ErrNotInCommittee = errors.New("party not in committee")

// getOrCreateSingleSession returns the signer for the given digest, or creates a new one if it doesn't exist.
func (p *Impl) getOrCreateSingleSession(trackingId *common.TrackingID) (*singleSession, error) {
	if err := BasicTrackingIDValidation(trackingId); err != nil {
		return nil, err
	}

	committee, err := p.computeCommittee(trackingId)
	if err != nil {
		return nil, err
	}

	if !common.UnSortedPartyIDs(committee).IsInCommittee(p.self) {
		p.rateLimiter.Remove(trackingId) // we don't store the session, so we remove any rate limiting state.

		return nil, ErrNotInCommittee
	}

	protocol, err := trackingId.GetProtocolType()
	if err != nil {
		return nil, err
	}

	dgst := Digest{}
	copy(dgst[:], trackingId.Digest)

	session, _ := p.sessionMap.LoadOrStore(trackingId.ToString(), &singleSession{
		// read-only fields
		startTime:       time.Now(),
		isKeygenSession: isDkg(protocol),
		digest:          dgst,
		protocol:        protocol,
		trackingId:      trackingId,
		committee:       committee,
		self:            p.self,
		outputChannels:  &p.outputChannels,

		mtx: sync.Mutex{},
		// mutable fields
		state:    atomic.Int64{}, // default is 0 == awaitingActivation
		messages: map[round.Number]map[strPartyID]*messageKeep{},
		session:  nil,
	})

	return session, nil
}

func (p *Impl) computeCommittee(trackid *common.TrackingID) (common.SortedPartyIDs, error) {
	prot, err := trackid.GetProtocolType()
	if err != nil {
		return nil, err
	}

	if isDkg(prot) {
		// everyone is in the committee (DKG case).
		return common.SortPartyIDs(p.peers), nil
	}

	validParties, err := p.getValidCommitteeMembers(trackid)
	if err != nil {
		return nil, err
	}

	committeeSize := p.committeeSize(prot)

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

	return common.SortPartyIDs(parties[:committeeSize]), nil
}

func (p *Impl) committeeSize(prot common.ProtocolType) int {
	switch prot {
	case common.ProtocolFROSTSign:
		if p.frostConfig != nil {
			return p.frostConfig.Threshold + 1
		}
	case common.ProtocolECDSASign:
		if p.ecdsaConfig != nil {
			return p.ecdsaConfig.Threshold + 1
		}
	}

	// default to 0 if no config found.
	return 0
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

	chn := p.frostWorkerChans
	protocol, err := trackid.GetProtocolType()
	if err != nil {
		return err
	}

	switch protocol {
	case common.ProtocolFROSTSign, common.ProtocolFROSTDKG:
		chn = p.frostWorkerChans
	case common.ProtocolECDSASign, common.ProtocolECDSADKG:
		chn = p.ecdsaWorkerChans
	default:
		return fmt.Errorf("unsupported protocol type in message: %s", protocol.ToString())
	}

	// we check rate limiting last so we don't have to cancel it if the message is invalid.
	canFeed := p.rateLimiter.Add(message.WireMsg().GetTrackingID(), peer)
	if !canFeed {
		return fmt.Errorf("peer %v has reached the maximum number of simultaneous sessions", peerID)
	}

	select {
	case chn.incomingMessages <- feedMessageTask{message: message}:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

func (p *Impl) handleMessage(task feedMessageTask) {
	// assumes the message has a tracking ID.
	message := task.message

	session, err := p.getOrCreateSingleSession(message.WireMsg().GetTrackingID())
	if err != nil {
		if errors.Is(err, ErrNotInCommittee) {
			return // no need to report to the client.
		}

		p.outputErr(common.NewTrackableError(
			err,
			"handleMessage",
			unknownRound,
			message.GetFrom(),
			message.WireMsg().GetTrackingID(),
		))

		return
	}

	// storing the message in case the session will be activated later.
	if err := session.storeMessage(message); err != nil {
		p.outputErr(err)

		return
	}

	if session.getState() != activated {
		// not allowed to consume/ finalize messages.
		return
	}

	if err := p.advanceSession(session); err != nil {
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
		IsParticipating:  common.UnSortedPartyIDs(sortedCommittee).IsInCommittee(p.self),
	}, nil
}

func (p *Impl) outputSig(sig *common.SignatureData) *common.Error {
	select {
	case p.outputChannels.SignatureOutputChannel <- sig:
	case <-p.ctx.Done():
		// nothing to report.
	}

	return nil
}

func (p *Impl) StartDKG(task DkgTask) error {
	if err := p.validateTaskConfiguration(task); err != nil {
		return err
	}

	if len(p.peers) <= task.Threshold {
		return fmt.Errorf("not enough parties to start DKG. Need at least: %d", task.Threshold+1)
	}

	tid := p.createTrackingID(task)

	s, err := p.getOrCreateSingleSession(tid)
	if err != nil {
		// since DKG involves all parties, not being in committee is an error.
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

	var sessionCreator protocol.StartFunc

	switch s.protocol {
	// TODO: find a nice way to merge all the switch cases that inspect protocol type.
	case common.ProtocolFROSTDKG:
		sessionCreator = frost.Keygen(curve.Secp256k1{}, party.FromTssID(s.self), pids2IDs(s.committee), threshold)
	case common.ProtocolECDSADKG:
		sessionCreator = cmp.Keygen(curve.Secp256k1{}, party.FromTssID(s.self), pids2IDs(s.committee), threshold, p.pool)
	default:
		return fmt.Errorf("unsupported dkg protocol: %s", s.protocol.ToString())
	}

	session, err := sessionCreator(s.trackingId.ToByteString())
	if err != nil {
		return err
	}

	s.session = session

	s.state.Store(int64(activated))

	return nil
}

package party

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	"github.com/xlabs/tss-lib/v2/common"
	"github.com/xlabs/tss-lib/v2/ecdsa/keygen"
	"github.com/xlabs/tss-lib/v2/ecdsa/signing"
	"github.com/xlabs/tss-lib/v2/tss"
	"golang.org/x/crypto/sha3"
)

type KeygenHandler struct {
	LocalParty  tss.Party
	StoragePath string
	// communication channels
	ProtocolEndOutput <-chan *keygen.LocalPartySaveData

	SavedData *keygen.LocalPartySaveData
}

type partyIdIndex int

type signerState int

const (
	unset signerState = iota
	set
	notInCommittee
)

type singleSigner struct {
	// time represents the moment this signleSigner is created.
	// Given a timeout parameter, bookkeeping and cleanup will use this parameter.
	time   time.Time
	digest Digest
	// This field might change during the lifetime of the signer.
	// every failed attempt to sign will change this field with a new value.
	trackingId *common.TrackingID

	// messageBuffer stores messages that are received before the signer receives the
	// signal to initiate signing.
	// It’s a map from hash(partyID.key || partyID.Id) to slices
	// that contains up to maxStoragePerParty messages..
	messageBuffer  map[Digest][]tss.ParsedMessage
	partyIdToIndex map[Digest]partyIdIndex
	committee      tss.SortedPartyIDs
	self           *tss.PartyID
	// nil if not started signing yet.
	// once a request to sign was received (via AsyncRequestNewSignature), this will be set,
	// and used.
	localParty tss.Party
	mtx        sync.Mutex

	// the state of the signer. can be one of { unset, set, started, notInCommittee }.
	state signerState

	sync.Once
}

// signingHandler handles all signers in the FullParty.
// The proper way to get a signer is to use getOrCreateSingleSigner method.
type signingHandler struct {

	// might store the same signer multiple times: once for each tracking id.
	// the signer itself holds the same TTL, and the number of attempts of signing.
	// [There can be multiple mappings for the same signer].
	trackingIDToSigner sync.Map

	sigPartReadyChan chan *common.SignatureData
}

// Impl handles multiple signers
type Impl struct {
	ctx        context.Context
	cancelFunc context.CancelFunc

	partyID    *tss.PartyID
	parameters *tss.Parameters

	keygenHandler  *KeygenHandler
	signingHandler *signingHandler

	incomingMessagesChannel chan tss.ParsedMessage

	errorChannel           chan<- *tss.Error
	outChan                chan tss.Message
	signatureOutputChannel chan *common.SignatureData
	cryptoWorkChan         chan func()
	maxTTl                 time.Duration
	loadDistributionSeed   []byte
}

func hash(msg []byte) Digest {
	return sha3.Sum256(msg)
}

func (p *Impl) cleanupWorker() {
	for {
		select {
		case <-p.ctx.Done():
			return

		case <-time.After(p.maxTTl):
			p.signingHandler.cleanup(p.maxTTl)
		}
	}
}

func (s *signingHandler) cleanup(maxTTL time.Duration) {
	currentTime := time.Now()

	keysToDelete := make([]any, 0)

	s.trackingIDToSigner.Range(func(key, value any) bool {
		signer, ok := value.(*singleSigner)
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
		s.trackingIDToSigner.Delete(key)
	}
}

func (s *singleSigner) getInitTime() time.Time {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.time
}

func (p *Impl) GetPublic() *ecdsa.PublicKey {
	if p.keygenHandler == nil {
		return nil
	}

	if p.keygenHandler.SavedData == nil {
		return nil
	}

	if p.keygenHandler.SavedData.ECDSAPub == nil {
		return nil
	}

	return p.keygenHandler.SavedData.ECDSAPub.ToECDSAPubKey()
}

func (k *KeygenHandler) setup(outChan chan tss.Message, selfId *tss.PartyID) error {
	_ = outChan

	if k.SavedData != nil {
		return nil
	}

	content, err := os.ReadFile(k.keysFileName(selfId))
	if err != nil {
		return err
	}

	if err := json.Unmarshal(content, &k.SavedData); err != nil {
		return err
	}

	// TODO: set up keygen.LocalParty, and run it.
	return nil
}

func (k *KeygenHandler) keysFileName(selfId *tss.PartyID) string {
	return path.Join(k.StoragePath, fmt.Sprintf("keygen_data_%d.json", selfId.Index))
}

func (k *KeygenHandler) storeKeygenData(toSave *keygen.LocalPartySaveData) error {
	k.SavedData = toSave

	content, err := json.Marshal(toSave)
	if err != nil {
		return err
	}

	return os.WriteFile(k.keysFileName(k.LocalParty.PartyID()), content, 0777)
}

func (k *KeygenHandler) getSavedParams() *keygen.LocalPartySaveData {
	return k.SavedData
}

// The worker serves as messages courier to all "localParty" instances.
func (p *Impl) worker() {
	for {
		select {
		case message := <-p.incomingMessagesChannel:
			switch findProtocolType(message) {
			case keygenProtocolType:
				fmt.Println("keygen protocol")
			case signingProtocolType:
				p.handleIncomingSigningMessage(message)
			default:
				p.errorChannel <- tss.NewError(errors.New("received unknown message type"), "", 0, p.partyID, message.GetFrom())
			}
		case o := <-p.keygenHandler.ProtocolEndOutput:
			if err := p.keygenHandler.storeKeygenData(o); err != nil {
				p.errorChannel <- tss.NewError(err, "keygen data storing", 0, p.partyID, nil)
			}
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *Impl) Start(outChannel chan tss.Message, signatureOutputChannel chan *common.SignatureData, errChannel chan<- *tss.Error) error {
	if outChannel == nil || signatureOutputChannel == nil || errChannel == nil {
		return errors.New("nil channel passed to Start()")
	}

	p.errorChannel = errChannel
	p.signatureOutputChannel = signatureOutputChannel
	p.outChan = outChannel

	for i := 0; i < runtime.NumCPU(); i++ {
		go p.worker()
	}

	p.initCryptopool()

	go p.cleanupWorker()

	if err := p.keygenHandler.setup(outChannel, p.partyID); err != nil {
		p.Stop()

		return fmt.Errorf("keygen handler setup failed: %w", err)
	}

	return nil
}

func (p *Impl) initCryptopool() {
	p.cryptoWorkChan = make(chan func(), runtime.NumCPU())
	p.parameters.Context = p.ctx
	p.parameters.AsyncWorkComputation = func(f func()) error {
		select {
		case p.cryptoWorkChan <- f:
			return nil
		case <-p.ctx.Done():
			return errors.New("context aborted")
		}
	}

	for i := 0; i < runtime.NumCPU()*2; i++ {
		go p.cryptoWorker()
	}
}

func (p *Impl) cryptoWorker() {
	for {
		select {
		case f := <-p.cryptoWorkChan:
			f()
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *Impl) Stop() {
	p.cancelFunc()
}

func (p *Impl) AsyncRequestNewSignature(s SigningTask) (*SigningInfo, error) {
	trackid := p.createTrackingID(s)

	// fast lock.
	signer, err := p.getOrCreateSingleSigner(trackid)
	if err != nil {
		return nil, err
	}

	info, err := p.GetSigningInfo(s)
	if err != nil {
		return nil, err
	}

	asyncTask := func() {
		// long lock for a single TSS task (not the entire FullParty).
		signer.mtx.Lock()
		defer signer.mtx.Unlock()

		// The following method initiates the localParty (if it’s a committee
		//  member). Starting the localParty will involve computationally
		// intensive cryptographic operations.
		if err := p.unsafeSetLocalParty(signer); err != nil {
			tsserr := tss.NewTrackableError(err, "starting protocol failed", -1, nil, trackid)
			p.reportError(tsserr)
			return
		}

		if signer.state != set {
			return // not in committee, or, any other reason
		}

		// If the single signer had received all messages from the committee,
		// the following loop would involve significant cryptographic computations.
		// Conversely, if the single signer hadn’t received all messages, the loop would be relatively light.
		for _, msgArr := range signer.messageBuffer {
			for _, message := range msgArr {
				ok, err := signer.unsafeFeedLocalParty(message)
				if !ok {
					p.reportError(err)
				}
			}
		}
	}

	select {
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	case p.cryptoWorkChan <- asyncTask:
		return info, nil
	}
}

// The signer isn't necessarily allowed to sign. as a result, we might return a nil signer - to ensure
// we don't sign messages blindly.
func (p *Impl) getSignerOrCacheMessage(message tss.ParsedMessage) (*singleSigner, *tss.Error) {
	signer, err := p.getOrCreateSingleSigner(message.WireMsg().GetTrackingID())
	if err != nil {
		return nil, tss.NewTrackableError(err, "get tss.signer", -1, nil, message.WireMsg().TrackingID)
	}

	shouldSign := signer.attemptToCacheIfShouldNotSign(message)
	if !shouldSign {
		return nil, nil
	}

	return signer, nil
}

// Since storing to cache is done strictly when this signer had not yet started to sign, this
// method will return a bool indicating whether it is allowed to sign.
func (signer *singleSigner) attemptToCacheIfShouldNotSign(message tss.ParsedMessage) (shouldSign bool) {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	if signer.state == set {
		shouldSign = true
		return
	}

	// Else we store the messages. we might not be in the committee right now,
	// but this signer might be later consolidated with the committee (due to changes with the committee).
	dgst := pidToDigest(message.GetFrom().MessageWrapper_PartyID)

	if len(signer.messageBuffer[dgst]) < maxStoragePerParty {
		signer.messageBuffer[dgst] = append(signer.messageBuffer[dgst], message)
	}

	return
}

func (signer *singleSigner) feedLocalParty(msg tss.ParsedMessage) (bool, *tss.Error) {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	// fmt.Println("Recived msg of type:", msg.Type())
	return signer.unsafeFeedLocalParty(msg)
}

func (signer *singleSigner) unsafeFeedLocalParty(msg tss.ParsedMessage) (bool, *tss.Error) {
	index, ok := signer.partyIdToIndex[pidToDigest(msg.GetFrom().MessageWrapper_PartyID)]
	if !ok {
		// committee changed, and this party is no longer in the committee.
		return true, nil
	}

	msg.GetFrom().Index = int(index) // setting the index of the according to the current committee.

	if signer.state != set {
		// can't feed a local party that hasn't started yet.
		return false, tss.NewTrackableError(fmt.Errorf("can't feed unset signer"), "", -1, nil, msg.WireMsg().TrackingID)
	}

	if signer.trackingId.ToString() != msg.WireMsg().GetTrackingID().ToString() {
		// tracking id changes due to fault tolarance order.
		// trackid is always advancing. so if we have something reaching this,
		// then it is old.
		return true, nil
	}

	return signer.localParty.Update(msg)
}

func pidToDigest(pid *tss.MessageWrapper_PartyID) Digest {
	bf := bytes.NewBuffer(nil)
	bf.WriteString(pid.Id)
	bf.Write(pid.Key)
	return hash(bf.Bytes())
}

var ErrNoSigningKey = errors.New("no key to sign with")

func isInCommittee(self *tss.PartyID, committee tss.UnSortedPartyIDs) bool {
	return indexInCommittee(self, tss.UnSortedPartyIDs(committee)) != -1
}

func indexInCommittee(self *tss.PartyID, committee tss.UnSortedPartyIDs) int {
	for i, v := range committee {
		if equalIDs(v, self) {
			return i
		}
	}

	return -1
}

func (p *Impl) unsafeSetLocalParty(signer *singleSigner) error {
	secrets := p.keygenHandler.getSavedParams()
	if secrets == nil {
		return ErrNoSigningKey
	}

	switch signer.state {
	case set:
		return nil

	case notInCommittee:
		return nil // not an error

	case unset:
		// check if notInCommittee:
		index := indexInCommittee(signer.self, tss.UnSortedPartyIDs(signer.committee))
		if index == -1 {
			signer.state = notInCommittee
			return nil
		}

		signer.state = set
		// updating the self to a copy with a different index
		// (matching the indices of the current committee).
		signer.self = signer.committee[index]

		signer.localParty = signing.NewLocalParty(
			(&big.Int{}).SetBytes(signer.digest[:]),
			// track id is what we use to identify the signer throughout messages.
			signer.trackingId,
			p.makeParams(signer.committee, signer.self),
			*secrets,
			p.outChan,
			p.signatureOutputChannel,
			DigestSize,
		)

		if err := signer.localParty.Start(); err != nil && err.Cause() != nil {
			return err.Cause()
		}
	}

	return nil
}

// since the parties and committee are shuffled we need to create specialized parameters for the signing protocol.
func (p *Impl) makeParams(parties []*tss.PartyID, selfIdInCurrentCommittee *tss.PartyID) *tss.Parameters {
	prms := tss.NewParameters(tss.S256(), tss.NewPeerContext(parties), selfIdInCurrentCommittee, len(parties), p.parameters.Threshold())
	prms.Context = p.parameters.Context
	prms.AsyncWorkComputation = p.parameters.AsyncWorkComputation

	return prms
}

// getOrCreateSingleSigner returns the signer for the given digest, or creates a new one if it doesn't exist.
func (p *Impl) getOrCreateSingleSigner(trackingId *common.TrackingID) (*singleSigner, error) {
	s := p.signingHandler

	dgst := Digest{}
	copy(dgst[:], trackingId.Digest)

	_signer, loaded := s.trackingIDToSigner.LoadOrStore(trackingId.ToString(), &singleSigner{
		time:          time.Now(),
		self:          p.partyID,
		messageBuffer: map[Digest][]tss.ParsedMessage{},

		digest:     dgst, // no digest yet.
		trackingId: trackingId,

		partyIdToIndex: map[Digest]partyIdIndex{},
		localParty:     nil,

		mtx:   sync.Mutex{},
		state: unset,
	})

	signer, ok := _signer.(*singleSigner)
	if !ok {
		return nil, errors.New("internal error, expected *singleSigner")
	}

	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	// Only a single concurrent run of this method will pass this point (due to the syncMap output).
	if !loaded {
		committee, err := p.computeCommittee(signer.trackingId)
		if err != nil {
			return nil, err
		}

		signer.unsafeSetCommittee(committee)
	}

	return signer, nil
}

func (p *Impl) computeCommittee(trackid *common.TrackingID) (tss.SortedPartyIDs, error) {
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

	return tss.SortPartyIDs(parties[:p.committeeSize()]), nil
}

func (p *Impl) committeeSize() int {
	return p.parameters.Threshold() + 1
}

func (p *Impl) makeShuffleSeed(trackid *common.TrackingID) []byte {
	seed := append(p.loadDistributionSeed, []byte(trackid.ToString())...)
	return seed
}

func equalIDs(a, b *tss.PartyID) bool {
	return a.Id == b.Id && bytes.Equal(a.Key, b.Key)
}

func (signer *singleSigner) unsafeSetCommittee(parties []*tss.PartyID) {
	signer.partyIdToIndex = make(map[Digest]partyIdIndex, len(parties))

	for _, party := range parties {
		pidDigest := pidToDigest(party.MessageWrapper_PartyID)
		signer.partyIdToIndex[pidDigest] = partyIdIndex(party.Index)
	}

	signer.committee = parties
}

func (p *Impl) Update(message tss.ParsedMessage) error {
	select {
	case p.incomingMessagesChannel <- message:
		return nil
	case <-p.ctx.Done():
		return errors.New("worker stopped")
	}
}

func (p *Impl) handleIncomingSigningMessage(message tss.ParsedMessage) {
	signer, err := p.getSignerOrCacheMessage(message)
	if err != nil {
		p.reportError(err)
		return
	}

	if signer == nil {
		// (SAFETY) To ensure messages aren't signed blindly because some rouge
		// Party started signing without a valid reason, this Party will only sign if it knows of the digest.
		return
	}

	ok, err := signer.feedLocalParty(message)
	if !ok {
		p.reportError(err)
	}
}

func (p *Impl) reportError(newError *tss.Error) {
	select {
	case p.errorChannel <- newError:
	case <-p.ctx.Done():
	default: // no one is waiting on error reporting channel/ no buffer.
	}
}

func (p *Impl) createTrackingID(s SigningTask) *common.TrackingID {
	offlineMap := map[string]bool{}
	for _, v := range s.Faulties {
		offlineMap[string(v.Key)] = true
	}

	pids := make([]bool, len(p.parameters.Parties().IDs()))
	for i, v := range p.parameters.Parties().IDs() {
		if !offlineMap[string(v.Key)] {
			pids[i] = true
		}
	}

	dgst := Digest{}
	copy(dgst[:], s.Digest[:])

	tid := &common.TrackingID{
		Digest:       dgst[:],
		PartiesState: common.ConvertBoolArrayToByteArray(pids),
		AuxilaryData: s.AuxilaryData,
	}

	return tid
}

// returns the parties that can still be part of the committee.
func (p *Impl) getValidCommitteeMembers(trackingId *common.TrackingID) (tss.UnSortedPartyIDs, error) {
	pids := p.parameters.Parties().IDs()

	ValidCommitteeMembers := make([]*tss.PartyID, 0, len(pids))

	if len(trackingId.PartiesState) < (len(pids)+7)/8 {
		return nil, errors.New("invalid tracking id")
	}

	for i, pid := range pids {
		if trackingId.PartyStateOk(i) {
			ValidCommitteeMembers = append(ValidCommitteeMembers, pid)
		}
	}

	return tss.UnSortedPartyIDs(ValidCommitteeMembers), nil
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
		IsSigner:         isInCommittee(p.partyID, tss.UnSortedPartyIDs(sortedCommittee)),
	}, nil
}

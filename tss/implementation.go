package tss

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"

	"sync"
	"sync/atomic"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	frosteth "github.com/xlabs/multi-party-sig/pkg/eth"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/protocols/cmp"
	"github.com/xlabs/multi-party-sig/protocols/frost"
	common "github.com/xlabs/tss-common"
	"github.com/xlabs/tss-common/service/signer"
	"github.com/xlabs/tss-lib/v2/party"
	tsscommv1 "github.com/xlabs/tss-lib/v2/tss/internal/proto/tsscomm/v1"
	"go.uber.org/zap"
)

type uuid digest // distinguishing between types to avoid confusion.

type fpCommunicationChannels party.OutputChannels

// Engine is the implementation of reliableTSS, it is a wrapper for the
// tss-lib fullParty and adds  hash-broadcast logic
// to the message sending and receiving.
type Engine struct {
	ctx context.Context

	logger *zap.Logger
	GuardianStorage

	fpParams *party.Parameters
	fp       party.FullParty

	fpCommChans    fpCommunicationChannels
	sigOutChan     chan *common.SignatureData // actual sig output.
	messageOutChan chan Sendable

	started         atomic.Uint32
	msgSerialNumber uint64

	// used to perform  hash-broadcast:
	mtx      *sync.Mutex
	received map[uuid]*broadcaststate

	sigCounter activeSigCounter

	SignatureMetrics sync.Map
}

type PEM []byte

// Contains the TSS related configurations.
type Configurations struct {
	maxSimultaneousSignatures int
	// MaxSignerTTL is the maximum time a signature is allowed to be active.
	// used to release resources.
	MaxSignerTTL time.Duration

	ChainsWithNoSelfReport []uint16

	// LeaderIdentity is used by the TSS engine protocol to determine who is responsible for telling
	// the other guardians about a new VAAv1.
	LeaderIdentity PEM // The public key of the leader in PEM format.

	// The list of chains that use ECDSA signatures.

}

// GuardianStorage is a struct that holds the data needed for a guardian to participate in the TSS protocol
// including its signing key, and the shared symmetric keys with other guardians.
// should be loaded from a file.
type GuardianStorage struct {
	Configurations

	Self           *Identity
	IdentitiesKeep `json:"IdentitiesKeep,inline"`

	// should be a certificate generated with SecretKey
	TlsX509    PEM
	PrivateKey PEM
	tlsCert    *tls.Certificate
	signingKey *ecdsa.PrivateKey // should be the unmarshalled value of PriavteKey.

	// Assumes threshold = 2f+1, where f is the maximal expected number of faulty nodes.
	Threshold int

	// all secret keys should be generated with specific value.
	TSSSecrets []byte
	frostconf  *frost.Config
	ecdsaconf  *cmp.Config

	LoadDistributionKey []byte

	isleader bool
}

// GuardianStorageFromFile loads a guardian storage from a file.
// If the storage file hadn't contained symetric keys, it'll compute them.
func NewGuardianStorageFromFile(storagePath string) (*GuardianStorage, error) {
	var storage GuardianStorage
	if err := storage.load(storagePath); err != nil {
		return nil, err
	}

	return &storage, nil
}

// ProducedSignature lets a listener receive the output signatures once they're ready.
func (t *Engine) ProducedSignature() <-chan *common.SignatureData {
	return t.sigOutChan
}

// ProducedOutputMessages ensures a listener can send the output messages to the network.
func (t *Engine) ProducedOutputMessages() <-chan Sendable {
	return t.messageOutChan
}

// GetCertificate implements ReliableTSS.
func (st *GuardianStorage) GetCertificate() *tls.Certificate {
	return st.tlsCert
}

var (
	errNilTssEngine        = fmt.Errorf("tss engine is nil")
	errTssEngineNotStarted = fmt.Errorf("tss engine hasn't started")
	errNilSignRequest      = fmt.Errorf("sign request is nil")

	errDigestSize = errors.New("digest size is not 32 bytes")
	errFPNotSet   = errors.New("tss engine is not set up correctly, use NewReliableTSS to create a new engine")
)

// BeginAsyncThresholdSigningProtocol used to start the TSS protocol over a specific msg.
func (t *Engine) BeginAsyncThresholdSigningProtocol(req *signer.SignRequest) error {
	if t == nil {
		return errNilTssEngine
	}

	if t.started.Load() != started {
		return errTssEngineNotStarted
	}

	if t.fp == nil {
		return errFPNotSet
	}

	if req == nil {
		return errNilSignRequest
	}

	protocol, err := common.ProtocolTypeFromString(req.Protocol)
	if err != nil {
		return err
	}

	if protocol != common.ProtocolECDSASign && protocol != common.ProtocolFROSTSign {
		return fmt.Errorf("unsupported signing protocol: %s", req.Protocol)
	}

	if len(req.Digest) != digestSize {
		return errDigestSize
	}

	d := party.Digest{}
	copy(d[:], req.Digest)

	excluded := []*common.PartyID{}
	if len(req.Committee) != 0 {
		members, err := t.translateEthCommitteeMembers(req.Committee)
		if err != nil {
			return err
		}

		excluded = t.findExcludeesFromCommittee(members)
	}

	return t.beginTSSSign(protocol, d, excluded)
}

func (t *Engine) beginTSSSign(protocolType common.ProtocolType, d party.Digest, fauilties []*common.PartyID) error {
	sigtask := party.SigningTask{
		Digest: d,
		// indicating the reviving guardian will be given a chance to join the protocol.
		Faulties:      fauilties,
		AuxiliaryData: nil, // not used anymore.
		ProtocolType:  protocolType,
	}

	t.logger.Info("signature requested",
		zap.String("digest", fmt.Sprintf("%x", d[:])),
		zap.String("signingProtocol", sigtask.ProtocolType.ToString()),
	)

	info, err := t.fp.GetSigningInfo(sigtask)
	if err != nil {
		return fmt.Errorf("couldnt generate signing task: %w", err)
	}

	if err := validateTrackingID(info.TrackingID); err != nil {
		return err
	}

	t.createSignatureMetrics(info.TrackingID)

	info, err = t.fp.AsyncRequestNewSignature(sigtask)
	if err != nil {
		return err
	}

	t.logger.Info(
		"guardian started signing protocol",

		zap.String("trackingID", info.TrackingID.ToString()),
		// zap.String("ChainID", chainID.String()),
		zap.Any("committee", t.getCommitteeNetworkNames(info.SigningCommittee)),
	)

	return nil
}

func (t *Engine) getCommitteeNetworkNames(pids []*common.PartyID) []string {
	ids := make([]string, 0, len(pids))
	for _, pid := range pids {
		id, err := t.GuardianStorage.fetchIdentityFromPartyID(pid)
		if err != nil {
			t.logger.Warn("couldn't find identity for partyID", zap.Any("partyID", pid))

			continue
		}

		ids = append(ids, id.NetworkName())
	}

	return ids
}

func NewKeyGenerator(storage *GuardianStorage) (KeyGenerator, error) {
	return newEngine(storage)
}

func NewReliableTSS(storage *GuardianStorage) (ReliableTSS, error) {
	return newEngine(storage)
}

func newEngine(storage *GuardianStorage) (*Engine, error) {
	if storage == nil {
		return nil, fmt.Errorf("the guardian's tss storage is nil")
	}

	if storage.maxSimultaneousSignatures < 0 {
		storage.maxSimultaneousSignatures = defaultMaxLiveSignatures
	}

	if storage.MaxSignerTTL == 0 {
		storage.MaxSignerTTL = defaultMaxSignerTTL
	}

	if storage.maxSimultaneousSignatures == 0 {
		storage.maxSimultaneousSignatures = defaultMaxLiveSignatures
	}

	if bytes.Equal(storage.Self.CertPem, storage.LeaderIdentity) {
		storage.isleader = true
	}

	fpParams := &party.Parameters{
		FrostSecrets: storage.frostconf,
		EcdsaSecrets: storage.ecdsaconf,
		PartyIDs:     storage.GetPartyIDs(),
		Self:         storage.Self.Pid,

		MaxSignerTTL:         storage.MaxSignerTTL,
		LoadDistributionSeed: storage.LoadDistributionKey,
	}

	fp, err := party.NewFullParty(fpParams)
	if err != nil {
		return nil, err
	}

	expectedMsgs := storage.maxSimultaneousSignatures *
		(numBroadcastsPerSignature + numUnicastsRounds*storage.NumGuardians()) * 2 // times 2 to stay on the safe side.
	t := &Engine{
		ctx: nil,

		logger:          discardLogger,
		GuardianStorage: *storage,

		fpParams: fpParams,
		fp:       fp,
		fpCommChans: fpCommunicationChannels{
			OutChannel:             make(chan common.ParsedMessage, expectedMsgs),
			SignatureOutputChannel: make(chan *common.SignatureData, storage.maxSimultaneousSignatures),
			ErrChannel:             make(chan *common.Error, storage.maxSimultaneousSignatures),
			WarningChannel:         make(chan *party.Warning, storage.maxSimultaneousSignatures),
			KeygenOutputChannel:    make(chan *party.TSSSecrets, 1), // shouldn't output often.
		},

		sigOutChan:     make(chan *common.SignatureData, storage.maxSimultaneousSignatures),
		messageOutChan: make(chan Sendable, expectedMsgs),

		msgSerialNumber: 0,
		mtx:             &sync.Mutex{},
		received:        map[uuid]*broadcaststate{},

		started: atomic.Uint32{}, // default value is 0

		sigCounter: newSigCounter(),

		// ftCommandChan: make(chan ftCommand, expectedMsgs),
	}

	return t, nil
}

func (t *Engine) MaxTTL() time.Duration {
	return t.GuardianStorage.maxSignerTTL()
}

// Start starts the TSS engine, and listens for the outputs of the full party.
func (t *Engine) Start(ctx context.Context, zapLogger *zap.Logger) error {
	if t == nil {
		return fmt.Errorf("tss engine is nil")
	}

	if !t.started.CompareAndSwap(notStarted, started) {
		return fmt.Errorf("tss engine has already started")
	}

	t.ctx = ctx

	if zapLogger != nil {
		t.logger = zapLogger.
			With(zap.String("hostname", t.GuardianStorage.Self.NetworkName())).
			Named("engine")
		t.logger.Debug("TSS Engine logger initialized")
	}

	if err := t.fp.Start(party.OutputChannels(t.fpCommChans)); err != nil {
		t.started.Store(notStarted)

		return err
	}

	// closing the t.fp.start inside th listener
	go t.fpListener()

	// go t.sigTracker()

	leaderIdentity, err := t.GuardianStorage.fetchIdentityFromKeyPEM(t.LeaderIdentity)
	if err != nil {
		return fmt.Errorf("leader identity not found in guardian storage: %w", err)
	}

	t.logger.Info(
		"tss engine started",
		zap.Any("configs", t.GuardianStorage.Configurations),
		zap.String("leaderID", leaderIdentity.Hostname),
	)

	return nil
}

func (t *Engine) GetPublicKey(prot common.ProtocolType) (curve.Point, error) {
	pk, err := t.fp.GetPublic(prot)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from full party: %w", err)
	}

	return pk, nil
}

func (t *Engine) GetEthAddress(prot common.ProtocolType) (ethcommon.Address, error) {
	pubkey, err := t.fp.GetPublic(prot)
	if err != nil {
		return ethcommon.Address{}, fmt.Errorf("failed to get public key from full party: %w", err)
	}

	ethaddress := ethcommon.Address{}

	add, err := frosteth.PointToAddress(pubkey)
	if err != nil {
		t.logger.Error("failed to convert public key to Ethereum address", zap.Error(err))
	}

	copy(ethaddress[:], add[:])

	return ethaddress, nil
}

func (st *GuardianStorage) maxSignerTTL() time.Duration {
	// SECURITY NOTE: when we clean the guardian map from received Echo's
	// we must use TTL > FullParty.TTL to ensure guardians can't use
	// the deletion time to perform equivication attacks (since a message
	// has no record after it was deleted).
	// *2 is to account for possible offset in the time of the guardian.
	return st.MaxSignerTTL * 2
}

// fpListener serves as a listining loop for the full party outputs.
// ensures the FP isn't being blocked on writing to fpOutChan, and wraps the result into a gossip message.
// IMPORTANT: the fpListener should not wait on writing to other channels!
// if the channel is full, the message should be dropped.
func (t *Engine) fpListener() {
	maxTTL := t.MaxTTL()

	cleanUpTicker := time.NewTicker(maxTTL)

	for {
		select {
		case <-t.ctx.Done():
			t.logger.Info(
				"shutting down TSS Engine",
			)

			t.fp.Stop()
			cleanUpTicker.Stop()

			return
		case m := <-t.fpCommChans.OutChannel:
			t.handleFpOutput(m)

		case err := <-t.fpCommChans.ErrChannel:
			t.handleFpError(err)

		case warn := <-t.fpCommChans.WarningChannel:
			t.handleFPWarning(warn)

		case sig := <-t.fpCommChans.SignatureOutputChannel:
			t.handleFpSignature(sig)

		case <-cleanUpTicker.C:
			t.cleanup(maxTTL)
		}
	}
}

func (t *Engine) handleFPWarning(warn *party.Warning) {
	if warn == nil || warn.Message == "" {
		return
	}

	flds := []zap.Field{}

	if warn.TrackingID != nil {
		flds = append(flds, zap.String("trackingId", warn.TrackingID.ToString()))
	}

	if warn.Protocol != "" {
		flds = append(flds, zap.String("protocol", string(warn.Protocol)))
	}

	if warn.SessionRound != 0 {
		flds = append(flds, zap.Int("round", int(warn.SessionRound)))
	}

	if id, err := t.GuardianStorage.fetchIdentityFromPartyID(warn.PossibleCulprit); err == nil {
		flds = append(flds, zap.String("possibleCulprit", id.Hostname))
	}

	t.logger.Warn(
		fmt.Sprintf("tss-lib.FullParty: %s", warn.Message),
		flds...,
	)
}

func (t *Engine) handleFpSignature(sig *common.SignatureData) {
	if sig == nil {
		return
	}

	t.logger.Debug("signature complete. updating inner state and forwarding it", zap.String("trackingId", sig.TrackingId.ToString()))

	t.sigCounter.remove(sig.TrackingId)

	select {
	case t.sigOutChan <- sig:
	default:
		// if the signature can't be delivered, we can't do much about it.
		t.logger.Error(
			"Couldn't deliver the signature, signature output channel buffer is full",
			zap.String("trackingId", sig.TrackingId.ToString()),
		)
	}

	t.sigMetricDone(sig.TrackingId, false) // false since there were no issues.
}

func (t *Engine) handleFpError(err *common.Error) {
	if err == nil {
		return
	}

	trackid := err.TrackingId()
	if trackid == nil {
		t.logger.Error("error (without trackingID) in signing protocol ", zap.Error(err.Cause()))

		return
	}

	// select {
	// case t.ftCommandChan <- &SigEndCommand{trackid}:
	// default:
	// 	t.logger.Error("couldn't inform the tracker of signature end due to error",
	// 		zap.Error(err),
	// 		zap.String("trackingId", trackid.ToString()),
	// 	)
	// }

	// if someone sent a message that caused an error -> we don't
	// accept an override to that message, therefore, we can remove it, since it won't change.
	t.sigCounter.remove(trackid)

	logErr(t.logger, &logableError{
		fmt.Errorf("error in signing protocol: %w", err.Cause()),
		trackid,
		intToRound(err.Round()),
	})

	t.sigMetricDone(trackid, true)
}

func (t *Engine) handleFpOutput(m common.Message) {
	tssMsg, err := t.intoSendable(m)
	if err == nil {

		select {
		case t.messageOutChan <- tssMsg:
		default:
			t.logger.Error("couldn't output tss message, network output channel buffer is full",
				zap.String("trackingId", m.WireMsg().GetTrackingID().ToString()),
			)
		}

		return
	}

	// else log error:
	lgErr := logableError{
		fmt.Errorf("failed to convert tss message and send it to network: %w", err),
		m.WireMsg().GetTrackingID(),
		"",
	}

	// The following should always pass, since FullParty outputs a
	// common.ParsedMessage and a valid message with a specific round.
	if parsed, ok := m.(common.ParsedMessage); ok {
		if rnd, e := getRound(parsed); e == nil {
			lgErr.round = rnd
		}
	}

	logErr(t.logger, lgErr)
}

func (t *Engine) cleanup(maxTTL time.Duration) {
	now := time.Now()

	keysToBeRemoved := make([]any, 0)

	t.SignatureMetrics.Range(func(k, v any) bool {
		mt, ok := v.(*signatureMetadata)
		if !ok {
			keysToBeRemoved = append(keysToBeRemoved, k)

			return true
		}

		tmp := now.Sub(mt.timeOfCreation)
		if tmp > maxTTL {
			keysToBeRemoved = append(keysToBeRemoved, k)
		}

		return true
	})

	for _, k := range keysToBeRemoved {
		t.SignatureMetrics.Delete(k)
	}

	t.sigCounter.cleanSelf(maxTTL)

	t.mtx.Lock()
	defer t.mtx.Unlock()

	for k, v := range t.received {
		if now.Sub(v.timeReceived) > maxTTL {
			delete(t.received, k)
		}
	}
}

func (t *Engine) intoSendable(m common.Message) (Sendable, error) {
	bts, routing, err := m.WireBytes()
	if err != nil {
		return nil, err
	}

	content := &tsscommv1.SignedMessage_TssContent{
		TssContent: &tsscommv1.TssContent{
			Payload:         bts,
			MsgSerialNumber: atomic.AddUint64(&t.msgSerialNumber, 1),
		},
	}

	var sendable Sendable

	if routing.IsBroadcast() {
		msgToSend := &tsscommv1.SignedMessage{
			Content:   content,
			Sender:    t.Self.CommunicationIndex.toProto(),
			Signature: nil,
		}

		tmp := serializeableMessage{&tssMessageWrapper{m}}

		if err := t.sign(tmp.getUUID(t.LoadDistributionKey), msgToSend); err != nil {
			return nil, err
		}

		sendable = newEcho(msgToSend, t.Identities)
	} else {
		recipient, err := t.GuardianStorage.fetchIdentityFromPartyID(routing.To)
		if err != nil {
			return nil, fmt.Errorf("intoSendable: couldn't fetch partyID: %w", err)
		}

		sendable = &Unicast{
			Unicast: &tsscommv1.Unicast{
				Content: &tsscommv1.Unicast_Tss{
					Tss: content.TssContent,
				},
			},
			Receipients: []*Identity{recipient},
		}
	}

	return sendable, nil
}

func (t *Engine) HandleIncomingTssMessage(msg Incoming) {
	if t == nil {
		return // TODO: Consider what to do.
	}

	if t.started.Load() != started {
		return // TODO: Consider what to do.
	}

	if err := t.handleIncomingTssMessage(msg); err != nil {
		t.logger.Error("failed to handle incoming TSS message", zap.Error(err))
	}
}

var (
	errNilIncoming                = fmt.Errorf("received nil incoming message")
	errNilSource                  = fmt.Errorf("no source in incoming message")
	errNeitherBroadcastNorUnicast = fmt.Errorf("received incoming message which is neither broadcast nor unicast")
)

func (t *Engine) handleIncomingTssMessage(msg Incoming) error {
	if msg == nil {
		return errNilIncoming
	}

	if msg.GetSource() == nil {
		return errNilSource
	}

	if msg.IsUnicast() {
		return t.handleUnicast(msg)
	} else if !msg.IsBroadcast() {
		return errNeitherBroadcastNorUnicast
	}

	if err := t.handleBroadcast(msg); err != nil {
		return err
	}

	return nil
}

func (t *Engine) sendEchoOut(parsed broadcastMessage, m Incoming) {
	select {
	case t.messageOutChan <- t.makeEcho(m, parsed):
	default:
		t.logger.Warn("couldn't echo the message, network output channel buffer is full")
	}
}

func (t *Engine) makeEcho(m Incoming, parsed broadcastMessage) *Echo {
	e := m.toBroadcastMsg()

	uuid := parsed.getUUID(t.LoadDistributionKey)
	contentDigest := hashSignedMessage(e.Message)

	content := &tsscommv1.SignedMessage{
		Sender:    e.Message.Sender,
		Signature: e.Message.Signature,
		Content: &tsscommv1.SignedMessage_HashEcho{
			HashEcho: &tsscommv1.HashEcho{
				SessionUuid:           uuid[:],
				OriginalContentDigest: contentDigest[:],
			},
		},
	}
	ech := newEcho(content, t.GuardianStorage.Identities)
	return ech
}

func (t *Engine) handleBroadcast(m Incoming) error {
	parsed, err := t.parseBroadcast(m)
	if err != nil {
		return err
	}

	shouldEcho, deliverable, err := t.broadcastInspection(parsed, m)
	if err != nil {
		return err
	}

	if shouldEcho {
		t.sendEchoOut(parsed, m)
	}

	if deliverable == nil {
		return nil
	}

	return deliverable.deliver(t)
}

func (t *Engine) feedIncomingToFp(parsed common.ParsedMessage) error {
	trackId := parsed.WireMsg().TrackingID
	from := parsed.GetFrom()

	id, err := t.GuardianStorage.fetchIdentityFromPartyID(from)
	if err != nil {
		return fmt.Errorf("error feeding fullParty: %w", err) // shouldn't happen.
	}

	maxLiveSignatures := t.GuardianStorage.maxSimultaneousSignatures

	if ok := t.sigCounter.add(trackId, from, maxLiveSignatures); !ok {
		tooManySimulSigsErrCntr.Inc()

		return fmt.Errorf("guardian %v has reached the maximum number of simultaneous signatures", id.Hostname)
	}

	if err := t.fp.Update(parsed); err != nil {
		return fmt.Errorf("failed to update full party with incoming message: %w", err)
	}

	return nil
}

// handleUnicast is responsible to handle any incoming unicast messages.
func (t *Engine) handleUnicast(m Incoming) error {
	unicast := m.toUnicast()
	if err := validateUnicastCorrectForm(unicast); err != nil {
		return err
	}

	switch v := unicast.Content.(type) {
	case *tsscommv1.Unicast_Tss:
		if err := t.handleUnicastTSS(v, m.GetSource()); err != nil {
			return fmt.Errorf("failed to handle unicast tss message: %w", err)
		}
	default:
		return fmt.Errorf("received unicast with unknown content type: %T", v)
	}

	return nil
}

// handleUnicastTSS is helper function. responsible for handling unicast.TSS messages.
func (t *Engine) handleUnicastTSS(v *tsscommv1.Unicast_Tss, src *Identity) error {
	fpmsg, err := t.parseTssContent(v.Tss, src)
	if err != nil {
		err = fmt.Errorf("couldn't parse unicast_tss payload: %w", err)
		if fpmsg != nil {
			err = fpmsg.wrapError(err)
		}

		return err
	}

	if !isKnownUnicastType(fpmsg) {
		return fmt.Errorf("unknown unicast message type received: %T", fpmsg.Content())
	}

	if err := validateTrackingID(fpmsg.getTrackingID()); err != nil {
		return err
	}

	err = t.validateUnicastDoesntExist(fpmsg)
	if err == errUnicastAlreadyReceived {
		return nil
	}
	if err != nil {
		return fpmsg.wrapError(fmt.Errorf("failed to ensure no equivication present in unicast: %w, sender:%v", err, src.Hostname))
	}

	if err := t.feedIncomingToFp(fpmsg); err != nil {
		return fpmsg.wrapError(fmt.Errorf("unicast failed to update the full party: %w", err))
	}

	return nil
}

var errUnicastAlreadyReceived = fmt.Errorf("unicast already received")

func (t *Engine) validateUnicastDoesntExist(parsed common.ParsedMessage) error {
	tmp := serializeableMessage{&tssMessageWrapper{parsed}}
	id := tmp.getUUID(t.LoadDistributionKey)

	bts, _, err := parsed.WireBytes()
	if err != nil {
		return fmt.Errorf("failed storing the unicast: %w", err)
	}

	msgDigest := hash(bts)

	t.mtx.Lock()
	defer t.mtx.Unlock()

	if stored, ok := t.received[id]; ok {
		if stored.verifiedDigest == nil {
			return fmt.Errorf("internal error. Unicast stored without verified hash")
		}

		if *stored.verifiedDigest != msgDigest {
			return fmt.Errorf("%w. (duration from prev unicast %v)", ErrEquivicatingGuardian, time.Since(stored.timeReceived))
		}

		return errUnicastAlreadyReceived
	}

	t.received[id] = &broadcaststate{
		timeReceived:   time.Now(), // used for GC.
		verifiedDigest: &msgDigest, // used to ensure no equivocation.
		votes:          nil,        // no votes should be stored for a unicast.
		echoedAlready:  true,       // ensuring this never echoed since it is a unicast.
		mtx:            nil,        // no need to lock this, just store it.
	}

	return nil
}

var (
	ErrUnkownEchoer = fmt.Errorf("echoer is not a known guardian")
	ErrUnkownSender = fmt.Errorf("sender is not a known guardian")
)

func (st *GuardianStorage) sign(uuid uuid, msg *tsscommv1.SignedMessage) error {
	tmp := hashSignedMessage(msg)
	digest := hash(append(uuid[:], tmp[:]...))

	sig, err := st.signingKey.Sign(rand.Reader, digest[:], nil)
	msg.Signature = sig

	return err
}

var ErrInvalidSignature = fmt.Errorf("invalid signature")

var errEmptySignature = fmt.Errorf("empty signature")

func (st *GuardianStorage) verifySignedMessage(uid uuid, msg *tsscommv1.SignedMessage) error {
	if msg == nil {
		return fmt.Errorf("nil signed message")
	}

	if msg.Signature == nil {
		return errEmptySignature
	}

	id, err := st.fetchIdentityFromIndex(SenderIndex(msg.Sender))
	if err != nil {
		return err
	}

	pk, ok := id.Cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificated stored with non-ecdsa public key, guardian storage is corrupted")
	}

	tmp := hashSignedMessage(msg)
	digest := hash(append(uid[:], tmp[:]...))

	isValid := ecdsa.VerifyASN1(pk, digest[:], msg.Signature)

	if !isValid {
		return ErrInvalidSignature
	}

	return nil
}

func (t *Engine) StartDKG(task party.DkgTask) (chan *party.TSSSecrets, error) {
	if t == nil {
		return nil, fmt.Errorf("tss engine is nil")
	}

	if t.started.Load() != started {
		return nil, fmt.Errorf("tss engine hasn't started")
	}

	if t.fp == nil {
		return nil, fmt.Errorf("tss engine is not set up correctly, use NewReliableTSS to create a new engine")
	}

	t.logger.Info("starting DKG")

	err := t.fp.StartDKG(task)

	return t.fpCommChans.KeygenOutputChannel, err
}

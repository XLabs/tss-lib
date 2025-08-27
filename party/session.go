package party

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xlabs/multi-party-sig/pkg/party"
	"github.com/xlabs/multi-party-sig/pkg/round"
	"github.com/xlabs/multi-party-sig/protocols/frost"
	common "github.com/xlabs/tss-common"
)

type signerState int

type strPartyID string

type messageKeep [2]common.ParsedMessage

// SingleSession represents a single invocation of a distributed protocol.
// It handles the protocol from start to finish. It holds the state of the protocol (whether it is
// activated, awaiting activation, or not in committee).
// The SingleSession offer thread-safe methods to store and consume messages, and to advance the protocol rounds.
// It does so, by holding a round.Session interface (from the multi-part-sig package), which represents the
// execution of a round-based protocol, and once a round is finalized, the session is advanced to the next round.
type singleSession struct {
	// time represents the moment this singleSession is created.
	// Given a timeout parameter, bookkeeping and cleanup will use this parameter.
	startTime time.Time

	isKeygenSession bool

	// the state of the signer. can be one of { awaitingActivation, activated, notInCommittee }.
	state atomic.Int64

	digest Digest

	// this index is unique, and is used to identify the signer.
	trackingId *common.TrackingID

	messages map[round.Number]map[strPartyID]*messageKeep

	committee common.SortedPartyIDs
	self      *common.PartyID

	// nil if not started signing yet.
	// once a request to sign was received (via AsyncRequestNewSignature), this will be set,
	// and used.
	session round.Session
	mtx     sync.Mutex

	// the following fields are references from the FullParty,
	// used for easy access to the FullParty's components.
	outputchan chan<- common.ParsedMessage
	peersmap   map[party.ID]*common.PartyID
}

func (s signerState) String() string {
	switch s {
	case awaitingActivation:
		return "awaitingActivation"
	case activated:
		return "activated"
	case notInCommittee:
		return "notInCommittee"
	default:
		return fmt.Sprintf("unknown state: %d", s)
	}
}

func (s *singleSession) getInitTime() time.Time {
	return s.startTime // read only value.
}

var errMessageEntryFull = errors.New("message entry already contains something")

func (r *messageKeep) addMsg(message common.ParsedMessage) error {
	cell := directMessagePos
	if message.IsBroadcast() {
		cell = broadcastMessagePos
	}

	// ensure cell is empty
	if r[cell] != nil {
		return errMessageEntryFull
	}

	r[cell] = message

	return nil
}

func (r *messageKeep) getMsgs() []common.ParsedMessage {
	if r == nil {
		return nil // no messages stored.
	}

	return (*r)[:]
}

var (
	errRoundTooLarge = errors.New("message round is greater than the session's final round")
	errRoundTooSmall = errors.New("message round is smaller than smallest round that receives messages")

	errNilSigner              = errors.New("nil signer")
	errShouldBeBroadcastRound = errors.New("frost sessions should be of type BroadcastRound")
	errSignerNotactivated     = errors.New("signer is not activated")
	errInvalidMessage         = errors.New("invalid message received, can't store it, or process it further")
)

// storeMessage stores the message in internal storage, allowing the session time to consume
// the message later, when it is ready to do so.
func (signer *singleSession) storeMessage(message common.ParsedMessage) *common.Error {
	if !message.ValidateBasic() {
		return common.NewTrackableError(
			errInvalidMessage,
			"storeMessage",
			int(signer.getRound()),
			signer.self,
			signer.trackingId,
			message.GetFrom(), // possible culprit
		)
	}

	msgRnd := round.Number(message.Content().RoundNumber())

	if msgRnd > frost.NumRounds {
		return common.NewTrackableError(
			errRoundTooLarge,
			"storeMessage:roundcheck",
			unknownRound,
			signer.self,
			signer.trackingId,
			message.GetFrom(), // possible culprit
		)
	}

	if msgRnd <= 1 {
		// no messages are received for round 1.
		return common.NewTrackableError(
			errRoundTooSmall,
			"storeMessage:roundcheck",
			unknownRound,
			signer.self,
			signer.trackingId,
			message.GetFrom(), // possible culprit
		)
	}

	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	signerRound := round.Number(0)
	if signer.session != nil {
		signerRound = signer.session.Number()
	}

	if msgRnd < signerRound {
		return nil // nothing to store.
	}

	if _, ok := signer.messages[msgRnd]; !ok {
		signer.messages[msgRnd] = make(map[strPartyID]*messageKeep)
	}

	from := strPartyID(message.GetFrom().ToString())

	if _, ok := signer.messages[msgRnd][from]; !ok {
		signer.messages[msgRnd][from] = &messageKeep{}
	}

	if err := signer.messages[msgRnd][from].addMsg(message); err != nil {
		return common.NewTrackableError(
			err,
			"storeMessage",
			int(signerRound),
			signer.self,
			signer.trackingId,
			message.GetFrom(), // possible culprit
		)
	}

	return nil
}

func (signer *singleSession) getState() signerState {
	return signerState(signer.state.Load())
}

// consumeStoredMessages is thread-UNSAFE will attempt to consume all messages stored for the current round.
func (signer *singleSession) consumeStoredMessages() *common.Error {
	if signer.session == nil {
		return common.NewError(errNilSigner, "consumeStoredMessages", -1, nil, signer.self)
	}

	if signer.getState() != activated {
		return common.NewError(
			errSignerNotactivated,
			"consumeStoredMessages:statecheck",
			int(signer.session.Number()),
			nil,
			signer.self,
		)
	}

	rnd := signer.session.Number()
	// rnd 0 is abort/ success.
	// and round 1 doesn't have messages to consume.
	if rnd > signer.session.FinalRoundNumber() || rnd <= 1 {
		return nil // nothing to do.
	}

	if _, ok := signer.messages[rnd]; !ok {
		signer.messages[rnd] = make(map[strPartyID]*messageKeep)
	}

	mp := signer.messages[rnd]

	for key, msgs := range mp {
		msgs.getMsgs()

		delete(mp, key) // remove the message store from the map.

		for _, msg := range msgs.getMsgs() {
			if msg == nil {
				continue // skip nil messages.
			}

			if !common.UnSortedPartyIDs(signer.committee).IsInCommittee(msg.GetFrom()) {
				slog.Warn("message from non-committee member dropped",
					slog.String("from", msg.GetFrom().ToString()),
					slog.String("tracking_id", msg.WireMsg().TrackingID.ToString()),
					slog.Int("round", int(rnd)),
				)

				continue
			}

			if err := signer.consumeMessage(msg); err != nil {
				return common.NewTrackableError(
					err,
					"consumeStoredMessages:consume",
					int(signer.session.Number()),
					signer.self,
					signer.trackingId,

					msg.GetFrom(), // possible culprit
				)
			}
		}
	}

	return nil
}

// consumeMessage is thread-UNSAFE and will attempt to consume the given message.
func (signer *singleSession) consumeMessage(msg common.ParsedMessage) error {
	m := round.Message{
		From:       party.ID(msg.GetFrom().GetID()),
		Broadcast:  msg.IsBroadcast(),
		Content:    msg.Content(),
		TrackingID: msg.WireMsg().TrackingID,
	}

	// The following storing (Both StoreMessage and StoreBroadcastMessage methods) of
	//  messages may perform some necessary checks and might even run
	// some cryptographic computations (depending on the protocol).
	if !m.Broadcast {
		return signer.session.StoreMessage(m)
	}

	// extends round.Round and can accept broadcast messages.
	r, ok := signer.session.(round.BroadcastRound)
	if !ok {
		return errShouldBeBroadcastRound
	}

	return r.StoreBroadcastMessage(m)
}

func (signer *singleSession) getRound() round.Number {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	if signer.session == nil {
		return 0
	}

	return signer.session.Number()
}

type finalizeReport struct {
	isSessionComplete bool
	advancedRound     bool
	currentRound      round.Number
}

var errFirstRoundCantFinalize = errors.New("first round can't finalize")

// attemptRoundFinalize is a thread-UNSAFE attempt to finalize the round. if the round was the protocol's final round,
// return true.
func (signer *singleSession) attemptRoundFinalize() (finalizeReport, *common.Error) {
	if signer.session == nil {
		return finalizeReport{}, common.NewTrackableError(
			errNilSigner,
			"attemptRoundFinalize:sessionNil",
			-1,
			signer.self,
			signer.trackingId,
		)
	}

	if signer.getState() != activated {
		return finalizeReport{}, common.NewError(
			errSignerNotactivated,
			"attemptRoundFinalize:statecheck",
			int(signer.session.Number()),
			nil,
			signer.self,
		)
	}

	rnd := signer.session.Number()
	sessionComplete := false

	report := finalizeReport{
		isSessionComplete: false,
		advancedRound:     false,
		currentRound:      rnd,
	}

	if !signer.session.CanFinalize() {
		if int(rnd) == 1 { // Should never happen.
			return report, common.NewTrackableError(
				errFirstRoundCantFinalize,
				"attemptRoundFinalize:firstRound",
				int(rnd),
				signer.self,
				signer.trackingId,
			)
		}

		return report, nil
	}

	// finalizing the final round of the session...
	// not updatingt the report until we PASS the finalization.
	sessionComplete = rnd == signer.session.FinalRoundNumber()

	roundNumberBeforeFinalization := signer.session.Number()
	newRound, err := signer.session.Finalize(signer.outputchan)
	if err != nil {
		if b, ok := signer.session.(*round.Abort); ok {
			culprits := make(common.UnSortedPartyIDs, len(b.Culprits))
			for i, culprit := range b.Culprits {
				culprits[i] = culprit.ToTssPartyID()
			}

			return report, common.NewTrackableError(
				b.Err,
				"attemptRoundFinalize:abort",
				int(rnd),
				signer.self,
				signer.trackingId,
				culprits...,
			)
		}

		return report, common.NewTrackableError(
			err,
			"attemptRoundFinalize:finalize",
			int(rnd),
			signer.self,
			signer.trackingId,
		)
	}

	// Updating the report.
	report = finalizeReport{
		// if the session was in final round, and advanced -> this session is done.
		isSessionComplete: sessionComplete,
		advancedRound:     roundNumberBeforeFinalization != newRound.Number(),
		currentRound:      newRound.Number(),
	}

	// advancing the inner session.
	signer.session = newRound

	return report, nil
}

var (
	errFinalRoundNotOfCorrectType = errors.New("session final round failed: not of type 'Output'")
)

func (session *singleSession) extractOutput() (*TSSSecrets, *frost.Signature, *common.Error) {
	session.mtx.Lock()
	defer session.mtx.Unlock()

	if session.session == nil {
		return nil, nil, common.NewTrackableError(
			errNilSigner,
			"extractSignature:sessionNil",
			-1,
			session.self,
			session.trackingId,
		)
	}

	r, ok := session.session.(*round.Output)
	if !ok {
		return nil, nil, common.NewTrackableError(
			errFinalRoundNotOfCorrectType,
			"extractSignature:roundConvert",
			-1,
			session.self,
			session.trackingId,
		)
	}

	switch res := r.Result.(type) {
	case *frost.Config:
		return &TSSSecrets{res, session.trackingId}, nil, nil
	case frost.Signature:
		return nil, &res, nil
	default:
		return nil, nil, common.NewTrackableError(
			fmt.Errorf("unknown output type: %T", res),
			"advanceSession:output",
			unknownRound,
			session.self,
			session.trackingId,
		)
	}
}

// advanceOnce is a thread-SAFE method that will attempt to finalize the current round.
func (signer *singleSession) advanceOnce() (finalizeReport, *common.Error) {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	if err := signer.consumeStoredMessages(); err != nil {
		return finalizeReport{}, err
	}

	return signer.attemptRoundFinalize()
}

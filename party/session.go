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

const (
	unset signerState = iota
	set
	notInCommittee
)

type strPartyID string

type singleSession struct {
	// time represents the moment this singleSession is created.
	// Given a timeout parameter, bookkeeping and cleanup will use this parameter.
	startTime time.Time

	// the state of the signer. can be one of { unset, set, notInCommittee }.
	state atomic.Int64

	digest Digest

	// this index is unique, and is used to identify the signer.
	trackingId *common.TrackingID

	messages map[round.Number]map[strPartyID]common.ParsedMessage

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
	case unset:
		return "unset"
	case set:
		return "set"
	case notInCommittee:
		return "notInCommittee"
	default:
		return fmt.Sprintf("unknown state: %d", s)
	}
}

func (s *singleSession) getInitTime() time.Time {
	return s.startTime // read only value.
}

var (
	errRoundTooLarge = errors.New("message round is greater than the session's final round")
	errRoundTooSmall = errors.New("message round is smaller than smallest round that receives messages")

	errNilSigner              = errors.New("nil signer")
	errShouldBeBroadcastRound = errors.New("frost sessions should be of type BroadcastRound")
	errSignerNotSet           = errors.New("signer is not set")
)

// storeMessage sets the message in internal storage, allowing the session time to consume
// the message later, when it is ready to do so.
func (signer *singleSession) storeMessage(message common.ParsedMessage) error {
	slog.Debug("storing message",
		slog.String("ID", signer.self.GetID()),
		slog.String("type", message.Type()),
		slog.String("from", message.GetFrom().GetID()),
	)

	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	signerRound := round.Number(0)
	if signer.session != nil {
		signerRound = signer.session.Number()
	}

	msgRnd := round.Number(message.Content().RoundNumber())

	if msgRnd > frost.NumRounds {
		return errRoundTooLarge
	}

	if msgRnd < signerRound {
		return nil // nothing need to store.
	}

	if msgRnd <= 1 {
		// no messages are received for round 1.
		return errRoundTooSmall
	}

	if _, ok := signer.messages[msgRnd]; !ok {
		signer.messages[msgRnd] = make(map[strPartyID]common.ParsedMessage)
	}

	from := strPartyID(message.GetFrom().ToString())
	if _, ok := signer.messages[msgRnd][from]; !ok {
		signer.messages[msgRnd][from] = message
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

	if signer.getState() != set {
		return common.NewError(
			errSignerNotSet,
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
		signer.messages[rnd] = make(map[strPartyID]common.ParsedMessage)
	}

	mp := signer.messages[rnd]

	for key, msg := range mp {
		if msg == nil {
			continue
		}

		delete(mp, key) // remove the message from the map.

		// TODO: support non-broadcast messages.
		r, ok := signer.session.(round.BroadcastRound)
		if !ok {
			return common.NewError(errShouldBeBroadcastRound, "consumeStoredMessages", int(signer.session.Number()), nil, signer.self)
		}

		m := round.Message{
			From:       party.ID(msg.GetFrom().GetID()),
			To:         "",
			Broadcast:  true,
			Content:    msg.Content(),
			TrackingID: msg.WireMsg().TrackingID,
		}

		// StoreBroadcastMessage will perform the necessary checks and might even run
		// some cryptographic computations (depending on the protocol).
		if err := r.StoreBroadcastMessage(m); err != nil {
			return common.NewError(err, "consumeStoredMessages", int(signer.session.Number()), nil, signer.self)
		}
	}

	return nil
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

	if signer.getState() != set {
		return finalizeReport{}, common.NewError(
			errSignerNotSet,
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
	errSigNotOfCorrectType        = errors.New("session final round failed: not of type frost.Signature")
)

func (signer *singleSession) extractSignature() (frost.Signature, *common.Error) {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	if signer.session == nil {
		return frost.Signature{}, common.NewTrackableError(
			errNilSigner,
			"extractSignature:sessionNil",
			-1,
			signer.self,
			signer.trackingId,
		)
	}

	// checking for output.
	var sig frost.Signature

	r, ok := signer.session.(*round.Output)
	if !ok {
		return sig, common.NewTrackableError(
			errFinalRoundNotOfCorrectType,
			"extractSignature:roundConvert",
			-1,
			signer.self,
			signer.trackingId,
		)
	}

	sig, ok = r.Result.(frost.Signature)
	if !ok {
		return sig, common.NewTrackableError(
			errSigNotOfCorrectType,
			"extractSignature:sigConvert",
			int(-1),
			signer.self,
			signer.trackingId,
		)
	}

	return sig, nil
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

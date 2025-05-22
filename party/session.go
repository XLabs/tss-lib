package party

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/xlabs/tss-lib/v2/common"
	"github.com/xlabs/tss-lib/v2/frost"
	"github.com/xlabs/tss-lib/v2/internal/party"
	"github.com/xlabs/tss-lib/v2/internal/round"
	"github.com/xlabs/tss-lib/v2/tss"
)

type singleSession struct {
	// time represents the moment this signleSigner is created.
	// Given a timeout parameter, bookkeeping and cleanup will use this parameter.
	time time.Time

	digest Digest

	// this index is unique, and is used to identify the signer.
	trackingId *common.TrackingID

	messages []map[Digest]tss.ParsedMessage

	committee tss.SortedPartyIDs
	self      *tss.PartyID
	// nil if not started signing yet.
	// once a request to sign was received (via AsyncRequestNewSignature), this will be set,
	// and used.
	session round.Session
	mtx     sync.Mutex

	// the state of the signer. can be one of { unset, set, started, notInCommittee }.
	state signerState

	// helpers:

	outputchan chan<- tss.ParsedMessage
	peersmap   map[party.ID]*tss.PartyID
}

func (s *singleSession) getInitTime() time.Time {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.time
}

// TODO: Create an ABORT message, and learn how to handle it. If even one party sends an ABORT message ->
//  the session will cancel, since it depends on everyone in that committee.

var (
	errRoundTooLarge = errors.New("message round is greater than the session's final round")
	errRoundTooSmall = errors.New("message round is smaller than smallest round that receives messages")
)

// When storing a message, we might not be able to finalize,
func (signer *singleSession) storeMessage(message tss.ParsedMessage) error {
	slog.Debug("storing message",
		slog.String("ID", signer.self.Id),
		slog.String("type", message.Type()),
		slog.String("from", message.GetFrom().Id),
	)

	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	signerRound, finalround := 0, frost.NumRounds
	if signer.session != nil {
		signerRound = int(signer.session.Number())
	}

	msgRnd := message.Content().RoundNumber()

	if msgRnd > finalround {
		return errRoundTooLarge
	}

	if msgRnd < signerRound {
		return nil // nothing need to store.
	}

	if msgRnd <= 1 {
		// no messages are received for round 1.
		return errRoundTooSmall
	}

	storePosition := msgRnd - 2

	if signer.messages[storePosition] == nil {
		signer.messages[storePosition] = make(map[Digest]tss.ParsedMessage)
	}

	dgst := pidToDigest(message.GetFrom())
	if _, ok := signer.messages[storePosition][dgst]; !ok {
		signer.messages[storePosition][dgst] = message
	}

	return nil
}

func (signer *singleSession) getState() signerState {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	return signer.state
}

// after storing a new message, the session can attempt to consume any dandling messages in its queues.
// Once all consumed, one can attempt to finailize the round.
func (signer *singleSession) consumeStoredMessages() *tss.Error {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	if signer.session == nil {
		return tss.NewError(errNilSigner, "consumeStoredMessages", -1, nil, signer.self)
	}

	rnd := signer.session.Number()
	// rnd 0 is abort/ success.
	// and round 1 doesn't have messages to consume.
	if rnd > signer.session.FinalRoundNumber() || rnd <= 1 {
		return nil // nothing to do.
	}

	storePosition := rnd - 2
	mp := signer.messages[storePosition]

	for key, msg := range mp {
		if msg == nil {
			continue
		}

		delete(mp, key) // remove the message from the map.

		// TODO: support non-broadcast messages.
		r, ok := signer.session.(round.BroadcastRound)
		if !ok {
			return tss.NewError(errShouldBeBroadcastRound, "consumeStoredMessages", int(signer.session.Number()), nil, signer.self)
		}

		m := round.Message{
			From:       party.ID(msg.GetFrom().Id),
			To:         "",
			Broadcast:  true,
			Content:    msg.Content(),
			TrackingID: msg.WireMsg().TrackingID,
		}

		if err := r.StoreBroadcastMessage(m); err != nil {
			return tss.NewError(err, "consumeStoredMessages", int(signer.session.Number()), nil, signer.self)
		}

	}

	return nil
}

func (signer *singleSession) culpritsToPartyIDs(culprits []party.ID) []*tss.PartyID {
	partyIDs := make([]*tss.PartyID, len(culprits))

	for i, culprit := range culprits {
		partyIDs[i] = signer.peersmap[culprit]
	}

	return partyIDs
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

// Attempt to finalize the round. if the round was the protocol's final round,
// return true.
func (signer *singleSession) attemptRoundFinalize() (finalizeReport, *tss.Error) {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	rnd := signer.session.Number()
	sessionComplete := false

	report := finalizeReport{
		isSessionComplete: false,
		advancedRound:     false,
		currentRound:      rnd,
	}

	if !signer.session.CanFinalize() {
		if int(rnd) == 1 { // Should never happen.
			return report, tss.NewTrackableError(
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

	tmp, err := signer.session.Finalize(signer.outputchan)
	if err != nil {
		if b, ok := signer.session.(*round.Abort); ok {
			return report, tss.NewTrackableError(
				b.Err,
				"attemptRoundFinalize:abort",
				int(rnd),
				signer.self,
				signer.trackingId,
				signer.culpritsToPartyIDs(b.Culprits)...,
			)
		}

		return report, tss.NewTrackableError(
			err,
			"attemptRoundFinalize:finalize",
			int(rnd),
			signer.self,
			signer.trackingId,
		)
	}

	// Updating the report.
	report = finalizeReport{
		isSessionComplete: sessionComplete,
		advancedRound:     true,
		currentRound:      tmp.Number(),
	}

	// if the session was in final round, and advanced -> this session is done.

	// advancing the inner session.
	signer.session = tmp

	return report, nil
}

var (
	errFinalRoundNotOfCorrectType = errors.New("session final round failed: not of type 'Output'")
	errSigNotOfCorrectType        = errors.New("session final round failed: not of type frost.Signature")
)

func (signer *singleSession) extractSignature() (frost.Signature, *tss.Error) {
	// checking for output.
	var sig frost.Signature

	r, ok := signer.session.(*round.Output)
	if !ok {
		return sig, tss.NewTrackableError(
			errFinalRoundNotOfCorrectType,
			"extractSignature:roundConvert",
			-1,
			signer.self,
			signer.trackingId,
		)
	}

	sig, ok = r.Result.(frost.Signature)
	if !ok {
		return sig, tss.NewTrackableError(
			errSigNotOfCorrectType,
			"extractSignature:sigConvert",
			int(-1),
			signer.self,
			signer.trackingId,
		)
	}

	return sig, nil
}

package tss

import (
	"errors"
	"fmt"

	cmpdkg "github.com/xlabs/multi-party-sig/protocols/cmp/keygen"
	cmpsign "github.com/xlabs/multi-party-sig/protocols/cmp/sign"
	frostdkg "github.com/xlabs/multi-party-sig/protocols/frost/keygen"
	frostsign "github.com/xlabs/multi-party-sig/protocols/frost/sign"
	common "github.com/xlabs/tss-common"
	"github.com/xlabs/tss-lib/v2/party"
	tsscommv1 "github.com/xlabs/tss-lib/v2/tss/internal/proto/tsscomm/v1"
	"go.uber.org/zap"
)

var (
	ErrBroadcastIsNil     = fmt.Errorf("broadcast is nil")
	ErrNilPartyId         = fmt.Errorf("party id is nil")
	ErrEmptyIDInPID       = fmt.Errorf("partyId identifier is empty")
	ErrEmptyKeyInPID      = fmt.Errorf("partyId doesn't contain a key")
	ErrSignedMessageIsNil = fmt.Errorf("SignedMessage is nil")
	ErrNoContent          = fmt.Errorf("SignedMessage doesn't contain a content")
	ErrNilPayload         = fmt.Errorf("SignedMessage doesn't contain a payload")
	ErrMissingTimestamp   = fmt.Errorf("problem struct missing timestamp field")
)

func validateBroadcastCorrectForm(e *tsscommv1.Echo) error {
	if e == nil {
		return ErrBroadcastIsNil
	}

	m := e.Message
	if m == nil {
		return ErrSignedMessageIsNil
	}

	if m.Content == nil {
		return ErrNoContent
	}

	if len(m.Signature) == 0 {
		return errEmptySignature
	}

	return nil
}

var (
	errNilEcho           = errors.New("echo is nil")
	errEchoDigestBadSize = errors.New("digest is not the correct size")
	errEchoSessionUUID   = errors.New("echo sessionUUID is not the correct size")
)

func validateHashEchoMessageCorrectForm(v *tsscommv1.SignedMessage_HashEcho) error {
	if v == nil || v.HashEcho == nil {
		return errNilEcho
	}

	if len(v.HashEcho.OriginalContentDigest) != len(digest{}) {
		return errEchoDigestBadSize
	}

	if len(v.HashEcho.SessionUuid) != len(uuid{}) {
		return errEchoSessionUUID
	}

	return nil
}

func validateUnicastCorrectForm(m *tsscommv1.Unicast) error {
	if m == nil {
		return ErrNoContent
	}

	if m.Content == nil {
		return ErrNoContent
	}

	return nil
}

func validateContentCorrectForm(m *tsscommv1.TssContent) error {
	if m == nil {
		return ErrNoContent
	}

	if m.Payload == nil {
		return ErrNilPayload
	}

	return nil
}

type signingRound string

const (
	round1Message signingRound = "round1"
	round2Message signingRound = "round2"
	round3Message signingRound = "round3"
	round4Message signingRound = "round4"
	round5Message signingRound = "round5"
)

var _intToRoundArr = []signingRound{
	round1Message,
	round2Message,
	round3Message,
	round4Message,
	round5Message,
}

func getRound(m common.ParsedMessage) (signingRound, error) {
	if m == nil {
		return "", fmt.Errorf("message is nil")
	}

	if m.Content() == nil {
		return "", fmt.Errorf("message content is nil")
	}

	rnd := m.Content().RoundNumber()
	if rnd < 1 || rnd > len(_intToRoundArr) {
		return "", fmt.Errorf("message content round number is out of range")
	}

	return _intToRoundArr[m.Content().RoundNumber()-1], nil
}

// ensures content of a known broadcast type.
func isBroadcastType(m common.ParsedMessage) bool {
	switch m.Content().(type) {
	case *frostsign.Broadcast2, *frostsign.Broadcast3:
		return true
	case *frostdkg.Broadcast2, *frostdkg.Broadcast3:
		return true

	case *cmpsign.Broadcast2, *cmpsign.Broadcast3, *cmpsign.Broadcast4, *cmpsign.Broadcast5:
		return true
	case *cmpdkg.Broadcast2, *cmpdkg.Broadcast3, *cmpdkg.Broadcast4, *cmpdkg.Broadcast5:
		return true
	default:
		return false
	}
}

func isUnicastType(m common.ParsedMessage) bool {
	switch m.Content().(type) {
	case *cmpsign.Message2, *cmpsign.Message3, *cmpsign.Message4:
		return true
	case *frostdkg.Message3, *cmpdkg.Message4:
		return true
	default:
		return false
	}
}

func (st *GuardianStorage) validateTrackingIDForm(tid *common.TrackingID) error {
	if tid == nil {
		return fmt.Errorf("trackingID is nil")
	}

	if len(tid.Digest) != party.DigestSize {
		return fmt.Errorf("trackingID digest is not in correct size")
	}

	// checking that the byte array is the correct size
	if len(tid.PartiesState) < (st.NumGuardians()+7)/8 {
		return fmt.Errorf("trackingID partiesState is too short")
	}

	// TODO: expecting AuxiliaryData to be set.

	return nil
}

type sigKey string

func trackingIdIntoSigKey(tid *common.TrackingID) sigKey {
	return sigKey(tid.ToString())
}

type SenderIndex uint32

func (s SenderIndex) toProto() uint32 {
	return uint32(s)
}

var discardLogger = zap.NewNop()

func validateTrackingID(tid *common.TrackingID) error {
	if err := party.BasicTrackingIDValidation(tid); err != nil {
		return err
	}

	if len(tid.GetAuxiliaryData()) > maxAuxiliaryDataSize {
		return fmt.Errorf("trackingID has invalid auxiliary data size")
	}

	if len(tid.GetPartiesState()) > maxParties/8 {
		return fmt.Errorf("trackingID has invalid parties state size")
	}

	return nil
}

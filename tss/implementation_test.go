package tss

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/xlabs/multi-party-sig/pkg/round"
	"github.com/xlabs/multi-party-sig/protocols/cmp"
	"github.com/xlabs/multi-party-sig/protocols/frost"
	"github.com/xlabs/multi-party-sig/protocols/frost/sign"
	common "github.com/xlabs/tss-common"
	"github.com/xlabs/tss-common/service/signer"
	"github.com/xlabs/tss-lib/v2/party"
	tsscommv1 "github.com/xlabs/tss-lib/v2/tss/internal/proto/tsscomm/v1"
	"github.com/xlabs/tss-lib/v2/tss/internal/testutils"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

var (
	unicastRounds   = []signingRound{}
	broadcastRounds = []signingRound{
		round2Message,
		round3Message,
	}

	allRounds                  = append(unicastRounds, broadcastRounds...)
	reportableConsistancyLevel = uint8(1) // TODO
	// nonReportableConsistancyLevel = instantConsistencyLevel // TODO
)

var (
	logger       *zap.Logger
	observedLogs *observer.ObservedLogs
	core         zapcore.Core
)

func init() {
	core, observedLogs = observer.New(zapcore.DebugLevel)
	logger = zap.New(core)
}
func parsedIntoEcho(a *assert.Assertions, t *Engine, parsed common.ParsedMessage) *IncomingMessage {
	payload, _, err := parsed.WireBytes()
	a.NoError(err)

	msg := &tsscommv1.Echo{
		Message: &tsscommv1.SignedMessage{
			Content: &tsscommv1.SignedMessage_TssContent{
				TssContent: &tsscommv1.TssContent{Payload: payload},
			},
			Sender:    uint32(t.Self.CommunicationIndex),
			Signature: nil,
		},
	}

	tmp := serializeableMessage{&tssMessageWrapper{parsed}}

	a.NoError(t.sign(tmp.getUUID(t.LoadDistributionKey), msg.Message))

	return &IncomingMessage{
		Source: t.Self,
		Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{
				Echo: msg,
			},
		},
	}
}

func (i *IncomingMessage) setSource(id *Identity) {
	i.Source = id
}

func TestBroadcast(t *testing.T) {

	// The tests here rely on n=5, threshold=2, meaning 3 guardians are needed to sign (f<=1).
	t.Run("forLeaderCreatingMessage", func(t *testing.T) {
		a := assert.New(t)
		// f = 1, n = 5
		engines := load5GuardiansSetupForBroadcastChecks(a)
		receiver := engines[4]

		e1 := engines[0]
		// make parsedMessage, and insert into e1
		// then add another one for the same round.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self.Pid, receiver.Self.Pid, rnd, party.Digest{byte(j)})

			echo := parsedIntoEcho(a, e1, parsed1)

			shouldBroadcast, shouldDeliver, err := receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, echo)
			a.NoError(err)
			a.True(shouldBroadcast)
			a.Nil(shouldDeliver)
		}
	})

	t.Run("forLeaderNotReBroadcasting", func(t *testing.T) {
		a := assert.New(t)
		// f = 1, n = 5
		engines := load5GuardiansSetupForBroadcastChecks(a)

		e1 := engines[0]
		receiver := e1
		// make parsedMessage, and insert into e1
		// then add another one for the same round.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self.Pid, receiver.Self.Pid, rnd, party.Digest{byte(j)})

			echo := parsedIntoEcho(a, e1, parsed1)

			shouldBroadcast, shouldDeliver, err := receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.Nil(shouldDeliver)
		}
	})

	t.Run("OnlyOnce", func(t *testing.T) {
		a := assert.New(t)
		// f = 1, n = 5
		engines := load5GuardiansSetupForBroadcastChecks(a)
		receiver := engines[4]

		e1 := engines[0]
		// make parsedMessage, and insert into e1
		// then add another one for the same round.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self.Pid, receiver.Self.Pid, rnd, party.Digest{byte(j)})

			echo := parsedIntoEcho(a, e1, parsed1)

			shouldBroadcast, shouldDeliver, err := receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, echo)
			a.NoError(err)
			a.True(shouldBroadcast)
			a.Nil(shouldDeliver)

			shouldBroadcast, shouldDeliver, err = receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.Nil(shouldDeliver)

			shouldBroadcast, shouldDeliver, err = receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.Nil(shouldDeliver)
		}
	})

	t.Run("waitForActualValueFromLeader", func(t *testing.T) {
		a := assert.New(t)
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1, e2, e3 := engines[0], engines[1], engines[2]

		receiver := engines[4]
		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self.Pid, receiver.Self.Pid, rnd, party.Digest{byte(j)})

			originalValue := parsedIntoEcho(a, e1, parsed1)

			echo := makeHashEcho(e1, parsed1, originalValue)

			parsed := &parsedHashEcho{
				HashEcho: echo.toBroadcastMsg().Message.GetHashEcho(),
			}

			echo.setSource(e2.Self)

			shouldBroadcast, deliverable, err := receiver.broadcastInspection(parsed, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.Nil(deliverable)

			echo.setSource(e3.Self)

			shouldBroadcast, deliverable, err = receiver.broadcastInspection(parsed, echo)
			a.NoError(err)
			a.False(shouldBroadcast) // should broadcast only for leader.
			a.Nil(deliverable)

			echo.setSource(e1.Self)

			shouldBroadcast, deliverable, err = receiver.broadcastInspection(parsed, echo)
			a.NoError(err)
			a.False(shouldBroadcast) // should not broadcast if it hadn't seen the actual value from the leader!
			a.Nil(deliverable)

			shouldBroadcast, deliverable, err = receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, originalValue)
			a.NoError(err)
			a.True(shouldBroadcast) // should echo when seeing the actual value from the leader.
			a.NotNil(deliverable)
		}
	})
}

func load5GuardiansSetupForBroadcastChecks(a *assert.Assertions) []*Engine {
	engines, err := loadGuardians(5, "tss5") // f=1, n=5.
	a.NoError(err)

	for _, v := range engines {
		v.GuardianStorage.Threshold = 2 // meaning 3 guardians are needed to sign.
	}

	return engines
}

func makeHashEcho(e *Engine, parsed common.ParsedMessage, in *IncomingMessage) *IncomingMessage {
	echocpy := proto.Clone(in.toBroadcastMsg()).(*tsscommv1.Echo)

	outgoing := &IncomingMessage{
		Source: in.Source,
		Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{
				Echo: echocpy,
			},
		}}

	tmp := serializeableMessage{&tssMessageWrapper{parsed}}

	uid := tmp.getUUID(e.LoadDistributionKey)
	dgst := hashSignedMessage(echocpy.Message)

	hshEcho := &tsscommv1.HashEcho{
		SessionUuid:           uid[:],
		OriginalContentDigest: dgst[:],
	}

	outgoing.toBroadcastMsg().Message.Content = &tsscommv1.SignedMessage_HashEcho{HashEcho: hshEcho}
	return outgoing

}
func TestDeliver(t *testing.T) {
	t.Run("After2fPlus1Messages", func(t *testing.T) {
		a := assert.New(t)
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1, e2, e3 := engines[0], engines[1], engines[2]

		receiver := engines[4]
		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self.Pid, receiver.Self.Pid, rnd, party.Digest{byte(j)})

			echo := parsedIntoEcho(a, e1, parsed1)
			hshEcho := makeHashEcho(e1, parsed1, echo)
			hshEcho.setSource(e2.Self)

			prsedHashEcho := &parsedHashEcho{hshEcho.toBroadcastMsg().Message.GetHashEcho()}
			shouldBroadcast, deliverable, err := receiver.broadcastInspection(prsedHashEcho, hshEcho)

			a.NoError(err)
			a.False(shouldBroadcast)
			a.Nil(deliverable)

			hshEcho.setSource(e3.Self)

			shouldBroadcast, deliverable, err = receiver.broadcastInspection(prsedHashEcho, hshEcho)
			a.NoError(err)
			a.False(shouldBroadcast) // haven't seen the actual value from the leader yet.
			a.Nil(deliverable)

			echo.setSource(e1.Self)

			shouldBroadcast, deliverable, err = receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, echo)
			a.NoError(err)
			a.True(shouldBroadcast)
			a.NotNil(deliverable)
		}
	})

	t.Run("doesn'tDeliverTwice", func(t *testing.T) {
		a := assert.New(t)
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1, e2, e3, e4 := engines[0], engines[1], engines[2], engines[3]

		receiver := engines[4]
		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self.Pid, receiver.Self.Pid, rnd, party.Digest{byte(j)})
			echo := parsedIntoEcho(a, e1, parsed1)
			hashecho := makeHashEcho(e1, parsed1, echo)
			hashecho.setSource(e2.Self)

			prsedHashEcho := &parsedHashEcho{hashecho.toBroadcastMsg().Message.GetHashEcho()}
			shouldBroadcast, deliverable, err := receiver.broadcastInspection(prsedHashEcho, hashecho)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.Nil(deliverable)

			hashecho.setSource(e3.Self)

			shouldBroadcast, deliverable, err = receiver.broadcastInspection(prsedHashEcho, hashecho)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.Nil(deliverable)

			echo.setSource(e1.Self)

			shouldBroadcast, deliverable, err = receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, echo)
			a.NoError(err)
			a.True(shouldBroadcast)
			a.NotNil(deliverable)

			// twice in a row
			shouldBroadcast, deliverable, err = receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.Nil(deliverable)

			// new hash echo, shouldn't deliver again too.
			hashecho.setSource(e4.Self)

			shouldBroadcast, deliverable, err = receiver.broadcastInspection(prsedHashEcho, hashecho)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.Nil(deliverable)
		}
	})
}

func TestUuidNotAffectedByMessageContentChange(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	e1 := engines[0]
	for i, rnd := range allRounds {
		trackingId := party.Digest{byte(i)}

		// each message is generated with some random content inside.
		parsed1 := generateFakeParsedMessageWithRandomContent(e1.Self.Pid, e1.Self.Pid, rnd, trackingId)
		parsed2 := generateFakeParsedMessageWithRandomContent(e1.Self.Pid, e1.Self.Pid, rnd, trackingId)

		uid1 := parsed1.getUUID(e1.LoadDistributionKey)

		uid2 := parsed2.getUUID(e1.LoadDistributionKey)

		a.Equal(uid1, uid2)
	}
}

func TestEquivocation(t *testing.T) {
	t.Run("inBroadcastLogic", func(t *testing.T) {
		a := assert.New(t)
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1, e2 := engines[0], engines[1]

		receiver := engines[4]
		for i, rndType := range allRounds {

			trackingId := party.Digest{byte(i)}

			parsed1 := generateFakeMessageWithRandomContent(e1.Self.Pid, receiver.Self.Pid, rndType, trackingId)

			shouldBroadcast, deliverable, err := receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, parsedIntoEcho(a, e2, parsed1))
			a.NoError(err)
			a.True(shouldBroadcast) //should broadcast since e2 is the source of this message.
			a.Nil(deliverable)

			parsed2 := generateFakeMessageWithRandomContent(e1.Self.Pid, e2.Self.Pid, rndType, trackingId)

			shouldBroadcast, deliverable, err = receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed2, ""}}, parsedIntoEcho(a, e2, parsed2))
			a.ErrorContains(err, "equivication")
			a.False(shouldBroadcast)
			a.Nil(deliverable)

			equvicatingEchoerMessage := parsedIntoEcho(a, e2, parsed1)
			equvicatingEchoerMessage.
				Content.
				GetEcho().
				Message.
				Content.(*tsscommv1.SignedMessage_TssContent).
				TssContent.
				Payload[0] += 1
			// now echoer is equivicating (change content, but of some seen message):
			_, _, err = receiver.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, equvicatingEchoerMessage)
			a.ErrorContains(err, e2.Self.Hostname)
		}
	})

	t.Run("inUnicast", func(t *testing.T) {
		a := assert.New(t)
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1, e2 := engines[0], engines[1]

		receiver := engines[4]
		ctx, cncl := context.WithCancel(context.Background())
		defer cncl()

		e1.Start(ctx, logger)
		e2.Start(ctx, logger)

		for i, rndType := range unicastRounds {

			trackingId := party.Digest{byte(i)}

			parsed1 := generateFakeMessageWithRandomContent(e1.Self.Pid, receiver.Self.Pid, rndType, trackingId)
			parsed2 := generateFakeMessageWithRandomContent(e1.Self.Pid, receiver.Self.Pid, rndType, trackingId)

			bts, _, err := parsed1.WireBytes()
			a.NoError(err)

			msg := &IncomingMessage{
				Content: &tsscommv1.PropagatedMessage{
					Message: &tsscommv1.PropagatedMessage_Unicast{
						Unicast: &tsscommv1.Unicast{
							Content: &tsscommv1.Unicast_Tss{
								Tss: &tsscommv1.TssContent{
									Payload:         bts,
									MsgSerialNumber: 0,
								},
							},
						},
					},
				},
			}

			msg.setSource(e1.Self)

			receiver.handleUnicast(msg)

			bts, _, err = parsed2.WireBytes()
			a.NoError(err)

			msg.Content.Message.(*tsscommv1.PropagatedMessage_Unicast).
				Unicast.Content.(*tsscommv1.Unicast_Tss).Tss.Payload = bts
			a.ErrorIs(receiver.handleUnicast(msg), ErrEquivicatingGuardian)
		}
	})
}

func TestBadInputs(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	e1, e2 := engines[0], engines[1]

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
	defer cancel()

	e1.Start(ctx, logger) // so it has a logger.

	t.Run("signature", func(t *testing.T) {
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self.Pid, e1.Self.Pid, rnd, party.Digest{byte(j)})
			echo := parsedIntoEcho(a, e1, parsed1)

			echo.setSource(e1.Self)

			echo.toBroadcastMsg().Message.Signature[0] += 1
			_, _, err := e1.broadcastInspection(&deliverableMessage{&parsedTssContent{parsed1, ""}}, echo)
			a.ErrorIs(err, ErrInvalidSignature)

			echo.setSource(e1.Self)
			err = e1.handleIncomingTssMessage(echo)
			a.ErrorIs(err, ErrInvalidSignature)
			e1.HandleIncomingTssMessage(echo) // to ensure we go through some code path, nothing to check really.
		}
	})

	t.Run("incoming message", func(t *testing.T) {
		var tmp *Engine = nil
		// these tests ensure we don't panic on bad inputs.
		// Shouldn't fail or panic.
		tmp.HandleIncomingTssMessage(nil)
		e1.HandleIncomingTssMessage(nil)
		e2.HandleIncomingTssMessage(nil) // e2 hadn't started.

		err := tmp.handleIncomingTssMessage(nil)
		a.ErrorIs(err, errNilIncoming)

		err = e1.handleIncomingTssMessage(&IncomingMessage{})
		a.ErrorIs(err, errNilSource)

		err = e1.handleIncomingTssMessage(&IncomingMessage{Source: e2.Self})
		a.ErrorIs(err, errNeitherBroadcastNorUnicast)

		err = e1.handleIncomingTssMessage(&IncomingMessage{
			Source:  e2.Self,
			Content: &tsscommv1.PropagatedMessage{}})
		a.ErrorIs(err, errNeitherBroadcastNorUnicast)

		err = e1.handleIncomingTssMessage(&IncomingMessage{
			Source: e2.Self,
			Content: &tsscommv1.PropagatedMessage{
				Message: &tsscommv1.PropagatedMessage_Echo{},
			},
		})
		a.ErrorIs(err, ErrBroadcastIsNil)

		err = e1.handleIncomingTssMessage(&IncomingMessage{
			Source: e2.Self,
			Content: &tsscommv1.PropagatedMessage{
				Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{}},
			},
		})
		a.ErrorIs(err, ErrSignedMessageIsNil)

		e2id, err := e2.fetchIdentityFromPartyID(e2.Self.Pid)
		a.NoError(err)

		err = e1.handleIncomingTssMessage(&IncomingMessage{Source: e2.Self, Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{
				Message: &tsscommv1.SignedMessage{
					Sender: uint32(e2id.CommunicationIndex),
				},
			}}},
		})
		a.ErrorIs(err, ErrNoContent)

		err = e1.handleIncomingTssMessage(&IncomingMessage{Source: e2.Self, Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{
				Message: &tsscommv1.SignedMessage{
					Content: &tsscommv1.SignedMessage_TssContent{
						TssContent: &tsscommv1.TssContent{},
					},
					Sender:    uint32(e2id.CommunicationIndex),
					Signature: []byte{1, 2, 3},
				},
			}}},
		})
		a.ErrorIs(err, ErrNilPayload)

		err = e1.handleIncomingTssMessage(&IncomingMessage{Source: e2.Self, Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{
				Message: &tsscommv1.SignedMessage{
					Content: &tsscommv1.SignedMessage_TssContent{
						TssContent: &tsscommv1.TssContent{
							Payload: []byte{1, 2, 3},
						},
					},
					Sender: uint32(e2id.CommunicationIndex),
				},
			}}},
		})
		a.ErrorIs(err, errEmptySignature)

		err = e1.handleIncomingTssMessage(&IncomingMessage{Source: e2.Self, Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{
				Message: &tsscommv1.SignedMessage{
					Content: &tsscommv1.SignedMessage_TssContent{
						TssContent: &tsscommv1.TssContent{
							Payload: []byte{1, 2, 3},
						},
					},
					Sender:    uint32(e2id.CommunicationIndex),
					Signature: []byte{1, 2, 3},
				},
			}}},
		})
		a.ErrorContains(err, "cannot parse")
	})

	t.Run("Begin signing", func(t *testing.T) {
		var tmp *Engine = nil
		engines2 := load5GuardiansSetupForBroadcastChecks(a)

		a.ErrorIs(tmp.BeginAsyncThresholdSigningProtocol(&signer.SignRequest{
			Digest:    make([]byte, 32),
			Protocol:  common.ProtocolFROSTSign.ToString(),
			Committee: [][]byte{},
		}), errNilTssEngine)

		a.ErrorIs(e2.BeginAsyncThresholdSigningProtocol(&signer.SignRequest{
			Digest:    make([]byte, 32),
			Protocol:  common.ProtocolFROSTSign.ToString(),
			Committee: [][]byte{},
		}), errTssEngineNotStarted)

		tmp = engines2[1]
		tmp.started.Store(started)

		a.ErrorContains(e1.BeginAsyncThresholdSigningProtocol(&signer.SignRequest{
			Digest:    make([]byte, 31, 32),
			Protocol:  common.ProtocolFROSTSign.ToString(),
			Committee: [][]byte{},
		}), "digest size is not 32 bytes")

		tmp.fp = nil
		a.ErrorContains(tmp.BeginAsyncThresholdSigningProtocol(&signer.SignRequest{
			Digest:    make([]byte, 32),
			Protocol:  common.ProtocolFROSTSign.ToString(),
			Committee: [][]byte{},
		}), "not set up correctly")
	})

	t.Run("fetch certificate", func(t *testing.T) {
		_, err := e1.fetchIdentityFromIndex(SenderIndex(e1.GuardianStorage.NumGuardians() + 1))
		a.ErrorIs(err, ErrUnkownSender)
	})
}

func createX509Cert(dnsName string) *x509.Certificate {
	// using random serial number
	var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := crand.Int(crand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"tsscomm"}},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 366 * 40), // valid for > 40 years used for tests...
		BasicConstraintsValid: true,

		DNSNames:    []string{"localhost", dnsName},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	return &tmpl
}

func TestFetchPartyId(t *testing.T) {
	a := assert.New(t)
	engines, err := loadGuardians(5, "tss5")
	a.NoError(err)

	e1 := engines[0]
	id, err := e1.FetchIdentity(e1.Self.Cert)
	a.NoError(err)
	a.True(e1.Self.Pid.Equals(id.Pid))

	crt := createX509Cert("localhost")
	_, err = e1.FetchIdentity(crt)
	a.ErrorContains(err, "unsupported") // cert.PublicKey=nil

	crt.PublicKey = []byte{1, 2, 3}
	_, err = e1.FetchIdentity(crt)
	a.ErrorContains(err, "unknown")
}

func TestCleanup(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	e1 := engines[0]

	uuid1 := uuid{1}
	e1.received[uuid1] = &broadcaststate{
		timeReceived: time.Now().Add(time.Minute * 10 * (-1)),
	}

	uuid2 := uuid{2}
	e1.received[uuid2] = &broadcaststate{
		timeReceived: time.Now(),
	}

	e1.cleanup(time.Minute * 5) // if more than 5 minutes passed -> delete
	a.Len(e1.received, 1)
	_, ok := e1.received[uuid{1}]
	a.False(ok)

	_, ok = e1.received[uuid{2}]
	a.True(ok)
}

type badtssMessage struct {
}

func (b *badtssMessage) ValidateBasic() bool            { return true }
func (b *badtssMessage) GetRound() int                  { return 2 }
func (b *badtssMessage) Content() common.MessageContent { return nil }
func (b *badtssMessage) GetFrom() *common.PartyID       { panic("unimplemented") }
func (b *badtssMessage) GetTo() *common.PartyID         { panic("unimplemented") }
func (b *badtssMessage) IsBroadcast() bool              { panic("unimplemented") }
func (b *badtssMessage) IsToOldAndNewCommittees() bool  { panic("unimplemented") }
func (b *badtssMessage) IsToOldCommittee() bool         { panic("unimplemented") }
func (b *badtssMessage) String() string                 { panic("unimplemented") }
func (b *badtssMessage) Type() string                   { return "badmessageType" }
func (b *badtssMessage) WireMsg() *common.MessageWrapper {
	return &common.MessageWrapper{
		TrackingID: nil,
	}
}
func (b *badtssMessage) WireBytes() ([]byte, *common.MessageRouting, error) {
	return nil, nil, errors.New("bad message")
}
func (b *badtssMessage) GetProtocol() common.ProtocolType {
	return common.ProtocolFROSTSign
}

func TestRouteCheck(t *testing.T) {
	// this test is a bit of a hack.
	// To ensure we don't panic on bad inputs.
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	e1 := engines[0]

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	e1.Start(ctx, logger)
	e1.fpCommChans.OutChannel <- &badtssMessage{}
	e1.fpCommChans.ErrChannel <- common.NewTrackableError(errors.New("test"), "test", -1, nil, &common.TrackingID{})
	e1.fpCommChans.ErrChannel <- nil

	time.Sleep(time.Millisecond * 200)
}

func TestDefaultSameLeader(t *testing.T) {
	a := assert.New(t)

	engines := load5GuardiansSetupForBroadcastChecks(a)

	leader := engines[0].LeaderIdentity
	a.NotNil(leader)

	for _, e := range engines {
		a.Equal(e.LeaderIdentity, leader)

		if bytes.Equal(e.Self.KeyPEM, leader) {
			a.True(e.isleader)
		} else {
			a.False(e.isleader)
		}
	}
}

func TestNoFaultsFlow(t *testing.T) {
	// checking metrics first since this is a bit flakey.
	t.Run("regularflow", func(t *testing.T) {
		a := assert.New(t)
		engines, err := loadGuardians(5, "tss5")
		a.NoError(err)

		dgst := party.Digest{1, 2, 3, 4, 5, 6, 7, 8, 9}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
		defer cancel()

		fmt.Println("starting engines.")
		for _, engine := range engines {
			a.NoError(engine.Start(ctx, logger))
		}

		fmt.Println("msgHandler settup:")
		dnchn := msgHandler(ctx, engines, 1)

		fmt.Println("engines started, requesting sigs")

		// all engines are started, now we can begin the protocol.
		for _, engine := range engines {
			tmp := make([]byte, 32)
			copy(tmp, dgst[:])

			err := engine.BeginAsyncThresholdSigningProtocol(&signer.SignRequest{
				Digest:   tmp,
				Protocol: common.ProtocolFROSTSign.ToString(),
			})

			a.NoError(err)
		}

		if ctxExpiredFirst(ctx, dnchn) {
			a.FailNow("context expired")
		}
	})

	// Setting up all engines (not just 5), each with a different guardian storage.
	// all will attempt to sign a single message, while outputing messages to each other,
	// and reliably broadcasting them.
	t.Run("Call multiple to sign the same digest", func(t *testing.T) {
		a := assert.New(t)
		engines, err := loadGuardians(5, "tss5")
		a.NoError(err)

		dgst := party.Digest{1, 2, 3, 4, 5, 6, 7, 8, 9}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		for _, engine := range engines {
			a.NoError(engine.Start(ctx, logger))
		}

		dnchn := msgHandler(ctx, engines, 1)

		// demand signing multiple times.
		for range 10 {
			for _, engine := range engines {
				tmp := make([]byte, 32)
				copy(tmp, dgst[:])
				engine.BeginAsyncThresholdSigningProtocol(&signer.SignRequest{
					Digest:   tmp,
					Protocol: common.ProtocolFROSTSign.ToString(),
				})
			}
			fmt.Println()
		}

		time.Sleep(time.Millisecond * 500)
		if ctxExpiredFirst(ctx, dnchn) {
			a.FailNow("context expired")
		}
	})

	t.Run("19 signers", func(t *testing.T) {
		t.SkipNow() // No tss19 engines available at the moment.
		a := assert.New(t)
		engines, err := loadGuardians(19, "tss19")
		a.NoError(err)

		dgst := party.Digest{1, 2, 3, 4, 5, 6, 7, 8, 9}

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
		defer cancel()

		for _, engine := range engines {
			a.NoError(engine.Start(ctx, logger))
		}

		dnchn := msgHandler(ctx, engines, 1)

		for _, engine := range engines {
			tmp := make([]byte, 32)
			copy(tmp, dgst[:])
			engine.BeginAsyncThresholdSigningProtocol(&signer.SignRequest{
				Digest:   tmp,
				Protocol: common.ProtocolFROSTSign.ToString(),
			})
		}

		time.Sleep(time.Millisecond * 500)
		if ctxExpiredFirst(ctx, dnchn) {
			a.FailNow("context expired")
		}
	})

	t.Run("with 5 sigs", func(t *testing.T) {
		a := assert.New(t)
		engines, err := loadGuardians(5, "tss5")
		a.NoError(err)

		digests := make([]party.Digest, 5)
		for i := 0; i < 5; i++ {
			digests[i] = party.Digest{byte(i)}
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
		defer cancel()

		fmt.Println("starting engines.")
		for _, engine := range engines {
			a.NoError(engine.Start(ctx, logger))
		}

		fmt.Println("msgHandler settup:")
		dnchn := msgHandler(ctx, engines, len(digests))

		fmt.Println("engines started, requesting sigs")

		// all engines have started, now we can begin the protocol.
		for _, d := range digests {

			for _, engine := range engines {
				tmp := make([]byte, 32)
				copy(tmp, d[:])

				engine.BeginAsyncThresholdSigningProtocol(&signer.SignRequest{
					Digest:   tmp,
					Protocol: common.ProtocolFROSTSign.ToString(),
				})
			}
		}

		if ctxExpiredFirst(ctx, dnchn) {
			a.FailNow("context expired")
		}
	})

	t.Run("ECDSA signature", func(t *testing.T) {
		// SLOW TEST.
		a := assert.New(t)
		engines, err := loadGuardians(5, "tss5")
		a.NoError(err)

		dgst := party.Digest{1, 2, 3, 4, 5, 6, 7, 8, 9}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*50)
		defer cancel()

		fmt.Println("starting engines.")
		for _, engine := range engines {
			a.NoError(engine.Start(ctx, logger))
		}

		fmt.Println("msgHandler settup:")
		dnchn := msgHandler(ctx, engines, 1)

		fmt.Println("engines started, requesting sigs")

		// all engines are started, now we can begin the protocol.
		for _, engine := range engines {
			tmp := make([]byte, 32)
			copy(tmp, dgst[:])
			a.NoError(
				engine.BeginAsyncThresholdSigningProtocol(&signer.SignRequest{
					Digest:   tmp,
					Protocol: common.ProtocolFROSTSign.ToString(),
				}),
			)
		}

		if ctxExpiredFirst(ctx, dnchn) {
			a.FailNow("context expired")
		}
	})
}

func ctxExpiredFirst[T any](ctx context.Context, ch chan T) bool {
	select {
	case <-ctx.Done():
		return true
	case <-ch:
		return false
	}
}

func TestFT(t *testing.T) {
	// t.Skip("Skipping these test until we decide about anouncing mechanism.")

	t.Run("single server crashes", func(t *testing.T) {
		t.Skip("TODO: handle server crashes")
	})

	t.Run("server crashes during signing multiple digests", func(t *testing.T) { t.Skip("TODO: handle server crashes") })

	t.Run("cant sign after f faults", func(t *testing.T) { t.Skip("TODO: handle server crashes") })

	t.Run("Two quorums only one guardian in conjunction", func(t *testing.T) {
		t.Skip("TODO: Make one of the signers of VAAv1 send the VAAv1 (similar to leader mechanism), so the others will also sign.")

		// This test simulates an error we've seen while testing with real data:
		// 3 servers manage to generate VAA but not VAAv2 (TSS signatuer).
		// That is, 3 servers saw the same digest, but only one of them was part of the tss-committee.
		// As a result, the VAA was generated, but the VAAv2 was not (since the others in the committee didn't f+1 messages that started signing).
		a := assert.New(t)

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		tsk := party.SigningTask{
			Digest:        party.Digest{1, 2, 3, 4, 5, 6, 7, 8, 9},
			Faulties:      []*common.PartyID{},
			AuxiliaryData: []byte{1, 2, 3, 4},
			ProtocolType:  common.ProtocolFROSTSign,
		}

		engines, err := loadGuardians(5, "tss5")
		a.NoError(err)

		fmt.Println("starting engines.")
		for _, engine := range engines {
			a.NoError(engine.Start(ctx, logger))
		}

		signers := getSigningGuardians(a, engines, tsk)
		a.Len(signers, 3)

		fmt.Println("msgHandler settup:")
		dnchn := msgHandler(ctx, engines, 1)

		nonSigners := make([]*Engine, 0, 2)
		for _, engine := range engines {
			if !contains(signers, engine) {
				nonSigners = append(nonSigners, engine)
			}
		}

		// starting 3 signers where two aren't in the committee and one is.
		for _, engine := range append(nonSigners, signers[0]) {
			tmp := make([]byte, 32)
			copy(tmp, tsk.Digest[:])

			engine.BeginAsyncThresholdSigningProtocol(&signer.SignRequest{
				Digest:   tmp,
				Protocol: common.ProtocolFROSTSign.ToString(),
			})
		}

		if ctxExpiredFirst(ctx, dnchn) {
			a.FailNow("context expired")
		}
	})
}

func TestMessagesWithBadRounds(t *testing.T) {
	a := assert.New(t)
	gs := load5GuardiansSetupForBroadcastChecks(a)
	e1, e2 := gs[0], gs[1]
	from := e1.Self
	to := e2.Self

	t.Run("Unicast", func(t *testing.T) {
		msgDigest := party.Digest{1}
		for _, rnd := range broadcastRounds {
			parsed := generateFakeMessageWithRandomContent(from.Pid, to.Pid, rnd, msgDigest)
			bts, _, err := parsed.WireBytes()
			a.NoError(err)

			m := &IncomingMessage{
				Source: from,
				Content: &tsscommv1.PropagatedMessage{Message: &tsscommv1.PropagatedMessage_Unicast{
					Unicast: &tsscommv1.Unicast{
						Content: &tsscommv1.Unicast_Tss{
							Tss: &tsscommv1.TssContent{Payload: bts},
						},
					},
				}},
			}

			err = e2.handleUnicast(m)
			a.ErrorContains(err, "unknown unicast message type received")
		}
	})

	t.Run("Echo", func(t *testing.T) {
		t.Skip("TODO: Right now there are no 'bad' rounds for echoes (since we've switched to frost), ecdsa might have those. so we might need to include a mechanism to review protocol type in each message.")

		msgDigest := party.Digest{2}
		for _, rnd := range unicastRounds {
			parsed := generateFakeMessageWithRandomContent(from.Pid, to.Pid, rnd, msgDigest)
			bts, _, err := parsed.WireBytes()
			a.NoError(err)

			m := &IncomingMessage{
				Source: from,
				Content: &tsscommv1.PropagatedMessage{Message: &tsscommv1.PropagatedMessage_Echo{
					Echo: &tsscommv1.Echo{
						Message: &tsscommv1.SignedMessage{
							Content: &tsscommv1.SignedMessage_TssContent{
								TssContent: &tsscommv1.TssContent{Payload: bts},
							},
							Sender:    uint32(from.CommunicationIndex),
							Signature: nil,
						},
					},
				}},
			}
			a.NoError(e1.sign(uuid{}, m.Content.GetEcho().Message))

			err = e2.handleBroadcast(m)
			// a.ErrorIs(err, errBadRoundsInBroadcast)
		}
	})
}

func generateFakeParsedMessageWithRandomContent(from, to *common.PartyID, rnd signingRound, digest party.Digest) broadcastMessage {
	fake := generateFakeMessageWithRandomContent(from, to, rnd, digest)
	return &deliverableMessage{&parsedTssContent{fake, ""}}
}

// if to == nil it's a broadcast message.
func generateFakeMessageWithRandomContent(from, to *common.PartyID, rnd signingRound, digest party.Digest) common.ParsedMessage {
	partiesState := make([]byte, maxParties/8)
	for i := range partiesState {
		partiesState[i] = 255
	}

	trackingId := &common.TrackingID{
		Digest:        digest[:],
		PartiesState:  partiesState,
		AuxiliaryData: []byte{},
		Protocol:      uint32(common.ProtocolECDSASign.ToInt()),
	}

	rndmBigNumber := &big.Int{}
	buf := make([]byte, 16)
	rand.Read(buf)
	rndmBigNumber.SetBytes(buf)

	var (
		meta    = common.MessageRouting{From: from, To: nil} // broadcast message since `To` is nil.
		content common.MessageContent
	)

	switch rnd {
	case round2Message:
		content = &sign.Broadcast2{
			Di: rndmBigNumber.Bytes(),
			Ei: rndmBigNumber.Bytes(),
		}
	case round3Message:
		if to == nil {
			panic("not a broadcast message")
		}
		meta = common.MessageRouting{From: from, To: to} // unicast message since `To` isn't nil.

		content = &sign.Broadcast3{
			Zi: rndmBigNumber.Bytes(),
		}
	default:
		panic("unknown round")
	}

	return common.NewMessage(meta, content, common.NewMessageWrapper(meta, content, trackingId))
}

func loadMockGuardianStorage(gstorageIndex int, from string) *GuardianStorage {
	path, err := testutils.GetMockGuardianTssStorage(gstorageIndex, from)
	if err != nil {
		panic(err)
	}

	st, err := LoadGuardianStorage(StorageLoader{
		Path:        path,
		DemandFrost: true,
		DemandECDSA: true,
	})
	if err != nil {
		panic(err)
	}
	return st
}

func loadGuardians(numParticipants int, from string) ([]*Engine, error) {
	engines := make([]*Engine, numParticipants)

	for i := 0; i < numParticipants; i++ {
		e, err := NewReliableTSS(loadMockGuardianStorage(i, from))
		if err != nil {
			return nil, err
		}
		en, ok := e.(*Engine)
		if !ok {
			return nil, errors.New("not an engine")
		}
		engines[i] = en
	}

	return engines, nil
}

type msgg struct {
	Sender *Identity
	Sendable
}

// its channel returns an array of ALL messages it received.
func msgHandler(ctx context.Context, engines []*Engine, numDiffSigsExpected int) chan []*IncomingMessage {
	messageBucket := make([]*IncomingMessage, 0, 10000)
	signalDone := make(chan []*IncomingMessage, 1)
	once := sync.Once{}

	nmsigs := map[string]struct{}{}
	lck := sync.Mutex{}

	go func() {
		wg := sync.WaitGroup{}
		wg.Add(len(engines) * 2)

		chns := make(map[string]chan msgg, len(engines))
		for _, en := range engines {
			chns[en.Self.Pid.GetID()] = make(chan msgg, 10000)
		}

		for _, e := range engines {
			engine := e

			// need a separate goroutine for handling engine output and engine input.
			// simulating network stream incoming and network stream outgoing.

			// incoming
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return

					case msg := <-chns[engine.Self.Pid.GetID()]:
						in := &IncomingMessage{
							Source:  msg.Sender,
							Content: msg.Sendable.GetNetworkMessage(),
						}

						engine.HandleIncomingTssMessage(in)

						lck.Lock() // used across multiple goroutines: must lock.
						messageBucket = append(messageBucket, in)
						lck.Unlock()
					}
				}
			}()

			//  Listener, responsible to receive output of engine, and direct it to the other engines.
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return

					case m := <-engine.ProducedOutputMessages():
						if m.IsBroadcast() {
							broadcast(chns, engine, m)
							continue
						}
						unicast(m, chns, engine)
					case s := <-engine.Responses():
						tmp, ok := s.Response.(*signer.SignResponse_Signature)
						if !ok {
							status, ok := s.Response.(*signer.SignResponse_Status)
							if !ok {
								panic("unknown response type")
							}

							if status.Status.Code == int32(codes.FailedPrecondition) && status.Status.Message == party.ErrNotInCommittee.Error() {
								continue // no need to inform about not being in committee. it is common case.
							}

							fmt.Printf("received status reportfrom engine: %v\n", status)
							continue
						}

						sig := tmp.Signature

						mustVerify(sig, engine)

						lck.Lock()
						nmsigs[sig.TrackingId.ToString()] = struct{}{}
						ln := len(nmsigs)
						lck.Unlock()

						fmt.Println("received signature", ln, sig.TrackingId.Digest[0])
						if ln < numDiffSigsExpected {
							continue
						}

						fmt.Printf("/////////\nreceived all signatures (%v)\n/////////\n", numDiffSigsExpected)
						once.Do(func() {
							lck.Lock()
							messageSlice := messageBucket
							lck.Unlock()

							signalDone <- messageSlice
							close(signalDone)
						})
					}
				}
			}()
		}

		wg.Wait()
	}()

	return signalDone
}

func mustVerify(sig *common.SignatureData, engine *Engine) {
	if sig.TrackingId.Protocol == uint32(common.ProtocolFROSTSign.ToInt()) {
		mustVerifyFrost(sig, engine)
	} else {
		mustVerifyCMP(sig, engine)
	}
}

func mustVerifyCMP(sig *common.SignatureData, engine *Engine) {
	sg, err := cmp.Secp256k1SignatureTranslate(sig)
	if err != nil {
		panic("failed to translate cmp signature:" + err.Error())
	}

	pk, err := engine.GetPublicKey(common.ProtocolECDSASign)
	if err != nil {
		panic("failed to get cmp  publickey:" + err.Error())
	}

	if !sg.Verify(pk, sig.M) {
		panic("failed to verify cmp signature:" + err.Error())
	}
}

func mustVerifyFrost(sig *common.SignatureData, engine *Engine) {
	sg, err := frost.Secp256k1SignatureTranslate(sig)
	if err != nil {
		panic("failed to translate frost signature:" + err.Error())
	}

	pk, err := engine.GetPublicKey(common.ProtocolFROSTSign)
	if err != nil {
		panic("failed to get frost public key:" + err.Error())
	}

	if err := sg.Verify(pk, sig.M); err != nil {
		panic("failed to verify frost signature:" + err.Error())
	}
}

func unicast(m Sendable, chns map[string]chan msgg, engine *Engine) {
	pids := m.GetDestinations()
	for _, id := range pids {
		feedChn := chns[id.Pid.GetID()]
		feedChn <- msgg{
			Sender:   engine.Self,
			Sendable: m.cloneSelf(),
		}
	}
}

func broadcast(chns map[string]chan msgg, engine *Engine, m Sendable) {
	for _, feedChn := range chns {
		feedChn <- msgg{
			Sender:   engine.Self,
			Sendable: m.cloneSelf(),
		}
	}
}

// strictly for the tests.
func (c *activeSigCounter) digestToGuardiansLen() int {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	return len(c.digestToGuardians)
}

// Used to receive all messages for some engine, then feed them all at once, and collect the result.
// on error returns err.
// simulates echoes for each message too!
type echoFeed struct {
	eng      *Engine
	peers    []*Engine
	messages []IncomingMessage
}

func (b *echoFeed) addMessage(src *Engine, m Sendable) {
	inc := IncomingMessage{
		Source:  src.Self,
		Content: m.GetNetworkMessage(),
	}

	b.messages = append(b.messages, inc)
}

func (b *echoFeed) feedWithEchoes() error {
	defer func() {
		b.messages = nil // clear messages after feeding.
	}()

	if b.messages == nil {
		return nil
	}

	for _, msg := range b.messages {
		if err := b.eng.handleIncomingTssMessage(&msg); err != nil {
			return err
		}

		echo := b.genEcho(msg)
		// for each message: create fictional echo, making the guardian think that all other guardians have echoed it.
		for _, v := range b.peers {
			Incoming := &IncomingMessage{
				Source:  v.Self,
				Content: echo.GetNetworkMessage(),
			}

			if err := b.eng.handleIncomingTssMessage(Incoming); err != nil {
				return err
			}
		}
	}

	return nil
}

func (b *echoFeed) genEcho(msg IncomingMessage) *Echo {
	// src := msg.GetSource()
	// sig := msg.Content.GetEcho().Message.Signature

	parsed, err := b.eng.parseBroadcast(&msg)
	if err != nil {
		panic(err) // shouldn't happen in the test.
	}

	return b.eng.makeEcho(&msg, parsed)
}

func TestSigCounter(t *testing.T) {
	a := assert.New(t)

	t.Run("MaxCountBlockAdditionalUpdates", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*10)
		defer cancel()

		// t.Skip("TODO: implement this test, fails since we've moved to broadcast only messages!")

		tsks := []party.SigningTask{
			party.SigningTask{Digest: party.Digest{1}, Faulties: []*common.PartyID{}, AuxiliaryData: nil, ProtocolType: common.ProtocolFROSTSign},
			party.SigningTask{Digest: party.Digest{2}, Faulties: []*common.PartyID{}, AuxiliaryData: nil, ProtocolType: common.ProtocolFROSTSign},
		}
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1 := getSigningGuardian(a, engines, tsks...)

		e1.MaxSimultaneousSignatures = 1
		feeder := &echoFeed{
			eng:   e1,
			peers: engines,
		}

		signersTask0 := getSigningGuardians(a, engines, tsks[0])
		signersTask1 := getSigningGuardians(a, engines, tsks[1])

		for taskNum, committee := range [][]*Engine{signersTask0, signersTask1} {
			for _, e := range committee {
				e.Start(ctx, logger)

				msg := beginSigningAndGrabMessage(e, tsks[taskNum].Digest[:])
				feeder.addMessage(e, msg)

				if err := feeder.feedWithEchoes(); err != nil {
					a.ErrorContains(err, "maximum number of simultaneous")

					return
				}
			}
		}

		// try grabbing another message from e1:
		a.NotPanics(func() {
			for {
				feeder.addMessage(e1, waitOnChannelForNonHashEcho(e1))
				if err := feeder.feedWithEchoes(); err != nil {
					a.ErrorContains(err, "maximum number of simultaneous")

					return
				}
			}
		})
	})

	t.Run("ErrorReduceCount", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
		defer cancel()

		// Tests might fail due to change of the GuardianStorage files

		tsks := []party.SigningTask{
			party.SigningTask{Digest: party.Digest{1}, Faulties: []*common.PartyID{}, AuxiliaryData: nil, ProtocolType: common.ProtocolFROSTSign},
		}
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1 := getSigningGuardian(a, engines, tsks...)
		e1.MaxSimultaneousSignatures = 1

		e1.Start(ctx, logger)

		msg := beginSigningAndGrabMessage(e1, tsks[0].Digest[:])

		feeder := &echoFeed{
			eng:   e1,
			peers: engines,
		}

		feeder.addMessage(e1, msg)
		a.NoError(feeder.feedWithEchoes())

		incoming := &IncomingMessage{
			Source:  e1.Self,
			Content: msg.GetNetworkMessage(),
		}

		parsed, err := e1.parseTssContent(incoming.toBroadcastMsg().Message.GetTssContent(), incoming.GetSource())
		a.NoError(err)

		tid := parsed.getTrackingID()
		// test:
		a.Equal(e1.sigCounter.digestToGuardiansLen(), 1)
		select {
		case e1.fpCommChans.ErrChannel <- common.NewTrackableError(fmt.Errorf("dummyerr"), "de", -1, e1.Self.Pid, tid):
		case <-time.After(time.Second * 1):
			t.FailNow()
			return
		}
		time.Sleep(time.Millisecond * 500)

		a.Equal(e1.sigCounter.digestToGuardiansLen(), 0)
	})

	t.Run("sigDoneReduceCount", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
		defer cancel()

		// Tests might fail due to change of the GuardianStorage files
		tsks := []party.SigningTask{
			party.SigningTask{Digest: party.Digest{1}, Faulties: []*common.PartyID{}, AuxiliaryData: nil, ProtocolType: common.ProtocolFROSTSign},
		}
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1 := getSigningGuardian(a, engines, tsks...)
		e1.MaxSimultaneousSignatures = 1

		e1.Start(ctx, logger)

		msg := beginSigningAndGrabMessage(e1, tsks[0].Digest[:])

		feeder := &echoFeed{
			eng:   e1,
			peers: engines,
		}

		feeder.addMessage(e1, msg)
		a.NoError(feeder.feedWithEchoes())

		incoming := &IncomingMessage{
			Source:  e1.Self,
			Content: msg.GetNetworkMessage(),
		}

		parsed, err := e1.parseTssContent(incoming.toBroadcastMsg().Message.GetTssContent(), incoming.GetSource())
		a.NoError(err)

		// test:
		a.Equal(e1.sigCounter.digestToGuardiansLen(), 1)
		e1.fpCommChans.SignatureOutputChannel <- &common.SignatureData{
			Signature:         []byte{},
			SignatureRecovery: []byte{},
			R:                 []byte{},
			S:                 []byte{},
			M:                 []byte{},
			TrackingId:        parsed.getTrackingID(),
		}
		s := <-e1.signResponseChan
		_, ok := s.Response.(*signer.SignResponse_Signature)
		a.True(ok, "expected signature response. got %T", s.Response)

		time.Sleep(time.Second * 1)
		a.Equal(e1.sigCounter.digestToGuardiansLen(), 0)
	})

	t.Run("CanHaveSimulSigners", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
		defer cancel()

		tsks := []party.SigningTask{
			party.SigningTask{Digest: party.Digest{1}, Faulties: []*common.PartyID{}, AuxiliaryData: nil, ProtocolType: common.ProtocolFROSTSign},
			party.SigningTask{Digest: party.Digest{2}, Faulties: []*common.PartyID{}, AuxiliaryData: nil, ProtocolType: common.ProtocolFROSTSign},
		}
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1 := getSigningGuardian(a, engines, tsks...)

		e1.MaxSimultaneousSignatures = 2
		feeder := &echoFeed{
			eng:   e1,
			peers: engines,
		}

		signersTask0 := getSigningGuardians(a, engines, tsks[0])
		signersTask1 := getSigningGuardians(a, engines, tsks[1])

		for taskNum, committee := range [][]*Engine{signersTask0, signersTask1} {
			for _, e := range committee {
				e.Start(ctx, logger)

				msg := beginSigningAndGrabMessage(e, tsks[taskNum].Digest[:])
				feeder.addMessage(e, msg)
				err := feeder.feedWithEchoes()
				a.NoError(err)
			}
		}
	})
}

func getSigningGuardian(a *assert.Assertions, engines []*Engine, tsks ...party.SigningTask) *Engine {
	return getSigningGuardians(a, engines, tsks...)[0]
}

func getSigningGuardians(a *assert.Assertions, engines []*Engine, tsks ...party.SigningTask) []*Engine {
	a.GreaterOrEqual(len(tsks), 1) // at least one

	guardians := make([]*Engine, 0, len(engines))
mainloop:
	for _, e := range engines {

		for _, tsk := range tsks {
			info1, err := e.fp.GetSigningInfo(tsk)
			a.NoError(err)

			if !info1.IsParticipating {
				continue mainloop
			}
		}

		guardians = append(guardians, e)
	}

	return guardians
}

func beginSigningAndGrabMessage(e1 *Engine, dgst []byte) Sendable {
	go e1.BeginAsyncThresholdSigningProtocol(&signer.SignRequest{
		Digest:   dgst,
		Protocol: common.ProtocolFROSTSign.ToString(),
	})

	return waitOnChannelForNonHashEcho(e1)
}

func waitOnChannelForNonHashEcho(e1 *Engine) Sendable {
	var msg Sendable
	for { // cleaning the channel, and taking one of the messages.
		select {
		case tmp := <-e1.ProducedOutputMessages():

			if isHashEcho(tmp) {
				fmt.Println("skipping hash echo message")
				continue
			}
			msg = tmp
			parsed, err := e1.parseBroadcast(&IncomingMessage{
				Source:  e1.Self,
				Content: tmp.GetNetworkMessage(),
			})
			if err != nil {
				panic("failed to parse broadcast message: " + err.Error())
			}

			if _, ok := parsed.(*deliverableMessage); !ok {
				continue
			}

			return msg

		case <-time.After(time.Second * 5):
			// This means the signer wasn't one of the signing committees. (did the Guardian storage change?)
			// if it did, just make sure this engine is expected to sign, else use the right engine in the test.
			panic("timeout!")
		}
	}
}

func isHashEcho(tmp Sendable) bool {
	if msg, ok := tmp.GetNetworkMessage().Message.(*tsscommv1.PropagatedMessage_Echo); ok {
		_, ok = msg.Echo.Message.Content.(*tsscommv1.SignedMessage_HashEcho)
		if ok {
			return true
		}
	}

	return false
}

func contains(lst []*Engine, e *Engine) bool {
	for _, l := range lst {
		if l.Self.Pid.Equals(e.Self.Pid) {
			return true
		}
	}

	return false
}

func TestTrackingIDSizeIsOkay(t *testing.T) {
	dgst := party.Digest{1, 2, 3, 4, 5, 6, 7, 8, 9}
	tid := common.TrackingID{
		Digest:        dgst[:],
		PartiesState:  make([]byte, (maxParties+7)/8),
		AuxiliaryData: dgst[:],
	}

	tidstr := tid.ToString()
	assert.Equal(t, trackingIDHexStrSize, len(tidstr))

	tid.AuxiliaryData = append(tid.AuxiliaryData, 0)
	assert.Error(t, validateTrackingID(&tid))
}

func TestDKG(t *testing.T) {
	a := assert.New(t)

	for _, prot := range []common.ProtocolType{common.ProtocolFROSTDKG} {
		engines, err := loadGuardians(5, "tss5")
		a.NoError(err)

		for _, e := range engines { // Checks things work when no frost config is set.
			e.GuardianStorage.frostconf = nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
		defer cancel()

		for _, engine := range engines {
			a.NoError(engine.Start(ctx, logger))
		}

		_ = msgHandler(ctx, engines, 1)

		promises := make([]chan *party.TSSSecrets, len(engines))
		for _, engine := range engines {
			chn, err := engine.StartDKG(party.DkgTask{
				Threshold:    3,
				Seed:         party.Digest{},
				ProtocolType: prot,
			})
			a.NoError(err)

			promises[engine.Self.CommunicationIndex] = chn
		}
		fmt.Println("dkg started, waiting for configs...")

		res := make([]*frost.Config, len(engines))
		for _, v := range engines {
			select {
			case <-ctx.Done():
				a.FailNow("context expired before DKG finished")
			case cfg := <-promises[v.Self.CommunicationIndex]:
				fmt.Println("received config for", v.Self.CommunicationIndex)
				res[v.Self.CommunicationIndex] = cfg.FrostConfigs
			}
		}

		fmt.Println("DKG finished, configs:")

		fmt.Println("")
	}
}

func TestHandleFPWarningLogging(t *testing.T) {
	// Create engines & give them their normal logger via your loader.
	engines, err := loadGuardians(5, "tss5")
	if err != nil {
		t.Fatalf("loadGuardians failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	for _, e := range engines {
		if err := e.Start(ctx, logger); err != nil {
			t.Fatalf("engine.Start failed: %v", err)
		}
	}

	// swap in an observer logger so we can assert on logs.
	e := engines[0]
	core, logs := observer.New(zapcore.WarnLevel)
	e.logger = zap.New(core) // replace the engine's logger with observed one

	// 1) nil warning => no logs
	e.handleFPWarning(nil)
	if logs.Len() != 0 {
		t.Fatalf("engine expected 0 logs for nil warning, got %d", logs.Len())
	}

	// 2) empty message => no logs
	e.handleFPWarning(&party.Warning{Message: ""})
	if logs.Len() != 0 {
		t.Fatalf("engine expected 0 logs for empty message, got %d", logs.Len())
	}

	// 3) message only => single warn, no structured fields
	msgOnly := &party.Warning{Message: "just a note"}
	e.handleFPWarning(msgOnly)
	if logs.Len() != 1 {
		t.Fatalf("engine expected 1 log after message-only warn, got %d", logs.Len())
	}
	entry := logs.All()[0]
	wantMsg := fmt.Sprintf("tss-lib.FullParty: %s", msgOnly.Message)
	if entry.Message != wantMsg {
		t.Fatalf("engine got log message %q, want %q", entry.Message, wantMsg)
	}
	if len(entry.Context) != 0 {
		t.Fatalf("engine expected no fields for message-only warn, got %v", entry.Context)
	}

	// 4) protocol + round + nil culprit => fields for protocol, round; no possibleCulprit
	core, logs = observer.New(zapcore.WarnLevel)
	e.logger = zap.New(core)

	dgst := sha512.Sum512_256([]byte("123"))
	tid := &common.TrackingID{
		Digest:        dgst[:],
		PartiesState:  nil,
		AuxiliaryData: []byte{dgst[0]},
	}
	w := &party.Warning{
		Message:      "something happened",
		Protocol:     common.ProtocolType("frost"),
		SessionRound: round.Number(7),
		TrackingID:   tid,
		// PossibleCulprit is nil on purpose → fetch should fail/skip, so field omitted
	}
	e.handleFPWarning(w)

	entry = logs.All()[0]
	if entry.Level != zapcore.WarnLevel {
		t.Fatalf("engine expected warn level, got %v", entry.Level)
	}
	got := observerToMap(entry)

	if got["protocol"] != "frost" {
		t.Fatalf("engine expected protocol field mismatch: got %q, want %q", got["protocol"], "frost")
	}
	if got["round"] != "7" {
		t.Fatalf("engine expected round field mismatch: got %q, want %q", got["round"], "7")
	}
	if _, ok := got["possibleCulprit"]; ok {
		t.Fatalf("engine expected possibleCulprit to be absent when lookup fails or culprit is nil")
	}
	if got["trackingId"] != w.TrackingID.ToString() {
		t.Fatalf("engine expected trackingId mismatch: got %q, want %q", got["trackingId"], "trk-123")
	}

	// last but not least, adding a valid culprit:
	core, logs = observer.New(zapcore.WarnLevel)
	e.logger = zap.New(core)
	w.PossibleCulprit = e.Self.Pid
	e.handleFPWarning(w)
	got = observerToMap(logs.All()[0])
	if got["possibleCulprit"] != e.Self.Hostname {
		t.Fatalf("engine expected possibleCulprit field mismatch: got %q, want %q", got["possibleCulprit"], e.Self.Hostname)
	}
}

func TestTranslateEthCommitteeMembers(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	storage := engines[0].GuardianStorage
	storage.Threshold = 3 // Need at least 3 guardians

	// Setup VAAv1 public keys for testing
	for i, id := range storage.Identities {
		addr := ethcommon.Address{}
		binary.BigEndian.PutUint64(addr[:], uint64(i+1)) // Simple unique address
		id.VAAv1PubKey = &addr
	}
	// Re-run SetInnerFields to populate the vaav1PubToIdentity map
	a.NoError(storage.SetInnerFields())

	t.Run("Valid committee", func(t *testing.T) {
		committee := [][]byte{
			storage.Identities[0].VAAv1PubKey.Bytes(),
			storage.Identities[1].VAAv1PubKey.Bytes(),
			storage.Identities[2].VAAv1PubKey.Bytes(),
		}
		members, err := storage.translateEthCommitteeMembers(committee)
		a.NoError(err)
		a.Len(members, 3)
		a.Contains(members, storage.Identities[0].CommunicationIndex)
		a.Contains(members, storage.Identities[1].CommunicationIndex)
		a.Contains(members, storage.Identities[2].CommunicationIndex)
	})

	t.Run("committee larger than threshold", func(t *testing.T) {
		committee := [][]byte{
			storage.Identities[0].VAAv1PubKey.Bytes(),
			storage.Identities[1].VAAv1PubKey.Bytes(),
			storage.Identities[2].VAAv1PubKey.Bytes(),
			storage.Identities[3].VAAv1PubKey.Bytes(),
		}
		members, err := storage.translateEthCommitteeMembers(committee)
		a.NoError(err)
		a.Len(members, 4)
		a.Contains(members, storage.Identities[0].CommunicationIndex)
		a.Contains(members, storage.Identities[1].CommunicationIndex)
		a.Contains(members, storage.Identities[2].CommunicationIndex)
		a.Contains(members, storage.Identities[3].CommunicationIndex)
	})

	t.Run("Committee with invalid member length", func(t *testing.T) {
		committee := [][]byte{
			storage.Identities[0].VAAv1PubKey.Bytes(),
			[]byte{1, 2, 3}, // Invalid length
		}
		_, err := storage.translateEthCommitteeMembers(committee)
		a.Error(err)
		a.ErrorContains(err, "invalid committee member length")
	})

	t.Run("Committee with unknown member", func(t *testing.T) {
		unknownAddr := ethcommon.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
		committee := [][]byte{
			storage.Identities[0].VAAv1PubKey.Bytes(),
			unknownAddr.Bytes(),
		}
		_, err := storage.translateEthCommitteeMembers(committee)
		a.Error(err)
		a.ErrorContains(err, "couldn't map committee member")
	})

	t.Run("Committee with repeating members", func(t *testing.T) {
		committee := [][]byte{
			storage.Identities[0].VAAv1PubKey.Bytes(),
			storage.Identities[0].VAAv1PubKey.Bytes(), // Duplicate
			storage.Identities[1].VAAv1PubKey.Bytes(),
		}
		_, err := storage.translateEthCommitteeMembers(committee)
		a.ErrorIs(err, errRepeatingCommitteeMembers)
	})

	t.Run("Committee too small", func(t *testing.T) {
		committee := [][]byte{
			storage.Identities[0].VAAv1PubKey.Bytes(),
			storage.Identities[1].VAAv1PubKey.Bytes(),
		}
		_, err := storage.translateEthCommitteeMembers(committee)
		a.ErrorIs(err, errCommitteeTooSmall)
	})
}

func TestFindExcludeesFromCommittee(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	engine := engines[0]
	engine.GuardianStorage.Threshold = 3 // Need 4 guardians to sign

	allIdentities := engine.GuardianStorage.Identities

	t.Run("Empty committee", func(t *testing.T) {
		excluded := engine.findExcludeesFromCommittee(map[SenderIndex]*Identity{})
		a.Nil(excluded)
	})

	t.Run("Committee smaller than threshold", func(t *testing.T) {
		members := map[SenderIndex]*Identity{
			allIdentities[0].CommunicationIndex: allIdentities[0],
			allIdentities[1].CommunicationIndex: allIdentities[1],
		}
		excluded := engine.findExcludeesFromCommittee(members)
		a.Nil(excluded)
	})

	t.Run("Committee with more than threshold members", func(t *testing.T) {
		// Committee has 4 members, threshold is 2.
		members := map[SenderIndex]*Identity{
			allIdentities[0].CommunicationIndex: allIdentities[0],
			allIdentities[1].CommunicationIndex: allIdentities[1],
			allIdentities[2].CommunicationIndex: allIdentities[2],
			allIdentities[3].CommunicationIndex: allIdentities[3],
		}
		excluded := engine.findExcludeesFromCommittee(members)
		a.Len(excluded, 1)
		a.True(excluded[0].Equals(allIdentities[4].Pid))
	})

	t.Run("Committee exact sized committee", func(t *testing.T) {
		// Committee has 3 members, threshold is 2.
		members := map[SenderIndex]*Identity{
			allIdentities[0].CommunicationIndex: allIdentities[0],
			allIdentities[1].CommunicationIndex: allIdentities[1],
			allIdentities[2].CommunicationIndex: allIdentities[2],
		}
		excluded := engine.findExcludeesFromCommittee(members)
		a.Len(excluded, 2)
		a.True(excluded[0].Equals(allIdentities[3].Pid))
		a.True(excluded[1].Equals(allIdentities[4].Pid))
	})

	t.Run("Full committee", func(t *testing.T) {
		members := make(map[SenderIndex]*Identity)
		for _, id := range allIdentities {
			members[id.CommunicationIndex] = id
		}
		excluded := engine.findExcludeesFromCommittee(members)
		a.Len(excluded, 0) // nothing to exclude, since the committee contains everyone.
	})
}

func TestNewEngine(t *testing.T) {
	a := assert.New(t)
	storage := loadMockGuardianStorage(0, "tss5")

	t.Run("Nil storage", func(t *testing.T) {
		_, err := newEngine(nil)
		a.Error(err)
		a.ErrorContains(err, "the guardian's tss storage is nil")
	})

	t.Run("Default values", func(t *testing.T) {
		storage.MaxSimultaneousSignatures = 0
		storage.MaxSignerTTL = 0
		engine, err := newEngine(storage)
		a.NoError(err)
		a.Equal(defaultMaxLiveSignatures, engine.GuardianStorage.MaxSimultaneousSignatures)
		a.Equal(defaultMaxSignerTTL, engine.GuardianStorage.MaxSignerTTL)
	})
}

func observerToMap(entry observer.LoggedEntry) map[string]string {
	got := map[string]string{}
	for _, f := range entry.Context {
		switch f.Type {
		case zapcore.StringType:
			got[f.Key] = f.String
		case zapcore.Int64Type: // zap.Int encodes as int64
			got[f.Key] = fmt.Sprintf("%d", f.Integer)
		}
	}
	return got
}

func TestHandleIncomingTssMessage_NilHashEcho(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	e1 := engines[0]
	receiver := engines[4]

	// Start the receiver engine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.NoError(receiver.Start(ctx, logger))

	// Create a valid SignedMessage, but with Content as a HashEcho with nil value
	signedMsg := &tsscommv1.SignedMessage{
		Sender:    uint32(e1.Self.CommunicationIndex),
		Signature: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},            // dummy signature
		Content:   &tsscommv1.SignedMessage_HashEcho{HashEcho: nil}, // <-- nil HashEcho
	}

	// Wrap in Echo and PropagatedMessage
	echo := &tsscommv1.Echo{
		Message: signedMsg,
	}
	incoming := &IncomingMessage{
		Source: e1.Self,
		Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{
				Echo: echo,
			},
		},
	}

	// Results in a panic, because the HashEcho is nil.
	_ = receiver.handleIncomingTssMessage(incoming)
}

func TestEngineErrorAndWarningHandling(t *testing.T) { // Renamed the function
	a := assert.New(t)
	// Create engines & give them their normal logger via your loader.
	engines := load5GuardiansSetupForBroadcastChecks(a)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	e := engines[0]                                          // Use the first engine for testing
	e.signResponseChan = make(chan *signer.SignResponse, 10) // Buffer to avoid blocking

	// Start the engine once. The logger will be swapped for observed ones in sub-tests.
	// Use a nop logger for the initial start to avoid polluting the global observedLogs if any.
	if err := e.Start(ctx, zap.New(zapcore.NewNopCore())); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	t.Run("handleFPWarning", func(t *testing.T) {
		// ensuring we pass through the branches.
		e.handleFPWarning(nil)
		e.handleFPWarning(&party.Warning{Message: ""})
		e.handleFPWarning(&party.Warning{Message: "just a note"})
		dgst := sha512.Sum512_256([]byte("123"))
		tid := &common.TrackingID{
			Digest:        dgst[:],
			PartiesState:  []byte{0xFF}, // Assuming maxParties is 256, this covers all.
			AuxiliaryData: []byte{dgst[0]},
			Protocol:      uint32(common.ProtocolFROSTSign.ToInt()),
		}
		w := &party.Warning{
			Message:      "something happened",
			Protocol:     common.ProtocolFROSTSign,
			SessionRound: round.Number(7),
			TrackingID:   tid,
			// PossibleCulprit is nil on purpose → fetch should fail/skip, so field omitted
		}
		e.handleFPWarning(w)

		// last but not least, adding a valid culprit:
		w.PossibleCulprit = e.Identities[1].Pid // Use an existing identity as culprit
		e.handleFPWarning(w)
	})

	// --- Test handleFpError ---
	t.Run("handleFpError", func(t *testing.T) {
		// Scenario 1: detailedErr is nil
		e.handleFpError(nil)
		select {
		case <-e.signResponseChan:
			a.Fail("unexpected message on signResponseChan for nil detailedErr")
		default:
			// Expected
		}

		// Scenario 2: detailedErr has a nil TrackingID
		errWithNilTID := common.NewError(errors.New("some error"), "task", 1, e.Self.Pid)
		e.handleFpError(errWithNilTID)
		select {
		case <-e.signResponseChan:
			a.Fail("unexpected message on signResponseChan for error with nil TrackingID")
		default:
			// Expected
		}

		// Scenario 3: detailedErr has a valid TrackingID
		initialSigCount := e.sigCounter.digestToGuardiansLen()

		// Add a dummy entry to sigCounter to ensure `remove` has an effect
		dummyDigest := party.Digest{1, 2, 3}
		dummyTID := &common.TrackingID{
			Digest:        dummyDigest[:],
			PartiesState:  []byte{0xFF},
			AuxiliaryData: []byte{},
			Protocol:      uint32(common.ProtocolFROSTSign.ToInt()),
		}
		// Simulate a guardian participating in a signature
		e.sigCounter.add(dummyTID, e.Self.Pid, 10)
		a.Equal(initialSigCount+1, e.sigCounter.digestToGuardiansLen(), "expected sigCounter to increase")

		testErr := errors.New("test error message")
		detailedErr := common.NewTrackableError(
			testErr,
			"testTask",
			2,
			e.Self.Pid,
			dummyTID,
			e.Identities[1].Pid, // Culprit
		)

		e.handleFpError(detailedErr)

		a.Equal(initialSigCount, e.sigCounter.digestToGuardiansLen(), "expected sigCounter to decrease after remove")

		select {
		case resp := <-e.signResponseChan:
			a.NotNil(resp, "expected a response on signResponseChan")
			statusResp := resp.GetStatus()
			a.NotNil(statusResp, "expected a status response")
			a.Equal(int32(codes.Internal), statusResp.Code)
			a.Contains(statusResp.Message, testErr.Error())
			a.Equal(dummyTID.GetDigest(), statusResp.Digest)
			a.Equal(common.ProtocolFROSTSign.ToString(), statusResp.Protocol)
			// Check details
			var details signer.ErrorDetails
			err := statusResp.Details.UnmarshalTo(&details)
			a.NoError(err)
			a.Equal("testTask", details.Task)
			a.Equal(int32(2), details.Round)
			a.Len(details.Culprits, 1)
			a.True(details.Culprits[0].Equals(e.Identities[1].Pid))
		default:
			a.Fail("expected message on signResponseChan for error with valid TrackingID")
		}
	})
}

func TestGetEthAddress(t *testing.T) {
	a := assert.New(t)

	engines := load5GuardiansSetupForBroadcastChecks(a)
	e := engines[0]

	address, err := e.GetEthAddress(common.ProtocolFROSTSign)
	a.NoError(err)
	a.NotEmpty(address)

	_, err = e.GetEthAddress("invalid_protocol")
	a.Error(err)
}

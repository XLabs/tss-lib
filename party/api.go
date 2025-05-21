package party

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/xlabs/tss-lib/v2/common"
	"github.com/xlabs/tss-lib/v2/frost"
	"github.com/xlabs/tss-lib/v2/internal/math/curve"
	"github.com/xlabs/tss-lib/v2/internal/party"
	"github.com/xlabs/tss-lib/v2/tss"
)

type Parameters struct {
	// for simplicity of testing:
	InitConfigs *frost.Config // maybe store this in a file

	PartyIDs []*tss.PartyID // should have the same string IDs as the ones that created the initConfigs.
	Self     *tss.PartyID

	MaxSignerTTL time.Duration

	// LoadDistributionSeed doesn't affect the security of the protocol. Instead, it is used to ensure malicious clients
	// can't target the load-balancing mechanisms of FullParty.
	// The secret can be nil or some random bytes shared across all guardians.
	//
	// NOTE: giving each guardian a different value will affect the protocol and might lead to never-ending
	// signature processes.
	LoadDistributionSeed []byte
}

type Digest [32]byte

type SigningTask struct {
	Digest       Digest
	Faulties     []*tss.PartyID // Can be nil
	AuxilaryData []byte         // can be nil
}

type SigningInfo struct {
	SigningCommittee tss.SortedPartyIDs
	TrackingID       *common.TrackingID
	IsSigner         bool
}

type FullParty interface {
	// Start sets up the FullParty and a few sub-components (including a few
	// goroutines). outChannel: this channel delivers messages that should be broadcast (using Reliable
	// Broadcast protocol) or Uni-cast over the network (messages should be signed and encrypted).
	// signatureOutputChannel: this channel delivers the final output of a signature protocol (a usable signature).
	// errChannel: this channel delivers any error during the protocol.
	Start(outChannel chan tss.ParsedMessage, signatureOutputChannel chan *common.SignatureData, errChannel chan<- *tss.Error) error

	// Stop stops the FullParty, and closes its sub-components.
	Stop()

	// AsyncRequestNewSignature begins the signing protocol over the given digest.
	// The signature protocol will not begin until Start() is called, even if this FullParty received
	// messages over the network.
	AsyncRequestNewSignature(SigningTask) (*SigningInfo, error)

	// Update updates the FullParty with messages from other FullParties.
	Update(tss.ParsedMessage) error

	// GetPublic returns the public key of the FullParty
	GetPublic() curve.Point

	//  GetSigningInfo is used to get the signing info without starting the signing protocol.
	GetSigningInfo(s SigningTask) (*SigningInfo, error)

	// TODO: Once ready, should be able to refresh the DKG config of this party.
	// RefreshDKGConfig() error
}

// NewFullParty returns a new FullParty instance.
func NewFullParty(p *Parameters) (FullParty, error) {
	if p == nil {
		return nil, errors.New("nil parameters")
	}

	if !p.ensurePartiesContainsSelf() {
		return nil, errors.New("self partyID not found in PartyIDs list")
	}

	if p.MaxSignerTTL == 0 {
		p.MaxSignerTTL = signerMaxTTL
	}

	peersMap := make(map[party.ID]*tss.PartyID, len(p.PartyIDs))
	for _, partyID := range p.PartyIDs {
		peersMap[party.ID(partyID.GetId())] = partyID
	}

	if len(peersMap) != len(p.PartyIDs) {
		return nil, errors.New("duplicate partyIDs found")
	}

	if len(p.PartyIDs) < 2 {
		return nil, errors.New("at least 2 partyIDs are required")
	}

	ctx, cancelF := context.WithCancel(context.Background())
	imp := &Impl{
		mtx: sync.Mutex{},

		ctx:        ctx,
		cancelFunc: cancelF,

		self:     p.Self,
		peers:    p.PartyIDs,
		peersmap: peersMap,
		peerIDs:  pids2IDs(p.PartyIDs),

		config: p.InitConfigs,
		signingHandler: &signingHandler{
			trackingIDToSigner: sync.Map{},
			sigPartReadyChan:   nil, // set up during Start()
		},

		incomingMessagesChannel: make(chan tss.ParsedMessage, len(p.PartyIDs)),
		startSignerTaskChan:     make(chan *singleSession),
		// the following fields should be provided in Start()
		errorChannel:           nil,
		outChan:                nil,
		signatureOutputChannel: nil,

		maxTTl:               p.MaxSignerTTL,
		loadDistributionSeed: p.LoadDistributionSeed,
	}

	return imp, nil
}

func (p *Parameters) ensurePartiesContainsSelf() bool {
	for _, party := range p.PartyIDs {
		if party.Id == p.Self.Id {
			return true
		}
	}
	return false
}

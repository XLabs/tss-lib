package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"

	ethcommon "github.com/ethereum/go-ethereum/common"
	common "github.com/xlabs/tss-common"
	engine "github.com/xlabs/tss-lib/v2/tss"
	"github.com/xlabs/tss-lib/v2/tss/internal"
)

type Identifier struct {
	Hostname string
	TlsX509  engine.PEM // PEM Encoded (see certs.go). Note, you must have the private key of this cert later.
	Port     int        // if one needs different ports, tell it here.

	// must be an EVM address hex encoded with 0x prefix
	EthAddress string // optional field. If empty DKG can proceed, but the leader mechanism fields won't be used.
}

type SetupConfigs struct {
	NumParticipants int
	WantedThreshold int // should be non inclusive. That is, if you have n=19,f=6, then threshold=12 (13 guardians needed to sign).

	Self            Identifier
	SelfSecret      engine.PEM // PEM Encoded (see certs.go). Note, you must have the private key of this cert later.
	StorageLocation string     // The folder where secrets.json file will be saved.

	Peers        []Identifier
	Secrets      []engine.PEM
	SaveLocation []string
}

func (cnfg *SetupConfigs) Validate() error {
	if cnfg.NumParticipants < 1 {
		return fmt.Errorf("number of participants should be at least 1")
	}

	if len(cnfg.Peers) != cnfg.NumParticipants {
		return fmt.Errorf("number of guardian identifiers should be equal to number of participants")
	}

	if cnfg.WantedThreshold >= cnfg.NumParticipants-1 {
		return fmt.Errorf("threshold should be less than number of participants")
	}

	return nil
}

func (cnfg *SetupConfigs) IntoMaps() (keyToEngineIdentity map[string]*engine.Identity, keyToID map[string]*Identifier, err error) {
	keyToEngineIdentity = make(map[string]*engine.Identity, cnfg.NumParticipants)

	keyToID = map[string]*Identifier{}
	for i, peer := range cnfg.Peers {
		crt, err := internal.PemToCert(peer.TlsX509)
		if err != nil {
			return nil, nil, err
		}

		if len(crt.DNSNames) == 0 {
			return nil, nil, fmt.Errorf("expected DNS names in the cert")
		}

		pk, ok := crt.PublicKey.(*ecdsa.PublicKey) // TODO
		if !ok {
			return nil, nil, fmt.Errorf("expected ecdsa public key in certs")
		}

		bts, err := internal.PublicKeyToPem(pk)
		if err != nil {
			return nil, nil, err
		}

		pidbytes := sha512.Sum512_256(bts)
		// convert the byte array to a string representation for use as the party ID
		pid := hex.EncodeToString(pidbytes[:])

		var ethAdd *ethcommon.Address
		if peer.EthAddress != "" {
			if !ethcommon.IsHexAddress(peer.EthAddress) {
				return nil, nil, fmt.Errorf("invalid eth address: %s", peer.EthAddress)
			}
			tmp := ethcommon.HexToAddress(peer.EthAddress)
			ethAdd = &tmp
		}

		keyToEngineIdentity[string(bts)] = &engine.Identity{
			Pid: &common.PartyID{
				ID: string(pid),
			},
			KeyPEM:             bts,
			CertPem:            peer.TlsX509,
			Cert:               nil, // not stored, since we have the certPem.
			CommunicationIndex: 0,   // unknown until all identites are sorted according to their Party ids.
			Hostname:           peer.Hostname,
			Port:               peer.Port,
			Key:                nil, // Filled by the guardian storage on boot.
			EthAddress:         ethAdd,
		}

		keyToID[string(bts)] = &cnfg.Peers[i]
	}

	return keyToEngineIdentity, keyToID, nil
}

// sorts the identities based on the partyID key (as tss-lib expects the parties to be sorted).
// then sets the communication index according to the sorted order.
func SortIdentities(unsortedIdentities map[string]*engine.Identity) []*engine.Identity {
	pids := make([]*common.PartyID, 0, len(unsortedIdentities))
	pidsToCertKey := make(map[string]string, len(unsortedIdentities))
	for _, p := range unsortedIdentities {
		pids = append(pids, p.Pid)
		pidsToCertKey[string(p.Pid.GetID())] = string(p.KeyPEM)
	}

	sortedPids := common.SortPartyIDs(pids)

	sortedIDS := make([]*engine.Identity, len(sortedPids))
	for i, pid := range sortedPids {
		key := pidsToCertKey[string(pid.GetID())]
		sortedIDS[i] = unsortedIdentities[key]
		sortedIDS[i].CommunicationIndex = engine.SenderIndex(i)
	}

	return sortedIDS
}

func serializeIdentifier(id *Identifier) []byte {
	// 4 bytes for cert length + cert bytes + 4 bytes for hostname length + hostname bytes + 8 bytes for port.
	buf := make([]byte, 0, 4+len(id.TlsX509)+4+len(id.Hostname)+8)

	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(id.TlsX509)))
	buf = append(buf, id.TlsX509...)

	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(id.Hostname)))
	buf = append(buf, id.Hostname...)

	return binary.LittleEndian.AppendUint64(buf, uint64(id.Port))
}

// PeersFingerprint computes a fingerprint of the peers in the config.
// It does this by serializing each peer's identifier, sorting them, and then hashing the
// concatenated result.
// This can be used to verify that all parties have the same view of the peers configuration.
func PeersFingerprint(cnfgs *SetupConfigs) string {
	peersAsBytes := make([][]byte, len(cnfgs.Peers))
	for i, peer := range cnfgs.Peers {
		peersAsBytes[i] = serializeIdentifier(&peer)
	}

	// Using stable sort to ensure that the order of peers with the same identifier
	// does not affect the fingerprint.
	slices.SortStableFunc(peersAsBytes, func(a, b []byte) int {
		return bytes.Compare(a, b)
	})

	h := sha512.New512_256()
	for _, peerBytes := range peersAsBytes {
		h.Write(peerBytes)
	}

	return hex.EncodeToString(h.Sum(nil))
}

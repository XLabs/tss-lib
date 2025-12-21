package tss

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/fxamacker/cbor/v2"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/protocols/cmp"
	"github.com/xlabs/multi-party-sig/protocols/frost"
	common "github.com/xlabs/tss-common"
	"github.com/xlabs/tss-lib/v2/party"
	"github.com/xlabs/tss-lib/v2/tss/internal"
)

// StorageLoader is a helper struct to load GuardianStorage from file.
// It allows configuring whether missing TSS secrets are allowed.
type StorageLoader struct {
	Path string

	// Used to demand a specific TSS scheme's secrets (or both).
	// Even if no demand exists, if no TSS secrets are found, an error is returned.
	// If both are false, then any existing TSS secrets is sufficient.
	DemandFrost bool
	DemandECDSA bool

	// The GuardianStorage to load into. is set by the loading functions.
	gs *GuardianStorage
}

// Default loader that does not allow missing TSS secrets.
// for a more configurable loader, use LoadGuardianStorage.
func NewGuardianStorageFromFile(storagePath string) (*GuardianStorage, error) {
	loader := StorageLoader{
		Path: storagePath,
		gs:   &GuardianStorage{},

		// not allowing missing TSS secrets by default.
		DemandFrost: true,
		DemandECDSA: true,
	}

	if err := loader.load(); err != nil {
		return nil, err
	}

	return loader.gs, nil
}

// LoadGuardianStorage loads GuardianStorage from file using the provided StorageLoader.
func LoadGuardianStorage(loader StorageLoader) (*GuardianStorage, error) {
	if err := loader.load(); err != nil {
		return nil, err
	}

	return loader.gs, nil
}

func (s *StorageLoader) load() error {
	if s == nil {
		return fmt.Errorf("GuardianStorage is nil")
	}
	if s.gs == nil {
		s.gs = &GuardianStorage{}
	}

	storageData, err := internal.ReadFileWithLimit(s.Path, maxConfigFileSize)
	if err != nil {
		return err
	}

	if err := s.unmarshalFromJSON(storageData); err != nil {
		return err
	}

	if err := s.gs.SetInnerFields(); err != nil {
		return err
	}

	if s.gs.frostconf == nil && s.gs.ecdsaconf == nil {
		return fmt.Errorf("no TSS secrets found in storage")
	}

	return nil
}

func (s *StorageLoader) unmarshalFromJSON(storageData []byte) error {
	if err := json.Unmarshal(storageData, &s.gs); err != nil {
		return err
	}

	if s.gs.PrivateKey == nil {
		return fmt.Errorf("TlsPrivateKey is nil")
	}

	if len(s.gs.IdentitiesKeep.Identities) == 0 {
		return fmt.Errorf("no guardians array given")
	}

	if s.gs.Threshold > len(s.gs.IdentitiesKeep.Identities) {
		return fmt.Errorf("threshold is higher than the number of guardians")
	}

	return s.attemptLoadTssSecrets()
}

func (s *StorageLoader) attemptLoadTssSecrets() error {
	if s.gs.TSSSecrets == nil {
		return fmt.Errorf("missing TSSSecrets")
	}

	cnf, err := UnmarshalTssSecrets(s.gs.TSSSecrets)
	if err != nil {
		return err
	}

	if err := s.storeFrostConf(cnf); err != nil {
		if s.DemandFrost {
			return err
		}

		s.gs.frostconf = nil
	}

	if err := s.storeCmpConf(cnf); err != nil {
		if s.DemandECDSA {
			return err
		}

		s.gs.ecdsaconf = nil
	}

	return nil
}

func (st *StorageLoader) storeCmpConf(cnf *party.TSSSecrets) error {
	if cnf == nil {
		return fmt.Errorf("TSSSecrets is nil")
	}

	// also validates conf != nil.
	if !cnf.EcdsaConfigs.ValidateBasic() {
		return fmt.Errorf("invalid ecdsa configs in stored TSSSecrets")
	}

	st.gs.ecdsaconf = cnf.EcdsaConfigs

	return nil
}

func (s *StorageLoader) storeFrostConf(cnf *party.TSSSecrets) error {
	if cnf == nil {
		return fmt.Errorf("TSSSecrets is nil")
	}

	// also validates conf != nil.
	if !cnf.FrostConfigs.ValidateBasic() {
		return fmt.Errorf("invalid frost configs in stored TSSSecrets")
	}

	if len(cnf.FrostConfigs.VerificationShares.Points) != len(s.gs.IdentitiesKeep.Identities) {
		return fmt.Errorf("number of verification shares does not match number of guardians")
	}

	s.gs.frostconf = cnf.FrostConfigs

	return nil
}

func UnmarshalTssSecrets(TSSsecrets []byte) (*party.TSSSecrets, error) {
	cnf := &party.TSSSecrets{
		FrostConfigs: frost.EmptyConfig(curve.Secp256k1{}),
		EcdsaConfigs: cmp.EmptyConfig(curve.Secp256k1{}),
		TrackingID:   &common.TrackingID{},
	}

	if err := cbor.Unmarshal(TSSsecrets, cnf); err != nil {
		return nil, fmt.Errorf("error unmarshalling TSSSecrets: %v", err)
	}

	return cnf, nil
}

func (s *GuardianStorage) SetInnerFields() error {
	signingKey, err := internal.PemToPrivateKey(s.PrivateKey)
	if err != nil {
		return fmt.Errorf("error parsing tls private key: %v", err)
	}

	s.signingKey = signingKey

	pk, err := internal.PemToPublicKey(s.Self.KeyPEM)
	if err != nil {
		return err
	}

	if !s.signingKey.PublicKey.Equal(pk) {
		return fmt.Errorf("signing key does not match the public key stored in Self.Key")
	}

	if !s.signingKey.Curve.IsOnCurve(pk.X, pk.Y) {
		return fmt.Errorf("invalid public key, it isn't on the curve")
	}

	tlsCert, err := tls.X509KeyPair(s.TlsX509, s.PrivateKey)
	if err != nil {
		return fmt.Errorf("error loading tls cert: %v", err)
	}

	s.tlsCert = &tlsCert

	if err := s.fillAndValidateStoredIdentities(); err != nil {
		return err
	}

	numGuardians := len(s.IdentitiesKeep.Identities)

	s.IdentitiesKeep.peerCerts = make([]*x509.Certificate, numGuardians)
	s.IdentitiesKeep.partyIds = make([]*common.PartyID, numGuardians)
	s.IdentitiesKeep.pemkeyToIndex = make(map[string]int)
	s.IdentitiesKeep.vaav1PubToIdentity = make(map[ethcommon.Address]int)
	s.IdentitiesKeep.partyidToIndex = make(map[string]int)
	// Since the guardians are sorted by key, we can use their position as their index.
	for i := range numGuardians {
		s.IdentitiesKeep.peerCerts[i] = s.IdentitiesKeep.Identities[i].Cert
		s.IdentitiesKeep.partyIds[i] = s.IdentitiesKeep.Identities[i].Pid
		s.IdentitiesKeep.pemkeyToIndex[string(s.IdentitiesKeep.Identities[i].KeyPEM)] = i
		s.IdentitiesKeep.partyidToIndex[string(s.IdentitiesKeep.Identities[i].Pid.GetID())] = i

		if s.IdentitiesKeep.Identities[i].VAAv1PubKey != nil {
			s.IdentitiesKeep.vaav1PubToIdentity[*(s.IdentitiesKeep.Identities[i].VAAv1PubKey)] = i
		}
	}

	if s.LeaderIdentity == nil {
		// since the guardians are expected to be sorted already, the first guardian is the leader.
		s.LeaderIdentity = s.IdentitiesKeep.Identities[0].KeyPEM
	}

	s.isleader = bytes.Equal(s.Self.KeyPEM, s.LeaderIdentity)

	return nil
}

// validates the stored Identity structs. Ensures that the cert and key are valid and match.
// ensures no nil values are stored. Verifies that the tss-lib.PartyIDs are unique.
func (s *GuardianStorage) fillAndValidateStoredIdentities() error {
	uniquePidIDs := make(map[string]struct{})

	for i, id := range s.Identities {
		if id == nil {
			return fmt.Errorf("error guardian %v is nil", i)
		}

		c, key, err := extractCertAndKeyFromPem(id.CertPem)
		if err != nil {
			return fmt.Errorf("error parsing guardian %v: %w", i, err)
		}

		if id.Pid == nil {
			return fmt.Errorf("error guardian %v PartyID is nil", i)
		}

		if len(id.Hostname) == 0 {
			return fmt.Errorf("error guardian %v hostname is empty", i)
		}

		if len(id.Pid.GetID()) == 0 {
			return fmt.Errorf("error guardian %v PartyID.Id is empty", i)
		}

		if _, ok := uniquePidIDs[id.Pid.GetID()]; ok {
			return fmt.Errorf("error guardian %v PartyID.Id is not unique", i)
		}
		uniquePidIDs[id.Pid.GetID()] = struct{}{}

		// storing the cert and key in the identity struct.
		id.Key = key
		id.Cert = c

		keypem, err := internal.PublicKeyToPem(key)
		if err != nil {
			return fmt.Errorf("error converting guardian %v  cert's PK  to pem: %v", i, err)
		}

		id.KeyPEM = keypem

		id.CommunicationIndex = SenderIndex(i)
		id.networkname = id.portAndHostToNetName()

		if bytes.Equal(id.KeyPEM, s.Self.KeyPEM) {
			s.Self = id.Copy() // ensuring Self is set up correctly.
		}
	}

	return nil
}

func extractCertAndKeyFromPem(pem PEM) (*x509.Certificate, *ecdsa.PublicKey, error) {
	c, err := internal.PemToCert(pem)
	if err != nil {
		return nil, nil, err
	}

	key, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("cert stored with non-ecdsa publickey")
	}

	return c, key, nil
}

func (s *GuardianStorage) NumGuardians() int {
	if s == nil {
		return 0
	}

	return len(s.Identities)
}

func (s *GuardianStorage) ExistingSecretsTypes() []common.ProtocolType {
	types := []common.ProtocolType{}

	if s.frostconf != nil {
		types = append(types, common.ProtocolFROSTDKG)
	}

	if s.ecdsaconf != nil {
		types = append(types, common.ProtocolECDSADKG)
	}

	return types
}

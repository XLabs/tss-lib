package tss

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/fxamacker/cbor/v2"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/protocols/cmp"
	"github.com/xlabs/multi-party-sig/protocols/frost"
	common "github.com/xlabs/tss-common"
	"github.com/xlabs/tss-common/service/signer"
	"github.com/xlabs/tss-lib/v2/party"
	"github.com/xlabs/tss-lib/v2/tss/internal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	storageData, err := internal.ReadFileWithLimit(s.Path, maxConfigFileSize)
	if err != nil {
		return err
	}

	return s.loadFromJSON(storageData)
}

func (s *StorageLoader) loadFromJSON(storageData []byte) error {
	if s.gs == nil {
		s.gs = &GuardianStorage{}
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

	if err := s.processIdentities(); err != nil {
		return err
	}

	numPeers := len(s.IdentitiesKeep.Identities)

	s.IdentitiesKeep.peerCerts = make([]*x509.Certificate, numPeers)
	s.IdentitiesKeep.partyIds = make([]*common.PartyID, numPeers)
	s.IdentitiesKeep.pemkeyToIndex = make(map[string]int)
	s.IdentitiesKeep.ethAddToIndex = make(map[ethcommon.Address]int)
	s.IdentitiesKeep.partyidToIndex = make(map[string]int)
	s.IdentitiesKeep.hasFullEthMappings = true

	// Since the guardians are sorted by key, we can use their position as their index.
	for i := range numPeers {
		s.IdentitiesKeep.peerCerts[i] = s.IdentitiesKeep.Identities[i].Cert
		s.IdentitiesKeep.partyIds[i] = s.IdentitiesKeep.Identities[i].Pid
		s.IdentitiesKeep.pemkeyToIndex[string(s.IdentitiesKeep.Identities[i].KeyPEM)] = i
		s.IdentitiesKeep.partyidToIndex[string(s.IdentitiesKeep.Identities[i].Pid.GetID())] = i

		if s.IdentitiesKeep.Identities[i].EthAddress != nil {
			s.IdentitiesKeep.ethAddToIndex[*(s.IdentitiesKeep.Identities[i].EthAddress)] = i
		} else {
			s.IdentitiesKeep.hasFullEthMappings = false
		}

		s.IdentitiesKeep.Identities[i].pos = i
	}

	return nil
}

// validates the stored Identity structs. Ensures that the cert and key are valid and match.
// ensures no nil values are stored. Verifies that the tss-lib.PartyIDs are unique and sets
// the communication indexes based on the sorted order of PartyIDs.
func (s *GuardianStorage) processIdentities() error {
	uniquePIDs := make(map[string]*Identity)
	pids := make([]*common.PartyID, len(s.Identities))

	for i, id := range s.Identities {
		if err := s.setupIdentity(id); err != nil {
			return fmt.Errorf("error processing guardian %d: %w", i, err)
		}

		if _, ok := uniquePIDs[id.Pid.GetID()]; ok {
			return fmt.Errorf("error guardian %v PartyID.Id is not unique", i)
		}
		uniquePIDs[id.Pid.GetID()] = id
		pids[i] = id.Pid
	}

	// sorting the PartyIDs to ensure a deterministic order for tss-lib,
	// since each is unique it's safe to use the sorted order to assign communication indexes.
	sortedPids := common.SortPartyIDs(pids)

	sortedIdentities := make([]*Identity, len(s.Identities))
	for i, pid := range sortedPids {
		sortedIdentities[i] = uniquePIDs[pid.GetID()]
		sortedIdentities[i].CommunicationIndex = SenderIndex(i)

		if bytes.Equal(sortedIdentities[i].KeyPEM, s.Self.KeyPEM) {
			s.Self = sortedIdentities[i].Copy() // ensuring Self is set up correctly.
		}
	}

	// re-assigning the sorted identities back to the storage.
	s.IdentitiesKeep.Identities = sortedIdentities

	return nil
}

func (s *GuardianStorage) setupIdentity(id *Identity) error {
	if id == nil {
		return fmt.Errorf("guardian is nil")
	}

	c, key, err := extractCertAndKeyFromPem(id.CertPem)
	if err != nil {
		return fmt.Errorf("error parsing guardian: %w", err)
	}

	if id.Pid == nil {
		return fmt.Errorf("guardian PartyID is nil")
	}

	if len(id.Hostname) == 0 {
		return fmt.Errorf("guardian hostname is empty")
	}

	if len(id.Pid.GetID()) == 0 {
		return fmt.Errorf("guardian PartyID.Id is empty")
	}

	// storing the cert and key in the identity struct.
	id.Key = key
	id.Cert = c

	keypem, err := internal.PublicKeyToPem(key)
	if err != nil {
		return fmt.Errorf("error converting guardian cert's PK to pem: %v", err)
	}

	// ensuring the stored KeyPEM matches the cert's public key.
	if !bytes.Equal(keypem, id.KeyPEM) {
		return fmt.Errorf("guardian stored KeyPEM does not match cert's public key")
	}

	id.networkname = id.portAndHostToNetName()

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

// ExistingSecretsForSigning returns the list of ProtocolTypes for which this GuardianStorage has a secret.
func (s *GuardianStorage) ExistingSecretsForSigning() []common.ProtocolType {
	types := []common.ProtocolType{}

	if s.frostconf != nil {
		types = append(types, common.ProtocolFROSTSign)
	}

	if s.ecdsaconf != nil {
		types = append(types, common.ProtocolECDSASign)
	}

	return types
}

// Copy performs a deep copy of the GuardianStorage by marshalling and unmarshalling it.
func (s *GuardianStorage) Copy() (*GuardianStorage, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("error marshalling guardian storage for copy: %v", err)
	}

	ldr := StorageLoader{
		// we don't need to demand any secrets for a copy: if they exist, they will be copied.
		DemandFrost: false,
		DemandECDSA: false,
	}

	if err := ldr.loadFromJSON(data); err != nil {
		return nil, fmt.Errorf("error unmarshalling guardian storage for copy: %v", err)
	}

	return ldr.gs, nil
}

func typedKeyAsString(typedKey *signer.TypedKey) string {
	return typedKey.Type.String() + "-" + string(typedKey.Key)
}

func checkDuplicated(rq *signer.UpdateKeysRequest) error {
	seen := make(map[string]struct{})

	for _, pair := range rq.GetPairs() {
		strRep := typedKeyAsString(pair.KnownKey) + typedKeyAsString(pair.UpdateKey)

		if _, exists := seen[strRep]; exists {
			return status.Error(codes.InvalidArgument, "duplicate key pairs in update request")
		}

		seen[strRep] = struct{}{}
	}

	return nil
}

type idExtractor interface {
	// finds the Identity's position in the IdentitiesKeep slice based on this key type and value.
	findIdPos(*IdentitiesKeep) (int, error)
}
type updaterKey interface {
	// sets this key's value into the provided Identity in the appropriate field.
	updateIdentity(*Identity) error
}

type peerUpdate interface {
	idExtractor
	updaterKey
}

// wrappers that implement the peerUpdate interface.
type ethKey struct{ *signer.TypedKey }
type certKey struct{ *signer.TypedKey }

func (k ethKey) findIdPos(ids *IdentitiesKeep) (int, error) {
	id, err := ids.fetchIdentityFromEthAddress(ethcommon.BytesToAddress(k.Key))
	if err != nil {
		return 0, status.Error(codes.NotFound, "couldn't find eth address, an error occurred: "+err.Error())
	}

	return id.pos, nil
}

func (k ethKey) updateIdentity(id *Identity) error {
	if len(k.Key) != ethcommon.AddressLength {
		return status.Errorf(codes.InvalidArgument, "invalid eth address length: %d", len(k.Key))
	}

	tmp := ethcommon.BytesToAddress(k.Key)
	id.EthAddress = &tmp

	return nil
}

func (k certKey) findIdPos(ids *IdentitiesKeep) (int, error) {
	cert, err := internal.PemToCert(k.Key)
	if err != nil {
		return 0, status.Error(codes.InvalidArgument, "invalid cert key: "+err.Error())
	}

	id, err := ids.FetchIdentity(cert)
	if err != nil {
		return 0, status.Error(codes.NotFound, "couldn't find cert key, an error occurred: "+err.Error())
	}

	return id.pos, nil
}

func (k certKey) updateIdentity(id *Identity) error {
	cert, key, err := extractCertAndKeyFromPem(k.Key)
	if err != nil {
		return status.Error(codes.InvalidArgument, "malformed update CertKey: "+err.Error())
	}
	keyPEM, err := internal.PublicKeyToPem(key)
	if err != nil {
		return status.Errorf(codes.Internal, "error converting update CertKey's public key to pem: %v", err)
	}

	id.CertPem = k.Key
	id.Cert = cert
	id.Key = key
	id.KeyPEM = keyPEM

	return nil
}

func typedKeyToPeerUpdater(typedKey *signer.TypedKey) (peerUpdate, error) {
	switch typedKey.Type {
	case signer.TypedKey_EthKey:
		return ethKey{typedKey}, nil
	case signer.TypedKey_CertKey:
		return certKey{typedKey}, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown key type %s", typedKey.Type.Descriptor().Name())
	}
}

func typedKeyToPeerExtractor(typedKey *signer.TypedKey) (idExtractor, error) {
	return typedKeyToPeerUpdater(typedKey)
}
func typedKeyToUpdaterKey(typedKey *signer.TypedKey) (updaterKey, error) {
	return typedKeyToPeerUpdater(typedKey)
}

func (s *GuardianStorage) UpdatePeerKeys(rq *signer.UpdateKeysRequest) (*GuardianStorage, error) {
	if err := checkDuplicated(rq); err != nil {
		return nil, err
	}

	gs, err := s.Copy()
	if err != nil {
		return nil, err
	}

	// apply update to the copy
	for _, pair := range rq.GetPairs() {
		knownkey, err := typedKeyToPeerExtractor(pair.GetKnownKey())
		if err != nil {
			return nil, err
		}

		idIndex, err := knownkey.findIdPos(&gs.IdentitiesKeep)
		if err != nil {
			return nil, err
		}

		idToUpdate := gs.Identities[idIndex]
		updater, err := typedKeyToUpdaterKey(pair.GetUpdateKey())
		if err != nil {
			return nil, err
		}

		if err := updater.updateIdentity(idToUpdate); err != nil {
			return nil, err
		}
	}

	return gs, gs.SetInnerFields()
}

// Save saves the GuardianStorage to the specified path.
// Will overwrite any existing file at that path.
func (s *GuardianStorage) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal guardian storage: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

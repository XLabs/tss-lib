package tss

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	common "github.com/xlabs/tss-common"
	"github.com/xlabs/tss-common/service/signer"
	"github.com/xlabs/tss-lib/v2/tss/internal"
)

func generateTestKeys(t *testing.T) ([]byte, []byte, []byte) {
	a := require.New(t)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a.NoError(err)

	privPem := internal.PrivateKeyToPem(priv)

	pubPem, err := internal.PublicKeyToPem(&priv.PublicKey)
	a.NoError(err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	_, certPem, err := internal.CreateCert(template, template, &priv.PublicKey, priv)
	a.NoError(err)

	return privPem, pubPem, certPem
}

func TestLoadGuardianStorage(t *testing.T) {
	privPem, pubPem, certPem := generateTestKeys(t)

	pid := &common.PartyID{ID: "party1"}

	id := &Identity{
		KeyPEM:   pubPem,
		CertPem:  certPem,
		Pid:      pid,
		Hostname: "localhost:8080",
	}

	// Construct a valid GuardianStorage
	// We populate both Identities and IdentitiesKeep to ensure compatibility with the loading logic
	gs := &GuardianStorage{
		PrivateKey: privPem,
		Self:       id,
		IdentitiesKeep: IdentitiesKeep{
			Identities: []*Identity{id},
		},
		Threshold: 1,
		TlsX509:   certPem,
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "storage.json")

	writeMockGuardianStorage(t, gs, path)

	t.Run("Fail missing secrets", func(t *testing.T) {
		loader := StorageLoader{
			Path: path,
		}
		_, err := LoadGuardianStorage(loader)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing TSSSecrets") {
			t.Errorf("expected error to contain 'missing TSSSecrets', got %v", err)
		}
	})

	t.Run("Fail invalid JSON", func(t *testing.T) {
		badPath := filepath.Join(tmpDir, "bad.json")
		os.WriteFile(badPath, []byte("{invalid"), 0600)
		loader := StorageLoader{Path: badPath}
		_, err := LoadGuardianStorage(loader)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("Fail file not found", func(t *testing.T) {
		loader := StorageLoader{Path: filepath.Join(tmpDir, "missing.json")}
		_, err := LoadGuardianStorage(loader)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestNewGuardianStorageFromFile(t *testing.T) {
	// This function enforces DemandFrost=true and DemandECDSA=true
	// Since we don't have valid secrets in the file, we expect it to fail.

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "storage.json")

	// Create a dummy file (valid JSON structure but missing secrets)
	privPem, pubPem, certPem := generateTestKeys(t)
	id := &Identity{
		KeyPEM:   pubPem,
		CertPem:  certPem,
		Pid:      &common.PartyID{ID: "p1"},
		Hostname: "h",
	}
	gs := &GuardianStorage{
		PrivateKey:     privPem,
		Self:           id,
		IdentitiesKeep: IdentitiesKeep{Identities: []*Identity{id}},
		Threshold:      1,
		TlsX509:        certPem,
	}

	writeMockGuardianStorage(t, gs, path)

	_, err := LoadGuardianStorage(StorageLoader{Path: path, DemandECDSA: true, DemandFrost: true})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing TSSSecrets") {
		t.Errorf("expected error to contain 'missing TSSSecrets', got %v", err)
	}
}

func TestUnmarshalTssSecrets(t *testing.T) {
	_, err := UnmarshalTssSecrets([]byte("invalid cbor"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestLoadGuardianStorage_WithSecrets(t *testing.T) {
	gs := loadMockGuardianStorage(0, "tss5")

	// corrupt frost secrets to simulate missing frost configs

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "storage_secrets.json")

	t.Run("missing frost secrets allowed", func(t *testing.T) {
		secretsAsString := string(gs.TSSSecrets)
		// corrupt frost configs so CBOR unmarshal fails
		gs.TSSSecrets = []byte(strings.Replace(secretsAsString, "FrostConfigs", "fr0stc0nf!gs", 1))
		defer func() { gs.TSSSecrets = []byte(secretsAsString) }() // restore

		writeMockGuardianStorage(t, gs, path)

		_, err := LoadGuardianStorage(StorageLoader{
			Path:        path,
			DemandECDSA: true,
			DemandFrost: false,
		})
		if err != nil {
			t.Fatal("expected no error, got:", err)
		}
	})

	t.Run("missing ecdsa secrets allowed", func(t *testing.T) {
		secretsAsString := string(gs.TSSSecrets)
		// corrupt ecdsa configs so CBOR unmarshal fails
		gs.TSSSecrets = []byte(strings.Replace(secretsAsString, "EcdsaConfigs", "3cds4c0nf!gs", 1))
		defer func() { gs.TSSSecrets = []byte(secretsAsString) }() // restore

		writeMockGuardianStorage(t, gs, path)

		if _, err := LoadGuardianStorage(StorageLoader{
			Path:        path,
			DemandECDSA: false,
			DemandFrost: true,
		}); err != nil {
			t.Fatal("expected no error, got:", err)
		}

		if _, err := LoadGuardianStorage(StorageLoader{
			Path:        path,
			DemandECDSA: true,
			DemandFrost: false,
		}); err == nil {
			t.Fatal("expected error")
		}

		if _, err := LoadGuardianStorage(StorageLoader{
			Path:        path,
			DemandECDSA: false,
			DemandFrost: false,
		}); err != nil {
			t.Fatal("no error should've occurred, got:", err)
		}
	})

	t.Run("missing secrets not allowed", func(t *testing.T) {
		secretsAsString := string(gs.TSSSecrets)
		// corrupt both configs so CBOR unmarshal fails
		gs.TSSSecrets = []byte(strings.Replace(strings.Replace(secretsAsString, "FrostConfigs", "fr0stc0nf!gs", 1), "EcdsaConfigs", "3cds4c0nf!gs", 1))
		defer func() { gs.TSSSecrets = []byte(secretsAsString) }() // restore

		writeMockGuardianStorage(t, gs, path)
		_, err := LoadGuardianStorage(StorageLoader{
			Path:        path,
			DemandECDSA: false,
			DemandFrost: false,
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func writeMockGuardianStorage(t *testing.T, gs *GuardianStorage, path string) {
	data, err := json.Marshal(gs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestUpdatePeerKeys(t *testing.T) {
	a := require.New(t)
	gs := loadMockGuardianStorage(0, "tss5")

	id1 := gs.Identities[0]
	id1.EthAddress = &ethcommon.Address{1, 2, 3, 4}
	id2 := gs.Identities[1]
	id2.EthAddress = &ethcommon.Address{4, 3, 2, 1}

	require.NoError(t, gs.SetInnerFields())

	t.Run("Duplicate keys", func(t *testing.T) {
		req := &signer.UpdateKeysRequest{
			Pairs: []*signer.UpdateKeyPair{
				{
					KnownKey:  &signer.TypedKey{Type: signer.TypedKey_EthKey, Key: id1.EthAddress.Bytes()},
					UpdateKey: &signer.TypedKey{Type: signer.TypedKey_EthKey, Key: id2.EthAddress.Bytes()},
				},
				{
					KnownKey:  &signer.TypedKey{Type: signer.TypedKey_EthKey, Key: id1.EthAddress.Bytes()},
					UpdateKey: &signer.TypedKey{Type: signer.TypedKey_EthKey, Key: id2.EthAddress.Bytes()},
				},
			},
		}
		_, err := gs.UpdatePeerKeys(req)
		a.ErrorContains(err, "duplicate key pairs")
	})

	t.Run("Unknown Key Type", func(t *testing.T) {
		req := &signer.UpdateKeysRequest{
			Pairs: []*signer.UpdateKeyPair{
				{
					KnownKey:  &signer.TypedKey{Type: signer.TypedKey_Unspecified, Key: []byte("foo")},
					UpdateKey: &signer.TypedKey{Type: signer.TypedKey_EthKey, Key: id2.EthAddress.Bytes()},
				},
			},
		}
		_, err := gs.UpdatePeerKeys(req)
		a.ErrorContains(err, "unknown key type")
	})

	t.Run("Identity Not Found", func(t *testing.T) {
		req := &signer.UpdateKeysRequest{
			Pairs: []*signer.UpdateKeyPair{
				{
					KnownKey:  &signer.TypedKey{Type: signer.TypedKey_EthKey, Key: []byte("random")},
					UpdateKey: &signer.TypedKey{Type: signer.TypedKey_EthKey, Key: id2.EthAddress.Bytes()},
				},
			},
		}
		_, err := gs.UpdatePeerKeys(req)
		a.ErrorContains(err, "unknown eth address")
	})

	t.Run("Update Eth Key", func(t *testing.T) {
		req := &signer.UpdateKeysRequest{
			Pairs: []*signer.UpdateKeyPair{
				{
					KnownKey:  &signer.TypedKey{Type: signer.TypedKey_EthKey, Key: id1.EthAddress.Bytes()},
					UpdateKey: &signer.TypedKey{Type: signer.TypedKey_EthKey, Key: id2.EthAddress.Bytes()},
				},
			},
		}
		newGs, err := gs.UpdatePeerKeys(req)
		require.NoError(t, err)
		a.Equal(*id2.EthAddress, *newGs.Identities[0].EthAddress)
		// Ensure original is untouched
		a.Equal(*id1.EthAddress, *gs.Identities[0].EthAddress)
	})

	t.Run("Update P256CertKey", func(t *testing.T) {
		req := &signer.UpdateKeysRequest{
			Pairs: []*signer.UpdateKeyPair{
				{
					KnownKey:  &signer.TypedKey{Type: signer.TypedKey_CertKey, Key: id1.CertPem},
					UpdateKey: &signer.TypedKey{Type: signer.TypedKey_CertKey, Key: id2.CertPem},
				},
			},
		}
		newGs, err := gs.UpdatePeerKeys(req)
		a.NoError(err)
		a.Equal(id2.CertPem, newGs.Identities[0].CertPem)
		a.NotEqual(gs.Identities[0].CertPem, newGs.Identities[0].CertPem)
	})

	t.Run("Invalid Update Key", func(t *testing.T) {
		req := &signer.UpdateKeysRequest{
			Pairs: []*signer.UpdateKeyPair{
				{
					KnownKey:  &signer.TypedKey{Type: signer.TypedKey_CertKey, Key: id1.CertPem},
					UpdateKey: &signer.TypedKey{Type: signer.TypedKey_CertKey, Key: []byte("invalid")},
				},
			},
		}
		_, err := gs.UpdatePeerKeys(req)
		assert.ErrorContains(t, err, "malformed update CertKey")
	})
}

func TestEthKey(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	storage := engines[0].GuardianStorage

	// Setup identities with eth addresses
	for i, id := range storage.Identities {
		addr := ethcommon.Address{}
		binary.BigEndian.PutUint64(addr[:], uint64(i+1))
		id.EthAddress = &addr
	}
	a.NoError(storage.SetInnerFields())

	t.Run("findIdPos", func(t *testing.T) {
		targetId := storage.Identities[1]
		k := ethKey{&signer.TypedKey{
			Type: signer.TypedKey_EthKey,
			Key:  targetId.EthAddress.Bytes(),
		}}

		pos, err := k.findIdPos(&storage.IdentitiesKeep)
		a.NoError(err)
		a.Equal(targetId.pos, pos)

		// Unknown address
		unknownAddr := ethcommon.Address{1}
		kUnknown := ethKey{&signer.TypedKey{
			Type: signer.TypedKey_EthKey,
			Key:  unknownAddr.Bytes(),
		}}
		_, err = kUnknown.findIdPos(&storage.IdentitiesKeep)
		a.Error(err)
	})

	t.Run("updateIdentity", func(t *testing.T) {
		id := storage.Identities[0]
		newAddr := ethcommon.Address{0xAA}
		k := ethKey{&signer.TypedKey{
			Type: signer.TypedKey_EthKey,
			Key:  newAddr.Bytes(),
		}}

		err := k.updateIdentity(id)
		a.NoError(err)
		a.Equal(newAddr, *id.EthAddress)

		// Invalid length
		kInvalid := ethKey{&signer.TypedKey{
			Type: signer.TypedKey_EthKey,
			Key:  []byte{1, 2},
		}}
		err = kInvalid.updateIdentity(id)
		a.Error(err)
	})
}

func TestCertKey(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	storage := engines[0].GuardianStorage

	t.Run("findIdPos", func(t *testing.T) {
		targetId := storage.Identities[1]
		k := certKey{&signer.TypedKey{
			Type: signer.TypedKey_CertKey,
			Key:  targetId.CertPem,
		}}

		pos, err := k.findIdPos(&storage.IdentitiesKeep)
		a.NoError(err)
		a.Equal(targetId.pos, pos)

		// Invalid cert pem
		kInvalid := certKey{&signer.TypedKey{
			Type: signer.TypedKey_CertKey,
			Key:  []byte("invalid"),
		}}
		_, err = kInvalid.findIdPos(&storage.IdentitiesKeep)
		a.Error(err)
	})

	t.Run("updateIdentity", func(t *testing.T) {
		id := storage.Identities[0]

		// Generate new cert
		_, _, certPem := generateTestKeys(t)

		k := certKey{&signer.TypedKey{
			Type: signer.TypedKey_CertKey,
			Key:  certPem,
		}}

		err := k.updateIdentity(id)
		a.NoError(err)
		a.Equal(PEM(certPem), id.CertPem)
		a.NotNil(id.Cert)
		a.NotNil(id.Key)

		// Invalid cert
		kInvalid := certKey{&signer.TypedKey{
			Type: signer.TypedKey_CertKey,
			Key:  []byte("invalid"),
		}}
		err = kInvalid.updateIdentity(id)
		a.Error(err)
	})
}

func TestSelfUpdatedAfterProcessIdentities(t *testing.T) {
	a := require.New(t)

	engines, err := loadGuardians(5, "tss5")
	a.NoError(err)

	// Use the last engine to ensure the index is not 0
	gs := &engines[4].GuardianStorage

	// Shuffle identities to ensure sorting is actually happening
	mathrand.Shuffle(
		len(gs.Identities),
		func(i, j int) { gs.Identities[i], gs.Identities[j] = gs.Identities[j], gs.Identities[i] },
	)
	fmt.Println("Shuffled Identities:", gs.Identities)

	incorrectIndex := SenderIndex(len(gs.Identities) + 10)
	gs.Self.CommunicationIndex = incorrectIndex

	// Call SetInnerFields which triggers processIdentities
	a.NoError(gs.SetInnerFields())

	// Verify incorrectIndex!=Self.CommunicationIndex <len(identities) updated correctly
	a.NotEqual(incorrectIndex, gs.Self.CommunicationIndex)
	a.Less(int(gs.Self.CommunicationIndex), len(gs.IdentitiesKeep.Identities))

	// verify self identity is in its stated position in identitiesKeep
	a.Equal(gs.IdentitiesKeep.Identities[gs.Self.CommunicationIndex].Pid, gs.Self.Pid)

	// Verify identities are sorted
	for i := 0; i < len(gs.Identities)-1; i++ {
		id1 := gs.Identities[i].Pid.GetID()
		id2 := gs.Identities[i+1].Pid.GetID()
		a.Less(id1, id2, "Identities should be sorted by PartyID")
	}
}

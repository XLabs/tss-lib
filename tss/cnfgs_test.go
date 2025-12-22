package tss

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	common "github.com/xlabs/tss-common"
)

func generateTestKeys(t *testing.T) ([]byte, []byte, []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

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

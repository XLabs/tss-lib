package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path"
	"path/filepath"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xlabs/multi-party-sig/pkg/ecdsa"
	"github.com/xlabs/multi-party-sig/pkg/eth"
	"github.com/xlabs/multi-party-sig/pkg/math/curve"
	"github.com/xlabs/multi-party-sig/pkg/math/sample"
	"github.com/xlabs/multi-party-sig/protocols/frost/sign"
	common "github.com/xlabs/tss-common"
	"github.com/xlabs/tss-common/service/signer"
	"github.com/xlabs/tss-lib/v2/party"
	"github.com/xlabs/tss-lib/v2/tss"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestGetPublicData(t *testing.T) {
	a := require.New(t)
	s := &server{
		logger: zap.NewNop(),
	}
	ctx := context.Background()

	t.Run("PublicDataNotInitialized", func(t *testing.T) {
		resp, err := s.GetPublicData(ctx, &signer.PublicDataRequest{})
		a.Error(err)
		a.Nil(resp)
		st, _ := status.FromError(err)
		a.Equal(codes.Internal, st.Code())
		a.Contains(err.Error(), "public data not initialized")
	})

	t.Run("Success", func(t *testing.T) {
		expectedPubData := &signer.PublicData{
			FrostPublicData: []byte("frost-key"),
			EcdsaPublicData: []byte("ecdsa-key"),
		}
		s.pubData = expectedPubData

		resp, err := s.GetPublicData(ctx, &signer.PublicDataRequest{})
		a.NoError(err)
		assert.Equal(t, expectedPubData, resp)
	})
}

func TestVerifySignature(t *testing.T) {
	s := &server{
		logger: zap.NewNop(),
	}
	ctx := context.Background()

	t.Run("InvalidRequest", func(t *testing.T) {
		_, err := s.VerifySignature(ctx, nil)
		assert.Error(t, err)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.InvalidArgument, st.Code())

		// Missing signature
		_, err = s.VerifySignature(ctx, &signer.VerifySignatureRequest{
			PublicData: &signer.PublicData{},
		})
		assert.Error(t, err)

		// Missing public data
		_, err = s.VerifySignature(ctx, &signer.VerifySignatureRequest{
			Signature: &common.SignatureData{
				TrackingId: &common.TrackingID{},
			},
		})
		assert.Error(t, err)
	})

	t.Run("InvalidProtocol", func(t *testing.T) {
		req := &signer.VerifySignatureRequest{
			Signature: &common.SignatureData{
				TrackingId: &common.TrackingID{
					Protocol: 999, // Invalid
				},
			},
			PublicData: &signer.PublicData{},
		}
		_, err := s.VerifySignature(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid protocol type")
	})

	t.Run("UnsupportedProtocol", func(t *testing.T) {
		req := &signer.VerifySignatureRequest{
			Signature: &common.SignatureData{
				TrackingId: &common.TrackingID{
					Protocol: uint32(common.ProtocolFROSTDKG.ToInt()),
				},
			},
			PublicData: &signer.PublicData{},
		}
		_, err := s.VerifySignature(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported protocol type")
	})

	t.Run("InvalidPublicKey", func(t *testing.T) {
		req := &signer.VerifySignatureRequest{
			Signature: &common.SignatureData{
				TrackingId: &common.TrackingID{
					Protocol: uint32(common.ProtocolFROSTSign.ToInt()),
				},
			},
			PublicData: &signer.PublicData{
				FrostPublicData: []byte("invalid-key"),
			},
		}
		_, err := s.VerifySignature(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid public key")
	})

	grp := curve.Secp256k1{}

	t.Run("ECDSA signature", func(t *testing.T) {
		secret := sample.Scalar(rand.Reader, grp)
		public := secret.ActOnBase()
		pkbytes, err := grp.MarshalPoint(public)
		require.NoError(t, err)

		msg := []byte("hello")
		msgDigest := crypto.Keccak256(msg)
		tid := &common.TrackingID{
			Digest:   msgDigest[:],
			Protocol: 0,
		}
		// Setting the server with our public key
		s.pubData = &signer.PublicData{
			FrostPublicData: pkbytes,
			EcdsaPublicData: pkbytes,
		}
		trackid := proto.CloneOf(tid)
		trackid.Protocol = uint32(common.ProtocolECDSASign.ToInt())

		ecdsaSig := NewEcdsaSignature(secret, msgDigest)
		ecdsaCommonSig, commonerr := party.EcdsaSigToCommonSig(ecdsaSig, nil, trackid)
		require.Nil(t, commonerr)

		req := &signer.VerifySignatureRequest{
			Signature:  ecdsaCommonSig,
			PublicData: &signer.PublicData{EcdsaPublicData: pkbytes},
		}

		resp, err := s.VerifySignature(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.IsValid)

		req.Signature.S[0] += 1
		resp, err = s.VerifySignature(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.False(t, resp.IsValid)
	})

	// TODO: a way to generate frost signatures, instead of hardcoded values.
	// Perhaps by exposing a method in multi-party-sig/protocol/frost package
	// consider exposing ecdsa basic signature generation as well while at it (and remove NewEcdsaSignature here).
	t.Run("FROST signature", func(t *testing.T) {
		secret := contractValidSecretKey(t)

		msgDigest := mustHexDecode("deadbeef00000000000000000000000000000000000000000000000000000000")
		sig, err := sign.SignEcSchnorr(secret, msgDigest)
		require.NoError(t, err)
		require.NotNil(t, sig)

		commonsig, commonerr := party.FrostSigToCommonSig(&sig, nil, &common.TrackingID{
			Protocol: uint32(common.ProtocolFROSTSign.ToInt()),
			Digest:   msgDigest,
		})
		require.Nil(t, commonerr)

		pk := secret.ActOnBase()
		pkbytes, err := grp.MarshalPoint(pk)
		require.NoError(t, err)

		req := &signer.VerifySignatureRequest{
			Signature: commonsig,
			PublicData: &signer.PublicData{
				FrostPublicData: pkbytes,
			},
		}

		resp, err := s.VerifySignature(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.IsValid)

		req.Signature.S[0] += 1 // invalidate signature
		resp, err = s.VerifySignature(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.False(t, resp.IsValid)
	})
}

func contractValidSecretKey(t *testing.T) curve.Scalar {
	var secret curve.Scalar
	for range 100 { // try up to 100 times to get a valid secret
		secret = sample.Scalar(rand.Reader, curve.Secp256k1{})
		if sign.PublicKeyValidForContract(secret.ActOnBase()) {
			return secret
		}
	}

	t.Fatal("failed to generate contract valid secret key")

	return nil
}

// Ensures that signatures created using NewSignature are valid for ECDSA verification according to multi-party-sig's ECDSA implementation.
func TestNewSignatureForECDSAValidity(t *testing.T) {
	// Generate standard ECDSA key using go-ethereum crypto (secp256k1)
	grp := curve.Secp256k1{}
	msg := []byte("hello")

	secret := sample.Scalar(rand.Reader, grp)
	public := secret.ActOnBase()

	sig := NewEcdsaSignature(secret, msg)

	valid := sig.Verify(public, msg)
	assert.True(t, valid, "signature should be valid")
}

// Ensure we can translate a multi-party-sig ECDSA signature to Ethereum format and recover the public key using Ecrecover.
func TestSigTranslateValidWithEcrecover(t *testing.T) {
	// Generate standard ECDSA key using go-ethereum crypto (secp256k1)
	grp := curve.Secp256k1{}
	msg := []byte("hello")

	secret := sample.Scalar(rand.Reader, grp)
	public := secret.ActOnBase()

	digest := crypto.Keccak256(msg)

	sig := NewEcdsaSignature(secret, digest)
	require.True(t, sig.Verify(public, digest))

	ethsig, err := sig.SigEthereum()
	require.NoError(t, err)
	require.NotNil(t, ethsig)

	ecOut, err := crypto.Ecrecover(digest, ethsig)
	require.NoError(t, err)
	require.NotNil(t, ecOut)

	pkAsEthAddress := crypto.Keccak256(ecOut[1:])[12:] // remove the 0x04 prefix, then hash and take last 20 bytes
	expected, err := eth.PointToAddress(public)
	require.NoError(t, err)
	require.Equal(t, expected[:], pkAsEthAddress)
}

func TestUpdateKeys(t *testing.T) {
	a := require.New(t)
	// Setup temporary directory for secrets
	secretsPath := path.Join(t.TempDir(), "secrets.json")
	a.NoError(os.WriteFile(secretsPath, []byte("original secrets"), 0600)) // creating new secrets file

	s := &server{
		secretsPath: secretsPath,
		logger:      zap.NewNop(),
	}
	ctx := context.Background()

	t.Run("RequestNil", func(t *testing.T) {
		resp, err := s.UpdateKeys(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, resp)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("NoPairs", func(t *testing.T) {
		resp, err := s.UpdateKeys(ctx, &signer.UpdateKeysRequest{})
		assert.Error(t, err)
		assert.Nil(t, resp)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("UpdatePeerKeysError", func(t *testing.T) {
		mockSigner := &mockUpdateKeysSigner{
			updateKeysFunc: func(rq *signer.UpdateKeysRequest) (*tss.GuardianStorage, error) {
				return nil, errors.New("update failed")
			},
		}
		s.Signer = mockSigner

		req := &signer.UpdateKeysRequest{
			Pairs: []*signer.UpdateKeyPair{{}},
		}
		resp, err := s.UpdateKeys(ctx, req)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "update failed")
	})

	t.Run("BackupSecretsError", func(t *testing.T) {
		tmpDir := t.TempDir()
		// Point to non-existent file to trigger backup error
		s.secretsPath = filepath.Join(tmpDir, "nonexistent.json")

		mockSigner := &mockUpdateKeysSigner{
			updateKeysFunc: func(rq *signer.UpdateKeysRequest) (*tss.GuardianStorage, error) {
				return &tss.GuardianStorage{}, nil
			},
		}
		s.Signer = mockSigner

		req := &signer.UpdateKeysRequest{
			Pairs: []*signer.UpdateKeyPair{{}},
		}
		resp, err := s.UpdateKeys(ctx, req)
		assert.Error(t, err)
		assert.Nil(t, resp)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Contains(t, err.Error(), "failed to backup")

		// Restore secretsPath
		s.secretsPath = secretsPath
	})

	t.Run("Success", func(t *testing.T) {
		secrets, err := tss.LoadGuardianStorage(tss.StorageLoader{
			Path:        testSecretsPath,
			DemandFrost: false,
			DemandECDSA: false,
		})
		a.NoError(err)

		sngr, err := tss.NewReliableTSS(secrets)
		a.NoError(err)

		s.Signer = sngr // use real signer for success case

		updateKey := ethcommon.BytesToAddress([]byte{1, 2, 3, 4, 45, 56, 67})
		req := &signer.UpdateKeysRequest{
			Pairs: []*signer.UpdateKeyPair{
				{
					KnownKey:  &signer.TypedKey{Type: signer.TypedKey_CertKey, Key: secrets.Identities[1].CertPem},
					UpdateKey: &signer.TypedKey{Type: signer.TypedKey_EthKey, Key: updateKey.Bytes()},
				},
			},
		}
		resp, err := s.UpdateKeys(ctx, req)
		a.NoError(err)
		a.NotNil(resp)

		// Verify backup created
		matches, err := filepath.Glob(secretsPath + ".*.old")
		a.NoError(err)
		a.Len(matches, 1)
		content, err := os.ReadFile(matches[0])
		a.NoError(err)
		a.Equal("original secrets", string(content))

		// Verify updated file created
		res, err := tss.LoadGuardianStorage(tss.StorageLoader{
			Path: secretsPath,
		})
		a.NoError(err)
		a.NotNil(res)
		a.Equal(*res.IdentitiesKeep.Identities[1].EthAddress, updateKey)
	})
	t.Run("multiple backups created", func(t *testing.T) {
		// Reset secrets file, and entire dir:
		secretsPath := path.Join(t.TempDir(), "secrets.json")
		a.NoError(os.WriteFile(secretsPath, []byte("original secrets"), 0600)) // creating new secrets file

		secrets, err := tss.LoadGuardianStorage(tss.StorageLoader{
			Path:        testSecretsPath,
			DemandFrost: false,
			DemandECDSA: false,
		})
		a.NoError(err)

		sngr, err := tss.NewReliableTSS(secrets)
		a.NoError(err)

		s.Signer = sngr             // use real signer for success case
		s.secretsPath = secretsPath // reset secrets path. Ensuring empty dir.

		updateKey := ethcommon.BytesToAddress([]byte{1, 2, 3, 4, 45, 56, 67})
		req := &signer.UpdateKeysRequest{
			Pairs: []*signer.UpdateKeyPair{
				{
					KnownKey:  &signer.TypedKey{Type: signer.TypedKey_CertKey, Key: secrets.Identities[1].CertPem},
					UpdateKey: &signer.TypedKey{Type: signer.TypedKey_EthKey, Key: updateKey.Bytes()},
				},
			},
		}
		resp, err := s.UpdateKeys(ctx, req)
		a.NoError(err)
		a.NotNil(resp)

		resp, err = s.UpdateKeys(ctx, req)
		a.NoError(err)
		a.NotNil(resp)

		matches, err := filepath.Glob(secretsPath + ".*.old")
		a.NoError(err)
		a.Len(matches, 2) // two backups should exist
	})

}

func NewEcdsaSignature(x curve.Scalar, hash []byte) *ecdsa.Signature {
	group := x.Curve()

	k := sample.Scalar(rand.Reader, x.Curve())
	m := curve.FromHash(group, hash)
	kInv := group.NewScalar().Set(k).Invert()
	R := kInv.ActOnBase()
	r := R.XScalar()
	s := r.Mul(x).Add(m).Mul(k)
	return &ecdsa.Signature{
		R: R,
		S: s,
	}
}

func mustHexDecode(s string) []byte {
	if len(s) > 1 && s[0:2] == "0x" {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type mockUpdateKeysSigner struct {
	tss.ReliableTSS
	updateKeysFunc func(rq *signer.UpdateKeysRequest) (*tss.GuardianStorage, error)
}

func (m *mockUpdateKeysSigner) UpdatePeerKeys(rq *signer.UpdateKeysRequest) (*tss.GuardianStorage, error) {
	if m.updateKeysFunc != nil {
		return m.updateKeysFunc(rq)
	}
	return nil, nil
}

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
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
	"github.com/xlabs/multi-party-sig/protocols/frost"
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
	s := &server{}
	ctx := context.Background()

	t.Run("PublicDataNotInitialized", func(t *testing.T) {
		resp, err := s.GetPublicData(ctx, &signer.PublicDataRequest{})
		assert.Error(t, err)
		assert.Nil(t, resp)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Contains(t, err.Error(), "public data not initialized")
	})

	t.Run("Success", func(t *testing.T) {
		expectedPubData := &signer.PublicData{
			FrostPublicData: []byte("frost-key"),
			EcdsaPublicData: []byte("ecdsa-key"),
		}
		s.pubData = expectedPubData

		resp, err := s.GetPublicData(ctx, &signer.PublicDataRequest{})
		assert.NoError(t, err)
		assert.Equal(t, expectedPubData, resp)
	})
}

func TestVerifySignature(t *testing.T) {
	s := &server{}
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
		// These values were generated using a real FROST signing session with multiple parties.
		sBytes := mustHexDecode("7543bc351af14435c68d9dda741fecd0ee5f493721dd1b5c46587a7409272f3e")
		z, err := grp.UnmarshalScalar(sBytes)
		require.NoError(t, err)

		rBytes := mustHexDecode("021ab28eac5cdbb509242f6bae290fee91f0265238f89ba40036d88fa7362eb7fd")
		r, err := grp.UnmarshalPoint(rBytes)
		require.NoError(t, err)
		sig := frost.Signature{
			R: r,
			Z: z,
		}

		msgDigest := mustHexDecode("deadbeef00000000000000000000000000000000000000000000000000000000")

		commonsig, commonerr := party.FrostSigToCommonSig(&sig, nil, &common.TrackingID{
			Protocol: uint32(common.ProtocolFROSTSign.ToInt()),
			Digest:   msgDigest,
		})
		require.Nil(t, commonerr)

		pk := mustHexDecode("0356ae26bf1fabda965a58baf385b8ab96c72bfdfbe8f2cdd3d65035af29d95a61")

		req := &signer.VerifySignatureRequest{
			Signature: commonsig,
			PublicData: &signer.PublicData{
				FrostPublicData: pk,
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
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "secrets.json")
	err := os.WriteFile(secretsPath, []byte("original secrets"), 0600)
	a.NoError(err)

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
		assert.NoError(t, err)
		assert.NotNil(t, resp)

		// Verify backup created
		_, err = os.Stat(secretsPath + ".old")
		assert.NoError(t, err)
		content, err := os.ReadFile(secretsPath + ".old")
		assert.NoError(t, err)
		assert.Equal(t, "original secrets", string(content))

		// Verify updated file created
		_, err = os.Stat(secretsPath + ".updated")
		assert.NoError(t, err)

		res, err := tss.LoadGuardianStorage(tss.StorageLoader{
			Path: secretsPath + ".updated",
		})
		assert.NoError(t, err)
		assert.NotNil(t, res)
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

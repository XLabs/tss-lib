// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/xlabs/tss-lib/v2/crypto/modproof"
	"github.com/xlabs/tss-lib/v2/ecdsa/keygen"
)

var Session = []byte("session")

func TestMod(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N

	proof, err := modproof.NewProof(Session, N, P, Q, rand.Reader)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = modproof.NewProofFromBytes(proofBzs[:])
	assert.NoError(test, err)

	ok := proof.Verify(Session, N)
	assert.True(test, ok, "proof must verify")
}

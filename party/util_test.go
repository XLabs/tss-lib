// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package party

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestNoDupsInShuffle(t *testing.T) {
	shuffleSize := 100
	elems := make([]int, shuffleSize)
	for i := 0; i < shuffleSize; i++ {
		elems[i] = i
	}

	d := crypto.Keccak256([]byte("hello, world"))

	err := randomShuffle(d, elems)
	require.NoError(t, err)
	set := map[int]any{}
	for _, e := range elems {
		set[e] = e
	}
	require.Len(t, set, shuffleSize)
}

func TestShuffleLoadBalances(t *testing.T) {
	a := require.New(t)

	numAttempts := 100000
	shuffleSize := 100
	cutoff := 10
	elems := make([]int, shuffleSize)
	for i := 0; i < shuffleSize; i++ {
		elems[i] = i
	}
	orderd := make([]int, shuffleSize)
	copy(orderd, elems)

	counters := make([]float64, shuffleSize)

	d := make([]byte, 8)
	for i := 0; i < numAttempts; i++ {
		binary.BigEndian.PutUint64(d[:], uint64(i))

		a.NoError(randomShuffle(d, elems))
		for _, elem := range elems[:cutoff] {
			counters[elem]++
		}

		copy(elems, orderd)
	}

	// mean of everything  should be ~ 1/shuffleSize*cutout
	_var, _mean := variance(counters)
	standarddiv := math.Sqrt(_var)

	// for 200 elements and 200 attempts, the avg should be close to the cutoff.
	// so mean ~= 10
	// in similar fashion, we need treat the ratio of attempts to find the correct mean.
	cutoffRation := float64(numAttempts / shuffleSize)
	expectedMean := cutoffRation * float64(cutoff)
	a.Equal(_mean, expectedMean)

	// the stdiv will reduce with more attempts, so i don't want to be too strict here. 0.1% error is fine.
	a.LessOrEqual(standarddiv/expectedMean, 0.01)
}

func variance(input []float64) (variance float64, m float64) {
	if len(input) == 0 {
		panic("empty input")
	}

	m = mean(input)

	// var == E[(X - E[X])^2]
	for _, n := range input {
		t := n - m
		variance += t * t
	}
	// we div to make it the average of (X-E[X])^2...
	return variance / float64((len(input))), m
}

func mean(input []float64) float64 {
	mean := 0.0
	for _, n := range input {
		mean += n
	}
	mean /= float64(len(input))
	return mean
}

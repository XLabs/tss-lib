// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	"github.com/xlabs/tss-lib/v2/common"
	"github.com/xlabs/tss-lib/v2/crypto"
	"github.com/xlabs/tss-lib/v2/ecdsa/keygen"
	"github.com/xlabs/tss-lib/v2/tss"
)

const (
	TaskName = "signing"
)

type (
	base struct {
		*tss.Parameters
		key     *keygen.LocalPartySaveData
		data    *common.SignatureData
		temp    *localTempData
		out     chan<- tss.Message
		end     chan<- *common.SignatureData
		ok      []bool // `ok` tracks parties which have been verified by Update()
		started bool
		number  int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	round4 struct {
		*round3
	}
	round5 struct {
		*round4
	}
	round6 struct {
		*round5
	}
	round7 struct {
		*round6
	}
	round8 struct {
		*round7
	}
	round9 struct {
		*round8
	}
	finalization struct {
		*round9
	}
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*round4)(nil)
	_ tss.Round = (*round5)(nil)
	_ tss.Round = (*round6)(nil)
	_ tss.Round = (*round7)(nil)
	_ tss.Round = (*round8)(nil)
	_ tss.Round = (*round9)(nil)
	_ tss.Round = (*finalization)(nil)
)

// ----- //

func (round *base) Params() *tss.Parameters {
	return round.Parameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range round.ok {
		if !ok {
			return false
		}
	}
	return true
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*tss.PartyID {
	Ps := round.Parties().IDs()
	ids := make([]*tss.PartyID, 0, len(round.ok))
	for j, ok := range round.ok {
		if ok {
			continue
		}
		ids = append(ids, Ps[j])
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewTrackableError(err, TaskName, round.number, round.PartyID(), round.temp.trackingID, culprits...)
}

// ----- //

// `ok` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

func (round *base) sendMessage(msg tss.ParsedMessage) *tss.Error {
	if round.out == nil {
		return round.WrapError(errors.New("received nil output channel"))
	}
	if round.Params() == nil {
		return round.WrapError(errors.New("received nil Params"))
	}

	if round.Params().Context == nil {
		round.out <- msg
		return nil
	}

	select {
	case round.out <- msg:
		return nil
	case <-round.Params().Context.Done():
		return round.WrapError(errors.New("round aborted"))
	}
}

func (round *base) sendSignature() {
	// shouldn't ever reach these cases, but it is better to be safe than sorry.
	if round.out == nil {
		return
	}
	if round.Params() == nil {
		return
	}

	if round.Params().Context == nil {
		round.end <- round.data
		return
	}

	select {
	case round.end <- round.data:
	// if context is nil, select clause will simply ignore it.
	case <-round.Params().Context.Done():
	}
}

// Attempts to run task asynchronly. if Params has a defined task-runner, will return whether it was successful or not.
func (round *base) runAsyncTask(f func()) *tss.Error {
	if round.Params() == nil || round.Params().AsyncWorkComputation == nil {
		go f()
		return nil
	}

	if err := round.Params().AsyncWorkComputation(f); err != nil {
		return round.WrapError(err)
	}

	return nil
}

// get ssid from local params
func (round *base) getSSID() ([]byte, error) {
	ssidList := []*big.Int{round.EC().Params().P, round.EC().Params().N, round.EC().Params().B, round.EC().Params().Gx, round.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)                                                                                // parties
	BigXjList, err := crypto.FlattenECPoints(round.key.BigXj)
	if err != nil {
		return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	}
	ssidList = append(ssidList, BigXjList...)                    // BigXj
	ssidList = append(ssidList, round.key.NTildej...)            // NTilde
	ssidList = append(ssidList, round.key.H1j...)                // h1
	ssidList = append(ssidList, round.key.H2j...)                // h2
	ssidList = append(ssidList, big.NewInt(int64(round.number))) // round number
	ssidList = append(ssidList, round.temp.ssidNonce)
	ssid := common.SHA512_256i(ssidList...).Bytes()

	return ssid, nil
}

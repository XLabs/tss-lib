// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import common "github.com/xlabs/tss-common"

type Round interface {
	Params() *Parameters
	Start() *common.Error
	Update() (bool, *common.Error)
	RoundNumber() int
	CanAccept(msg common.ParsedMessage) bool
	CanProceed() bool
	NextRound() Round
	WaitingFor() []*common.PartyID
	WrapError(err error, culprits ...*common.PartyID) *common.Error
}

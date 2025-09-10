// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package party

import (
	"time"
)

const (
	signerMaxTTL      = time.Minute * 5
	maxActiveSessions = 1000
)

const DigestSize = 32

const unknownRound = -1

const (
	directMessagePos    = 0
	broadcastMessagePos = 1
)

const (
	awaitingActivation signerState = iota
	activated
	notInCommittee
)

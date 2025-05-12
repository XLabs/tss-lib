// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package party

import (
	"time"
)

const signerMaxTTL = time.Minute * 5
const maxStoragePerParty = 100

const DigestSize = 32

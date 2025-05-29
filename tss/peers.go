// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import common "github.com/xlabs/tss-common"

type (
	PeerContext struct {
		partyIDs common.SortedPartyIDs
	}
)

func NewPeerContext(parties common.SortedPartyIDs) *PeerContext {
	return &PeerContext{partyIDs: parties}
}

func (p2pCtx *PeerContext) IDs() common.SortedPartyIDs {
	return p2pCtx.partyIDs
}

func (p2pCtx *PeerContext) SetIDs(ids common.SortedPartyIDs) {
	p2pCtx.partyIDs = ids
}

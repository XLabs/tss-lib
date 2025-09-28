package party

import (
	"sync"
	"time"

	common "github.com/xlabs/tss-common"
)

type set[T comparable] map[T]struct{}

type trackidString string

// rateLimiter is a helper struct to keep track of active sessions.
// Each session has a digest, and each peer is allowed to be active
// for a certain number of sessions.
// a peer is allowed to send how many messages it wants per session, but not allowed to
// participate in more than maxActiveSessions sessions at a time.
type rateLimiter struct {
	maxActiveSessions int
	mtx               sync.Mutex

	digestToPeer map[trackidString]set[strPartyID]
	peerToDigest map[strPartyID]set[trackidString]
	firstSeen    map[trackidString]time.Time
}

func newRateLimiter(maxActiveSessions int) rateLimiter {
	return rateLimiter{
		maxActiveSessions: maxActiveSessions,

		mtx:          sync.Mutex{},
		digestToPeer: map[trackidString]set[strPartyID]{},
		peerToDigest: map[strPartyID]set[trackidString]{},
		firstSeen:    map[trackidString]time.Time{},
	}
}

// Add adds a peer to the counter for a given digest.
// returns false if this peer is active for too many signatures ( > r.maxActiveSessions).
func (r *rateLimiter) add(trackId *common.TrackingID, peer *common.PartyID) bool {
	if trackId == nil || peer == nil {
		return false
	}

	sgkey := trackidString(trackId.ToString())
	strPartyId := strPartyID(peer.ToString())

	r.mtx.Lock()
	defer r.mtx.Unlock()

	if _, ok := r.digestToPeer[sgkey]; !ok {
		r.digestToPeer[sgkey] = make(set[strPartyID])
	}

	if _, ok := r.peerToDigest[strPartyId]; !ok {
		r.peerToDigest[strPartyId] = make(set[trackidString])
	}

	// if already an active signature for this participant, then it doesn't count as an additional signature
	if _, ok := r.peerToDigest[strPartyId][sgkey]; ok {
		return true
	}

	// the participant hasn't yet participated in this signing for the digest, we must ensure an additional signature is allowed
	if len(r.peerToDigest[strPartyId])+1 > r.maxActiveSessions {
		return false
	}

	r.digestToPeer[sgkey][strPartyId] = struct{}{}
	r.peerToDigest[strPartyId][sgkey] = struct{}{}

	if _, ok := r.firstSeen[sgkey]; !ok {
		r.firstSeen[sgkey] = time.Now()
	}

	return true
}

func (r *rateLimiter) remove(trackid *common.TrackingID) {
	if trackid == nil {
		return
	}

	key := trackidString(trackid.ToString())

	r.mtx.Lock()
	defer r.mtx.Unlock()

	r.unsafeRemove(key)

}

func (r *rateLimiter) unsafeRemove(key trackidString) {
	peers := r.digestToPeer[key]
	delete(r.digestToPeer, key)

	for g := range peers {
		delete(r.peerToDigest[g], key)
	}

	delete(r.firstSeen, key)
}

func (r *rateLimiter) cleanSelf(maxDuration time.Duration) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	for k, v := range r.firstSeen {
		if time.Since(v) > maxDuration {
			r.unsafeRemove(k)
		}
	}
}

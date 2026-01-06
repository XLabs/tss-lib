package party

import (
	"sync"
	"time"
)

type set[T comparable] map[T]struct{}

type trackidString string

// RateLimiter is a helper struct to track and limit the number of trackables a peer can be involved in.
// trackable can be any type that implements the trackable interface.
//
// For instance, in our case, we want to limit the number of active sessions a peer can be involved in.
// Each session has a digest, and each peer is allowed to be active
// for a certain number of sessions.
// a peer is allowed to send how many messages it wants per session, but not allowed to
// participate in more than maxActiveSessions sessions at a time.
type RateLimiter struct {
	maxActiveSessions int
	mtx               sync.Mutex

	trackedToPeer map[trackidString]set[strPartyID]
	peerToTracked map[strPartyID]set[trackidString]
	firstSeen     map[trackidString]time.Time
}

func NewRateLimiter(maxActiveSessions int) RateLimiter {
	return RateLimiter{
		maxActiveSessions: maxActiveSessions,

		mtx:           sync.Mutex{},
		trackedToPeer: map[trackidString]set[strPartyID]{},
		peerToTracked: map[strPartyID]set[trackidString]{},
		firstSeen:     map[trackidString]time.Time{},
	}
}

// trackable is an interface for types that can be tracked by the RateLimiter.
type trackable interface {
	ToString() string
}

// Add adds a peer to the counter for a given trackable.
// returns false if this peer is active for too many trackables ( > r.maxActiveSessions).
func (r *RateLimiter) Add(toTrack, peer trackable) bool {
	if toTrack == nil || peer == nil {
		return false
	}

	trackedKey := trackidString(toTrack.ToString())
	strPartyId := strPartyID(peer.ToString())

	r.mtx.Lock()
	defer r.mtx.Unlock()

	if _, ok := r.trackedToPeer[trackedKey]; !ok {
		r.trackedToPeer[trackedKey] = make(set[strPartyID])
	}

	if _, ok := r.peerToTracked[strPartyId]; !ok {
		r.peerToTracked[strPartyId] = make(set[trackidString])
	}

	// if already an active trackable for this participant, then it doesn't count as an additional trackable
	if _, ok := r.peerToTracked[strPartyId][trackedKey]; ok {
		return true
	}

	// the participant hasn't yet participated for the trackable, we must ensure an additional trackable is allowed
	if len(r.peerToTracked[strPartyId])+1 > r.maxActiveSessions {
		return false
	}

	r.trackedToPeer[trackedKey][strPartyId] = struct{}{}
	r.peerToTracked[strPartyId][trackedKey] = struct{}{}

	if _, ok := r.firstSeen[trackedKey]; !ok {
		r.firstSeen[trackedKey] = time.Now()
	}

	return true
}

func (r *RateLimiter) Remove(trackid trackable) {
	if trackid == nil {
		return
	}

	key := trackidString(trackid.ToString())

	r.mtx.Lock()
	defer r.mtx.Unlock()

	r.unsafeRemove(key)

}

func (r *RateLimiter) unsafeRemove(key trackidString) {
	peers := r.trackedToPeer[key]
	delete(r.trackedToPeer, key)

	for g := range peers {
		delete(r.peerToTracked[g], key)
	}

	delete(r.firstSeen, key)
}

func (r *RateLimiter) CleanSelf(maxDuration time.Duration) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	for k, v := range r.firstSeen {
		if time.Since(v) > maxDuration {
			r.unsafeRemove(k)
		}
	}
}

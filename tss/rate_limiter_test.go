package tss

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/xlabs/tss-lib/v2/party"
)

func TestEngine_RateLimiter(t *testing.T) {
	a := assert.New(t)

	// Setup engines using the helper from implementation_test.go
	// This ensures we have valid identities, keys, and storage for signature verification.
	engines := load5GuardiansSetupForBroadcastChecks(a)
	receiver := engines[0]
	sender1 := engines[1]
	sender2 := engines[2]

	// Define a limit
	limit := 1

	// Initialize RateLimiter on the receiver
	rl := party.NewRateLimiter(limit)
	receiver.rateLimiter = &rl

	// Helper to generate and send a broadcast message
	sendMessage := func(sender *Engine, digestByte byte) error {
		// Create a fake broadcast message (round2Message is broadcast)
		// We use a unique digest to ensure the message is treated as unique if needed,
		// though rate limiter tracks by trackingID
		// generateFakeMessageWithRandomContent creates a message with a TrackingID based on the digest.
		parsed := generateFakeMessageWithRandomContent(sender.Self.Pid, nil, round2Message, party.Digest{digestByte})

		// Convert to Echo (IncomingMessage) which is signed by the sender
		msg := parsedIntoEcho(a, sender, parsed)

		// Handle it on receiver
		return receiver.handleIncomingTssMessage(msg)
	}

	// Test Case 1: Add message within limit
	err := sendMessage(sender1, 1)
	a.NoError(err, "First message from sender1 should be accepted")

	// Test Case 2: Exceed limit
	err = sendMessage(sender1, 2)
	a.Error(err, "Second message from sender1 should be rejected")
	a.Contains(err.Error(), "rate limit exceeded")

	// Test Case 3: Different peer should not be affected
	err = sendMessage(sender2, 3)
	a.NoError(err, "Message from sender2 should be accepted")

	// Test Case 4: Cleanup
	// Wait for a bit to ensure time difference
	time.Sleep(50 * time.Millisecond)

	// Cleanup with small TTL (should remove old entries)
	receiver.cleanup(1 * time.Millisecond)

	// Test Case 5: Send message from sender1 again (should succeed after cleanup)
	err = sendMessage(sender1, 4)
	a.NoError(err, "Message from sender1 should be accepted after cleanup")
}

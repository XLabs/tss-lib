package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	engine "github.com/xlabs/tss-lib/v2/tss"
)

func TestSerializeIdentifierDistinguishesAbsentAndPresentEthAddress(t *testing.T) {
	withoutEth := &Identifier{
		Hostname: "node-1",
		TlsX509:  engine.PEM("cert-1"),
		Port:     1001,
	}
	withEth := &Identifier{
		Hostname:   "node-1",
		TlsX509:    engine.PEM("cert-1"),
		Port:       1001,
		EthAddress: "0x52908400098527886E0F7030069857D2E4169EE7",
	}

	serialize, err := serializeIdentifier(withoutEth)
	require.NoError(t, err)

	serializeWithEth, err := serializeIdentifier(withEth)
	require.NoError(t, err)

	require.NotEqual(t, serialize, serializeWithEth)
}

func TestSerializeIdentifierRejectsInvalidEthAddress(t *testing.T) {
	id := &Identifier{
		Hostname:   "node-1",
		TlsX509:    engine.PEM("cert-1"),
		Port:       1001,
		EthAddress: "not-an-eth-address",
	}

	_, err := serializeIdentifier(id)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid eth address")
}

func TestPeersFingerprintOrderIndependent(t *testing.T) {
	cnfgA := &SetupConfigs{
		Peers: []Identifier{
			{
				Hostname: "node-1",
				TlsX509:  engine.PEM("cert-1"),
				Port:     1001,
			},
			{
				Hostname:   "node-2",
				TlsX509:    engine.PEM("cert-2"),
				Port:       1002,
				EthAddress: "0xde709f2102306220921060314715629080e2fb77",
			},
		},
	}

	cnfgB := &SetupConfigs{
		Peers: []Identifier{
			cnfgA.Peers[1],
			cnfgA.Peers[0],
		},
	}

	fingerprintA, err := PeersFingerprint(cnfgA)
	require.NoError(t, err)

	fingerprintB, err := PeersFingerprint(cnfgB)
	require.NoError(t, err)

	require.Equal(t, fingerprintA, fingerprintB)
}

func TestPeersFingerprintReturnsErrorOnInvalidPeerIdentifier(t *testing.T) {
	cnfgs := &SetupConfigs{
		Peers: []Identifier{
			{
				Hostname: "node-1",
				TlsX509:  engine.PEM("cert-1"),
				Port:     1001,
			},
			{
				Hostname:   "node-2",
				TlsX509:    engine.PEM("cert-2"),
				Port:       1002,
				EthAddress: "invalid",
			},
		},
	}

	_, err := PeersFingerprint(cnfgs)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to serialize peer 1 identifier")
}

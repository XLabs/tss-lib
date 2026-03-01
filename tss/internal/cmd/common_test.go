package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	engine "github.com/xlabs/tss-lib/v2/tss"
)

func TestPeersFingerprintNormalizesEthAddressCase(t *testing.T) {
	mixedCase := "0x52908400098527886E0F7030069857D2E4169EE7"
	lowerCase := "0x52908400098527886e0f7030069857d2e4169ee7"

	cnfg1 := &SetupConfigs{
		Peers: []Identifier{{
			Hostname:   "node-1",
			TlsX509:    engine.PEM("cert-1"),
			Port:       1001,
			EthAddress: mixedCase,
		}},
	}
	cnfg2 := &SetupConfigs{
		Peers: []Identifier{{
			Hostname:   "node-1",
			TlsX509:    engine.PEM("cert-1"),
			Port:       1001,
			EthAddress: lowerCase,
		}},
	}

	require.Equal(t, PeersFingerprint(cnfg1), PeersFingerprint(cnfg2))
}

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

	require.NotEqual(t, serializeIdentifier(withoutEth), serializeIdentifier(withEth))
}

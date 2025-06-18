module github.com/xlabs/tss-lib/v2

go 1.23

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/cronokirby/saferith v0.33.0
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.3
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0
	github.com/ethereum/go-ethereum v1.14.7
	github.com/fxamacker/cbor/v2 v2.8.0
	github.com/ipfs/go-log v1.0.5
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.9.0
	github.com/xlabs/multi-party-sig v1.0.0
	github.com/xlabs/tss-common v0.0.0-20250618120842-76eedd6f3270
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.22.0
	golang.org/x/sync v0.7.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/BurntSushi/toml v1.3.2 // indirect
	github.com/agl/ed25519 v0.0.0-20200225211852-fd4d107ace12 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/holiman/uint256 v1.3.0 // indirect
	github.com/ipfs/go-log/v2 v2.1.3 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0 // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/sys v0.20.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	honnef.co/go/tools v0.1.3 // indirect
)

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43

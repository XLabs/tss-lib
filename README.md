# TSS Library (tss-lib)

`tss-lib/v2` is a Go library for Threshold Signing Schemes (TSS).
It provides robust implementations for Distributed Key Generation (DKG) and threshold signing using **FROST** (Schnorr) and **CMP** (ECDSA) protocols.

`tss-lib/v2` wraps a cryptographic library (github.com/xlabs/multi-party-sig) with a facade that simplifies the usage of the protocol.
It provides ease-of-use, concurrency safety, and message handling for distributed protocols. 
It is responsible for starting and guiding a distributed protocol execution throughout its multiple stages and rounds. It handles multiple and parallel protocol executions. It ensures that messages aren’t lost if multiple nodes had started the protocol before the current guardian had (i.e., and thus hadn’t started the TSS protocol along with them). 

This library is designed for distributed systems, such as bridge guardians or MPC wallets, allowing a group of parties to collaboratively sign messages without any single party holding the full private key.

## Features
*   **Protocols**:
    *   **FROST** (Flexible Round-Optimized Schnorr Threshold) for Schnorr signatures.
    *   **CMP** (Canetti-Gennaro-Goldfeder-Makriyannis-Peled) for ECDSA signatures.
*   **Distributed Key Generation (DKG)**: Securely generate shared secrets without a trusted dealer.
*   **Reliable Communication**: Built-in abstractions for hash-broadcast and unicast messaging via mTLS

## CLI Tools

The repository includes command-line tools for running DKG and runing a Signer.
*   [**DKG Runner**](docs/DKG.md): Located in `tss/internal/cmd`, this tool allows running the DKG protocol as a standalone binary. See tss/internal/cmd/README.md for details.
*   **Signer**: Located in the `service` package. This tool sets up a TSS signer, connects to its peers and offers gRPC API to sign messages.


## Testing

The library includes extensive tests covering the cryptographic protocols and networking resilience.

```bash
go test ./...
```

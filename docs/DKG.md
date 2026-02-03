# DKG

## Distributed Key Generation

The execution of the DKG program will generate a `Secret` type configuration that must be supplied for the node to participate in the TSS protocol, containing data for signing. It will be stored in the `secrets.json` file inside the `StorageLocation` directory defined in the configuration file.
****
```go
type Secret struct {
	MaxSimultaneousSignatures int      `json:"MaxSimultaneousSignatures"`
	MaxSignerTTL              int64    `json:"MaxSignerTTL"`
	ChainsWithNoSelfReport    []string `json:"ChainsWithNoSelfReport"`
	LeaderIdentity            string   `json:"LeaderIdentity"`
	Self                      Identity `json:"Self"`
	IdentitiesKeep            struct {
		Identities []Identity `json:"Identities"`
	} `json:"IdentitiesKeep"`
	TlsX509             string `json:"TlsX509"`
	PrivateKey          string `json:"PrivateKey"`
	Threshold           int    `json:"Threshold"`
	TSSSecrets          string `json:"TSSSecrets"`
	LoadDistributionKey string `json:"LoadDistributionKey"`
}

type Identity struct {
	Pid                PeerID `json:"Pid"`
	KeyPEM             string `json:"KeyPEM"`
	CertPem            string `json:"CertPem"`
	CommunicationIndex int    `json:"CommunicationIndex"`
	Hostname           string `json:"Hostname"`
	Port               int    `json:"Port"`
}

type PeerID struct {
	ID string `json:"ID"`
}
```


The DKG protocol is used to generate secrets for TSS, and it assumes a public key infrastructure (PKI). In particular, each participant of the DKG protocol must know the public key of all of its peers. These public keys are stored in X509 certificates inside Peers[i].TlsX509, and are used later by the TSS node to establish TLS channels between the participants. The certificates can be self-signed root-level certificates or issued by a CA that authorizes participants. You should put the secret key used to sign your certificate in the field `SelfSecret`.

**Note:** Each time the participant set changes, DKG must be run again to generate a new public key and new shares of the corresponding secret key. This library does not support incrementally updating secret key shares.

> **:warning:** When creating the X509 certificates, be aware that the DNS name you set in the certificate will be used as the hostname for connecting to the node. Make sure to enter the secret key you used to sign your certificate in the `SelfSecret` field. As a result, please refrain from using hostnames that are unreachable.

### Configuration files
> **:bulb:** Understanding the DKG configuration is important for the process, and it is recommended to note this section, but the used script will generate all the necessary config automatically.

In the line of the above statement, the DKG generation program requires a configuration defined like in the following schema:

```json
{
  "NumParticipants": int,
  "WantedThreshold": int,
  "Self": Identifier
  "SelfSecret" : PEM encoding of a secret key (as a byte array).
  "StorageLocation": directory path
  "Peers" : array of `Identifier`
}
```
where Identifier  is a subobject with fields:
```json
{
  "Hostname": string,
  "TlsX509": PEM encoding of key
  "Port": int
}
```
> **:warning:** This file contains secret keys. Do not share and keep in mind security measures when handling.

| Field | Explanation |
|-------|-------------|
| `NumParticipants` | The number of nodes in the system. |
| `WantedThreshold` | The minimum count of signers to reach signature threshold. |
| `Self` | Describes the runner of the binary. Hostname must be a valid DNS host used in the X509 certificate. |
| `SelfSecret` | The runner node's secret key used to sign your certificate. |
| `StorageLocation` | tbd (use `.`) |
| `Peers` | An array of all possible participants, including self. |
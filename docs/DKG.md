# DKG

## Distributed Key Generation

The execution of the DKG program will generate a `Storage` type configuration that must be supplied for the node to participate in the TSS protocol, containing data for signing.

```go
type PEM []byte

type Storage struct {
	Configurations

	Self           *Identity
	IdentitiesKeep `json:"IdentitiesKeep,inline"`

	// should be a certificate generated with SecretKey
	TlsX509    PEM
	PrivateKey PEM
	tlsCert    *tls.Certificate
	signingKey *ecdsa.PrivateKey // should be the unmarshalled value of PriavteKey.

	// Assumes threshold = 2f+1, where f is the maximal expected number of faulty nodes.
	Threshold int

	// all secret keys should be generated with specific value.
	TSSSecrets []byte
	frostconf  *frost.Config
	ecdsaconf  *cmp.Config

	LoadDistributionKey []byte
}


type IdentitiesKeep struct {
	// sorted by KeyPem.
	Identities []*Identity

	// maps and slices to ensure quick lookups.
	pemkeyToIndex  map[string]int
	ethAddToIndex  map[ethcommon.Address]int
	partyidToIndex map[string]int
	peerCerts      []*x509.Certificate
	partyIds       []*common.PartyID
}


type Identity struct {
	Pid     *common.PartyID   `json:"Pid,inline"` // used for tss protocol.
	KeyPEM  PEM               `json:"KeyPEM"`     // the public key in PEM format.
	Key     *ecdsa.PublicKey  `json:"-"`          // ensuring this isn't stored in non-pem format.
	CertPem PEM               `json:"CertPem"`    // the certificate in PEM format.
	Cert    *x509.Certificate `json:"-"`          // ensuring this isn't stored in non-pem format.

	// the number representing the node when passing messages.
	CommunicationIndex SenderIndex `json:"CommunicationIndex"`
	// the hostname of the node, used to connect to it.
	Hostname string `json:"Hostname"`
	// the port the node is listening on. if 0 -> use the default port.
	Port int `json:"Port,omitempty"`
	// the combination of hostname and port. Used to establish a network connection.
	networkname string `json:"-"`

	// TODO: is this field mutable? in the future, when this field is set via node communications,
	// would it be set ONCE, or multiple times? (if once, we can use atomics to indicate whether it is set or not).
	// otherwise, we'll need a lock.
	EthAddress *ethcommon.Address `json:"EthAddress,omitempty"` // mapping between EthhAddress and PID (used in TSS)

	pos int // internal use only: position in the IdentitiesKeep slice.
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
| `numParticipants` | The number of nodes in the system. |
| `wantedThreshold` | The minimum count of signers to reach signature threshold. |
| `Self` | Describes the runner of the binary. Hostname must be a valid DNS host used in the X509 certificate. |
| `SelfSecret` | The runner node's secret key used to sign your certificate. |
| `StorageLocation` | tbd (use `.`) |
| `Peers` | An array of all possible participants, including self. |
package tss

import (
	"time"
	"unsafe"

	cmpdkg "github.com/xlabs/multi-party-sig/protocols/cmp/keygen"
	cmpsign "github.com/xlabs/multi-party-sig/protocols/cmp/sign"
	frostdkg "github.com/xlabs/multi-party-sig/protocols/frost/keygen"
	frostsign "github.com/xlabs/multi-party-sig/protocols/frost/sign"
	"github.com/xlabs/tss-lib/v2/party"

	"google.golang.org/protobuf/reflect/protoreflect"
)

var tssProtoMessageNames = []string{}

var tssProtoMessageSize = 0

func init() {
	tssProtoMessageNames = append(tssProtoMessageNames, extractProtoTypeNames(frostsign.File_proto_frost_signing_proto)...)
	tssProtoMessageNames = append(tssProtoMessageNames, extractProtoTypeNames(cmpsign.File_proto_cmp_signing_proto)...)

	tssProtoMessageNames = append(tssProtoMessageNames, extractProtoTypeNames(frostdkg.File_proto_frost_keygen_proto)...)
	tssProtoMessageNames = append(tssProtoMessageNames, extractProtoTypeNames(cmpdkg.File_proto_cmp_keygen_proto)...)

	for _, name := range tssProtoMessageNames {
		tssProtoMessageSize = max(tssProtoMessageSize, len(name))
	}
}
func extractProtoTypeNames(protoreflectDesc protoreflect.FileDescriptor) []string {
	names := make([]string, protoreflectDesc.Messages().Len())

	for i := range protoreflectDesc.Messages().Len() {
		m := protoreflectDesc.Messages().Get(i)
		names[i] = string(m.FullName())
	}

	return names
}

const (
	maxConfigFileSize = 10 * 1024 * 1024 // 10 MB
	DefaultPort       = "8998"

	digestSize           = party.DigestSize
	maxAuxiliaryDataSize = 32

	notStarted uint32 = 0 // using 0 since it's the default value
	started    uint32 = 1

	// byte sizes
	pemKeySize = 178

	maxParties = 256

	// hex string sizes use 2x since each byte is represented by 2 hex characters
	// e.g. 0xFF = "FF"
	auxStrHexSize            = 2 * maxAuxiliaryDataSize
	maxPartiesStrHexSize     = 2 * (maxParties / 8) // divided by 8 since it's a bitmap
	digestStrHexSize         = 2 * digestSize
	protocolTypeSize         = int(unsafe.Sizeof(uint8(0))) // uint8 currently
	numdashesInTrackingIDStr = 3
	// TrackingID  is a string composed of: protocolType-Digest-AuxiliaryData-MaxParties
	// where:
	// *protocolType is 1 byte (uint8)
	// *Digest is 32 bytes (sha256)
	// *AuxiliaryData is variable length (max 32 bytes), currently used for flags (e.g. leaderRequested)
	// *MaxParties is 32 bytes (bitmap of max parties, currently set to 256 max parties)
	trackingIDHexStrSize = protocolTypeSize + digestStrHexSize + auxStrHexSize + maxPartiesStrHexSize + numdashesInTrackingIDStr

	defaultMaxLiveSignatures = 20000

	defaultMaxSignerTTL = time.Minute * 5

	numBroadcastsPerSignature = 8 // GG18
	numUnicastsRounds         = 2 // GG18

	// Domain separation strings for hashing.
	// Ensures that similar digest are different for different domains.
	tssContentDomain = "content"

	specificCommitteeFlag = 1 << 0
)

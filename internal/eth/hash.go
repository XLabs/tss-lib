package eth

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"reflect"

	pkghash "github.com/xlabs/tss-lib/v2/internal/hash"
	"golang.org/x/crypto/sha3"
)

type Hash interface {
	hash.Hash
	WriteMany(...any) error
}

type ethHash struct {
	hash.Hash
}

// returns the hash function used in Ethereum's smart contracts
func NewHash() Hash {
	h := &ethHash{sha3.NewLegacyKeccak256()}

	return h
}

func (h *ethHash) WriteMany(data ...any) error {
	var toBeWritten []byte
	for _, d := range data {
		switch t := d.(type) {
		case []byte:
			if t == nil {
				return errors.New("hash.WriteAny: nil []byte")
			}

			toBeWritten = t
		case *big.Int:
			if t == nil {
				return fmt.Errorf("hash.WriteAny: write *big.Int: nil")
			}

			toBeWritten = t.Bytes()
		case pkghash.WriterToWithDomain:
			var buf = new(bytes.Buffer)
			_, err := t.WriteTo(buf)
			if err != nil {
				name := reflect.TypeOf(t)
				return fmt.Errorf("hash.WriteAny: %s: %w", name.String(), err)
			}

			toBeWritten = append([]byte(t.Domain()), buf.Bytes()...)
		case encoding.BinaryMarshaler:
			bytes, err := t.MarshalBinary()
			if err != nil {
				name := reflect.TypeOf(t)

				return fmt.Errorf("hash.WriteAny: %s: %w", name.String(), err)
			}

			toBeWritten = bytes
		case EthAddress:
			toBeWritten = t[:]
		default:
			// This should panic or something
			return fmt.Errorf("hash.WriteAny: invalid type provided as input")
		}

		n, err := h.Write(toBeWritten)
		if err != nil {
			return fmt.Errorf("hash.WriteAny: failed to write data: %w", err)
		}
		if n != len(toBeWritten) {
			return fmt.Errorf("hash.WriteAny: failed to write all data: %d != %d", n, len(toBeWritten))
		}
	}

	return nil
}

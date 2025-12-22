package internal

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var ErrExceedMaxFileSize = errors.New("file size exceeds maximum allowed size")

// ReadFileWithLimit reads the file at the given path, ensuring that the file size does not exceed maxBytes.
// If the file size exceeds maxBytes, a specific error ErrExceedMaxFileSize is returned.
// other than that, it behaves like os.ReadFile.
func ReadFileWithLimit(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	// Read one byte more than the limit to detect if the file exceeds the limit.
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}

	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: %d > %d", ErrExceedMaxFileSize, len(data), maxBytes)
	}

	return data, nil
}

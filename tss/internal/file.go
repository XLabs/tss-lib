package internal

import (
	"fmt"
	"io"
	"os"
)

/*
ReadFileWithLimit reads the file at the given path, ensuring that its
size does not exceed maxBytes.
*/
func ReadFileWithLimit(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	if stats, err := f.Stat(); err == nil && stats.Size() > maxBytes {
		return nil, fmt.Errorf("file size exceeds limit of %d bytes", maxBytes)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return nil, err
	}

	return data, nil
}

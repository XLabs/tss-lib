package internal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileWithLimit(t *testing.T) {
	// Create a temporary directory for test files.
	// t.TempDir automatically cleans up after the test.
	tmpDir := t.TempDir()

	tests := []struct {
		name          string
		content       string
		maxBytes      int64
		expectedData  string
		expectedError error
	}{
		{
			name:          "valid file within limit",
			content:       "hello world",
			maxBytes:      100,
			expectedData:  "hello world",
			expectedError: nil,
		},
		{
			name:          "valid file exactly at limit",
			content:       "hello",
			maxBytes:      5,
			expectedData:  "hello",
			expectedError: nil,
		},
		{
			name:          "file exceeds limit",
			content:       "hello world",
			maxBytes:      5,
			expectedData:  "",
			expectedError: ErrExceedMaxFileSize,
		},
		{
			name:          "empty file",
			content:       "",
			maxBytes:      10,
			expectedData:  "",
			expectedError: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(tmpDir, tc.name)
			// Write the test content to a file
			if err := os.WriteFile(filename, []byte(tc.content), 0644); err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}

			got, err := ReadFileWithLimit(filename, tc.maxBytes)

			if tc.expectedError != nil {
				if !errors.Is(err, tc.expectedError) {
					t.Errorf("expected error %v, got %v", tc.expectedError, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(got) != tc.expectedData {
				t.Errorf("expected content %q, got %q", tc.expectedData, string(got))
			}
		})
	}

	t.Run("non-existent file", func(t *testing.T) {
		_, err := ReadFileWithLimit(filepath.Join(tmpDir, "does-not-exist"), 10)
		if !os.IsNotExist(err) {
			t.Errorf("expected os.ErrNotExist, got %v", err)
		}
	})
}

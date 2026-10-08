package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

type Storage struct {
	baseDir string
}

func NewStorage(baseDir string) (*Storage, error) {
	if baseDir == "" {
		baseDir = "uploads"
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create upload dir: %w", err)
	}
	return &Storage{baseDir: baseDir}, nil
}

// SaveEncryptedBlob writes encrypted byte slice to disk under given filename.
func (s *Storage) SaveEncryptedBlob(filename string, data []byte) (string, error) {
	fullPath := filepath.Join(s.baseDir, filename)
	if err := os.WriteFile(fullPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to save encrypted file: %w", err)
	}
	return fullPath, nil
}

// ReadEncryptedBlob reads encrypted bytes from path.
func (s *Storage) ReadEncryptedBlob(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file: %w", err)
	}
	return data, nil
}

// DeleteFile removes a file from disk.
func (s *Storage) DeleteFile(filePath string) error {
	if filePath == "" {
		return nil
	}
	_ = os.Remove(filePath)
	return nil
}

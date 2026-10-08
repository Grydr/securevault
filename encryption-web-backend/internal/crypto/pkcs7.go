package crypto

import (
	"crypto/subtle"
	"errors"
	"fmt"
)

var (
	ErrInvalidPKCS7Padding = errors.New("invalid pkcs7 padding")
	ErrEmptyData           = errors.New("cannot unpad empty data")
)

// PKCS7Pad adds PKCS#7 padding to data to align with blockSize.
// It creates a new byte slice to guarantee caller slice immutability.
func PKCS7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, fmt.Errorf("invalid block size: %d", blockSize)
	}
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded, nil
}

// PKCS7Unpad removes and validates PKCS#7 padding from data.
// It performs constant-time validation to prevent padding oracle side-channels.
func PKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, ErrEmptyData
	}
	if length%blockSize != 0 {
		return nil, errors.New("data length is not a multiple of block size")
	}

	padding := int(data[length-1])
	if padding == 0 || padding > blockSize || padding > length {
		return nil, ErrInvalidPKCS7Padding
	}

	var diff byte
	for i := length - padding; i < length; i++ {
		diff |= data[i] ^ byte(padding)
	}
	if subtle.ConstantTimeByteEq(diff, 0) != 1 {
		return nil, ErrInvalidPKCS7Padding
	}

	return data[:length-padding], nil
}

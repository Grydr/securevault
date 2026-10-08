package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

var (
	ErrInvalidCiphertext = errors.New("ciphertext too short or corrupted")
	ErrInvalidKeySize    = errors.New("invalid key size")
)

// DerivedKeys holds the symmetric keys for AES, RC4, and DES derived from user master key.
type DerivedKeys struct {
	AESKey []byte // 32 bytes (256 bits)
	RC4Key []byte // 16 bytes (128 bits)
	DESKey []byte // 8 bytes (64 bits)
}

// DeriveUserKeys derives 3 distinct keys for AES-256, RC4, and DES from password and salt using PBKDF2-HMAC-SHA256.
func DeriveUserKeys(password string, salt []byte) *DerivedKeys {
	// Derive 56 bytes total:
	// 32 bytes for AES-256
	// 16 bytes for RC4-128
	// 8 bytes for DES-64
	derived := pbkdf2.Key([]byte(password), salt, 100_000, 56, sha256.New)

	aesKey := make([]byte, 32)
	copy(aesKey, derived[0:32])

	rc4Key := make([]byte, 16)
	copy(rc4Key, derived[32:48])

	desKey := make([]byte, 8)
	copy(desKey, derived[48:56])

	return &DerivedKeys{
		AESKey: aesKey,
		RC4Key: rc4Key,
		DESKey: desKey,
	}
}

// GenerateRandomBytes generates n cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// ========================
// AES-256-CBC Implementation
// ========================

// EncryptAES encrypts plaintext using AES-256-CBC with PKCS#7 padding.
// Returns [16-byte IV] + [CBC ciphertext], encryption duration, and error.
func EncryptAES(plaintext, key []byte) ([]byte, time.Duration, error) {
	if len(key) != 32 {
		return nil, 0, fmt.Errorf("%w: AES-256 requires 32-byte key, got %d", ErrInvalidKeySize, len(key))
	}

	start := time.Now()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	padded, err := PKCS7Pad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, 0, fmt.Errorf("pkcs7 pad failed: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, 0, fmt.Errorf("failed to generate iv: %w", err)
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	duration := time.Since(start)
	if duration <= 0 {
		duration = time.Nanosecond
	}

	// Result format: IV (16 bytes) || Ciphertext
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:aes.BlockSize], iv)
	copy(result[aes.BlockSize:], ciphertext)

	return result, duration, nil
}

// DecryptAES decrypts data encrypted with EncryptAES using AES-256-CBC.
func DecryptAES(ciphertextWithIV, key []byte) ([]byte, time.Duration, error) {
	if len(key) != 32 {
		return nil, 0, fmt.Errorf("%w: AES-256 requires 32-byte key, got %d", ErrInvalidKeySize, len(key))
	}
	if len(ciphertextWithIV) < aes.BlockSize*2 {
		return nil, 0, ErrInvalidCiphertext
	}

	start := time.Now()

	iv := ciphertextWithIV[:aes.BlockSize]
	ciphertext := ciphertextWithIV[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, 0, errors.New("ciphertext is not a multiple of aes block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	padded := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(padded, ciphertext)

	plaintext, err := PKCS7Unpad(padded, aes.BlockSize)
	if err != nil {
		return nil, 0, fmt.Errorf("aes unpad failed: %w", err)
	}

	duration := time.Since(start)
	if duration <= 0 {
		duration = time.Nanosecond
	}
	return plaintext, duration, nil
}

// ========================
// DES-CBC Implementation
// ========================

// EncryptDES encrypts plaintext using DES-CBC with PKCS#7 padding.
// Returns [8-byte IV] + [CBC ciphertext], encryption duration, and error.
func EncryptDES(plaintext, key []byte) ([]byte, time.Duration, error) {
	if len(key) != des.BlockSize {
		return nil, 0, fmt.Errorf("%w: DES requires 8-byte key, got %d", ErrInvalidKeySize, len(key))
	}

	start := time.Now()

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, 0, fmt.Errorf("des.NewCipher failed: %w", err)
	}

	padded, err := PKCS7Pad(plaintext, des.BlockSize)
	if err != nil {
		return nil, 0, fmt.Errorf("pkcs7 pad failed: %w", err)
	}

	iv := make([]byte, des.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, 0, fmt.Errorf("failed to generate des iv: %w", err)
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	duration := time.Since(start)
	if duration <= 0 {
		duration = time.Nanosecond
	}

	// Result format: IV (8 bytes) || Ciphertext
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:des.BlockSize], iv)
	copy(result[des.BlockSize:], ciphertext)

	return result, duration, nil
}

// DecryptDES decrypts data encrypted with EncryptDES using DES-CBC.
func DecryptDES(ciphertextWithIV, key []byte) ([]byte, time.Duration, error) {
	if len(key) != des.BlockSize {
		return nil, 0, fmt.Errorf("%w: DES requires 8-byte key, got %d", ErrInvalidKeySize, len(key))
	}
	if len(ciphertextWithIV) < des.BlockSize*2 {
		return nil, 0, ErrInvalidCiphertext
	}

	start := time.Now()

	iv := ciphertextWithIV[:des.BlockSize]
	ciphertext := ciphertextWithIV[des.BlockSize:]

	if len(ciphertext)%des.BlockSize != 0 {
		return nil, 0, errors.New("ciphertext is not a multiple of des block size")
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, 0, fmt.Errorf("des.NewCipher failed: %w", err)
	}

	padded := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(padded, ciphertext)

	plaintext, err := PKCS7Unpad(padded, des.BlockSize)
	if err != nil {
		return nil, 0, fmt.Errorf("des unpad failed: %w", err)
	}

	duration := time.Since(start)
	if duration <= 0 {
		duration = time.Nanosecond
	}
	return plaintext, duration, nil
}

// ========================
// RC4 (ARC4) Implementation
// ========================

const rc4NonceSize = 16

// deriveRC4StreamKey derives an ephemeral RC4 key per stream using HKDF-SHA256 to prevent keystream reuse attacks.
func deriveRC4StreamKey(masterKey, nonce []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, masterKey, nonce, []byte("rc4-stream-key"))
	streamKey := make([]byte, 16)
	if _, err := io.ReadFull(h, streamKey); err != nil {
		return nil, err
	}
	return streamKey, nil
}

// EncryptRC4 encrypts plaintext using RC4 stream cipher with a 16-byte unique nonce.
// Returns [16-byte nonce] + [stream ciphertext], encryption duration, and error.
func EncryptRC4(plaintext, key []byte) ([]byte, time.Duration, error) {
	if len(key) < 1 {
		return nil, 0, ErrInvalidKeySize
	}

	start := time.Now()

	nonce := make([]byte, rc4NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, 0, fmt.Errorf("failed to generate rc4 nonce: %w", err)
	}

	streamKey, err := deriveRC4StreamKey(key, nonce)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to derive rc4 stream key: %w", err)
	}

	cipherInstance, err := rc4.NewCipher(streamKey)
	if err != nil {
		return nil, 0, fmt.Errorf("rc4.NewCipher failed: %w", err)
	}

	ciphertext := make([]byte, len(plaintext))
	cipherInstance.XORKeyStream(ciphertext, plaintext)

	duration := time.Since(start)
	if duration <= 0 {
		duration = time.Nanosecond
	}

	result := make([]byte, rc4NonceSize+len(ciphertext))
	copy(result[:rc4NonceSize], nonce)
	copy(result[rc4NonceSize:], ciphertext)

	return result, duration, nil
}

// DecryptRC4 decrypts data encrypted with EncryptRC4.
func DecryptRC4(ciphertextWithNonce, key []byte) ([]byte, time.Duration, error) {
	if len(key) < 1 {
		return nil, 0, ErrInvalidKeySize
	}
	if len(ciphertextWithNonce) < rc4NonceSize {
		return nil, 0, ErrInvalidCiphertext
	}

	start := time.Now()

	nonce := ciphertextWithNonce[:rc4NonceSize]
	ciphertext := ciphertextWithNonce[rc4NonceSize:]

	streamKey, err := deriveRC4StreamKey(key, nonce)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to derive rc4 stream key: %w", err)
	}

	cipherInstance, err := rc4.NewCipher(streamKey)
	if err != nil {
		return nil, 0, fmt.Errorf("rc4.NewCipher failed: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	cipherInstance.XORKeyStream(plaintext, ciphertext)

	duration := time.Since(start)
	if duration <= 0 {
		duration = time.Nanosecond
	}
	return plaintext, duration, nil
}

package crypto_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/user/encryption-web-backend/internal/crypto"
)

func TestPKCS7PadAndUnpad(t *testing.T) {
	testCases := []struct {
		name      string
		data      []byte
		blockSize int
	}{
		{"Empty data", []byte(""), 16},
		{"Single byte", []byte("a"), 16},
		{"Exact block size 16", []byte("1234567890123456"), 16},
		{"Exact block size 8", []byte("12345678"), 8},
		{"Block size - 1", []byte("123456789012345"), 16},
		{"Long text", []byte("The quick brown fox jumps over the lazy dog. Personal Data GDPR UU PDP 2026!"), 16},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded, err := crypto.PKCS7Pad(tc.data, tc.blockSize)
			if err != nil {
				t.Fatalf("PKCS7Pad failed: %v", err)
			}
			if len(padded)%tc.blockSize != 0 {
				t.Fatalf("padded length %d is not multiple of %d", len(padded), tc.blockSize)
			}

			unpadded, err := crypto.PKCS7Unpad(padded, tc.blockSize)
			if err != nil {
				t.Fatalf("PKCS7Unpad failed: %v", err)
			}
			if !bytes.Equal(unpadded, tc.data) {
				t.Fatalf("unpadded data does not match original: got %q, want %q", unpadded, tc.data)
			}
		})
	}
}

func TestPKCS7UnpadInvalid(t *testing.T) {
	// Empty data
	_, err := crypto.PKCS7Unpad([]byte{}, 16)
	if err == nil {
		t.Errorf("expected error for empty data")
	}

	// Corrupted padding byte
	badPadding := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 20}
	_, err = crypto.PKCS7Unpad(badPadding, 16)
	if err == nil {
		t.Errorf("expected error for invalid padding byte")
	}

	// Not multiple of block size
	_, err = crypto.PKCS7Unpad([]byte{1, 2, 3}, 16)
	if err == nil {
		t.Errorf("expected error for non-multiple block size")
	}
}

func TestPKCS7SliceImmutability(t *testing.T) {
	// Slices with spare capacity must not have their underlying buffer overwritten
	original := []byte("hello")
	buf := make([]byte, 5, 32)
	copy(buf, original)

	padded, err := crypto.PKCS7Pad(buf, 16)
	if err != nil {
		t.Fatalf("PKCS7Pad failed: %v", err)
	}

	if len(padded) != 16 {
		t.Fatalf("expected padded length 16, got %d", len(padded))
	}

	if !bytes.Equal(buf, original) {
		t.Fatalf("PKCS7Pad mutated input slice! got %v, want %v", buf, original)
	}

	// Check underlying array capacity area was not mutated
	fullCap := buf[:32]
	for i := 5; i < 32; i++ {
		if fullCap[i] != 0 {
			t.Fatalf("PKCS7Pad wrote into spare capacity of input slice at index %d", i)
		}
	}
}

func TestCiphersEncryptDecrypt(t *testing.T) {
	password := "SecretPassword!123"
	salt, _ := crypto.GenerateRandomBytes(32)
	keys := crypto.DeriveUserKeys(password, salt)

	sampleData := [][]byte{
		[]byte("Short GDPR identity record: NIK=3171012345670001, Name=Budi Santoso"),
		[]byte(""),
		bytes.Repeat([]byte("A"), 16),
		bytes.Repeat([]byte("B"), 8),
		bytes.Repeat([]byte("Multikilobyte document text for encryption benchmarking... "), 500),
	}

	for idx, data := range sampleData {
		t.Run("Data_Sample", func(t *testing.T) {
			// AES-256-CBC
			aesCipher, aesDuration, err := crypto.EncryptAES(data, keys.AESKey)
			if err != nil {
				t.Fatalf("EncryptAES failed: %v", err)
			}
			if len(aesCipher) < 32 { // At least 16 byte IV + 16 byte block
				t.Fatalf("EncryptAES output too short: %d", len(aesCipher))
			}
			if aesDuration <= 0 {
				t.Logf("AES duration: %v", aesDuration)
			}
			aesDecrypted, _, err := crypto.DecryptAES(aesCipher, keys.AESKey)
			if err != nil {
				t.Fatalf("DecryptAES failed: %v", err)
			}
			if !bytes.Equal(aesDecrypted, data) {
				t.Fatalf("AES decrypted does not match original for sample %d", idx)
			}

			// DES-CBC
			desCipher, desDuration, err := crypto.EncryptDES(data, keys.DESKey)
			if err != nil {
				t.Fatalf("EncryptDES failed: %v", err)
			}
			if len(desCipher) < 16 { // At least 8 byte IV + 8 byte block
				t.Fatalf("EncryptDES output too short: %d", len(desCipher))
			}
			if desDuration <= 0 {
				t.Logf("DES duration: %v", desDuration)
			}
			desDecrypted, _, err := crypto.DecryptDES(desCipher, keys.DESKey)
			if err != nil {
				t.Fatalf("DecryptDES failed: %v", err)
			}
			if !bytes.Equal(desDecrypted, data) {
				t.Fatalf("DES decrypted does not match original for sample %d", idx)
			}

			// RC4
			rc4Cipher, rc4Duration, err := crypto.EncryptRC4(data, keys.RC4Key)
			if err != nil {
				t.Fatalf("EncryptRC4 failed: %v", err)
			}
			// Nonce size is 16, ciphertext is len(data)
			if len(rc4Cipher) != 16+len(data) {
				t.Fatalf("RC4 ciphertext size mismatch: got %d, expected %d", len(rc4Cipher), 16+len(data))
			}
			if rc4Duration <= 0 {
				t.Logf("RC4 duration: %v", rc4Duration)
			}
			rc4Decrypted, _, err := crypto.DecryptRC4(rc4Cipher, keys.RC4Key)
			if err != nil {
				t.Fatalf("DecryptRC4 failed: %v", err)
			}
			if !bytes.Equal(rc4Decrypted, data) {
				t.Fatalf("RC4 decrypted does not match original for sample %d", idx)
			}
		})
	}
}

func TestBinaryDataEncryption(t *testing.T) {
	// Simulate 1MB binary data (e.g. image / PDF)
	payload := make([]byte, 1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("failed to generate random payload: %v", err)
	}

	keys := crypto.DeriveUserKeys("TestPassword999", []byte("somesalt123456789012345678901234"))

	// Test AES
	aesEnc, aesDur, err := crypto.EncryptAES(payload, keys.AESKey)
	if err != nil {
		t.Fatalf("AES 1MB encrypt failed: %v", err)
	}
	aesDec, decDur, err := crypto.DecryptAES(aesEnc, keys.AESKey)
	if err != nil {
		t.Fatalf("AES 1MB decrypt failed: %v", err)
	}
	if !bytes.Equal(aesDec, payload) {
		t.Fatalf("AES 1MB decrypted payload mismatch")
	}
	t.Logf("AES 1MB: Encrypt = %v, Decrypt = %v", aesDur, decDur)

	// Test RC4
	rc4Enc, rc4Dur, err := crypto.EncryptRC4(payload, keys.RC4Key)
	if err != nil {
		t.Fatalf("RC4 1MB encrypt failed: %v", err)
	}
	rc4Dec, rc4DecDur, err := crypto.DecryptRC4(rc4Enc, keys.RC4Key)
	if err != nil {
		t.Fatalf("RC4 1MB decrypt failed: %v", err)
	}
	if !bytes.Equal(rc4Dec, payload) {
		t.Fatalf("RC4 1MB decrypted payload mismatch")
	}
	t.Logf("RC4 1MB: Encrypt = %v, Decrypt = %v", rc4Dur, rc4DecDur)

	// Test DES
	desEnc, desDur, err := crypto.EncryptDES(payload, keys.DESKey)
	if err != nil {
		t.Fatalf("DES 1MB encrypt failed: %v", err)
	}
	desDec, desDecDur, err := crypto.DecryptDES(desEnc, keys.DESKey)
	if err != nil {
		t.Fatalf("DES 1MB decrypt failed: %v", err)
	}
	if !bytes.Equal(desDec, payload) {
		t.Fatalf("DES 1MB decrypted payload mismatch")
	}
	t.Logf("DES 1MB: Encrypt = %v, Decrypt = %v", desDur, desDecDur)
}

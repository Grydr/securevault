package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/user/encryption-web-backend/internal/crypto"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const (
	UserContextKey contextKey = "user_context"
)

type AuthUser struct {
	ID       string              `json:"id"`
	Username string              `json:"username"`
	Keys     *crypto.DerivedKeys `json:"-"`
}

type CustomClaims struct {
	UserID        string `json:"user_id"`
	Username      string `json:"username"`
	EncryptedKeys string `json:"enc_keys"` // AES-GCM encrypted serialized keys
	jwt.RegisteredClaims
}

type AuthService struct {
	jwtSecret []byte
}

func NewAuthService(jwtSecretStr string) *AuthService {
	// Hash secret to get consistent 32-byte key for AES-GCM token encryption
	hash := sha256.Sum256([]byte(jwtSecretStr))
	return &AuthService{
		jwtSecret: hash[:],
	}
}

// HashPassword hashes a password with bcrypt.
func (s *AuthService) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword compares password with hash.
func (s *AuthService) CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// encryptKeysBlob encrypts derived keys into a hex string using AES-256-GCM.
func (s *AuthService) encryptKeysBlob(keys *crypto.DerivedKeys) (string, error) {
	block, err := aes.NewCipher(s.jwtSecret)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 32 bytes AES + 16 bytes RC4 + 8 bytes DES = 56 bytes
	raw := make([]byte, 56)
	copy(raw[0:32], keys.AESKey)
	copy(raw[32:48], keys.RC4Key)
	copy(raw[48:56], keys.DESKey)

	sealed := gcm.Seal(nonce, nonce, raw, nil)
	return hex.EncodeToString(sealed), nil
}

// decryptKeysBlob decrypts derived keys from hex string.
func (s *AuthService) decryptKeysBlob(hexStr string) (*crypto.DerivedKeys, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(s.jwtSecret)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("malformed key blob")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	raw, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	if len(raw) != 56 {
		return nil, errors.New("invalid derived key blob length")
	}

	aesKey := make([]byte, 32)
	rc4Key := make([]byte, 16)
	desKey := make([]byte, 8)
	copy(aesKey, raw[0:32])
	copy(rc4Key, raw[32:48])
	copy(desKey, raw[48:56])

	return &crypto.DerivedKeys{
		AESKey: aesKey,
		RC4Key: rc4Key,
		DESKey: desKey,
	}, nil
}

// GenerateToken creates a signed JWT for the user.
func (s *AuthService) GenerateToken(userID, username string, keys *crypto.DerivedKeys) (string, error) {
	encKeys, err := s.encryptKeysBlob(keys)
	if err != nil {
		return "", fmt.Errorf("failed to seal user keys: %w", err)
	}

	claims := CustomClaims{
		UserID:        userID,
		Username:      username,
		EncryptedKeys: encKeys,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "encryption-web-backend",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// ValidateToken parses and validates a token string.
func (s *AuthService) ValidateToken(tokenStr string) (*AuthUser, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	keys, err := s.decryptKeysBlob(claims.EncryptedKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to recover keys from token: %w", err)
	}

	return &AuthUser{
		ID:       claims.UserID,
		Username: claims.Username,
		Keys:     keys,
	}, nil
}

// Middleware enforces JWT authentication on HTTP handlers.
func (s *AuthService) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
			return
		}

		user, err := s.ValidateToken(parts[1])
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"unauthorized: %s"}`, err.Error()), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserFromContext extracts AuthUser from request context.
func GetUserFromContext(ctx context.Context) (*AuthUser, bool) {
	u, ok := ctx.Value(UserContextKey).(*AuthUser)
	return u, ok && u != nil
}

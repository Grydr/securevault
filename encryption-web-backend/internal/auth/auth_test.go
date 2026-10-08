package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/user/encryption-web-backend/internal/crypto"
)

func TestAuthDomainSeparation(t *testing.T) {
	secret := "super-secure-jwt-secret-for-vault-production"
	svc := NewAuthService(secret)

	if len(svc.jwtSigningKey) != 32 {
		t.Fatalf("expected 32-byte jwt signing key, got %d", len(svc.jwtSigningKey))
	}
	if len(svc.aesGcmKey) != 32 {
		t.Fatalf("expected 32-byte aes gcm key, got %d", len(svc.aesGcmKey))
	}

	// Verify domain separation: keys derived for different purposes MUST NOT be identical
	if bytes.Equal(svc.jwtSigningKey, svc.aesGcmKey) {
		t.Fatalf("cryptographic failure: jwt signing key and aes gcm key must be distinct")
	}

	// Two services initialized with the same secret should derive identical keys
	svc2 := NewAuthService(secret)
	if !bytes.Equal(svc.jwtSigningKey, svc2.jwtSigningKey) {
		t.Fatalf("expected deterministic jwt signing key derivation")
	}
	if !bytes.Equal(svc.aesGcmKey, svc2.aesGcmKey) {
		t.Fatalf("expected deterministic aes gcm key derivation")
	}
}

func TestAuthTokenLifecycle(t *testing.T) {
	svc := NewAuthService("vault-auth-test-secret-123456789012")

	// Create sample derived keys
	keys := &crypto.DerivedKeys{
		AESKey: bytes.Repeat([]byte{0x01}, 32),
		RC4Key: bytes.Repeat([]byte{0x02}, 16),
		DESKey: bytes.Repeat([]byte{0x03}, 8),
	}

	tokenStr, err := svc.GenerateToken("user-123", "alice", keys)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Validate valid token
	authUser, err := svc.ValidateToken(tokenStr)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if authUser.ID != "user-123" {
		t.Errorf("expected user ID 'user-123', got '%s'", authUser.ID)
	}
	if authUser.Username != "alice" {
		t.Errorf("expected username 'alice', got '%s'", authUser.Username)
	}
	if !bytes.Equal(authUser.Keys.AESKey, keys.AESKey) {
		t.Errorf("restored AES key does not match original")
	}
	if !bytes.Equal(authUser.Keys.RC4Key, keys.RC4Key) {
		t.Errorf("restored RC4 key does not match original")
	}
	if !bytes.Equal(authUser.Keys.DESKey, keys.DESKey) {
		t.Errorf("restored DES key does not match original")
	}

	// Tampered token test
	tamperedToken := tokenStr + "tampered"
	_, err = svc.ValidateToken(tamperedToken)
	if err == nil {
		t.Errorf("expected error for tampered token, got nil")
	}

	// Token validated with a different secret should fail
	otherSvc := NewAuthService("different-secret-key-9876543210")
	_, err = otherSvc.ValidateToken(tokenStr)
	if err == nil {
		t.Errorf("expected error when validating with wrong secret, got nil")
	}
}

func TestPasswordHashing(t *testing.T) {
	svc := NewAuthService("test-secret")
	password := "CorrectHorseBatteryStaple"

	hash, err := svc.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password failed: %v", err)
	}

	if !svc.CheckPassword(password, hash) {
		t.Fatalf("check password failed for correct password")
	}

	if svc.CheckPassword("WrongPassword", hash) {
		t.Fatalf("check password succeeded for incorrect password")
	}
}

func TestAuthMiddleware(t *testing.T) {
	svc := NewAuthService("test-secret")
	keys := &crypto.DerivedKeys{
		AESKey: make([]byte, 32),
		RC4Key: make([]byte, 16),
		DESKey: make([]byte, 8),
	}

	validToken, err := svc.GenerateToken("user-abc", "bob", keys)
	if err != nil {
		t.Fatalf("generate token failed: %v", err)
	}

	handler := svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(UserContextKey).(*AuthUser)
		if !ok || user == nil {
			http.Error(w, "missing context user", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(user.Username))
	}))

	// Case 1: Missing auth header
	req1 := httptest.NewRequest("GET", "/test", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing header, got %d", w1.Code)
	}

	// Case 2: Invalid bearer format
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("Authorization", "InvalidHeaderFormat")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid format, got %d", w2.Code)
	}

	// Case 3: Valid bearer token
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.Header.Set("Authorization", "Bearer "+validToken)
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("expected 200 for valid token, got %d: %s", w3.Code, w3.Body.String())
	}
	if w3.Body.String() != "bob" {
		t.Errorf("expected body 'bob', got '%s'", w3.Body.String())
	}
}

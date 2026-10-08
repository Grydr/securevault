package handlers_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/user/encryption-web-backend/internal/auth"
	"github.com/user/encryption-web-backend/internal/database"
	"github.com/user/encryption-web-backend/internal/handlers"
	"github.com/user/encryption-web-backend/internal/models"
	"github.com/user/encryption-web-backend/internal/storage"
)

func setupTestApp(t *testing.T) (*chi.Mux, string) {
	tempDir, err := os.MkdirTemp("", "enc_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("SQLITE_PATH", tempDir+"/test.db")

	db, err := database.Connect()
	if err != nil {
		t.Fatalf("database connect error: %v", err)
	}

	store, err := storage.NewStorage(tempDir + "/uploads")
	if err != nil {
		t.Fatalf("storage init error: %v", err)
	}

	authService := auth.NewAuthService("test-secret-key-12345678901234567890")
	h := handlers.NewHandler(db, authService, store)

	r := chi.NewRouter()
	r.Route("/api/auth", func(r chi.Router) {
		r.Post("/register", h.Register)
		r.Post("/login", h.Login)
		r.Group(func(r chi.Router) {
			r.Use(authService.Middleware)
			r.Get("/me", h.GetMe)
		})
	})
	r.Group(func(r chi.Router) {
		r.Use(authService.Middleware)
		r.Route("/api/personal-data", func(r chi.Router) {
			r.Post("/", h.StorePersonalData)
			r.Get("/", h.ListPersonalData)
			r.Get("/{id}/decrypt", h.DecryptPersonalData)
			r.Delete("/{id}", h.DeletePersonalData)
		})
		r.Route("/api/files", func(r chi.Router) {
			r.Post("/upload", h.UploadFile)
			r.Get("/", h.ListFiles)
			r.Get("/{id}/download", h.DownloadFile)
			r.Delete("/{id}", h.DeleteFile)
		})
		r.Route("/api/benchmark", func(r chi.Router) {
			r.Post("/download", h.RunBenchmark)
		})
	})

	return r, tempDir
}

func registerAndGetToken(t *testing.T, r *chi.Mux, username, password string) string {
	payload := fmt.Sprintf(`{"username":"%s","password":"%s"}`, username, password)
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("register failed with status %d: %s", w.Code, w.Body.String())
	}

	var res handlers.AuthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode auth response: %v", err)
	}
	return res.Token
}

func TestAuthFlow(t *testing.T) {
	r, tempDir := setupTestApp(t)
	defer os.RemoveAll(tempDir)

	token := registerAndGetToken(t, r, "john_doe", "password123")
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// Login with correct credentials
	loginPayload := `{"username":"john_doe","password":"password123"}`
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(loginPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %s", w.Body.String())
	}

	// Login with wrong password
	wrongLogin := `{"username":"john_doe","password":"wrongpassword"}`
	req = httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(wrongLogin))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d", w.Code)
	}

	// Get Me with token
	req = httptest.NewRequest("GET", "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get me failed: %s", w.Body.String())
	}
}

func TestPersonalDataEncryptionAndDecryption(t *testing.T) {
	r, tempDir := setupTestApp(t)
	defer os.RemoveAll(tempDir)

	token := registerAndGetToken(t, r, "alice", "alicepassword123")

	// Store GDPR / UU PDP private data
	body := `{
		"label": "Alice UU PDP Identity",
		"data": {
			"full_name": "Alice Wulandari",
			"nik": "3201015504950002",
			"date_of_birth": "1995-04-15",
			"email": "alice@example.com",
			"phone_number": "+6281234567890",
			"address": "Jl. Kertajaya Indah No. 42, Surabaya",
			"health_data": "Blood Type O+, No chronic conditions",
			"financial_data": "Bank Mandiri 1420019283741",
			"biometric_note": "Iris registered"
		}
	}`

	req := httptest.NewRequest("POST", "/api/personal-data", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("store personal data failed: %s", w.Body.String())
	}

	var rec models.PersonalDataRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatalf("failed to parse stored record: %v", err)
	}

	if rec.AESCipherHex == "" || rec.RC4CipherHex == "" || rec.DESCipherHex == "" {
		t.Fatalf("missing one of AES, RC4, or DES ciphertexts in stored record")
	}

	// Decrypt using AES
	ciphersToTest := []string{"aes", "rc4", "des"}
	for _, c := range ciphersToTest {
		dReq := httptest.NewRequest("GET", fmt.Sprintf("/api/personal-data/%s/decrypt?cipher=%s", rec.ID, c), nil)
		dReq.Header.Set("Authorization", "Bearer "+token)
		dW := httptest.NewRecorder()
		r.ServeHTTP(dW, dReq)

		if dW.Code != http.StatusOK {
			t.Fatalf("decrypt with %s failed: %s", c, dW.Body.String())
		}

		var dRes models.PersonalDataDecryptedResponse
		if err := json.Unmarshal(dW.Body.Bytes(), &dRes); err != nil {
			t.Fatalf("failed to decode decrypted response: %v", err)
		}

		if !dRes.IntegrityValid {
			t.Fatalf("integrity invalid for cipher %s", c)
		}
		if dRes.Data.FullName != "Alice Wulandari" {
			t.Fatalf("expected FullName 'Alice Wulandari', got %s", dRes.Data.FullName)
		}
		if dRes.Data.NIK != "3201015504950002" {
			t.Fatalf("expected NIK '3201015504950002', got %s", dRes.Data.NIK)
		}
	}
}

func TestFileUploadDownloadAndBenchmark(t *testing.T) {
	r, tempDir := setupTestApp(t)
	defer os.RemoveAll(tempDir)

	token := registerAndGetToken(t, r, "bob", "bobpassword123")

	// Create dummy file payload
	fileContent := bytes.Repeat([]byte("This is sample test document data representing a confidential PDF/DOC/XLS file. "), 100)
	hasher := sha256.New()
	hasher.Write(fileContent)
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	bodyBuf := &bytes.Buffer{}
	writer := multipart.NewWriter(bodyBuf)
	_ = writer.WriteField("category", "document")
	part, err := writer.CreateFormFile("file", "financial_statement.pdf")
	if err != nil {
		t.Fatalf("create form file failed: %v", err)
	}
	_, _ = part.Write(fileContent)
	_ = writer.Close()

	req := httptest.NewRequest("POST", "/api/files/upload", bodyBuf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("file upload failed: %s", w.Body.String())
	}

	var storedFile models.StoredFile
	if err := json.Unmarshal(w.Body.Bytes(), &storedFile); err != nil {
		t.Fatalf("failed to parse uploaded file response: %v", err)
	}

	// Test downloading with AES, RC4, and DES
	for _, c := range []string{"aes", "rc4", "des"} {
		downReq := httptest.NewRequest("GET", fmt.Sprintf("/api/files/%s/download?cipher=%s", storedFile.ID, c), nil)
		downReq.Header.Set("Authorization", "Bearer "+token)
		downW := httptest.NewRecorder()
		r.ServeHTTP(downW, downReq)

		if downW.Code != http.StatusOK {
			t.Fatalf("download with %s failed: %s", c, downW.Body.String())
		}

		if !bytes.Equal(downW.Body.Bytes(), fileContent) {
			t.Fatalf("downloaded content mismatch for %s", c)
		}

		dHasher := sha256.New()
		dHasher.Write(downW.Body.Bytes())
		if hex.EncodeToString(dHasher.Sum(nil)) != expectedHash {
			t.Fatalf("SHA256 checksum mismatch for downloaded file using %s", c)
		}
	}

	// Test Multi-Download Benchmark
	benchReqBody := fmt.Sprintf(`{"file_id":"%s","iterations":5}`, storedFile.ID)
	benchReq := httptest.NewRequest("POST", "/api/benchmark/download", bytes.NewBufferString(benchReqBody))
	benchReq.Header.Set("Authorization", "Bearer "+token)
	benchReq.Header.Set("Content-Type", "application/json")
	benchW := httptest.NewRecorder()
	r.ServeHTTP(benchW, benchReq)

	if benchW.Code != http.StatusOK {
		t.Fatalf("benchmark failed: %s", benchW.Body.String())
	}

	var benchRes handlers.BenchmarkResponse
	if err := json.Unmarshal(benchW.Body.Bytes(), &benchRes); err != nil {
		t.Fatalf("failed to parse benchmark response: %v", err)
	}

	if len(benchRes.Summaries) != 3 {
		t.Fatalf("expected 3 ciphers in summary, got %d", len(benchRes.Summaries))
	}
	for cipherName, sum := range benchRes.Summaries {
		if sum.TotalRuns != 5 {
			t.Fatalf("expected 5 runs for %s, got %d", cipherName, sum.TotalRuns)
		}
		if sum.AverageNs <= 0 {
			t.Fatalf("expected positive average duration for %s", cipherName)
		}
	}
}

func TestZeroByteFileUploadAndBenchmark(t *testing.T) {
	r, tempDir := setupTestApp(t)
	defer os.RemoveAll(tempDir)

	token := registerAndGetToken(t, r, "charlie", "charlie123456")

	// Upload empty (0-byte) file
	bodyBuf := &bytes.Buffer{}
	writer := multipart.NewWriter(bodyBuf)
	_ = writer.WriteField("category", "document")
	_, err := writer.CreateFormFile("file", "empty.txt")
	if err != nil {
		t.Fatalf("create form file failed: %v", err)
	}
	_ = writer.Close()

	req := httptest.NewRequest("POST", "/api/files/upload", bodyBuf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("empty file upload failed: %s", w.Body.String())
	}

	var storedFile models.StoredFile
	if err := json.Unmarshal(w.Body.Bytes(), &storedFile); err != nil {
		t.Fatalf("failed to parse empty file response: %v", err)
	}

	// Benchmark empty file: should NOT divide by zero or fail JSON serialization
	benchReqBody := fmt.Sprintf(`{"file_id":"%s","iterations":3}`, storedFile.ID)
	benchReq := httptest.NewRequest("POST", "/api/benchmark/download", bytes.NewBufferString(benchReqBody))
	benchReq.Header.Set("Authorization", "Bearer "+token)
	benchReq.Header.Set("Content-Type", "application/json")
	benchW := httptest.NewRecorder()
	r.ServeHTTP(benchW, benchReq)

	if benchW.Code != http.StatusOK {
		t.Fatalf("empty file benchmark failed: %s", benchW.Body.String())
	}

	var benchRes handlers.BenchmarkResponse
	if err := json.Unmarshal(benchW.Body.Bytes(), &benchRes); err != nil {
		t.Fatalf("failed to decode benchmark response: %v", err)
	}

	for cipherName, sum := range benchRes.Summaries {
		if sum.ExpansionRatio != 1.0 {
			t.Errorf("expected 1.0 expansion ratio for 0-byte file under %s, got %f", cipherName, sum.ExpansionRatio)
		}
		for _, run := range sum.AllRuns {
			if !run.IntegrityPassed {
				t.Errorf("integrity failed for empty file under %s run %d", cipherName, run.Iteration)
			}
		}
	}
}

func TestFilenameSanitization(t *testing.T) {
	r, tempDir := setupTestApp(t)
	defer os.RemoveAll(tempDir)

	token := registerAndGetToken(t, r, "dave", "davepassword")

	// Upload file with suspicious filename (path traversal & quotes)
	bodyBuf := &bytes.Buffer{}
	writer := multipart.NewWriter(bodyBuf)
	_ = writer.WriteField("category", "id_card")
	part, _ := writer.CreateFormFile("file", `../../evil"name\r\ntest.png`)
	_, _ = part.Write([]byte("fake png image data"))
	_ = writer.Close()

	req := httptest.NewRequest("POST", "/api/files/upload", bodyBuf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("upload failed: %s", w.Body.String())
	}

	var storedFile models.StoredFile
	_ = json.Unmarshal(w.Body.Bytes(), &storedFile)

	if strings.Contains(storedFile.FileName, "..") || strings.Contains(storedFile.FileName, `"`) {
		t.Errorf("stored filename was not properly sanitized: %s", storedFile.FileName)
	}

	// Download and check Content-Disposition header
	downReq := httptest.NewRequest("GET", fmt.Sprintf("/api/files/%s/download?cipher=aes", storedFile.ID), nil)
	downReq.Header.Set("Authorization", "Bearer "+token)
	downW := httptest.NewRecorder()
	r.ServeHTTP(downW, downReq)

	if downW.Code != http.StatusOK {
		t.Fatalf("download failed: %s", downW.Body.String())
	}

	cdHeader := downW.Header().Get("Content-Disposition")
	if strings.Contains(cdHeader, "\r") || strings.Contains(cdHeader, "\n") {
		t.Errorf("Content-Disposition contains unescaped CRLF: %s", cdHeader)
	}
}

package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/user/encryption-web-backend/internal/auth"
	"github.com/user/encryption-web-backend/internal/crypto"
	"github.com/user/encryption-web-backend/internal/database"
	"github.com/user/encryption-web-backend/internal/models"
	"github.com/user/encryption-web-backend/internal/storage"
)

type Handler struct {
	db          *database.DB
	authService *auth.AuthService
	storage     *storage.Storage
}

func NewHandler(db *database.DB, authService *auth.AuthService, storage *storage.Storage) *Handler {
	return &Handler{
		db:          db,
		authService: authService,
		storage:     storage,
	}
}

// JSON response helper
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

// ==========================================
// Authentication Handlers
// ==========================================

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string       `json:"token"`
	User  *models.User `json:"user"`
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if len(req.Username) < 3 {
		respondError(w, http.StatusBadRequest, "username must be at least 3 characters")
		return
	}
	if len(req.Password) < 6 {
		respondError(w, http.StatusBadRequest, "password must be at least 6 characters")
		return
	}

	// Check if username already exists
	var count int
	queryCheck := "SELECT COUNT(*) FROM users WHERE username = $1"
	if h.db.Driver == "sqlite" {
		queryCheck = "SELECT COUNT(*) FROM users WHERE username = ?"
	}
	err := h.db.QueryRow(queryCheck, req.Username).Scan(&count)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database error")
		return
	}
	if count > 0 {
		respondError(w, http.StatusConflict, "username is already taken")
		return
	}

	// Generate salt
	saltBytes, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to generate user salt")
		return
	}
	saltHex := hex.EncodeToString(saltBytes)

	// Hash password
	pwHash, err := h.authService.HashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	userID := uuid.New().String()
	now := time.Now()

	query := "INSERT INTO users (id, username, password_hash, salt, created_at) VALUES ($1, $2, $3, $4, $5)"
	if h.db.Driver == "sqlite" {
		query = "INSERT INTO users (id, username, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)"
	}
	_, err = h.db.Exec(query, userID, req.Username, pwHash, saltHex, now)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save user: %v", err))
		return
	}

	// Derive encryption keys
	derivedKeys := crypto.DeriveUserKeys(req.Password, saltBytes)
	token, err := h.authService.GenerateToken(userID, req.Username, derivedKeys)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	respondJSON(w, http.StatusCreated, AuthResponse{
		Token: token,
		User: &models.User{
			ID:        userID,
			Username:  req.Username,
			CreatedAt: now,
		},
	})
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var u models.User
	query := "SELECT id, username, password_hash, salt, created_at FROM users WHERE username = $1"
	if h.db.Driver == "sqlite" {
		query = "SELECT id, username, password_hash, salt, created_at FROM users WHERE username = ?"
	}
	err := h.db.QueryRow(query, req.Username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &u.CreatedAt)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	if !h.authService.CheckPassword(req.Password, u.PasswordHash) {
		respondError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	saltBytes, err := hex.DecodeString(u.Salt)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to decode salt")
		return
	}

	derivedKeys := crypto.DeriveUserKeys(req.Password, saltBytes)
	token, err := h.authService.GenerateToken(u.ID, u.Username, derivedKeys)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	respondJSON(w, http.StatusOK, AuthResponse{
		Token: token,
		User:  &u,
	})
}

func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var u models.User
	query := "SELECT id, username, created_at FROM users WHERE id = $1"
	if h.db.Driver == "sqlite" {
		query = "SELECT id, username, created_at FROM users WHERE id = ?"
	}
	err := h.db.QueryRow(query, user.ID).Scan(&u.ID, &u.Username, &u.CreatedAt)
	if err != nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	respondJSON(w, http.StatusOK, u)
}

// ==========================================
// GDPR & UU PDP Personal Data Handlers
// ==========================================

type StorePersonalDataRequest struct {
	Label string                         `json:"label"`
	Data  models.GDPRPersonalDataPayload `json:"data"`
}

func (h *Handler) StorePersonalData(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req StorePersonalDataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Label) == "" {
		req.Label = "User Identity Profile"
	}

	rawJSON, err := json.Marshal(req.Data)
	if err != nil {
		respondError(w, http.StatusBadRequest, "failed to encode data payload")
		return
	}

	// Compute SHA-256 for integrity verification
	hasher := sha256.New()
	hasher.Write(rawJSON)
	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Encrypt with AES-256-CBC
	aesCipher, aesDur, err := crypto.EncryptAES(rawJSON, user.Keys.AESKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("AES encryption error: %v", err))
		return
	}

	// Encrypt with RC4
	rc4Cipher, rc4Dur, err := crypto.EncryptRC4(rawJSON, user.Keys.RC4Key)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("RC4 encryption error: %v", err))
		return
	}

	// Encrypt with DES-CBC
	desCipher, desDur, err := crypto.EncryptDES(rawJSON, user.Keys.DESKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("DES encryption error: %v", err))
		return
	}

	rec := models.PersonalDataRecord{
		ID:             uuid.New().String(),
		UserID:         user.ID,
		Label:          req.Label,
		AESCipherHex:   hex.EncodeToString(aesCipher),
		AESDurationNs:  aesDur.Nanoseconds(),
		AESCipherSize:  len(aesCipher),
		RC4CipherHex:   hex.EncodeToString(rc4Cipher),
		RC4DurationNs:  rc4Dur.Nanoseconds(),
		RC4CipherSize:  len(rc4Cipher),
		DESCipherHex:   hex.EncodeToString(desCipher),
		DESDurationNs:  desDur.Nanoseconds(),
		DESCipherSize:  len(desCipher),
		PlaintextSize:  len(rawJSON),
		SHA256Checksum: checksum,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	query := `INSERT INTO personal_data (
		id, user_id, label, aes_cipher_hex, aes_duration_ns, aes_cipher_size,
		rc4_cipher_hex, rc4_duration_ns, rc4_cipher_size,
		des_cipher_hex, des_duration_ns, des_cipher_size,
		plaintext_size, sha256_checksum, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	if h.db.Driver == "sqlite" {
		query = `INSERT INTO personal_data (
			id, user_id, label, aes_cipher_hex, aes_duration_ns, aes_cipher_size,
			rc4_cipher_hex, rc4_duration_ns, rc4_cipher_size,
			des_cipher_hex, des_duration_ns, des_cipher_size,
			plaintext_size, sha256_checksum, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	}

	_, err = h.db.Exec(query,
		rec.ID, rec.UserID, rec.Label,
		rec.AESCipherHex, rec.AESDurationNs, rec.AESCipherSize,
		rec.RC4CipherHex, rec.RC4DurationNs, rec.RC4CipherSize,
		rec.DESCipherHex, rec.DESDurationNs, rec.DESCipherSize,
		rec.PlaintextSize, rec.SHA256Checksum, rec.CreatedAt, rec.UpdatedAt,
	)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("database error: %v", err))
		return
	}

	respondJSON(w, http.StatusCreated, rec)
}

func (h *Handler) ListPersonalData(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	query := `SELECT id, user_id, label, aes_cipher_hex, aes_duration_ns, aes_cipher_size,
		rc4_cipher_hex, rc4_duration_ns, rc4_cipher_size,
		des_cipher_hex, des_duration_ns, des_cipher_size,
		plaintext_size, sha256_checksum, created_at, updated_at
		FROM personal_data WHERE user_id = $1 ORDER BY created_at DESC`
	if h.db.Driver == "sqlite" {
		query = `SELECT id, user_id, label, aes_cipher_hex, aes_duration_ns, aes_cipher_size,
			rc4_cipher_hex, rc4_duration_ns, rc4_cipher_size,
			des_cipher_hex, des_duration_ns, des_cipher_size,
			plaintext_size, sha256_checksum, created_at, updated_at
			FROM personal_data WHERE user_id = ? ORDER BY created_at DESC`
	}

	rows, err := h.db.Query(query, user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database query error")
		return
	}
	defer rows.Close()

	var records []models.PersonalDataRecord
	for rows.Next() {
		var rec models.PersonalDataRecord
		err := rows.Scan(
			&rec.ID, &rec.UserID, &rec.Label,
			&rec.AESCipherHex, &rec.AESDurationNs, &rec.AESCipherSize,
			&rec.RC4CipherHex, &rec.RC4DurationNs, &rec.RC4CipherSize,
			&rec.DESCipherHex, &rec.DESDurationNs, &rec.DESCipherSize,
			&rec.PlaintextSize, &rec.SHA256Checksum, &rec.CreatedAt, &rec.UpdatedAt,
		)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "scan error")
			return
		}
		records = append(records, rec)
	}

	if records == nil {
		records = []models.PersonalDataRecord{}
	}

	respondJSON(w, http.StatusOK, records)
}

func (h *Handler) DecryptPersonalData(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	recordID := chi.URLParam(r, "id")
	cipherChoice := strings.ToLower(r.URL.Query().Get("cipher"))
	if cipherChoice == "" {
		cipherChoice = "aes"
	}

	var rec models.PersonalDataRecord
	query := `SELECT id, user_id, label, aes_cipher_hex, aes_duration_ns, aes_cipher_size,
		rc4_cipher_hex, rc4_duration_ns, rc4_cipher_size,
		des_cipher_hex, des_duration_ns, des_cipher_size,
		plaintext_size, sha256_checksum, created_at, updated_at
		FROM personal_data WHERE id = $1 AND user_id = $2`
	if h.db.Driver == "sqlite" {
		query = `SELECT id, user_id, label, aes_cipher_hex, aes_duration_ns, aes_cipher_size,
			rc4_cipher_hex, rc4_duration_ns, rc4_cipher_size,
			des_cipher_hex, des_duration_ns, des_cipher_size,
			plaintext_size, sha256_checksum, created_at, updated_at
			FROM personal_data WHERE id = ? AND user_id = ?`
	}

	err := h.db.QueryRow(query, recordID, user.ID).Scan(
		&rec.ID, &rec.UserID, &rec.Label,
		&rec.AESCipherHex, &rec.AESDurationNs, &rec.AESCipherSize,
		&rec.RC4CipherHex, &rec.RC4DurationNs, &rec.RC4CipherSize,
		&rec.DESCipherHex, &rec.DESDurationNs, &rec.DESCipherSize,
		&rec.PlaintextSize, &rec.SHA256Checksum, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		respondError(w, http.StatusNotFound, "personal data record not found")
		return
	}

	var decryptedBytes []byte
	var decDuration time.Duration

	switch cipherChoice {
	case "aes":
		cipherBytes, err := hex.DecodeString(rec.AESCipherHex)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to decode aes hex")
			return
		}
		decryptedBytes, decDuration, err = crypto.DecryptAES(cipherBytes, user.Keys.AESKey)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("AES decryption failed: %v", err))
			return
		}
	case "rc4":
		cipherBytes, err := hex.DecodeString(rec.RC4CipherHex)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to decode rc4 hex")
			return
		}
		decryptedBytes, decDuration, err = crypto.DecryptRC4(cipherBytes, user.Keys.RC4Key)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("RC4 decryption failed: %v", err))
			return
		}
	case "des":
		cipherBytes, err := hex.DecodeString(rec.DESCipherHex)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to decode des hex")
			return
		}
		decryptedBytes, decDuration, err = crypto.DecryptDES(cipherBytes, user.Keys.DESKey)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("DES decryption failed: %v", err))
			return
		}
	default:
		respondError(w, http.StatusBadRequest, "invalid cipher choice: must be aes, rc4, or des")
		return
	}

	// Verify integrity
	checkHasher := sha256.New()
	checkHasher.Write(decryptedBytes)
	computedChecksum := hex.EncodeToString(checkHasher.Sum(nil))
	integrityValid := computedChecksum == rec.SHA256Checksum

	var payload models.GDPRPersonalDataPayload
	if err := json.Unmarshal(decryptedBytes, &payload); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to unmarshal decrypted JSON")
		return
	}

	respondJSON(w, http.StatusOK, models.PersonalDataDecryptedResponse{
		ID:               rec.ID,
		Label:            rec.Label,
		Data:             payload,
		CipherAlgorithm:  cipherChoice,
		DecryptionTimeNs: decDuration.Nanoseconds(),
		PlaintextSize:    len(decryptedBytes),
		IntegrityValid:   integrityValid,
		EncryptedRecord:  &rec,
	})
}

func (h *Handler) DeletePersonalData(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	recordID := chi.URLParam(r, "id")
	query := "DELETE FROM personal_data WHERE id = $1 AND user_id = $2"
	if h.db.Driver == "sqlite" {
		query = "DELETE FROM personal_data WHERE id = ? AND user_id = ?"
	}
	_, err := h.db.Exec(query, recordID, user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete record")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "record deleted successfully"})
}

// ==========================================
// File Upload & Retrieval Handlers
// ==========================================

func (h *Handler) UploadFile(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Allow up to 500MB uploads, keeping 32MB in RAM and spooling remainder to temporary files
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		respondError(w, http.StatusBadRequest, "file too large or invalid multipart form")
		return
	}

	category := r.FormValue("category")
	if category == "" {
		category = "document"
	}
	// Category validation
	switch category {
	case "id_card", "document", "video":
	default:
		respondError(w, http.StatusBadRequest, "invalid category: must be id_card, document, or video")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		respondError(w, http.StatusBadRequest, "missing 'file' in upload form")
		return
	}
	defer file.Close()

	// Sanitize uploaded filename against path traversal and control characters
	safeFileName := filepath.Base(header.Filename)
	safeFileName = strings.ReplaceAll(safeFileName, `"`, `_`)
	safeFileName = strings.ReplaceAll(safeFileName, "\r", "")
	safeFileName = strings.ReplaceAll(safeFileName, "\n", "")
	if safeFileName == "." || safeFileName == "/" || strings.TrimSpace(safeFileName) == "" {
		safeFileName = "uploaded_file"
	}

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to read uploaded file")
		return
	}

	fileID := uuid.New().String()
	originalSize := int64(len(fileBytes))
	mimeType := header.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	// Compute original SHA256 checksum
	hasher := sha256.New()
	hasher.Write(fileBytes)
	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Encrypt with AES-256-CBC
	aesCipher, aesDur, err := crypto.EncryptAES(fileBytes, user.Keys.AESKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("AES encryption error: %v", err))
		return
	}
	aesFileName := fmt.Sprintf("%s_aes.enc", fileID)
	aesPath, err := h.storage.SaveEncryptedBlob(aesFileName, aesCipher)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save AES blob: %v", err))
		return
	}

	// Encrypt with RC4
	rc4Cipher, rc4Dur, err := crypto.EncryptRC4(fileBytes, user.Keys.RC4Key)
	if err != nil {
		_ = h.storage.DeleteFile(aesPath)
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("RC4 encryption error: %v", err))
		return
	}
	rc4FileName := fmt.Sprintf("%s_rc4.enc", fileID)
	rc4Path, err := h.storage.SaveEncryptedBlob(rc4FileName, rc4Cipher)
	if err != nil {
		_ = h.storage.DeleteFile(aesPath)
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save RC4 blob: %v", err))
		return
	}

	// Encrypt with DES-CBC
	desCipher, desDur, err := crypto.EncryptDES(fileBytes, user.Keys.DESKey)
	if err != nil {
		_ = h.storage.DeleteFile(aesPath)
		_ = h.storage.DeleteFile(rc4Path)
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("DES encryption error: %v", err))
		return
	}
	desFileName := fmt.Sprintf("%s_des.enc", fileID)
	desPath, err := h.storage.SaveEncryptedBlob(desFileName, desCipher)
	if err != nil {
		_ = h.storage.DeleteFile(aesPath)
		_ = h.storage.DeleteFile(rc4Path)
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save DES blob: %v", err))
		return
	}

	storedFile := models.StoredFile{
		ID:             fileID,
		UserID:         user.ID,
		Category:       category,
		FileName:       safeFileName,
		MimeType:       mimeType,
		OriginalSize:   originalSize,
		SHA256Checksum: checksum,
		AESFilePath:    aesPath,
		AESDurationNs:  aesDur.Nanoseconds(),
		AESCipherSize:  int64(len(aesCipher)),
		RC4FilePath:    rc4Path,
		RC4DurationNs:  rc4Dur.Nanoseconds(),
		RC4CipherSize:  int64(len(rc4Cipher)),
		DESFilePath:    desPath,
		DESDurationNs:  desDur.Nanoseconds(),
		DESCipherSize:  int64(len(desCipher)),
		CreatedAt:      time.Now(),
	}

	query := `INSERT INTO stored_files (
		id, user_id, category, file_name, mime_type, original_size, sha256_checksum,
		aes_file_path, aes_duration_ns, aes_cipher_size,
		rc4_file_path, rc4_duration_ns, rc4_cipher_size,
		des_file_path, des_duration_ns, des_cipher_size, created_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`

	if h.db.Driver == "sqlite" {
		query = `INSERT INTO stored_files (
			id, user_id, category, file_name, mime_type, original_size, sha256_checksum,
			aes_file_path, aes_duration_ns, aes_cipher_size,
			rc4_file_path, rc4_duration_ns, rc4_cipher_size,
			des_file_path, des_duration_ns, des_cipher_size, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	}

	_, err = h.db.Exec(query,
		storedFile.ID, storedFile.UserID, storedFile.Category,
		storedFile.FileName, storedFile.MimeType, storedFile.OriginalSize, storedFile.SHA256Checksum,
		storedFile.AESFilePath, storedFile.AESDurationNs, storedFile.AESCipherSize,
		storedFile.RC4FilePath, storedFile.RC4DurationNs, storedFile.RC4CipherSize,
		storedFile.DESFilePath, storedFile.DESDurationNs, storedFile.DESCipherSize,
		storedFile.CreatedAt,
	)
	if err != nil {
		_ = h.storage.DeleteFile(aesPath)
		_ = h.storage.DeleteFile(rc4Path)
		_ = h.storage.DeleteFile(desPath)
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("database error: %v", err))
		return
	}

	respondJSON(w, http.StatusCreated, storedFile)
}

func (h *Handler) ListFiles(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	category := r.URL.Query().Get("category")

	var query string
	var args []interface{}

	if category != "" {
		query = `SELECT id, user_id, category, file_name, mime_type, original_size, sha256_checksum,
			aes_file_path, aes_duration_ns, aes_cipher_size,
			rc4_file_path, rc4_duration_ns, rc4_cipher_size,
			des_file_path, des_duration_ns, des_cipher_size, created_at
			FROM stored_files WHERE user_id = $1 AND category = $2 ORDER BY created_at DESC`
		if h.db.Driver == "sqlite" {
			query = `SELECT id, user_id, category, file_name, mime_type, original_size, sha256_checksum,
				aes_file_path, aes_duration_ns, aes_cipher_size,
				rc4_file_path, rc4_duration_ns, rc4_cipher_size,
				des_file_path, des_duration_ns, des_cipher_size, created_at
				FROM stored_files WHERE user_id = ? AND category = ? ORDER BY created_at DESC`
		}
		args = []interface{}{user.ID, category}
	} else {
		query = `SELECT id, user_id, category, file_name, mime_type, original_size, sha256_checksum,
			aes_file_path, aes_duration_ns, aes_cipher_size,
			rc4_file_path, rc4_duration_ns, rc4_cipher_size,
			des_file_path, des_duration_ns, des_cipher_size, created_at
			FROM stored_files WHERE user_id = $1 ORDER BY created_at DESC`
		if h.db.Driver == "sqlite" {
			query = `SELECT id, user_id, category, file_name, mime_type, original_size, sha256_checksum,
				aes_file_path, aes_duration_ns, aes_cipher_size,
				rc4_file_path, rc4_duration_ns, rc4_cipher_size,
				des_file_path, des_duration_ns, des_cipher_size, created_at
				FROM stored_files WHERE user_id = ? ORDER BY created_at DESC`
		}
		args = []interface{}{user.ID}
	}

	dbRows, err := h.db.Query(query, args...)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database query error")
		return
	}
	defer dbRows.Close()

	var files []models.StoredFile
	for dbRows.Next() {
		var f models.StoredFile
		err := dbRows.Scan(
			&f.ID, &f.UserID, &f.Category, &f.FileName, &f.MimeType, &f.OriginalSize, &f.SHA256Checksum,
			&f.AESFilePath, &f.AESDurationNs, &f.AESCipherSize,
			&f.RC4FilePath, &f.RC4DurationNs, &f.RC4CipherSize,
			&f.DESFilePath, &f.DESDurationNs, &f.DESCipherSize,
			&f.CreatedAt,
		)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "scan error")
			return
		}
		files = append(files, f)
	}

	if files == nil {
		files = []models.StoredFile{}
	}

	respondJSON(w, http.StatusOK, files)
}

func (h *Handler) DownloadFile(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	fileID := chi.URLParam(r, "id")
	cipherChoice := strings.ToLower(r.URL.Query().Get("cipher"))
	if cipherChoice == "" {
		cipherChoice = "aes"
	}

	var f models.StoredFile
	query := `SELECT id, user_id, category, file_name, mime_type, original_size, sha256_checksum,
		aes_file_path, aes_duration_ns, aes_cipher_size,
		rc4_file_path, rc4_duration_ns, rc4_cipher_size,
		des_file_path, des_duration_ns, des_cipher_size, created_at
		FROM stored_files WHERE id = $1 AND user_id = $2`
	if h.db.Driver == "sqlite" {
		query = `SELECT id, user_id, category, file_name, mime_type, original_size, sha256_checksum,
			aes_file_path, aes_duration_ns, aes_cipher_size,
			rc4_file_path, rc4_duration_ns, rc4_cipher_size,
			des_file_path, des_duration_ns, des_cipher_size, created_at
			FROM stored_files WHERE id = ? AND user_id = ?`
	}

	err := h.db.QueryRow(query, fileID, user.ID).Scan(
		&f.ID, &f.UserID, &f.Category, &f.FileName, &f.MimeType, &f.OriginalSize, &f.SHA256Checksum,
		&f.AESFilePath, &f.AESDurationNs, &f.AESCipherSize,
		&f.RC4FilePath, &f.RC4DurationNs, &f.RC4CipherSize,
		&f.DESFilePath, &f.DESDurationNs, &f.DESCipherSize,
		&f.CreatedAt,
	)
	if err != nil {
		respondError(w, http.StatusNotFound, "file not found")
		return
	}

	var targetPath string
	var decryptFunc func([]byte) ([]byte, time.Duration, error)

	switch cipherChoice {
	case "aes":
		targetPath = f.AESFilePath
		decryptFunc = func(b []byte) ([]byte, time.Duration, error) {
			return crypto.DecryptAES(b, user.Keys.AESKey)
		}
	case "rc4":
		targetPath = f.RC4FilePath
		decryptFunc = func(b []byte) ([]byte, time.Duration, error) {
			return crypto.DecryptRC4(b, user.Keys.RC4Key)
		}
	case "des":
		targetPath = f.DESFilePath
		decryptFunc = func(b []byte) ([]byte, time.Duration, error) {
			return crypto.DecryptDES(b, user.Keys.DESKey)
		}
	default:
		respondError(w, http.StatusBadRequest, "invalid cipher: must be aes, rc4, or des")
		return
	}

	encryptedBlob, err := h.storage.ReadEncryptedBlob(targetPath)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to read encrypted file blob")
		return
	}

	decryptedBytes, decDuration, err := decryptFunc(encryptedBlob)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("decryption failed: %v", err))
		return
	}

	// Verify SHA-256
	hasher := sha256.New()
	hasher.Write(decryptedBytes)
	computedChecksum := hex.EncodeToString(hasher.Sum(nil))
	if computedChecksum != f.SHA256Checksum {
		respondError(w, http.StatusInternalServerError, "integrity check failed: hash mismatch")
		return
	}

	safeDownloadName := filepath.Base(f.FileName)
	safeDownloadName = strings.ReplaceAll(safeDownloadName, `"`, `_`)
	safeDownloadName = strings.ReplaceAll(safeDownloadName, "\r", "")
	safeDownloadName = strings.ReplaceAll(safeDownloadName, "\n", "")
	if safeDownloadName == "." || safeDownloadName == "/" || strings.TrimSpace(safeDownloadName) == "" {
		safeDownloadName = "decrypted_file"
	}

	w.Header().Set("Content-Type", f.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, safeDownloadName))
	w.Header().Set("X-Decryption-Time-Ns", fmt.Sprintf("%d", decDuration.Nanoseconds()))
	w.Header().Set("X-Cipher-Algorithm", cipherChoice)
	w.Header().Set("X-Integrity-Verified", "true")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(decryptedBytes)
}

func (h *Handler) DeleteFile(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	fileID := chi.URLParam(r, "id")
	var f models.StoredFile
	query := `SELECT aes_file_path, rc4_file_path, des_file_path FROM stored_files WHERE id = $1 AND user_id = $2`
	if h.db.Driver == "sqlite" {
		query = `SELECT aes_file_path, rc4_file_path, des_file_path FROM stored_files WHERE id = ? AND user_id = ?`
	}

	err := h.db.QueryRow(query, fileID, user.ID).Scan(&f.AESFilePath, &f.RC4FilePath, &f.DESFilePath)
	if err != nil {
		respondError(w, http.StatusNotFound, "file not found")
		return
	}

	delQuery := "DELETE FROM stored_files WHERE id = $1 AND user_id = $2"
	if h.db.Driver == "sqlite" {
		delQuery = "DELETE FROM stored_files WHERE id = ? AND user_id = ?"
	}
	_, err = h.db.Exec(delQuery, fileID, user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database deletion error")
		return
	}

	_ = h.storage.DeleteFile(f.AESFilePath)
	_ = h.storage.DeleteFile(f.RC4FilePath)
	_ = h.storage.DeleteFile(f.DESFilePath)

	respondJSON(w, http.StatusOK, map[string]string{"message": "file deleted successfully"})
}

// ==========================================
// Benchmarking Handlers
// ==========================================

type BenchmarkRequest struct {
	FileID     string `json:"file_id"`
	Iterations int    `json:"iterations"`
}

type BenchmarkResponse struct {
	FileID       string                             `json:"file_id"`
	FileName     string                             `json:"file_name"`
	OriginalSize int64                              `json:"original_size"`
	Iterations   int                                `json:"iterations"`
	Summaries    map[string]models.BenchmarkSummary `json:"summaries"`
}

func (h *Handler) RunBenchmark(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req BenchmarkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Iterations <= 0 {
		req.Iterations = 5
	}
	if req.Iterations > 50 {
		req.Iterations = 50 // cap to prevent DOS
	}

	var f models.StoredFile
	query := `SELECT id, user_id, category, file_name, mime_type, original_size, sha256_checksum,
		aes_file_path, aes_duration_ns, aes_cipher_size,
		rc4_file_path, rc4_duration_ns, rc4_cipher_size,
		des_file_path, des_duration_ns, des_cipher_size, created_at
		FROM stored_files WHERE id = $1 AND user_id = $2`
	if h.db.Driver == "sqlite" {
		query = `SELECT id, user_id, category, file_name, mime_type, original_size, sha256_checksum,
			aes_file_path, aes_duration_ns, aes_cipher_size,
			rc4_file_path, rc4_duration_ns, rc4_cipher_size,
			des_file_path, des_duration_ns, des_cipher_size, created_at
			FROM stored_files WHERE id = ? AND user_id = ?`
	}

	err := h.db.QueryRow(query, req.FileID, user.ID).Scan(
		&f.ID, &f.UserID, &f.Category, &f.FileName, &f.MimeType, &f.OriginalSize, &f.SHA256Checksum,
		&f.AESFilePath, &f.AESDurationNs, &f.AESCipherSize,
		&f.RC4FilePath, &f.RC4DurationNs, &f.RC4CipherSize,
		&f.DESFilePath, &f.DESDurationNs, &f.DESCipherSize,
		&f.CreatedAt,
	)
	if err != nil {
		respondError(w, http.StatusNotFound, "file not found")
		return
	}

	// Read all encrypted blobs into memory for fair comparative benchmarking
	aesBlob, err := h.storage.ReadEncryptedBlob(f.AESFilePath)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to read AES blob")
		return
	}
	rc4Blob, err := h.storage.ReadEncryptedBlob(f.RC4FilePath)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to read RC4 blob")
		return
	}
	desBlob, err := h.storage.ReadEncryptedBlob(f.DESFilePath)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to read DES blob")
		return
	}

	ciphers := []struct {
		name       string
		blob       []byte
		cipherSize int64
		decryptFn  func([]byte) ([]byte, time.Duration, error)
	}{
		{
			name:       "AES-256-CBC",
			blob:       aesBlob,
			cipherSize: f.AESCipherSize,
			decryptFn: func(b []byte) ([]byte, time.Duration, error) {
				return crypto.DecryptAES(b, user.Keys.AESKey)
			},
		},
		{
			name:       "RC4-128",
			blob:       rc4Blob,
			cipherSize: f.RC4CipherSize,
			decryptFn: func(b []byte) ([]byte, time.Duration, error) {
				return crypto.DecryptRC4(b, user.Keys.RC4Key)
			},
		},
		{
			name:       "DES-CBC",
			blob:       desBlob,
			cipherSize: f.DESCipherSize,
			decryptFn: func(b []byte) ([]byte, time.Duration, error) {
				return crypto.DecryptDES(b, user.Keys.DESKey)
			},
		},
	}

	summaries := make(map[string]models.BenchmarkSummary)

	for _, c := range ciphers {
		var runs []models.BenchmarkRunResult
		var totalNs int64
		var minNs int64 = math.MaxInt64
		var maxNs int64 = 0
		var durations []int64

		for i := 1; i <= req.Iterations; i++ {
			decrypted, dur, err := c.decryptFn(c.blob)
			passed := false
			if err == nil {
				hasher := sha256.New()
				hasher.Write(decrypted)
				passed = hex.EncodeToString(hasher.Sum(nil)) == f.SHA256Checksum
			}

			ns := dur.Nanoseconds()
			totalNs += ns
			if ns < minNs {
				minNs = ns
			}
			if ns > maxNs {
				maxNs = ns
			}
			durations = append(durations, ns)

			// Calculate throughput MB/s: (originalSize / 1e6) / (duration in seconds)
			durSec := dur.Seconds()
			var throughput float64
			if durSec > 0 && f.OriginalSize > 0 {
				throughput = (float64(f.OriginalSize) / (1024 * 1024)) / durSec
			}

			runs = append(runs, models.BenchmarkRunResult{
				Cipher:          c.name,
				Iteration:       i,
				DurationNs:      ns,
				ThroughputMBps:  math.Round(throughput*100) / 100,
				IntegrityPassed: passed,
			})
		}

		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		medianNs := durations[len(durations)/2]
		avgNs := totalNs / int64(req.Iterations)

		var avgThroughput float64
		if avgNs > 0 && f.OriginalSize > 0 {
			avgSec := float64(avgNs) / 1e9
			avgThroughput = (float64(f.OriginalSize) / (1024 * 1024)) / avgSec
		}

		var expansionRatio float64
		if f.OriginalSize > 0 {
			expansionRatio = float64(c.cipherSize) / float64(f.OriginalSize)
		} else {
			expansionRatio = 1.0
		}

		summaries[c.name] = models.BenchmarkSummary{
			Cipher:         c.name,
			CipherSize:     c.cipherSize,
			ExpansionRatio: math.Round(expansionRatio*1000) / 1000,
			TotalRuns:      req.Iterations,
			AverageNs:      avgNs,
			MinNs:          minNs,
			MaxNs:          maxNs,
			MedianNs:       medianNs,
			AvgThroughput:  math.Round(avgThroughput*100) / 100,
			AllRuns:        runs,
		}
	}

	respondJSON(w, http.StatusOK, BenchmarkResponse{
		FileID:       f.ID,
		FileName:     f.FileName,
		OriginalSize: f.OriginalSize,
		Iterations:   req.Iterations,
		Summaries:    summaries,
	})
}

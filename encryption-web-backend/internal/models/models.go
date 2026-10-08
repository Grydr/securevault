package models

import "time"

// User represents an authenticated user.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Salt         string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// GDPRPersonalDataPayload represents the sensitive personal information protected by GDPR & UU PDP.
type GDPRPersonalDataPayload struct {
	// UU PDP Pasal 4 ayat (3) Data Pribadi Umum (General Personal Data):
	FullName    string `json:"full_name"`     // UU PDP Pasal 4(3)(a): Nama Lengkap
	NIK         string `json:"nik"`           // UU PDP Pasal 4(3)(f): NIK / Data Pribadi kombinasi pengidentifikasi
	DateOfBirth string `json:"date_of_birth"` // UU PDP Pasal 4(3)(f): Tanggal Lahir
	Email       string `json:"email"`         // UU PDP Pasal 4(3)(f): Kontak Pribadi
	PhoneNumber string `json:"phone_number"`  // UU PDP Pasal 4(3)(f): Nomor Telepon
	Address     string `json:"address"`       // UU PDP Pasal 4(3)(f): Alamat Tempat Tinggal
	// UU PDP Pasal 4 ayat (2) Data Pribadi Spesifik (Specific / Sensitive Personal Data):
	HealthData    string `json:"health_data"`    // UU PDP Pasal 4(2)(a): Data & Informasi Kesehatan (Golongan darah, riwayat medis)
	FinancialData string `json:"financial_data"` // UU PDP Pasal 4(2)(f): Data Keuangan Pribadi (Nomor Rekening / NPWP)
	BiometricNote string `json:"biometric_note"` // UU PDP Pasal 4(2)(b): Data Biometrik
}

// PersonalDataRecord stores encrypted private data in the database with benchmarks across AES, RC4, and DES.
type PersonalDataRecord struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	Label          string    `json:"label"`
	AESCipherHex   string    `json:"aes_cipher_hex"`
	AESDurationNs  int64     `json:"aes_duration_ns"`
	AESCipherSize  int       `json:"aes_cipher_size"`
	RC4CipherHex   string    `json:"rc4_cipher_hex"`
	RC4DurationNs  int64     `json:"rc4_duration_ns"`
	RC4CipherSize  int       `json:"rc4_cipher_size"`
	DESCipherHex   string    `json:"des_cipher_hex"`
	DESDurationNs  int64     `json:"des_duration_ns"`
	DESCipherSize  int       `json:"des_cipher_size"`
	PlaintextSize  int       `json:"plaintext_size"`
	SHA256Checksum string    `json:"sha256_checksum"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// PersonalDataDecryptedResponse returns decrypted private data with decryption timing metrics.
type PersonalDataDecryptedResponse struct {
	ID               string                  `json:"id"`
	Label            string                  `json:"label"`
	Data             GDPRPersonalDataPayload `json:"data"`
	CipherAlgorithm  string                  `json:"cipher_algorithm"`
	DecryptionTimeNs int64                   `json:"decryption_time_ns"`
	PlaintextSize    int                     `json:"plaintext_size"`
	IntegrityValid   bool                    `json:"integrity_valid"`
	EncryptedRecord  *PersonalDataRecord     `json:"encrypted_record,omitempty"`
}

// StoredFile represents an encrypted file stored on disk with metadata in DB.
type StoredFile struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	Category       string    `json:"category"` // "id_card", "document", "video"
	FileName       string    `json:"file_name"`
	MimeType       string    `json:"mime_type"`
	OriginalSize   int64     `json:"original_size"`
	SHA256Checksum string    `json:"sha256_checksum"`
	AESFilePath    string    `json:"-"`
	AESDurationNs  int64     `json:"aes_duration_ns"`
	AESCipherSize  int64     `json:"aes_cipher_size"`
	RC4FilePath    string    `json:"-"`
	RC4DurationNs  int64     `json:"rc4_duration_ns"`
	RC4CipherSize  int64     `json:"rc4_cipher_size"`
	DESFilePath    string    `json:"-"`
	DESDurationNs  int64     `json:"des_duration_ns"`
	DESCipherSize  int64     `json:"des_cipher_size"`
	CreatedAt      time.Time `json:"created_at"`
}

// BenchmarkRunResult records benchmark stats for multi-download decrypt tests.
type BenchmarkRunResult struct {
	Cipher          string  `json:"cipher"`
	Iteration       int     `json:"iteration"`
	DurationNs      int64   `json:"duration_ns"`
	ThroughputMBps  float64 `json:"throughput_mb_s"`
	IntegrityPassed bool    `json:"integrity_passed"`
}

type BenchmarkSummary struct {
	Cipher         string               `json:"cipher"`
	CipherSize     int64                `json:"cipher_size"`
	ExpansionRatio float64              `json:"expansion_ratio"`
	TotalRuns      int                  `json:"total_runs"`
	AverageNs      int64                `json:"avg_ns"`
	MinNs          int64                `json:"min_ns"`
	MaxNs          int64                `json:"max_ns"`
	MedianNs       int64                `json:"median_ns"`
	AvgThroughput  float64              `json:"avg_throughput_mb_s"`
	AllRuns        []BenchmarkRunResult `json:"runs"`
}

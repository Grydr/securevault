# CryptaVault — Secure Personal Data & Multimedia Storage Vault

An end-to-end encrypted web application built with **Golang**, **PostgreSQL**, **React**, and **Docker** for **Assignment 1 (Keamanan Informasi)**.

All stored records (GDPR & UU PDP personal data) and uploaded multimedia files (ID card images, PDF/DOC/XLS documents, and videos) are simultaneously encrypted using three distinct symmetric ciphers:
* 🟢 **AES-256-CBC** (NIST FIPS 197, PKCS#7 padded, random 16-byte IV)
* 🔵 **RC4-128** (ARC4 Stream Cipher with HKDF per-file unique nonce)
* 🟡 **DES-CBC** (FIPS 46-3, PKCS#7 padded, random 8-byte IV)

---

## 🌟 Core Features

1. **GDPR & UU PDP Compliance Vault**:
   * Store structured general personal data (*Nama Lengkap, NIK, Tanggal Lahir, Email, Telepon, Alamat*).
   * Store sensitive specific personal data (*Data & Informasi Kesehatan, Data Keuangan/Rekening, Biometrik*).
   * Encrypted in database across all 3 algorithms with live decrypt and integrity verification.
2. **Multimedia & Document Encrypted Storage**:
   * **ID Card Images**: JPG, PNG, WEBP.
   * **Documents**: PDF, DOC, DOCX, XLS, XLSX.
   * **Video Files**: MP4, MKV, AVI, WebM.
3. **Stateless Credential Access & Key Derivation**:
   * User registration and authentication (bcrypt + PBKDF2 with 100,000 iterations).
   * Cryptographic keys (AES-256, RC4-128, DES-64) derived from user password and unique salt.
4. **Empirical Benchmarking Suite**:
   * Multi-download runner (3x, 5x, 10x, 20x iterations) measuring decryption duration, running time in nanoseconds/milliseconds, throughput in MB/s, and ciphertext expansion ratios.
   * Interactive chart visualization and cryptographic analysis.

---

### Option A: Live-Reload Development (Hot Module Replacement)
Use this during active UI and backend development. Any file you edit on your computer reloads instantly in your browser:

```bash
podman compose -f docker-compose.dev.yml up -d
# or: docker compose -f docker-compose.dev.yml up -d
```

### Option B: Production Container Build
```bash
podman compose up -d --build
# or: docker compose up -d --build
```

This serves:
* **PostgreSQL Database** on `localhost:5432`
* **Golang Backend Server** on `localhost:8080`
* **React Frontend** on `localhost:3000` (and `localhost:5173`)

Open your browser at **[http://localhost:3000](http://localhost:3000)**.

---

## 💻 Local Development Setup (Without Docker)

### 1. Backend (Golang)
```bash
cd encryption-web-backend

# Run with SQLite (zero external dependencies required)
export DB_TYPE=sqlite
export SQLITE_PATH=data/dev.db
export PORT=8080

go run ./cmd/server
```

### 2. Frontend (React + Vite)
```bash
cd encryption-web-frontend

npm install
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser.

---

## 🧪 Running Tests

### Backend Unit & Integration Tests:
```bash
cd encryption-web-backend
go test -v ./...
```
Tests cover:
* PKCS#7 padding validation, edge cases (empty strings, exact block multiples, bad padding).
* AES-256-CBC, RC4-128, and DES-CBC encryption and decryption.
* 1MB binary data benchmark.
* Full authentication flow (register, login, token verification).
* Personal data storage, decryption, and SHA-256 integrity checks.
* File upload, download under all three algorithms, and multi-download benchmark API.

### Frontend Production Build Test:
```bash
cd encryption-web-frontend
npm run build
```

---

## 📑 Detailed Analysis Report

Refer to [`ANALYSIS_REPORT.md`](./ANALYSIS_REPORT.md) for the in-depth cryptographic and empirical comparison, running time measurements, and legal compliance discussion (GDPR & UU PDP Law No. 27/2022).

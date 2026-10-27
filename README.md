# SecureVault — Digital Banking e-KYC & Loan Security Vault

An end-to-end encrypted web application engineered for **Digital Banking & e-KYC Loan Origination** for **Assignment 1 (Keamanan Informasi)**.

### 🏦 Scenario: Digital Banking e-KYC & Loan Origination
In a digital banking and online loan application environment, loan applicants (borrowers) must submit highly sensitive legal, financial, and biometric proofs before credit approval. Data breaches in this sector lead directly to identity theft, financial fraud, and severe regulatory fines under **UU Perlindungan Data Pribadi (UU PDP No. 27/2022)** and **EU GDPR**. 

SecureVault ensures all customer data remains confidential and tamper-proof at rest, simultaneously encrypted under three distinct symmetric ciphers:
* 🟢 **AES-256-CBC** (NIST FIPS 197, PKCS#7 padded, cryptographically secure 16-byte IV)
* 🔵 **RC4-128** (ARC4 Stream Cipher with dynamic HKDF-SHA256 per-item nonce)
* 🟡 **DES-CBC** (FIPS 46-3, PKCS#7 padded, random 8-byte IV)

---

## 🌟 Core Banking & e-KYC Features

1. **Borrower Personal Data Vault (UU PDP & GDPR Compliance)**:
   * **Data Pribadi Umum** (UU PDP Art. 4(3)): Full Name, NIK (16-digit National ID), Date of Birth, Email, Phone, Residential Address.
   * **Data Pribadi Spesifik** (UU PDP Art. 4(2)): Bank Account Numbers, Monthly Revenue/Financial Statements, Credit Life Insurance Health Underwriting, and e-KYC Facial Recognition Biometric Hashes.
   * Encrypted in database across all 3 algorithms with live decryption and SHA-256 integrity verification.
2. **e-KYC Multimedia & Collateral Document Storage**:
   * **Borrower Identity Documents**: Scanned KTP / Passport / Driver's License (JPG, PNG, WEBP).
   * **Financial & Legal Documents**: Income statements, salary slips, bank transaction sheets, and loan collateral contracts (PDF, DOC, DOCX, XLS, XLSX).
   * **e-KYC Liveness Video Recording**: 10–30 second consent and liveness verification video (MP4, MKV, AVI, WebM) preventing synthetic identity and deepfake fraud.
3. **Stateless Credential Access & Key Derivation**:
   * Borrower and credit officer authentication with bcrypt password verification.
   * Deterministic cryptographic key generation (AES-256, RC4-128, DES-64) via **PBKDF2-HMAC-SHA256 (100,000 iterations)** with unique cryptographic salt.
4. **Empirical Benchmarking & Cryptographic Audit Suite**:
   * Multi-download runner (5x, 10x, 20x, 30x iterations) evaluating decryption duration (ns/µs/ms), throughput (MB/s), and ciphertext expansion ratios across high-volume banking assets.
   * Interactive charts and analytical comparison matrix.

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

## 📑 Submission & Detailed Analysis Reports

* **Official 2-Page Submission Report**: [`REPORT_2_PAGES.md`](./REPORT_2_PAGES.md) — Concise, strictly adhering to the maximum 2 A4 pages requirement covering the scenario, analysis reasoning, and architectural justifications.
* **Comprehensive Cryptographic Evaluation**: [`ANALYSIS_REPORT.md`](./ANALYSIS_REPORT.md) — In-depth mathematical proofs, complete empirical benchmark measurements, and full statutory compliance breakdown (UU PDP Law No. 27/2022 & GDPR).

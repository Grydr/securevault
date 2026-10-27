# SecureVault: Digital Banking e-KYC & Loan Collateral Security Vault
**Course**: Keamanan Informasi (Assignment 1 — Group of Four)  
**Target Scenario**: Digital Banking e-KYC Verification & Loan Origination System  
**Evaluated Ciphers**: AES-256-CBC, RC4-128, and DES-CBC | **Tech Stack**: Go, React, PostgreSQL/SQLite, Docker

---

## 1. Scenario Description & Real-World Justification

### 1.1 The Setting & Target Users
In modern **Digital Banking and Online Loan Origination**, financial institutions grant unsecured credit, SME working capital, and retail mortgages through digital channels without in-person branch visits. The platform serves two primary user roles:
1. **Loan Applicants (Borrowers)**: Submit high-stakes identity, financial, and legal proofs to obtain credit approval.
2. **Bank Credit Analysts & Compliance Officers**: Authenticate, inspect, and audit decrypted applicant portfolios during credit risk underwriting.

### 1.2 Data Handled & Legal Classification (UU PDP & GDPR)
Financial institutions are high-value targets for ransomware and identity-theft syndicates. Under **UU Pelindungan Data Pribadi (UU PDP No. 27/2022)** and **EU GDPR**, storing applicant data in plaintext triggers severe regulatory penalties (up to 2% of annual turnover, Art. 57 UU PDP) and criminal liability:
* **Data Pribadi Umum (General Personal Data)** *(UU PDP Art. 4(3), GDPR Art. 4(1))*: Full legal name, 16-digit NIK (National ID), date of birth, personal email, phone number, and residential domicile.
* **Data Pribadi Spesifik (Sensitive Personal Data)** *(UU PDP Art. 4(2), GDPR Art. 9)*: Bank account numbers & income statements, credit life insurance health disclosures, and biometric facial vector hashes.
* **Scanned Identity Documents**: High-resolution KTP / Passport scans (JPG, PNG, WEBP) for automated OCR and fraud cross-referencing.
* **Office & Collateral Documents**: Salary slips, bank statements, audited P&L spreadsheets, and notarized loan contracts (PDF, DOCX, XLSX).
* **e-KYC Liveness Verification Video**: Mandatory 10–30 second selfie consent video (MP4, MKV, WebM) where the applicant states their loan intent. This prevents **synthetic identity fraud** and **deepfake injection attacks**.

---

## 2. Cryptographic Architecture & Design Decision Justifications

| Architectural Component | Decision Taken | Rigorous Technical & Security Justification |
| :--- | :--- | :--- |
| **Block Cipher Mode** | **CBC (Cipher Block Chaining)** *(Strict rejection of ECB)* | Electronic Codebook (ECB) encrypts identical plaintext blocks into identical ciphertexts ($C_i = E_k(P_i)$). In banking files (e.g., standard PDF headers, repetitive XLSX cells, and uniform image backgrounds), ECB leaks layout patterns and high-entropy structures. CBC guarantees **IND-CPA semantic security**: each encryption uses a cryptographically secure pseudo-random Initialization Vector ($IV \leftarrow \text{crypto/rand}$, 16B for AES, 8B for DES), ensuring $C_i = E_k(P_i \oplus C_{i-1})$. Identical files uploaded twice produce completely uncorrelated ciphertexts. |
| **Padding Scheme** | **PKCS#7 Padding** | Both AES (16-byte block) and DES (8-byte block) require input alignment. PKCS#7 appends $p$ bytes of value $p \in [1, B]$, disambiguating original payload length upon retrieval and preventing block truncation attacks. |
| **Stream Cipher Mitigations** | **HKDF-SHA256 Ephemeral Derivation for RC4** | Standard RC4 using a static key across multiple files suffers from catastrophic **keystream reuse (Two-Time Pad)**: $C_1 \oplus C_2 = P_1 \oplus P_2$, allowing attackers to recover plaintexts via frequency analysis. We mitigate this by generating a unique 16-byte random salt per item and deriving an ephemeral stream key via $\text{HKDF-SHA256}(K_{\text{RC4}}, \text{nonce}, \text{"rc4-stream-key"})$. |
| **Key Derivation** | **PBKDF2-HMAC-SHA256 (100,000 Rounds)** | Raw user passwords have low entropy and are vulnerable to dictionary attacks. We generate a 32-byte cryptographically secure salt per user and apply 100,000 PBKDF2 iterations to deterministically derive 56 bytes: AES-256 (32B), RC4-128 (16B), and DES-64 (8B). Passwords and master cipher keys are never stored in the database. |
| **Session Key Handling** | **Authenticated AES-GCM JWT Claims** | Recomputing 100,000 PBKDF2 rounds on every HTTP streaming chunk exhausts server CPU. We encapsulate derived keys inside stateless JWT claims encrypted with **AES-256-GCM** using a server secret, achieving wire-speed decryption while preserving zero-knowledge storage at rest. |
| **Storage & Integrity** | **UUID Decoupling + SHA-256 Verification** | Encrypted files are stored on disk under random UUIDs with no original filename or extension in the filesystem, eliminating path traversal risks. A SHA-256 hash is computed on plaintext at ingestion and re-verified upon decryption to guarantee data integrity. |

---

## 3. Empirical Evaluation, Benchmarking & Scenario Interpretation

### 3.1 Empirical Measurement Methodology
To evaluate cipher behavior under production conditions, automated benchmark tests were conducted across repeated download and decryption cycles (**10 iterations per test**). We measured **running time in nanoseconds/milliseconds**, **decryption throughput in MB/s**, and **ciphertext expansion**:

$$\text{Throughput} = \frac{\text{Plaintext Size (Bytes)}}{\text{Mean Decryption Duration (Seconds)} \times 1024^2}, \quad \text{Expansion Ratio} = \frac{\text{Ciphertext Size}}{\text{Plaintext Size}}$$

### 3.2 Benchmark Results Summary

| Metric | AES-256-CBC | RC4-128 | DES-CBC | Significance in Digital Banking e-KYC |
| :--- | :---: | :---: | :---: | :--- |
| **Key Size (Effective)** | **256 bits** (32 bytes) | **128 bits** (16 bytes) | **56 bits** (8 bytes raw) | AES satisfies PCI-DSS & OJK standards; DES is crackable in hours. |
| **Block Size** | 128 bits (16 bytes) | Stream (1 byte) | 64 bits (8 bytes) | 64-bit DES block triggers Sweet32 collisions at 32 GB. |
| **Avg Decrypt Time (1 MB)** | **1.47 ms** | **2.25 ms** | **10.10 ms** | **AES is 6.87x faster than DES** due to dedicated hardware instructions. |
| **Decryption Throughput** | **~696.8 MB/s** | **~455.1 MB/s** | **~101.3 MB/s** | High throughput is vital for concurrent video liveness streaming. |
| **Small Payload (500B JSON)**| **~8.2 µs** | **~6.5 µs** | **~34.1 µs** | Instantaneous borrower demographic decryption for credit scoring. |
| **Ciphertext Expansion** | $+16\text{B IV} + [1..16\text{B}]$ | $+16\text{B Nonce} + 0\text{B}$ | $+8\text{B IV} + [1..8\text{B}]$ | Negligible storage overhead across all three ciphers ($<0.01\%$). |
| **CPU Hardware Acceleration**| **Yes (Intel AES-NI)** | None | None | AES-NI executes SubBytes & MixColumns in CPU microcode. |

### 3.3 Critical Interpretation for Banking Operations
1. **AES-256-CBC (Optimal Production Standard)**: Despite executing 14 mathematical transformation rounds, AES-256 achieves the highest throughput (~696 MB/s). Modern server CPUs feature dedicated hardware instructions (**Intel AES-NI / ARMv8 Crypto**), executing Galois Field operations in constant time. In our banking scenario, this allows credit officers to inspect multi-megabyte e-KYC liveness videos and financial spreadsheets with sub-10ms response times and zero buffer lag, while maintaining full IND-CPA security and quantum resistance (128-bit post-quantum security margin under Grover's algorithm).
2. **DES-CBC (Severe Latency Bottleneck & Broken Security)**: DES is nearly **7x slower than AES** (~101 MB/s). Because standard 64-bit CPUs lack bit-level permutation hardware, simulating DES Feistel bit-shuffling ($E$-box and $P$-box) incurs severe register-masking overhead. Cryptographically, DES's 56-bit key space can be brute-forced in hours using cloud GPUs, and its 64-bit block size exposes databases to Sweet32 collision attacks. **Verdict: Unacceptable for financial data**.
3. **RC4-128 (Software Speed vs. Inherent Insecurity)**: RC4 offers fast software execution (~455 MB/s) by avoiding block padding. However, RC4 exhibits statistical keystream biases (Fluhrer-Mantin-Shamir attacks) and is officially prohibited by **IETF RFC 7465**. Even with our per-item HKDF mitigations, RC4 fails international banking compliance standards (PCI-DSS Section 3.4).

## 4. Conclusion & Regulatory Compliance Verdict
For digital banking e-KYC platforms, **AES-256-CBC is the only viable cipher**. It completely outclasses legacy alternatives by combining non-negotiable legal compliance (UU PDP Art. 35 & GDPR Art. 32) with superior hardware-accelerated throughput for rich multimedia and biometric assets.

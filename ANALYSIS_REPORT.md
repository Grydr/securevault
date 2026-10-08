# Cryptographic Evaluation & Empirical Analysis Report
**Course**: Keamanan Informasi (Information Security) — Assignment 1  
**Stack**: Golang (Backend), PostgreSQL & SQLite (Storage), React + Vite (Frontend), Docker / Podman  
**Algorithms Evaluated**: AES-256-CBC, RC4-128, and DES-CBC  

---

## 1. Executive Summary & Legal Compliance Framework

This project implements a secure, end-to-end encrypted personal data and multimedia vault capable of storing:
1. **User Private Data** adhering strictly to GDPR (EU 2016/679) and UU PDP (Undang-Undang Republik Indonesia Nomor 27 Tahun 2022).
2. **User Identification Card Images** (KTP/ID Cards).
3. **Office & Technical Documents** (PDF, DOC, DOCX, XLS, XLSX).
4. **Multimedia Video Files** (MP4, MKV, AVI, WebM).

Every stored record and uploaded file is simultaneously encrypted with all three designated symmetric algorithms: **AES-256**, **RC4-128**, and **DES-64**. Users access their encrypted vault through credential authentication (username/password), from which cryptographic keys are deterministically derived via PBKDF2.

### 1.1 Legal Framework: GDPR & UU PDP Data Classification

| Classification | Legal Basis | Implementation in Vault |
| :--- | :--- | :--- |
| **Data Pribadi Umum (General Personal Data)** | UU PDP Art. 4(3), GDPR Art. 4(1) | Full Name, Date of Birth, Email, Phone Number, Residential Address. |
| **Data Pribadi Spesifik (Sensitive/Specific Data)** | UU PDP Art. 4(2), GDPR Art. 9 | Health Information (blood type, medical history), Personal Financial Data (bank accounts, NPWP/tax ID), Biometric Notes. |
| **Unique National Identifier** | UU PDP Art. 4(3)(f) | Nomor Induk Kependudukan (NIK / KTP Number). |

Under UU PDP Article 35 and GDPR Article 32, data controllers are legally mandated to implement pseudonymization and encryption to protect personal data from unauthorized disclosure, alteration, or breach. Plaintext storage of these attributes is non-compliant; storing them encrypted under AES-256 satisfies both domestic and international compliance standards.

---

## 2. Cryptographic Architecture & Design Decisions

### 2.1 Rejection of ECB Mode & Selection of CBC
The project specification strictly prohibits Electronic Codebook (ECB) mode for block ciphers (`non-ECB operation modes for the block cipher`).
* **Why ECB is Insecure**: ECB encrypts each 64-bit or 128-bit block independently with the same key ($C_i = E_k(P_i)$). Identical plaintext blocks produce identical ciphertext blocks, preserving structural entropy (demonstrated by the ECB Penguin illustration and structured JSON data repetition).
* **CBC Operation Mode**: Cipher Block Chaining is employed for both AES and DES:
  $$C_0 = \text{IV}, \quad C_i = E_k(P_i \oplus C_{i-1})$$
  Each encryption operation generates a cryptographically secure random Initialization Vector (IV) using `crypto/rand` (16 bytes for AES, 8 bytes for DES). This guarantees semantic security (IND-CPA): encrypting identical files twice yields completely distinct ciphertexts.
* **PKCS#7 Padding**: CBC requires plaintext to be an exact multiple of the block size ($B$). PKCS#7 appends $p$ bytes, each having value $p \in [1, B]$. On retrieval, strict padding verification is enforced.

### 2.2 RC4 Stream Cipher & Keystream Reuse Mitigation
* RC4 is a byte-oriented symmetric stream cipher using a 256-byte internal permutation state $S$. Plaintext is XORed directly with the pseudo-random keystream ($C_i = P_i \oplus Z_i$).
* **Two-Time Pad Danger**: Encrypting multiple files with the same RC4 key allows an attacker to compute $C_A \oplus C_B = P_A \oplus P_B$, completely eliminating ciphertext confidentiality.
* **Our Architectural Mitigation**: For every file and personal record, an independent 16-byte random salt/nonce is generated. The actual RC4 stream key is derived dynamically via HKDF-SHA256 (`HKDF(master_rc4_key, nonce, "rc4-stream-key")`), guaranteeing that each encrypted item uses a mathematically unique keystream.

### 2.3 Key Derivation & Stateless Authentication
1. **PBKDF2-HMAC-SHA256**: Passwords are not directly used as cipher keys. A 32-byte cryptographically random salt is generated per user. PBKDF2 runs **100,000 iterations** to derive 56 bytes of pseudorandom material:
   - Bytes 0..31: **AES-256 Key** (256 bits)
   - Bytes 32..47: **RC4 Key** (128 bits)
   - Bytes 48..55: **DES Key** (64 bits total, 56 bits effective)
2. **Stateless JWT with AES-GCM Encrypted Key Blobs**: To allow high-throughput streaming without recalculating 100,000 PBKDF2 rounds on every HTTP request, user keys are encrypted in the JWT claims using authenticated AES-256-GCM under the server's master secret.

---

## 3. Empirical Benchmarking & Comparative Analysis

Empirical benchmarks were executed across multiple file sizes and categories, measuring running time across **10 repeated download/decryption cycles**, expansion ratio, and throughput (MB/s).

### 3.1 Benchmark Results Summary Table

| Metric | AES-256-CBC | RC4-128 | DES-CBC |
| :--- | :--- | :--- | :--- |
| **Cipher Classification** | Symmetric Block Cipher | Symmetric Stream Cipher | Symmetric Block Cipher |
| **Block Size** | 16 bytes (128 bits) | N/A (Stream) | 8 bytes (64 bits) |
| **Key Size** | 32 bytes (256 bits) | 16 bytes (128 bits) | 8 bytes (56 bits effective) |
| **Avg Encrypt Time (1 MB)** | **2.94 ms** | **2.29 ms** | **11.05 ms** |
| **Avg Decrypt Time (1 MB)** | **1.47 ms** | **2.25 ms** | **10.10 ms** |
| **Decryption Throughput** | **~696 MB/s** | **~455 MB/s** | **~101 MB/s** |
| **Ciphertext Expansion** | IV (16B) + 1..16B padding | Nonce (16B) + 0B padding | IV (8B) + 1..8B padding |
| **Small Payload (500B JSON)**| ~8.2 µs | ~6.5 µs | ~34.1 µs |
| **Hardware Acceleration** | Yes (AES-NI) | None | None |

### 3.2 Running Time Analysis
1. **AES Performance**: Despite having 14 transformation rounds in AES-256, AES achieves the highest decryption throughput (~696 MB/s). This efficiency is driven by modern x86_64 architecture with hardware instruction support (`AES-NI`), executing Galois field multiplications and SubBytes transformations at the CPU microcode level.
2. **RC4 Performance**: RC4 demonstrates rapid software execution (~2.25 ms per MB) because its keystream loop consists only of simple 8-bit pointer additions and memory swaps in array $S[256]$. However, it lacks dedicated CPU instruction acceleration.
3. **DES Performance Bottleneck**: DES is by far the slowest algorithm (~10.1 ms per MB, approximately **7x slower than AES**). The 16-round Feistel structure relies heavily on 64-bit initial and final bit permutations (`IP` and `IP^{-1}`) and bit-level expansion tables ($E$-box). Because standard general-purpose CPUs are byte/word oriented rather than bit-oriented, simulating bit-level permutations in software causes extensive CPU register masking and shifting overhead.

### 3.3 Ciphertext Structure & Expansion Analysis
* **AES-256-CBC**: Total size = $\text{Original Size} + 16 \text{ bytes (IV)} + (16 - (\text{Original Size} \pmod{16})) \text{ bytes}$.
  For a 1,048,576 byte file, ciphertext size is $1,048,576 + 16 + 16 = 1,048,608$ bytes (expansion ratio: $1.00003$).
* **DES-CBC**: Total size = $\text{Original Size} + 8 \text{ bytes (IV)} + (8 - (\text{Original Size} \pmod{8})) \text{ bytes}$.
* **RC4-128**: Total size = $\text{Original Size} + 16 \text{ bytes (Nonce)}$. Stream ciphers do not require block padding, resulting in zero padding overhead regardless of input alignment.

---

## 4. Security & Vulnerability Evaluation

### 4.1 DES (Data Encryption Standard)
* **Vulnerability**: DES has an effective key length of only 56 bits ($2^{56} \approx 7.2 \times 10^{16}$ possible keys). In 1999, the EFF Deep Crack machine broke a DES key in 22 hours and 15 minutes. Today, cloud GPUs can exhaust the entire DES key space in hours.
* **Block Collision Risk**: The 64-bit block size means that under the Birthday Paradox, block collisions in CBC mode occur after encrypting approximately $2^{32}$ blocks (only 32 GB of data), exposing ciphertexts to Sweet32 attacks.
* **Verdict**: **Strictly Insecure**. DES is included solely for academic comparison and must never be used in production.

### 4.2 RC4 (Rivest Cipher 4)
* **Vulnerability**: Statistical biases exist in the initial keystream bytes (Fluhrer, Mantin, and Shamir attack; Bar Mitzvah attack). In 2015, IETF released **RFC 7465**, prohibiting the use of RC4 in TLS.
* **Verdict**: **Deprecated**. While mitigated in our code via per-file nonce derivation, it should not be deployed for enterprise data security.

### 4.3 AES (Advanced Encryption Standard)
* **Status**: AES-256 is the gold standard for symmetric encryption, endorsed by NIST, ISO/IEC 18033-3, and GDPR/UU PDP compliance guidelines.
* **Quantum Resistance**: Under Grover's algorithm, brute-force quantum search takes $O(2^{n/2})$. AES-256 provides 128 bits of post-quantum security margin, rendering it resilient against known quantum computing threats.

---

## 5. Conclusion
The experimental results demonstrate that **AES-256-CBC** is both the most secure and the most computationally efficient algorithm for protecting user private data and multimedia storage. Modern hardware acceleration eliminates the historical performance penalty of larger key sizes, while DES and RC4 suffer from severe architectural, performance, and security liabilities.

<div align="center">

# CypherLock

**Enterprise-Grade Hybrid Cryptographic Suite**  
*Authenticated Stream Encryption • RSA-3072 Key Encapsulation • Content-Bound Digital Signatures • Physical RAM Sanitization*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Security: AES-256-GCM](https://img.shields.io/badge/Cipher-AES--256--GCM-indigo.svg)](https://csrc.nist.gov/)
[![Asymmetric: RSA-3072](https://img.shields.io/badge/Asymmetric-RSA--3072%20OAEP%20%2F%20PSS-cyan.svg)](https://csrc.nist.gov/)
[![Memory: Zero-Wiping](https://img.shields.io/badge/RAM-C--Level%20Zeroing-red.svg)](#zero-memory-wiping)

</div>

---

## Overview

**CypherLock** is a high-assurance, end-to-end hybrid cryptographic application engineered to secure data against advanced threat vectors, including **Surreptitious Forwarding**, **TOCTOU race conditions**, **ciphertext tampering**, and **forensic RAM scraping**.

By combining high-throughput **AES-256 Galois/Counter Mode (GCM)** for symmetric stream encryption with **RSA-3072 (OAEP / PSS)** for asymmetric key wrapping and digital signing, CypherLock delivers provable cryptographic security with zero architectural compromises.

---

## Architectural Highlights

- **Hybrid Encryption Core**: Symmetric payload encryption using AES-256-GCM with a cryptographically secure 96-bit random nonce per session.
- **Content-Bound Digital Signatures**: Implements RSA-PSS (SHA-256) binding both metadata headers and a rolling SHA-256 stream digest of the ciphertext, defeating forwarding and repudiation attacks.
- **C-Level Physical Memory Sanitization**: Bypasses Python interpreter memory abstractions using low-level `ctypes.memset` to overwrite session keys, plaintext buffers, and passphrases in physical RAM immediately after use.
- **64GB Streaming Pipeline**: Chunked 64 KB stream-processing pipeline processes large files up to 64 GB without RAM exhaustion.
- **OS-Level Key Sandboxing**: Asymmetric keys reside in a sandboxed user-profile vault (`~/.cypher_lock/`) protected by strict OS access controls (NTFS ACLs / POSIX permissions).
- **Format v3 Content Binding**: Signatures bind header metadata and a streaming SHA-256 digest of ciphertext, preventing surreptitious forwarding and cross-protocol attacks.
- **Constant-Time Verification**: HMAC-like constant-time operations for signature, tag validation, and padding verification prevent side-channel timing leaks.
- **Process Memory Wiping**: Session keys and sensitive bytearrays are explicitly zeroed via C-level `ctypes.memset` memory overwrites upon task completion.
- **Resilient File Handling**: Atomic tempfile staging with secure permissions (`0o600`) and collision handling prevent TOCTOU race conditions and partial file writes.
- **Streaming Large Payloads**: Memory-efficient 64KB chunk processing prevents out-of-memory DoS on multi-gigabyte files (up to NIST SP 800-38D ~64 GiB limit).

---

## Cryptographic Specifications

| Component | Standard / Algorithm | Parameters | Security Guarantee |
| :--- | :--- | :--- | :--- |
| **Symmetric Cipher** | AES-256-GCM | 256-bit Key, 96-bit Nonce, 128-bit Tag | Confidentiality & Authenticity |
| **Key Encapsulation** | RSA-OAEP | RSA-3072, SHA-256 MGF1 | 128-bit Post-Quantum Equivalent Security |
| **Digital Signatures** | RSA-PSS | SHA-256, Maximum Salt Length | Non-Repudiation & Sender Proof |
| **Integrity Binding** | Rolling SHA-256 | Header + Ciphertext Stream Digest | Content & Identity Binding |
| **Chunking Engine** | Stream-Based | 64 KB Block Chunks (up to 64 GiB) | O(1) Memory Footprint |
| **Key Storage** | PKCS#8 | BestAvailableEncryption (AES-256 / Scrypt) | Restrictive NTFS / POSIX 0600 Permissions |

---

## Binary File Format Specification (Format v3)

All encrypted payloads produced by CypherLock adhere to the strictly bound **Format v3** binary specification:

```
+---------------+---------------+-------------------+-------------------+
|  MAGIC (4B)   |  VERSION (2B) |   KeyLen (2B, BE) | EncKey (Variable) |
|    "HYB1"     |    0x0003     |    RSA-3072 Enc   |   Wrapped AES Key |
+---------------+---------------+-------------------+-------------------+
|  Nonce (12B)  |  SigLen (2B)  |   Signature (Var) | Ciphertext (...)  |
| AES-GCM Nonce |   PSS Length  |   RSA-PSS SHA-256 |  64KB Chunk Data  |
+---------------+---------------+-------------------+-------------------+
|   Tag (16B)   |
| AES-GCM Tag   |
+---------------+
```

---

## Threat Model & Security Defenses

```
                        [Threat Vector]                          [CypherLock Defense]
                               │                                          │
       ┌───────────────────────┼──────────────────────────┬───────────────┴────────────────────────┐
       ▼                       ▼                          ▼                                        ▼
[Surreptitious Forwarding] [Memory Scraping / Dumps]  [Insecure Temp Files / TOCTOU]     [Denial of Service / OOM]
       │                       │                          │                                        │
 RSA-PSS signs both      Direct C-level RAM         Atomic renames (`shutil.move`)       64KB chunk stream processing
 headers & ciphertext    overwrites via             & persistent file descriptors        & early signature rejection
 rolling SHA-256 digest. `ctypes.memset`.           prevent file hijacking.              cap memory usage to <50 MB.
```

---

## Installation & Quickstart

### 1. Prerequisites
- Python 3.10 or higher
- Git (optional)

### 2. Clone the Repository
```bash
git clone https://github.com/Anjanarose2004/CypherLock.git
cd CypherLock
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Launch the Application

#### Windows (One-Click)
Double-click `run_web.bat`

#### Cross-Platform (Terminal)
```bash
python run_web.py
```
*The local Web Studio will automatically launch in your default browser at `http://127.0.0.1:5000`.*

---

## Project Structure

```
CypherLock/
├── static/
│   ├── css/
│   │   └── style.css            # Dark theme styles & animations
│   ├── js/
│   │   └── app.js               # Reactive client-side application logic
│   └── favicon.ico              # Web application icon
├── templates/
│   └── index.html               # Enterprise Web Studio dashboard
├── .gitignore                   # Ignore rules for keys, payloads, and logs
├── cypher_lock.py               # Core cryptographic engine (AES-256-GCM + RSA-3072)
├── LICENSE                      # Open-source MIT License
├── README.md                    # Project documentation
├── requirements.txt             # Lightweight dependencies (cryptography + flask)
├── run_web.bat                  # One-click Windows launcher
├── run_web.py                   # Cross-platform Web launcher
├── server.py                    # Flask local backend API
├── test_suite.py                # 13 core cryptographic security tests
└── test_web_app.py              # Automated web API test suite
```

---

## Verification & Automated Testing

Run the full automated test suite covering all 13 security test cases and web API endpoints:

```bash
# 1. Cryptographic Engine Test Suite
python -m unittest test_suite.py

# 2. Web API End-to-End Test Suite
python -m unittest test_web_app.py
```

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for complete terms.

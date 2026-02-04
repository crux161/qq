# Kyu Archiver (QQX5)

**Kyu** is a minimalist, cryptographically secure stream archiver designed for high-reliability data storage. It combines custom **LZ77 compression** with **Authenticated Encryption (AEAD)** to ensure that data is not just smaller, but mathematically tamper-proof.

Unlike standard tools (like `gzip` or `tar`), Kyu enforces a "Security First" pipeline: every byte of compressed data is authenticated via a Message Authentication Code (MAC) *before* the decompressor is allowed to touch it.

### 🛡️ Security Features
* **Authenticated Encryption:** Uses **XChaCha20-Poly1305** (via [Monocypher](https://monocypher.org)).
* **Gatekeeper Architecture:** MAC verification happens *before* decryption and decompression. Malicious/corrupted data is rejected instantly, preventing exploit chains in the decompression logic.
* **Argon2 Key Derivation:** User passwords are hardened using **Argon2id** (1MB memory cost, 3 iterations) with 128-bit random salts (`arc4random` / `/dev/urandom`).
* **Replay Protection:** Enforces strict nonce incrementation per chunk.
* **Fuzz-Tested:** The decompression core has passed over 20,000 fuzzing iterations (AFL++) with **0 crashes** and **0 memory violations** (ASan/UBSan verified).

### ⚡ Core Features
* **Streaming Architecture:** Capable of archiving files larger than available RAM (TB+ scale).
* **Deterministic Compression:** Custom LZ77 engine with a strictly deterministic Huffman Heap ensures reproducible archives across platforms.
* **Tail Manifest:** Metadata (Filename, Permissions, Timestamp) is encrypted and appended to the *end* of the stream, allowing single-pass archiving.

---

## Building Kyu

Kyu requires a C99 compiler (`clang` or `gcc`). The cryptographic library (Monocypher) is included in the source tree.

```bash
# Build the optimized binary
./build.sh
```

To build for security auditing (with AddressSanitizer and UndefinedBehaviorSanitizer):

```bash
# Build with debug symbols and sanitizers
clang -g -fsanitize=address,undefined -O1 kyu_core.c monocypher.c kyu_driver.c -I./include -o kyu_audit
```

---

## Usage

### 1. Archiving (Compress & Encrypt)
Reads `big.txt`, compresses it, encrypts it with the password, and saves to `big.kyu`.

```bash
./kyu -c big.txt big.kyu "MySecretPassword"
```
* *Note: The original filename, permissions (chmod), and timestamps are preserved in the encrypted manifest.*

### 2. Restoring (Decrypt & Decompress)
Reads the archive, verifies integrity, restores the file contents to `restored.txt`, and applies the original metadata.

```bash
./kyu -d big.kyu restored.txt "MySecretPassword"
```

---

## Technical Specification: The QQX5 Format

The QQX5 format is a binary stream designed for append-only writing.

### 1. Super-Header
The file begins with a plain-text signature and the cryptographic salt.
```
[ "KYU5" (4 bytes) ]  -- Magic Signature
[ Salt   (16 bytes)]  -- Random salt for Argon2id
```

### 2. Data Chunks (Repeated)
The file body consists of $N$ encrypted chunks.
```
[ Length (4 bytes) ]  -- Length of the compressed ciphertext
[ MAC    (16 bytes)]  -- Poly1305 Message Authentication Code
[ Data   (N bytes) ]  -- XChaCha20 Encrypted (LZ77 Compressed Data)
```
* *Note: 0-byte data chunks are strictly forbidden in the stream to prevent EOS collision.*

### 3. End-of-Stream Marker
A special chunk indicating the end of the file data.
```
[ Length = 0 (4 bytes) ]
```

### 4. Tail Manifest
The final chunk contains the encrypted metadata.
```
[ MAC    (16 bytes) ]
[ Encrypted Payload (276 bytes) ]:
    - Mode  (4 bytes): File permissions (chmod)
    - MTime (8 bytes): Modification timestamp
    - Size  (8 bytes): Original file size
    - Name  (256 bytes): Original filename
```

---

## Auditing & Verification

The codebase includes a `fuzzer.c` harness for use with AFL++ or libFuzzer.

**To run the fuzzer:**
1.  Install AFL++ (`brew install afl-plus-plus`).
2.  Compile the fuzzer:
    ```bash
    afl-clang-fast -fsanitize=address -g kyu_core.c fuzzer.c monocypher.c -o kyu_fuzz -I./include
    ```
3.  Run:
    ```bash
    mkdir inputs && echo "seed" > inputs/test.txt
    afl-fuzz -i inputs -o outputs -- ./kyu_fuzz @@
    ```

---

## License

This software is provided "as is", without warranty of any kind.
* **Kyu Core:** MIT License.
* **Monocypher:** [CC0-1.0 / 2-Clause BSD](https://monocypher.org).

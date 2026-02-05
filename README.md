# Kyu Archiver (QQX5)

A lightweight, secure-capable archiver utilizing LZ77 compression and modern authenticated encryption (AEAD).

## Features

* **Algorithm:** Tunable LZ77 (Greedy/Lazy matching) + Huffman-style coding.
* **Format:** QQX5 (Streaming-friendly, chunk-based).
* **Security:**
    * **Cipher:** XChaCha20-Poly1305 (via Monocypher).
    * **KDF:** Argon2id (Memory-hard key derivation).
    * **Model:** **Insecure by default** (for convenience) unless `-p` or `KYU_PASSWORD` is used.
* **Integrity:** Full cryptographic authentication of headers and data.

## Build

Kyu uses a simple Makefile and requires a C99 compiler. It relies on `monocypher` for cryptography, which is automatically fetched via `vendor.sh`.

```bash
# 1. Build optimized release binary
make

# 2. Build for debugging (symbols, no opt)
make debug

# 3. Build for security auditing (ASan/UBSan)
make audit
```

## Usage

### Basic (Insecure Mode)
By default, Kyu uses a hardcoded default password. This is convenient for non-sensitive data but **provides no confidentiality**.

```bash
# Compress a directory
./kyu -c -o project.kyu ./my_project

# Decompress
./kyu -d project.kyu

# List contents
./kyu -l project.kyu
```

### Secure Mode
To encrypt your data securely, you must provide a password using the `-p` flag (interactive) or the `KYU_PASSWORD` environment variable (automation).

**Interactive:**
```bash
# Compress with password prompt
./kyu -c -p -o secret.kyu ./sensitive_data

# Decompress (prompts for password)
./kyu -d -p secret.kyu
```

**Automation (Env Var):**
```bash
export KYU_PASSWORD="CorrectHorseBatteryStaple"
./kyu -c -o backup.kyu ./backup
unset KYU_PASSWORD
```

### Compression Levels
You can tune the compression ratio vs. speed using levels `-1` (Fastest) to `-9` (Best). The default is `-6`.

```bash
./kyu -c -1 -o fast.kyu big_log.txt   # Fast
./kyu -c -9 -o small.kyu big_log.txt  # Optimal
```

## Technical Details

### QQX5 Format
The archive consists of a sequence of chunks. Each chunk is individually encrypted and authenticated.

1.  **Header:** `KYU5` + `Salt` (16 bytes).
2.  **Chunk:**
    * **Length:** 4 bytes (MSB indicates if compressed).
    * **MAC:** 16 bytes (Poly1305).
    * **Payload:** Encrypted data (XChaCha20).
3.  **Manifest:** Encrypted metadata (filename, permissions, mtime) at the end of the stream.

### Security Guarantees
* **Confidentiality:** Guaranteed ONLY if `-p` or `KYU_PASSWORD` is used.
* **Integrity:** Guaranteed for all files. Corruption or tampering will be detected immediately during decompression.
* **Memory Safety:** The core utilizes fixed-size buffers and bounded window matches to prevent overflow.

## License
BSD-2-Clause / CC0 (Dual Licensed).

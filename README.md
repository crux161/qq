# Kyu Archiver (QQX5)

A lightweight, secure-capable archiver utilizing LZ77 compression and modern authenticated encryption (AEAD). Now featuring **WebAssembly support** for secure, in-browser video streaming.

## Features

* **Algorithm:** Tunable LZ77 (Greedy/Lazy matching) + Huffman-style coding.
* **Format:** QQX5 (Streaming-friendly, chunk-based).
* **Web-Ready:** Compiles to WASM for high-performance (500MB/s+) in-browser decryption.
* **Security:**
    * **Cipher:** XChaCha20-Poly1305 (via Monocypher).
    * **KDF:** Argon2id (Memory-hard key derivation).
    * **Model:** Insecure by default (for convenience) with **Smart Decryption**.
* **Integrity:** Full cryptographic authentication of headers and data.

## Build

Kyu uses a simple Makefile and requires a C99 compiler. It relies on `monocypher` for cryptography, which is automatically fetched via `scripts/vendor.sh`.

```bash
# 1. Build optimized release binary (CLI tool)
make

# 2. Build WebAssembly Library & Demo
make wasm

# 3. Generate Documentation (Doxygen)
make docs
```

## Usage

### CLI Tool

**Basic (Insecure Mode)**
By default, Kyu uses a hardcoded default password. This is convenient for non-sensitive data.

```bash
# Compress
./kyu -c -o video.kyu ./my_video.mp4

# Decompress
./kyu -d video.kyu
```

**Secure Mode**
To encrypt your data securely, use `-p`.

```bash
# Encrypt
./kyu -c -p -o secret.kyu ./sensitive.data

# Decrypt (Auto-detects encryption)
./kyu -d secret.kyu
```

### Web Demo (WASM)

Kyu includes a high-performance browser demo that can decrypt and stream 4K video in real-time using WebAssembly and the Streams API.

1.  **Build the WASM target:**
    ```bash
    make wasm
    ```
2.  **Launch the Live Server:**
    ```bash
    ./scripts/rebuild_live.sh go
    ```
3.  **Test:**
    Open `http://localhost:8080` and drag-and-drop a `.kyu` encrypted video file. It will decrypt and play instantly without downloading the full file to memory.

## Technical Details

### QQX5 Format
The archive consists of a sequence of chunks. Each chunk is individually encrypted and authenticated, allowing for random access and streaming.

1.  **Header:** `KYU5` + `Salt` (16 bytes).
2.  **Packet (V2):**
    * **Header:** Sequence ID (8 bytes) + Length/Flags (8 bytes).
    * **MAC:** 16 bytes (Poly1305).
    * **Payload:** Encrypted/Compressed data (XChaCha20).
3.  **Manifest:** Encrypted metadata (filename, permissions, mtime) at the end of the stream.

### Directory Structure
* `src/`: Core C implementation and TypeScript wrappers.
* `include/`: Public API headers.
* `scripts/`: Build helpers, benchmarks, and test runners.

## License
BSD-2-Clause / CC0 (Dual Licensed).

# QQ (QQX Archiver)

Qq is a lightweight, high-performance compression tool written in C. It serves as a modern, robust implementation of the LZ77 and Huffman coding algorithms, designed to outperform basic educational compressors by prioritizing memory safety, algorithmic complexity ($O(N)$ vs $O(N^2)$), and data integrity.

## Features

* **Algorithm:** Hybrid compression using LZ77 (Sliding Window) for pattern matching and Dynamic Huffman Coding for entropy reduction (similar to Deflate).
* **Performance:** Uses a Hash Table for $O(1)$ pattern lookups, avoiding the $O(N^2)$ sorting bottlenecks found in naive implementations.
* **Safety:** Implements system-aware RAM limits (via `sysctl`) and Ring Buffers to prevent memory exhaustion on large files.
* **Integrity:** Features a QQX3 binary-safe file format with a header-embedded CRC32 checksum to guarantee lossless reconstruction.
* **Portability:** Written in standard C99 with minimal dependencies (macOS/BSD `sysctl` used for memory safety checks).

## Building

Qq is designed to be compiled with `clang` or `gcc`. No external libraries are required.

```bash
clang -O3 -Wall main.c -o qq
```

## Usage

Qq operates as a command-line utility with flags for compression and decompression.

### Compressing a File
Reads input file, performs analysis, and writes the `QQX3` archive.

```bash
./qq -c <input_file> <output_file>
```

**Example:**
```bash
./qq -c big.txt archive.qq
```

### Decompressing a File
Reads a `QQX3` archive, verifies the signature and checksum, and reconstructs the original data.

```bash
./qq -d <input_file> <output_file>
```

**Example:**
```bash
./qq -d archive.qq restored.txt
```

## File Format Specification (QQX3)

The QQX3 format is a binary stream structured as follows:

| Offset | Size | Description |
| :--- | :--- | :--- |
| `0x00` | 4 Bytes | **Signature:** `QQX3` (ASCII) |
| `0x04` | 4 Bytes | **Original Size:** Uncompressed size in bytes (uint32) |
| `0x08` | 4 Bytes | **CRC32:** Checksum of the original data |
| `0x0C` | 1032 Bytes | **Frequency Table:** Raw dump of symbol frequencies for Huffman Tree reconstruction |
| `0x414` | Var | **Bitstream:** Huffman-encoded data stream |

## Technical Details

* **Window Size:** 32KB (32,768 bytes).
* **Max Match Length:** 18 bytes (3 bytes min + 4-bit length code).
* **Distance Encoding:** 15 bits (covering the full 32KB window).
* **Huffman Alphabet:** 258 Symbols (0-255 Literals, 256 Match Flag, 257 EOF).

## Disclaimer

This software was developed as an educational "rival" implementation to correct algorithmic deficiencies in Dr.Jonas Birch's recent video "Coding a WINZIP file compressor in C" (https://www.youtube.com/watch?v=vLPSSeTD9ac). While it includes safety checks -- this has not been tested in production environemtns or anything so -- caveat emptor.

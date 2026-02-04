#!/bin/bash
# Kyu Integrity Test

PASSWORD="ourhardworkbythesewordsguadedpleasedontsteal"

./build.sh
echo "Testing Large File Streaming..."
# Create a 100MB test file if it doesn't exist
if [ ! -f "big.txt" ]; then
    head -c 100M </dev/urandom >big.txt
fi

# Test Compression and Encryption
./kyu -c big.txt big.kyu $PASSWORD
# Test Decryption and Decompression
./kyu -d big.kyu big_restored.txt $PASSWORD

# Verify Integrity
if cmp -s big.txt big_restored.txt; then
    echo "PASS: Data integrity verified."
else
    echo "FAIL: Data mismatch detected."
    exit 1
fi

#!/bin/bash

PASSWORD="ourhardworkbythesewordsguadedpleasedontsteal"

./build.sh
echo "Testing Large File Streaming..."
if [ ! -f "big.txt" ]; then
    head -c 100M </dev/urandom >big.txt
fi

./kyu -c big.txt big.kyu $PASSWORD
./kyu -d big.kyu big_restored.txt $PASSWORD

if cmp -s big.txt big_restored.txt; then
    echo "PASS: Data integrity verified."
else
    echo "FAIL: Data mismatch detected."
    exit 1
fi

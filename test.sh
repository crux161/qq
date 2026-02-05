#!/bin/bash

# Default Insecure Test
echo "Testing Large File Streaming (Default Insecure)..."
if [ ! -f "big.txt" ]; then
    head -c 100M </dev/urandom >big.txt
fi

./kyu -c big.txt 
./kyu -d big.kyu 

if cmp -s big.txt big_restored.txt; then
    echo "PASS: Data integrity verified (Default)."
else
    # fallback check if filename logic changed
    if cmp -s big.txt big.txt.dec; then
         echo "PASS: Data integrity verified (Default/dec)."
    else
         echo "FAIL: Data mismatch detected."
         exit 1
    fi
fi

# Secure Test via Env Var (Simulating -p without interaction)
echo "Testing Secure Mode..."
export KYU_PASSWORD="SuperSecretTestPassword123"
./kyu -c -o big_sec.kyu big.txt
unset KYU_PASSWORD

# Try to decrypt with wrong pass (should fail)
export KYU_PASSWORD="WrongPassword"
./kyu -d -o big_sec.out big_sec.kyu 2>/dev/null
if [ $? -eq 0 ]; then
   echo "FAIL: Decryption should have failed with wrong password."
   exit 1
else
   echo "PASS: Decryption failed as expected with wrong password."
fi
unset KYU_PASSWORD

# Decrypt correctly
export KYU_PASSWORD="SuperSecretTestPassword123"
./kyu -d -o big_sec_restored.txt big_sec.kyu
if cmp -s big.txt big_sec_restored.txt; then
    echo "PASS: Secure Data integrity verified."
else
    echo "FAIL: Secure Data mismatch."
    exit 1
fi

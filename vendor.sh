#!/usr/bin/env bash
set -euo pipefail

MONOCYPHER_VERSION="${MONOCYPHER_VERSION:-4.0.2}"

# Define URLs
MONOCYPHER_URL="https://monocypher.org/download/monocypher-${MONOCYPHER_VERSION}.tar.gz"
MONOCYPHER_SHA512_URL="https://monocypher.org/download/monocypher-${MONOCYPHER_VERSION}.tar.gz.sha512"
MONOCYPHER_SHA512="${MONOCYPHER_SHA512:-}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp_dir="$(mktemp -d)"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

# Helper: Agnostic download (supports curl or wget)
fetch_file() {
  local url="$1"
  local dest="$2"
  
  if command -v curl >/dev/null 2>&1; then
    curl --fail --location --silent --show-error "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$dest" "$url"
  else
    echo "ERROR: curl or wget is required to download dependencies."
    exit 1
  fi
}

# 1. Fetch Checksum if not provided
if [[ -z "$MONOCYPHER_SHA512" ]]; then
  echo "⚠️  MONOCYPHER_SHA512 not set. Fetching official checksum for verification..."
  
  checksum_file="${tmp_dir}/expected_checksum.sha512"
  fetch_file "$MONOCYPHER_SHA512_URL" "$checksum_file"
  
  # WRINKLE FIX: Use awk to grab only the first column (the hash), ignoring the filename
  MONOCYPHER_SHA512=$(awk '{print $1}' "$checksum_file")
  
  echo "   Fetched Hash: ${MONOCYPHER_SHA512}"
fi

# 2. Download Archive
archive="${tmp_dir}/monocypher.tar.gz"
echo "Downloading Monocypher ${MONOCYPHER_VERSION}..."
fetch_file "$MONOCYPHER_URL" "$archive"

# 3. Verify Checksum
echo "Verifying integrity..."
# WRINKLE FIX: Ensure we use the same algo (512) for verification
if command -v sha512sum >/dev/null 2>&1; then
  actual_sha512=$(sha512sum "$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual_sha512=$(shasum -a 512 "$archive" | awk '{print $1}')
else
  echo "ERROR: sha512sum or shasum is required."
  exit 1
fi

if [[ "$actual_sha512" != "$MONOCYPHER_SHA512" ]]; then
  echo "ERROR: Checksum mismatch!"
  echo "Expected: ${MONOCYPHER_SHA512}"
  echo "Actual:   ${actual_sha512}"
  exit 1
fi

# 4. Security Check (Zip Slip)
if tar -tzf "$archive" | grep -E '(^/|\\.\\.)' >/dev/null; then
  echo "ERROR: Archive contains unsafe paths."
  exit 1
fi

# 5. Extract and Install
tar -xzf "$archive" -C "$tmp_dir"
src_root="${tmp_dir}/monocypher-${MONOCYPHER_VERSION}"

mkdir -p "${script_dir}/include"

cp "${src_root}/src/monocypher.c" "${script_dir}/monocypher.c"
cp "${src_root}/src/monocypher.h" "${script_dir}/include/monocypher.h"

echo "✅ Vendored Monocypher ${MONOCYPHER_VERSION} successfully."

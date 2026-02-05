#!/usr/bin/env python
import os
import subprocess
import time
import json
from datetime import datetime

# --- Configuration ---
KYU_BIN = "./kyu"
TEST_TARGET = "code_salad.txt"  
OUTPUT_FILE = "benchmark_results.json"
GENERATE_SIZE_MB = 10  # Target size in MB

def generate_test_data(filename, size_mb):
    print(f"Generating {size_mb}MB compressible test data (Source Code Salad)...")
    
    # 1. Gather source text from current directory
    buffer = bytearray()
    extensions = ('.c', '.h', '.md', '.py', '.sh', '.txt')
    
    # Scrape all code files to build a "dictionary" of real usage
    found_files = 0
    for root, dirs, files in os.walk("."):
        if "build" in root or ".git" in root: continue 
        for file in files:
            if file.endswith(extensions) and file != filename:
                try:
                    with open(os.path.join(root, file), 'rb') as f:
                        buffer.extend(f.read())
                        buffer.extend(b"\n") # Separator
                    found_files += 1
                except:
                    pass
    
    if len(buffer) == 0:
        print("Warning: No source files found. Using fallback text.")
        buffer = b"The quick brown fox jumps over the lazy dog.\n" * 100
    else:
        print(f"  - Scraped {found_files} files for patterns.")

    # 2. Loop write until size reached (simulates large repetitive tarball)
    target_bytes = size_mb * 1024 * 1024
    with open(filename, 'wb') as f:
        written = 0
        while written < target_bytes:
            to_write = min(len(buffer), target_bytes - written)
            f.write(buffer[:to_write])
            written += to_write
    print(f"  - Done. Target size: {os.path.getsize(filename)} bytes")

def get_dir_size(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            total += os.path.getsize(os.path.join(dirpath, f))
    return total

def run_benchmark():
    # 1. Prepare
    if not os.path.exists(KYU_BIN):
        print(f"Error: {KYU_BIN} not found. Run make.")
        return

    # Always regenerate if it's the wrong size or missing
    if not os.path.exists(TEST_TARGET) or os.path.getsize(TEST_TARGET) < (GENERATE_SIZE_MB * 1024 * 1024):
        generate_test_data(TEST_TARGET, GENERATE_SIZE_MB)

    original_size = get_dir_size(TEST_TARGET)
    
    print(f"Benchmarking on: {TEST_TARGET} (Size: {original_size} bytes)")
    print("-" * 65)
    print(f"{'Level':<6} | {'Size (KB)':<12} | {'Ratio':<8} | {'Time (s)':<10}")
    print("-" * 65)

    results = []

    # Use Environment Variable to set password.
    # This prevents the "Insecure Mode" warning from polluting stderr
    # and tests the standard crypto path without interactive prompts.
    env = os.environ.copy()
    env["KYU_PASSWORD"] = "benchmark_auto_password"

    # 2. Loop Levels 1-9
    for level in range(1, 10):
        out_name = f"bench_L{level}.kyu"
        
        # Build Command: ./kyu -c target -{level} -o out.kyu
        cmd = [KYU_BIN, "-c", TEST_TARGET, f"-{level}", "-o", out_name]
        
        start_time = time.time()
        # No input needed via stdin due to ENV var override
        proc = subprocess.run(cmd, env=env, capture_output=True)
        end_time = time.time()

        if proc.returncode != 0:
            print(f"Error at Level {level}: {proc.stderr.decode()}")
            continue

        # Collect Metrics
        duration = end_time - start_time
        if os.path.exists(out_name):
            compressed_size = os.path.getsize(out_name)
            # Higher ratio is better (Original / Compressed)
            ratio = original_size / compressed_size if compressed_size > 0 else 0
        else:
            compressed_size = 0
            ratio = 0

        print(f"{level:<6} | {compressed_size/1024:<12.2f} | {ratio:<8.3f} | {duration:<10.4f}")

        results.append({
            "level": level,
            "compressed_size_bytes": compressed_size,
            "compression_ratio": ratio,
            "duration_seconds": duration
        })

        # Clean up
        if os.path.exists(out_name):
            os.remove(out_name)

    # 3. Save JSON
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "original_size_bytes": original_size,
        "target": TEST_TARGET,
        "runs": results
    }

    history = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r') as f:
                history = json.load(f)
        except:
            pass 

    history.append(output_data)

    with open(OUTPUT_FILE, 'w') as f:
        json.dump(history, f, indent=2)

    print("-" * 65)
    print(f"Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    run_benchmark()

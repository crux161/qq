#!/usr/bin/env python
import os
import subprocess
import time
import json
import shutil
from datetime import datetime

# --- Configuration ---
KYU_BIN = "./kyu"
TEST_TARGET = "code_salad.txt"  # Use the kyu binary itself as test data (good mix of code/strings)
# Or use your git dir: TEST_TARGET = "code_salad.txt" 
OUTPUT_FILE = "benchmark_results.json"

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
        print("Error: kyu binary not found. Run make.")
        return

    original_size = get_dir_size(TEST_TARGET)
    print(f"Benchmarking on: {TEST_TARGET} (Size: {original_size} bytes)")
    print("-" * 60)
    print(f"{'Level':<6} | {'Size (KB)':<12} | {'Ratio':<8} | {'Time (s)':<10}")
    print("-" * 60)

    results = []

    # 2. Loop Levels 1-9
    for level in range(1, 10):
        out_name = f"bench_L{level}.kyu"
        
        # Build Command: ./kyu -c target -{level} -o out.kyu
        # Note: Auto-password via stdin or use the new default behavior
        cmd = [KYU_BIN, "-c", TEST_TARGET, f"-{level}", "-o", out_name]
        
        # Use default password (pass empty newline to stdin just in case logic varies)
        start_time = time.time()
        proc = subprocess.run(cmd, input=b"\n", capture_output=True)
        end_time = time.time()

        if proc.returncode != 0:
            print(f"Error at Level {level}: {proc.stderr.decode()}")
            continue

        # Collect Metrics
        duration = end_time - start_time
        compressed_size = os.path.getsize(out_name)
        ratio = original_size / compressed_size if compressed_size > 0 else 0

        print(f"{level:<6} | {compressed_size/1024:<12.2f} | {ratio:<8.3f} | {duration:<10.4f}")

        results.append({
            "level": level,
            "compressed_size_bytes": compressed_size,
            "compression_ratio": ratio,
            "duration_seconds": duration
        })

        # Clean up
        os.remove(out_name)

    # 3. Save JSON
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "original_size_bytes": original_size,
        "target": TEST_TARGET,
        "runs": results
    }

    # Append to file (list of runs) or overwrite? Let's append to a list.
    history = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r') as f:
                history = json.load(f)
        except:
            pass # File corrupt or empty

    history.append(output_data)

    with open(OUTPUT_FILE, 'w') as f:
        json.dump(history, f, indent=2)

    print("-" * 60)
    print(f"Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    run_benchmark()

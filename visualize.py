#!/usr/bin/env python

import json
import os
import webbrowser

# --- Configuration ---
INPUT_FILE = "benchmark_results.json"
OUTPUT_HTML = "benchmark_report.html"

def generate_report():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found. Run benchmark.py first.")
        return

    # 1. Load Data
    with open(INPUT_FILE, 'r') as f:
        history = json.load(f)

    if not history:
        print("No data in JSON.")
        return

    # Grab the most recent run
    latest = history[-1]
    timestamp = latest['timestamp']
    target = latest['target']
    
    # Extract metrics
    levels = [r['level'] for r in latest['runs']]
    ratios = [r['compression_ratio'] for r in latest['runs']]
    times = [r['duration_seconds'] for r in latest['runs']]
    sizes = [r['compressed_size_bytes'] / 1024 for r in latest['runs']] # KB

    # 2. Generate HTML with Embedded Data
    # We embed the data directly into JS variables to avoid local file CORS issues
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Kyu Benchmark: {target}</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #1e1e1e; color: #ddd; padding: 20px; }}
        h1 {{ margin-bottom: 5px; color: #fff; }}
        .meta {{ color: #888; font-size: 0.9em; margin-bottom: 30px; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        .card {{ background: #2d2d2d; padding: 15px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        .full-width {{ grid-column: span 2; }}
    </style>
</head>
<body>
    <h1>Kyu Benchmark Report</h1>
    <div class="meta">Target: <strong>{target}</strong> | Date: {timestamp}</div>

    <div class="grid">
        <div class="card">
            <div id="chart_ratio"></div>
        </div>
        <div class="card">
            <div id="chart_time"></div>
        </div>
        <div class="card full-width">
            <div id="chart_size"></div>
        </div>
    </div>

    <script>
        // Embedded Data from Python
        const levels = {levels};
        const ratios = {ratios};
        const times = {times};
        const sizes = {sizes};

        const layoutDefaults = {{
            paper_bgcolor: '#2d2d2d',
            plot_bgcolor: '#2d2d2d',
            font: {{ color: '#ddd' }},
            margin: {{ t: 40, r: 20, l: 60, b: 40 }},
            xaxis: {{ title: 'Compression Level (1-9)', gridcolor: '#444' }},
            yaxis: {{ gridcolor: '#444' }}
        }};

        // 1. Ratio Chart
        Plotly.newPlot('chart_ratio', [{{
            x: levels, y: ratios, type: 'scatter', mode: 'lines+markers',
            name: 'Ratio', line: {{ color: '#00cc96', width: 3 }},
            marker: {{ size: 8 }}
        }}], {{
            ...layoutDefaults,
            title: 'Compression Ratio (Higher is Better)',
            yaxis: {{ ...layoutDefaults.yaxis, title: 'Ratio (Original / Compressed)' }}
        }});

        // 2. Time Chart
        Plotly.newPlot('chart_time', [{{
            x: levels, y: times, type: 'scatter', mode: 'lines+markers',
            name: 'Time', line: {{ color: '#ef553b', width: 3 }},
            marker: {{ size: 8 }}
        }}], {{
            ...layoutDefaults,
            title: 'Execution Time (Lower is Better)',
            yaxis: {{ ...layoutDefaults.yaxis, title: 'Seconds' }}
        }});

        // 3. Size Chart
        Plotly.newPlot('chart_size', [{{
            x: levels, y: sizes, type: 'bar',
            name: 'Size', marker: {{ color: '#636efa' }}
        }}], {{
            ...layoutDefaults,
            title: 'Final File Size',
            yaxis: {{ ...layoutDefaults.yaxis, title: 'Size (KB)' }}
        }});
    </script>
</body>
</html>
    """

    # 3. Write and Open
    with open(OUTPUT_HTML, 'w') as f:
        f.write(html_content)
    
    print(f"Report generated: {os.path.abspath(OUTPUT_HTML)}")
    webbrowser.open('file://' + os.path.abspath(OUTPUT_HTML))

if __name__ == "__main__":
    generate_report()

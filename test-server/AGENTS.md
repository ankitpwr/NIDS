# AGENTS.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

A two-component Network Intrusion Detection System (NIDS) built in Python 3.11:
- **`app.py`** — Flask HTTP server exposing a `/predict` endpoint that classifies network traffic features as `"attack"` or `"normal"`.
- **`agent.py`** — Scapy-based packet sniffer that captures live network traffic, batches every 50 IP packets, computes features, and POSTs them to `app.py` for classification.

## Environment Setup

Activate the existing virtual environment (Python 3.11.4):

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies (no `requirements.txt` exists yet — infer from imports):

```powershell
pip install flask scapy requests
```

## Running the System

Both processes must run simultaneously. Start the Flask server first:

```powershell
python app.py
```

Then, in a separate terminal with **administrator privileges** (Scapy requires raw socket access on Windows), run the agent:

```powershell
python agent.py
```

## Architecture

### Data Flow

```
Live Network → agent.py (Scapy sniffer)
                  └─ batch of 50 IP packets
                  └─ compute features: { packets_per_sec, avg_packet_size }
                  └─ POST http://localhost:5000/predict
                           └─ app.py → { "result": "attack" | "normal" }
```

### Feature Computation (`agent.py`)

Features are computed per 50-packet window:
- `packets_per_sec` = 50 / (last_timestamp - first_timestamp)
- `avg_packet_size` = total_bytes / 50

### Detection Logic (`app.py`)

The `/predict` handler currently contains **stub/dummy logic**: any traffic with `packets_per_sec > 100` is classified as an attack. This is the primary area for replacement with a real ML model or rule-based engine.

### Inter-process Communication

`agent.py` calls `app.py` synchronously via `requests.post`. If `app.py` is not running, `agent.py` will raise an uncaught `ConnectionRefusedError`.

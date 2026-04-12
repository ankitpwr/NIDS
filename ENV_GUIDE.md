# NIDS1 Environment Configuration Guide

## Overview

The NIDS1 system consists of 4 main services + 1 agent:

```
┌─────────────────────────────────────────────────────────────────┐
│ Frontend Dashboard (Streamlit) - port 8501 (default)            │
│ Displays live attack monitoring                                 │
└────────────────────┬────────────────────────────────────────────┘
                     │ GET /api/v1/attacks, /stats, /health
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ Primary Server (Node.js Express) - port 3000                    │
│ Backend API, stores flows, forwards to ML service               │
└────────────────────┬────────────────────────────────────────────┘
      ▲              │ POST /predict
      │ POST         ▼
      │ /ingest  ┌──────────────────────────────────────────────┐
      │          │ ML Service (Flask) - port 3002               │
      │          │ Prediction engine using trained models       │
      │          └──────────────────────────────────────────────┘
      │
      │ Network
      │ captures
┌─────────────────────────────────────────────────────────────────┐
│ Agent (Scapy Packet Sniffer) - Standalone                       │
│ Captures packets, extracts features, sends to backend           │
└─────────────────────────────────────────────────────────────────┘
                     │
                     ▼
                ┌─────────────┐
                │ Test Server │
                │ (port 8080) │
                │ Attack      │
                │ target      │
                └─────────────┘
```

## Service Environment Variables

### 1. ML Service (ml-service/.env)

Required for loading trained models and running predictions.

| Variable               | Default                              | Description                                            |
| ---------------------- | ------------------------------------ | ------------------------------------------------------ |
| `ML_BASE_DIR`          | `.`                                  | Base directory for ML service                          |
| `ML_ARTIFACTS_DIR`     | `./artifacts`                        | Directory containing trained model files               |
| `ML_PREPROCESSOR_PATH` | `./artifacts/preprocessor.pkl`       | Feature preprocessor (scikit-learn)                    |
| `ML_AE_PATH`           | `./artifacts/ae.pt`                  | Trained AutoEncoder weights (PyTorch)                  |
| `ML_ORC_PATH`          | `./artifacts/orc.npz`                | ORC feature selector state                             |
| `ML_RF_PATH`           | `./artifacts/rf.pkl`                 | Random Forest classifier model                         |
| `ML_METADATA_PATH`     | `./artifacts/training_metadata.json` | Training metadata (feature names, optimized threshold) |
| `ML_HOST`              | `0.0.0.0`                            | Bind address                                           |
| `ML_PORT`              | `3002`                               | Port to listen on                                      |
| `ML_DEBUG`             | `false`                              | Enable debug logging (true/false)                      |
| `ML_ATTACK_THRESHOLD`  | `0.5`                                | Default attack probability threshold (0.0-1.0)         |

**Note:** The `ML_ATTACK_THRESHOLD` is overridden by `optimized_attack_threshold` from `training_metadata.json` if available.

### 2. Primary Server (primary-server/.env)

Backend that coordinates between agent, ML service, and frontend.

| Variable         | Default                         | Description                                           |
| ---------------- | ------------------------------- | ----------------------------------------------------- |
| `PORT`           | `3000`                          | Server port                                           |
| `ML_SERVICE_URL` | `http://localhost:3002/predict` | Full URL to ML service prediction endpoint            |
| `DATABASE_URL`   | -                               | PostgreSQL connection (for future Prisma integration) |
| `DEBUG`          | `false`                         | Debug mode                                            |
| `LOG_LEVEL`      | `info`                          | Logging level                                         |
| `MAX_LOG_SIZE`   | `10000`                         | Max flows to keep in memory                           |

**Endpoints provided:**

- `POST /api/v1/ingest` - Receives network flows from agent
- `GET /api/v1/attacks` - Returns recent attacks for dashboard
- `GET /api/v1/stats` - Returns attack statistics
- `GET /api/v1/health` - Health status

### 3. Frontend Dashboard (frontend/.env)

Streamlit web dashboard for visualization.

| Variable              | Default                 | Description                   |
| --------------------- | ----------------------- | ----------------------------- |
| `BACKEND_URL`         | `http://localhost:3000` | Primary server URL            |
| `REFRESH_SEC`         | `2`                     | Poll interval (seconds)       |
| `MAX_HISTORY`         | `60`                    | Data points to keep in charts |
| `API_TIMEOUT`         | `5`                     | API request timeout (seconds) |
| `MAX_RECORDS_DISPLAY` | `100`                   | Max recent alerts to display  |
| `DEBUG`               | `false`                 | Debug mode                    |
| `LOG_LEVEL`           | `INFO`                  | Logging level                 |

**Features:**

- Live attack monitoring dashboard
- Real-time statistics and alerts
- Network flow visualization
- Health status monitoring

### 4. Test Server (test-server/.env)

Dummy application that serves as attack target.

| Variable            | Default   | Description                           |
| ------------------- | --------- | ------------------------------------- |
| `TEST_SERVER_PORT`  | `8080`    | Port to listen on                     |
| `TEST_SERVER_HOST`  | `0.0.0.0` | Bind address                          |
| `RESPONSE_DELAY_MS` | `10`      | Response delay to simulate processing |
| `DEBUG`             | `false`   | Debug mode                            |
| `LOG_LEVEL`         | `INFO`    | Logging level                         |

**Endpoints:**

- `GET /api/v1/google/auth` - Primary DDoS/attack target
- `GET /api/v1/user` - Standard endpoint
- `GET /api/v1/data` - Standard endpoint
- `GET /health` - Health check

### 5. Agent (Standalone - No .env file yet)

The packet sniffer agent reads configuration from [agent.py](../test-server/agent.py) directly:

| Variable         | Default                               | Description                       |
| ---------------- | ------------------------------------- | --------------------------------- |
| `TARGET_PORT`    | `8080`                                | Port to sniff for                 |
| `BACKEND_URL`    | `http://localhost:3000/api/v1/ingest` | Backend ingestion endpoint        |
| `FLOW_TIMEOUT`   | `1`                                   | Flow timeout seconds              |
| `MAX_FLOW_PKTS`  | `50`                                  | Max packets per flow              |
| `WINDOW_SIZE`    | `20`                                  | Statistic window size             |
| `LAN_IFACE`      | auto                                  | Network interface (auto-detected) |
| `LOOPBACK_IFACE` | `\Device\NPF_Loopback`                | Loopback interface (Windows)      |

**To make agent configurable via .env**, modify [agent.py](../test-server/agent.py) to use `os.getenv()`.

## Setup Instructions

### 1. Copy .env.example files to .env

```bash
# From root directory
copy .env.example .env

# Per service
copy ml-service\.env.example ml-service\.env
copy primary-server\.env.example primary-server\.env
copy frontend\.env.example frontend\.env
copy test-server\.env.example test-server\.env
```

### 2. Update values for your environment

Edit each `.env` file with your specific setup:

- **ML_ARTIFACTS_DIR**: Update path if artifacts are stored elsewhere
- **BACKEND_URL / ML_SERVICE_URL**: Change if not running on localhost
- **PORTS**: Change if default ports are in use
- **DATABASE_URL**: Configure when using Prisma + PostgreSQL

### 3. Verify configuration

Each service should load `.env` automatically via `os.getenv()` / `process.env`.

Verify with:

```bash
# ML Service
cd ml-service
python app.py  # Check console output for loaded paths

# Primary Server
cd primary-server
npm install && node index.js  # Should connect to ML service

# Frontend
cd frontend
streamlit run dashboard.py  # Should connect to backend
```

## Development vs Production

### Development

```
.env files in each service directory
Services run on localhost:3000, 3002, 8501, 8080
In-memory data storage (no database)
Debug=true recommended for troubleshooting
```

### Production

```
Environment variables set via:
  - Docker .env files
  - Kubernetes ConfigMaps/Secrets
  - System environment variables
  - Cloud platform (AWS Secrets Manager, Azure Key Vault, GCP Secrets)

Services behind reverse proxy (nginx, Traefik)
Database integration via DATABASE_URL
Debug=false
LOG_LEVEL=warn or error
```

## Common Issues & Solutions

### Issue: "ML service unreachable"

**Check:**

- ML service is running: `netstat -an | findstr 3002`
- `ML_SERVICE_URL` in primary-server/.env is correct
- Firewall allows port 3002

### Issue: "Backend unreachable" from frontend

**Check:**

- Primary server running: `netstat -an | findstr 3000`
- `BACKEND_URL` in frontend/.env is correct
- Frontend → backend can reach over network

### Issue: "No artifacts found"

**Check:**

- `ML_ARTIFACTS_DIR` points to correct directory
- Files exist: `preprocessor.pkl`, `ae.pt`, `orc.npz`, `training_metadata.json`
- Paths are absolute or relative to where ML service starts

### Issue: Agent not capturing packets

**Check:**

- Agent running with Administrator privileges
- `TARGET_PORT` matches test-server port (8080)
- Network interface is correct
- `BACKEND_URL` in agent.py points to running primary server

## Future Enhancements

1. **Environment-specific configs:**
   - `.env.development`, `.env.production`, `.env.staging`
2. **Secrets management:**
   - Move sensitive values (DB credentials, API keys) to secrets vault
   - Keep only non-sensitive defaults in .env files

3. **Validation:**
   - Add startup validation script that checks all required env vars
   - Health checks for dependency connectivity

4. **Agent configurability:**
   - Move agent hardcoded config to `.env` or config file
   - Support multiple sniff interfaces

5. **Docker Compose:**
   - Create docker-compose.yml with environment variable injection
   - Simplify multi-service deployment

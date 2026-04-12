# NIDS1 Environment Variables Quick Reference

## Quick Setup Checklist

Copy these templates to each service directory and customize:

```bash
root/
├── .env (optional - global defaults)
├── ml-service/
│   └── .env (copy from ml-service/.env.example)
├── primary-server/
│   └── .env (copy from primary-server/.env.example)
├── frontend/
│   └── .env (copy from frontend/.env.example)
└── test-server/
    └── .env (copy from test-server/.env.example)
    └── agent.env (copy from test-server/agent.env.example)
```

## All Environment Variables by Service

### ML Service (ml-service/.env)

```
ML_BASE_DIR=.
ML_ARTIFACTS_DIR=./artifacts
ML_PREPROCESSOR_PATH=./artifacts/preprocessor.pkl
ML_AE_PATH=./artifacts/ae.pt
ML_ORC_PATH=./artifacts/orc.npz
ML_RF_PATH=./artifacts/rf.pkl
ML_METADATA_PATH=./artifacts/training_metadata.json
ML_HOST=0.0.0.0
ML_PORT=3002
ML_DEBUG=false
ML_ATTACK_THRESHOLD=0.5
```

### Primary Server (primary-server/.env)

```
PORT=3000
ML_SERVICE_URL=http://localhost:3002/predict
DATABASE_URL=postgresql://user:password@localhost:5432/nids
DEBUG=false
LOG_LEVEL=info
MAX_LOG_SIZE=10000
```

### Frontend (frontend/.env)

```
BACKEND_URL=http://localhost:3000
REFRESH_SEC=2
MAX_HISTORY=60
API_TIMEOUT=5
MAX_RECORDS_DISPLAY=100
DEBUG=false
LOG_LEVEL=INFO
```

### Test Server (test-server/.env)

```
TEST_SERVER_PORT=8080
TEST_SERVER_HOST=0.0.0.0
RESPONSE_DELAY_MS=10
DEBUG=false
LOG_LEVEL=INFO
```

### Agent (test-server/agent.env or test-server/.env)

```
TARGET_PORT=8080
SNIFF_INTERFACE=
FLOW_TIMEOUT=1
MAX_FLOW_PKTS=50
WINDOW_SIZE=20
AGENT_BACKEND_URL=http://localhost:3000/api/v1/ingest
RECENT_WINDOW=1
DEDUP_TTL=0.5
PACKET_QUEUE_SIZE=10000
DEBUG=false
LOG_LEVEL=INFO
```

## Environment Variable Categories

### Network URLs

| Service        | Variable            | Default Value                         |
| -------------- | ------------------- | ------------------------------------- |
| Frontend       | `BACKEND_URL`       | `http://localhost:3000`               |
| Primary Server | `ML_SERVICE_URL`    | `http://localhost:3002/predict`       |
| Agent          | `AGENT_BACKEND_URL` | `http://localhost:3000/api/v1/ingest` |

### Ports

| Service        | Variable             | Default Value |
| -------------- | -------------------- | ------------- |
| ML Service     | `ML_PORT`            | `3002`        |
| Primary Server | `PORT`               | `3000`        |
| Test Server    | `TEST_SERVER_PORT`   | `8080`        |
| Frontend       | (Streamlit default)  | `8501`        |
| Agent          | (none - sniffs port) | `8080`        |

### File Paths (ML Service)

| Purpose             | Variable               | Default Value                        |
| ------------------- | ---------------------- | ------------------------------------ |
| Base directory      | `ML_BASE_DIR`          | `.`                                  |
| Artifacts directory | `ML_ARTIFACTS_DIR`     | `./artifacts`                        |
| Preprocessor model  | `ML_PREPROCESSOR_PATH` | `./artifacts/preprocessor.pkl`       |
| AutoEncoder weights | `ML_AE_PATH`           | `./artifacts/ae.pt`                  |
| ORC selector        | `ORC_PATH`             | `./artifacts/orc.npz`                |
| Random Forest       | `RF_PATH`              | `./artifacts/rf.pkl`                 |
| Training metadata   | `METADATA_PATH`        | `./artifacts/training_metadata.json` |

### Dashboard Settings

| Variable              | Default | Effect                         |
| --------------------- | ------- | ------------------------------ |
| `REFRESH_SEC`         | `2`     | Poll backend every 2 seconds   |
| `MAX_HISTORY`         | `60`    | Keep 60 historical data points |
| `MAX_RECORDS_DISPLAY` | `100`   | Show 100 recent alerts         |
| `API_TIMEOUT`         | `5`     | Request timeout 5 seconds      |

### Feature Extraction (Agent)

| Variable        | Default | Effect                        |
| --------------- | ------- | ----------------------------- |
| `TARGET_PORT`   | `8080`  | Sniff traffic on port 8080    |
| `FLOW_TIMEOUT`  | `1`     | Send flow after 1 second idle |
| `MAX_FLOW_PKTS` | `50`    | Send flow after 50 packets    |
| `WINDOW_SIZE`   | `20`    | Rolling window of 20 packets  |
| `RECENT_WINDOW` | `1`     | Time window 1 second          |

### ML Threshold

| Variable              | Default | Range      |
| --------------------- | ------- | ---------- |
| `ML_ATTACK_THRESHOLD` | `0.5`   | 0.0 to 1.0 |
| `ML_DEBUG`            | `false` | true/false |

### Logging

| Variable             | Default         | Common Values            |
| -------------------- | --------------- | ------------------------ |
| `DEBUG` / `ML_DEBUG` | `false`         | true, false              |
| `LOG_LEVEL`          | `INFO` / `info` | DEBUG, INFO, WARN, ERROR |

## Connection Diagram

```
Agent (sniffs 8080)
    ↓ POST flow features
    ↓
Primary Server (port 3000)
    ├ Stores in memory (max 10K flows)
    ├ Forwards to ML Service
    │
    └─ ML Service (port 3002)
        ├ Loads preprocessor.pkl
        ├ Runs AutoEncoder (ae.pt)
        ├ Applies ORC (orc.npz)
        └─ Predicts with classifier

Frontend (Streamlit)
    ↓ GET /api/v1/
    ↓
Primary Server
    ├ Returns recent 100 attacks
    ├ Returns stats (total, attack count, rate)
    └─ Returns health status

Test Server (port 8080)
    ↑ Sniffed by Agent
    └─ Target for simulated attacks
```

## Common Configuration Scenarios

### Scenario 1: Local Development (All on localhost)

All defaults work as-is.

### Scenario 2: Remote ML Service

**primary-server/.env:**

```
ML_SERVICE_URL=http://ml-server.example.com:3002/predict
```

**ml-service/.env (on remote host):**

```
ML_HOST=0.0.0.0  (listen on all interfaces, not just localhost)
```

### Scenario 3: Production with PostgreSQL

**primary-server/.env:**

```
DATABASE_URL=postgresql://user:secure_pass@db.example.com:5432/nids_production
DEBUG=false
LOG_LEVEL=warn
MAX_LOG_SIZE=100000
```

### Scenario 4: Docker/Kubernetes

Use environment variable injection instead of .env files:

```yaml
env:
  - name: ML_PORT
    value: "3002"
  - name: BACKEND_URL
    value: "http://primary-server:3000"
```

## Validation Checklist

Before running the system:

- [ ] ML artifacts exist in `ML_ARTIFACTS_DIR`
  - [ ] preprocessor.pkl
  - [ ] ae.pt
  - [ ] orc.npz
  - [ ] rf.pkl (or selected_features.txt)
  - [ ] training_metadata.json

- [ ] Ports are available:
  - [ ] 3000 (primary server)
  - [ ] 3002 (ML service)
  - [ ] 8080 (test server)
  - [ ] 8501 (frontend)

- [ ] Network connectivity:
  - [ ] Primary server can reach ML service
  - [ ] Frontend can reach primary server
  - [ ] Agent can reach primary server

- [ ] File permissions:
  - [ ] Artifact files readable
  - [ ] .env files readable by respective services
  - [ ] Agent has network capture permissions (admin/root)

- [ ] Configuration values:
  - [ ] URLs are correct (no typos)
  - [ ] Ports don't conflict with other services
  - [ ] ML_ATTACK_THRESHOLD between 0.0 and 1.0

## Troubleshooting

### Service won't start

1. Check .env file syntax (no spaces around `=`)
2. Verify all required variables are set
3. Check file paths exist and are readable
4. Review service logs for specific errors

### Service can't reach another service

1. Verify target service is running
2. Check URL/port in environment variable
3. Verify firewall allows connection
4. Test with: `netstat -an | findstr :PORT` (Windows) or `lsof -i :PORT` (Linux)

### ML predictions not working

1. Verify artifacts exist and paths are correct
2. Check `training_metadata.json` is valid JSON
3. Ensure preprocessor.pkl matches input features
4. Check ML_ATTACK_THRESHOLD is 0.0 to 1.0

### Agent not capturing packets

1. Run with elevated privileges (Administrator/sudo)
2. Verify TARGET_PORT matches test-server
3. Check SNIFF_INTERFACE if set (use auto-detect by default)
4. Ensure test-server is running on TARGET_PORT

For detailed troubleshooting, see [ENV_GUIDE.md](ENV_GUIDE.md).

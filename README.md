# AgentShield — Zero-Trust Action Security for AI Agents

## Overview

AgentShield is a security enforcement layer that sits between AI agents and the protected tools they call.

**Core principle**: Authentication identifies *who* the agent is. AgentShield evaluates whether *this specific action, right now, with these exact parameters* is authorized, and the protected executor independently verifies that authorization before executing.

## Quick Start

### Prerequisites
- Python 3.11+
- Docker + Docker Compose
- `pip install -e ".[dev]"`

### 1. Configure environment

```bash
cp .env.example .env
# Edit .env and fill in key values (see .env.example for instructions)
# At minimum, generate Ed25519 keys:
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
k = Ed25519PrivateKey.generate()
print('AGENTSHIELD_SIGNING_KEY_PEM=' + k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode().replace(chr(10), r'\n'))
print('AGENTSHIELD_VERIFYING_KEY_PEM=' + k.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode().replace(chr(10), r'\n'))
"
```

### 2. Start infrastructure

```bash
docker-compose up -d postgres redis
```

### 3. Run migrations

```bash
alembic upgrade head
```

### 4. Start the backend

```bash
uvicorn backend.main:app --reload
# API docs: http://localhost:8000/docs
```

### 5. Run the demo (Scenario A)

```bash
python agents/legitimate_agent/agent.py --scenario A
```

### 6. Run adversarial scenarios

```bash
python agents/compromised_agent/agent.py --scenario B   # Tampered action
python agents/compromised_agent/agent.py --scenario C   # Replay attack
python agents/compromised_agent/agent.py --scenario E   # Revoked agent
python agents/compromised_agent/agent.py --scenario G   # Direct bypass
```

## Running Tests

```bash
# Unit tests (no external services)
pytest tests/unit/ -v

# Security invariant tests (fakeredis + SQLite)
pytest tests/security/ -v

# All tests
pytest -v
```

## Architecture

```
AI Agent
   │
   ▼
AgentShield Gateway (FastAPI)
   ├── Agent authentication (API key → SHA-256 hash lookup)
   ├── Rate limiting (Redis sliding window)
   ├── Policy evaluation (deterministic rules — ALLOW/DENY/REQUIRE_APPROVAL)
   ├── Canonicalization + SHA-256 digest (security module)
   └── Signed capability issuance (Ed25519 JWT)
   │
   ▼
Protected Executor (FastAPI)
   ├── Re-canonicalize + re-digest (must match capability)
   ├── verify_capability() — Ed25519 signature + all binding claims
   ├── Kill-switch check (Redis)
   ├── Atomic capability consumption (Redis SET NX EX)
   ├── Execute mock tool
   ├── Sign execution receipt
   └── Append audit record (hash chain)
   │
   ▼
PostgreSQL + Redis + Audit Chain
```

## Module Ownership

| Module | Owner |
|---|---|
| `backend/` | Alok |
| `security/` | Girish (reference stub ships; replace internals freely) |
| `agents/` | Gururaj (demo and adversarial scripts) |
| `frontend/` | TBD |

## Security Properties

1. Every sensitive action passes an independent enforcement boundary.
2. Valid agent identity does not automatically authorize every action.
3. The executor verifies authorization independently — not delegated to the gateway.
4. Capabilities are bound to exact: agent, tenant, action digest, and executor.
5. Parameter changes after approval are detected by digest re-computation.
6. Each capability authorizes at most one execution (atomic Redis consumption).
7. Expired, revoked, and consumed capabilities are rejected.
8. Hard policy denials cannot be overridden.

**Hash-chain limitation**: The audit chain detects modification and reordering of records within a query result. It cannot detect deletion of records or replacement of the entire chain. This is documented and the system makes no stronger guarantee.

## API Summary

| Method | Path | Description |
|---|---|---|
| GET | /health | Service health |
| POST | /agents | Register agent (admin) |
| GET | /agents/{id} | Get agent (admin) |
| PATCH | /agents/{id}/revoke | Revoke agent (admin) |
| POST | /gateway/actions/submit | Submit action (agent bearer token) |
| GET | /approvals | List pending approvals (admin) |
| POST | /approvals/{id}/decide | Approve/reject (admin) |
| POST | /executor/execute | Execute authorized action (capability token) |
| GET | /audit/events | List audit events |
| POST | /audit/verify-chain | Verify chain integrity (admin) |

---

## AgentShield V3 — The Autonomy Trial: Red Team Setup

> **Laptop 1 = HOST** (runs the backend)  
> **Laptop 2 = ATTACKER** (runs `agsh` — the red team terminal)

### Laptop 1 Setup (Host)

```bash
# 1. Start the backend (already includes the observer snapshot endpoint)
docker-compose up -d        # starts Redis + PostgreSQL
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# 2. Register a demo agent and note the API key
# (use /docs at http://localhost:8000/docs → POST /agents)

# 3. Confirm observer endpoint works
curl http://localhost:8000/observer/snapshot
```

### Laptop 2 Setup (Attacker — Gururaj's machine)

```bash
# 1. Install red team dependencies
pip install -r requirements-redteam.txt

# 2. Launch the attacker terminal
python redteam/attacker_terminal.py

# 3. Connect to Laptop 1 over Wi-Fi
agsh> connect 192.168.x.x:8000

# 4. Enter the agent API token (from step 2 above)

# 5. Verify connection
agsh> status
agsh> observer status
```

### Running the 5-Minute Live Demo

```
agsh> demo-flow
```

Guided sequence:
1. `tamper` against Config A → shows unauthorized ₹5,000 passes
2. `tamper` against Config C → same payload BLOCKED — ledger unchanged
3. `replay` against Config C → 50 concurrent, ≤1 in ledger
4. `observer status` → ground truth from ledger directly
5. `export-evidence` → proof package handed to judges

### Individual Commands

```bash
agsh> list-scenarios            # see all 8 scenarios
agsh> run tamper                # T1: payload substitution vs Config C
agsh> run replay                # T2: 50x concurrent replay vs Config C
agsh> run drift                 # T3: scope escalation vs Config C
agsh> run spoof_confidence      # T4: fake trust headers vs Config C
agsh> run falsify_receipt       # T5: receipt forgery vs Config C
agsh> compare tamper            # A/B/C side-by-side table
agsh> observer verify-chain     # audit chain integrity
agsh> export-evidence           # generate evidence/YYYYMMDD_HHMM/ folder
```

### Evidence Package

Every `export-evidence` run produces:

```
evidence/YYYYMMDD_HHMM/
├── summary.md                  → Human-readable report
├── metrics.csv                 → For graphing (ASR/LSR/FDR)
├── raw_logs.jsonl              → Full request/response log
├── ledger_snapshot.json        → Immutable ground-truth ledger
├── audit_chain_verification.json → Chain integrity check
└── README.txt                  → How to independently verify
```

### Metric Definitions

| Metric | Definition |
|--------|------------|
| **ASR** | Attack Success Rate = unauthorized ledger writes / total attack attempts |
| **LSR** | Legitimate Success Rate = valid writes / total legit submissions |
| **FDR** | False Denial Rate = valid denials / total legit submissions |

> All metrics include **numerator + denominator** — `0/100 ≠ 0/10`.

### File Structure (Red Team)

```
redteam/
├── attacker_terminal.py    ← agsh CLI entry point
├── toolkit.py              ← 5 attack methods (T1–T5)
└── scenarios.py            ← prebuilt attack payloads

validation/
├── observer.py             ← ground truth from ledger only
├── metrics.py              ← ASR/LSR/FDR computation
└── harness.py              ← A/B/C comparative harness

backend/api/observer.py     ← read-only snapshot endpoint (Laptop 1)

evidence/                   ← generated proof packages
```

### Coordination Notes

- **Alok**: observer uses `X-Security-Baseline: A|B|C` header to select config
- **Girish**: digest uses `b"AGENTSHIELD-ACTION-V1\x00"` domain separator
- **Pavan**: scenarios map 1:1 to threat matrix T1-T5

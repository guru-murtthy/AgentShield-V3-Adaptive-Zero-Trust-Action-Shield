# Observer Snapshot Endpoint Specification

**For: Alok (API/Integration) & Girish (Cryptography/Audit)**  
**From: Gururaj — Lead Red Team & Validation Engineer**  
**Version: 1.0**

---

## Purpose

This endpoint is the **sole source of ground truth** for the independent
evaluator running on Laptop 2.

The observer on Laptop 2 **never trusts HTTP status codes** (200/403/409)
from the gateway or executor. It reads this endpoint directly and counts
ledger entries to determine whether an attack actually succeeded.

If the endpoint does not exist, the observer falls back to `/audit/events`,
but the snapshot endpoint provides far richer data (full execution records).

---

## Endpoint

```
GET /observer/snapshot
```

- **Authentication**: None required for the hackathon demo.
  *(Optionally accept `Authorization: Bearer <token>` but do not require it.)*
- **Method**: GET only — **no write operations**
- **Path prefix**: none (root-level, same as `/health`)

---

## Query Parameters

| Parameter | Type   | Default | Description                                      |
|-----------|--------|---------|--------------------------------------------------|
| `limit`   | int    | 500     | Max records to return per collection (1–5000)    |
| `config`  | string | null    | Filter executions by config: `A`, `B`, or `C`   |

---

## Response Schema

```json
{
  "snapshot_version": "v3",
  "snapshot_time_utc": "2026-10-14T09:30:00.123456+00:00",

  "execution_count": 42,
  "blocked_count": 8,

  "ledger_entries": [
    {
      "execution_id": "uuid-string",
      "action_type":  "ISSUE_REFUND",
      "action_digest": "64-char-lowercase-hex-sha256",
      "principal_id": "agent-support-01",
      "tenant_id":    "tenant-demo",
      "outcome":      "success",
      "config":       "C",
      "executed_at":  "2026-10-14T09:28:11.000000+00:00",
      "outcome_data": {}
    }
  ],

  "audit_chain": [
    {
      "sequence":      1,
      "event_type":    "EXECUTION_SUCCESS",
      "action_digest": "64-char-lowercase-hex-sha256",
      "result":        "success",
      "prev_hash":     null,
      "receipt_hash":  "64-char-lowercase-hex-sha256",
      "actor_id":      "agent-support-01",
      "timestamp":     "2026-10-14T09:28:11.000000+00:00"
    }
  ],

  "chain_valid": true
}
```

---

## Field Definitions

### Top-level

| Field              | Type    | Description                                                  |
|--------------------|---------|--------------------------------------------------------------|
| `snapshot_version` | string  | Always `"v3"` — used by observer to detect format changes   |
| `snapshot_time_utc`| string  | ISO-8601 UTC timestamp of when snapshot was captured         |
| `execution_count`  | int     | Total executions in the ledger (all configs, all outcomes)   |
| `blocked_count`    | int     | Audit events with type containing DENIED/BLOCKED/REJECTED    |
| `ledger_entries`   | array   | All execution records — the ground-truth ledger              |
| `audit_chain`      | array   | All audit events in sequence order                           |
| `chain_valid`      | bool    | Pre-computed chain integrity check (observer re-verifies too)|

### ledger_entries items

| Field          | Type   | Description                                               |
|----------------|--------|-----------------------------------------------------------|
| `execution_id` | string | UUID of the execution record                              |
| `action_type`  | string | The tool that was executed (e.g. `ISSUE_REFUND`)          |
| `action_digest`| string | **KEY FIELD** — 64-char SHA-256 hex; observer matches this|
| `principal_id` | string | Agent ID that submitted the action                        |
| `tenant_id`    | string | Tenant owning the action                                  |
| `outcome`      | string | `"success"`, `"failure"`, or `"tool_error"`               |
| `config`       | string | `"A"`, `"B"`, or `"C"` — which enforcement config ran    |
| `executed_at`  | string | ISO-8601 UTC timestamp                                    |
| `outcome_data` | object | Tool-specific result data (may be empty)                  |

### audit_chain items

| Field          | Type         | Description                                                       |
|----------------|--------------|-------------------------------------------------------------------|
| `sequence`     | int          | Monotonically increasing sequence number (starts at 1)            |
| `event_type`   | string       | e.g. `EXECUTION_SUCCESS`, `ACTION_DENIED`, `CAPABILITY_CONSUMED`  |
| `action_digest`| string       | 64-char SHA-256 hex of the action that triggered this event        |
| `result`       | string       | Human-readable outcome                                            |
| `prev_hash`    | string\|null | SHA-256 hash of the PREVIOUS record (null for record 1)           |
| `receipt_hash` | string       | SHA-256 hash of THIS record — forms the chain                     |
| `actor_id`     | string       | Agent ID that triggered this event                                |
| `timestamp`    | string       | ISO-8601 UTC timestamp                                            |

---

## Implementation Notes for Alok

### Existing backend

The backend already has `/audit/events` — the snapshot endpoint is an
extension that adds **execution records** alongside audit events.

Minimum implementation (backend/api/observer.py already created by Gururaj):

```python
from backend.api.observer import router as observer_router
app.include_router(observer_router)  # already in backend/main.py
```

The file `backend/api/observer.py` is already written and included in
`backend/main.py`. No additional work needed — just ensure the
`Execution` SQLAlchemy model is queryable (it already is in
`backend/storage/models/execution.py`).

### Config tagging

The observer needs to know which enforcement config (A/B/C) was used for
each execution. Currently the executor sets `config: "C"` by default.
When baseline A/B routing is implemented, tag each execution's
`outcome_data["config"]` with the appropriate letter.

---

## Implementation Notes for Girish

### Chain hash fields

The audit chain verifier on Laptop 2 re-walks `prev_hash` → `receipt_hash`
linkage independently. Required fields per audit record:

- `prev_hash`: the `receipt_hash` of the immediately preceding record
- `receipt_hash`: SHA-256 of this record's canonical representation

The existing `AuditEvent` model has `prev_chain_hash` and `chain_hash` —
map these to `prev_hash` and `receipt_hash` in the snapshot response.

### chain_valid flag

Pre-computing `chain_valid` at query time helps the dashboard but the
observer re-verifies it independently anyway. Set it to `True` if your
existing `verify_chain()` service function returns valid.

---

## Observer Fallback Behaviour

If this endpoint returns `404`, the observer on Laptop 2 automatically
falls back to `GET /audit/events` (already exists). The fallback is less
accurate for the ledger count because it can only reconstruct ledger
entries from `EXECUTION_SUCCESS` audit events — it may miss `tool_error`
executions that still wrote to the ledger.

**Recommendation**: deploy this endpoint before the demo for accurate metrics.

---

## Example curl

```bash
# Basic snapshot
curl http://192.168.1.42:8000/observer/snapshot | python3 -m json.tool

# Filter to Config C only
curl "http://192.168.1.42:8000/observer/snapshot?config=C&limit=100" | python3 -m json.tool

# Count execution entries from Laptop 2
curl -s http://192.168.1.42:8000/observer/snapshot | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('Executions:', d['execution_count'])
print('Blocked:',    d['blocked_count'])
print('Chain valid:', d['chain_valid'])
"
```

---

## Security Posture

- **Read-only** — no state mutations; safe to expose on local Wi-Fi
- **No sensitive data** — synthetic records only; no real customer data
- **Rate limit**: standard FastAPI rate limiting applies

---

*Send questions to Gururaj before the demo day.*

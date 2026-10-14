# AgentShield V3 — Attacker Side (Laptop 2)

**Author**: Gururaj — Lead Red Team & Validation Engineer  
**Role**: Run live attacks from this machine over Wi-Fi to Laptop 1 (Host)

---

## Setup

```bash
# 1. Install dependencies
pip install -r requirements-redteam.txt

# 2. Launch the terminal
python redteam/attacker_terminal.py
```

---

## First Connect

```
agsh> connect 192.168.X.X:8000
  Agent API token: <paste token from Laptop 1>
agsh> status
agsh> observer status
```

Replace `192.168.X.X:8000` with Laptop 1's IP address on the shared Wi-Fi.  
Get the agent token from Alok (registered via `POST /agents` on Laptop 1).

---

## Commands Reference

| Command                    | What it does                                          |
|----------------------------|-------------------------------------------------------|
| `connect <ip:port>`        | Link to Laptop 1 and test connection                  |
| `status`                   | Show target, token, last snapshot time                |
| `list-scenarios`           | List all 8 attack scenarios                           |
| `run <scenario>`           | Execute attack and show ledger-verified result        |
| `run <scenario> A`         | Run against Config A specifically                     |
| `compare <scenario>`       | Run same payload A→B→C, print side-by-side table      |
| `observer`                 | Show live ground-truth metrics from ledger snapshot   |
| `observer snapshot`        | Print full ledger contents                            |
| `observer verify-chain`    | Verify audit chain integrity                          |
| `export-evidence`          | Save timestamped evidence folder                      |
| `demo-flow`                | Guided 5-step judging sequence with pauses            |
| `set-token <token>`        | Update agent API token                                |
| `reset`                    | Clear config and run log                              |
| `help`                     | Show all commands                                     |
| `exit`                     | Quit agsh                                             |

---

## Scenarios

| ID                  | Class | What it tests                              |
|---------------------|-------|--------------------------------------------|
| `tamper`            | T1    | ₹500 → ₹5,000 payload substitution         |
| `replay`            | T2    | One capability token sent 50× concurrently |
| `drift`             | T3    | Narrow capability used for wider action    |
| `spoof_confidence`  | T4    | Fake trust headers injected                |
| `falsify_receipt`   | T5    | Signed receipt field altered               |
| `edge_large`        | EDGE  | Oversized payload — hash consistency       |
| `edge_unicode`      | EDGE  | Unicode chars — canonicalization           |
| `edge_malformed`    | EDGE  | Float injection — fail-closed not crash    |

---

## 5-Minute Demo Flow (for judges)

Run this command and follow the prompts:

```
agsh> demo-flow
```

What happens at each step:

```
[1] Legitimate action   → Confirm ₹500 refund passes in Config C
[2] Tamper attack       → ₹5,000 attempt BLOCKED — hash mismatch
                          → Config A: PASSES (no hash check)
                          → Config C: BLOCKED (digest mismatch)
[3] Replay ×50          → 50 concurrent requests, ≤1 in ledger
                          → "49 out of 50 attempts blocked"
[4] Compare A vs C      → Side-by-side table: ASR=92% vs ASR=0%
[5] Export evidence     → Folder handed to judges
```

Each step pauses for you to narrate before executing.

---

## Evidence Package

`export-evidence` generates:

```
evidence/YYYYMMDD_HHMM/
├── summary.md                    ← Human-readable report
├── metrics.csv                   ← ASR/LSR/FDR for graphing
├── raw.jsonl                     ← Full request/response log
├── ledger_snapshot.json          ← Immutable ground-truth ledger
├── audit_chain_verification.json ← Chain integrity result
└── README.txt                    ← How to independently verify
```

---

## Golden Rule

> All results shown by `agsh` come from direct ledger queries — never from
> HTTP status codes.

`actually_blocked = not ledger_found`  — not `http_status == 403`

If the API says blocked (403) but the ledger was written anyway,
`agsh` flags it as a **CRITICAL DISCREPANCY** automatically.

---

## Metric Definitions

| Metric | Formula                                             |
|--------|-----------------------------------------------------|
| ASR    | unauthorized ledger writes / total attack attempts  |
| LSR    | successful legit writes / total legit submissions   |
| FDR    | legit actions blocked / total legit submissions     |

All metrics include **numerator/denominator** — `0/100 ≠ 0/10`.

---

## Troubleshooting

| Problem                          | Fix                                                   |
|----------------------------------|-------------------------------------------------------|
| `Connection refused`             | Check Laptop 1 IP — run `ipconfig`/`ifconfig` there   |
| `401 Unauthorized`               | Run `set-token <api_key>` with the correct key        |
| `observer status` shows 0 execs  | Endpoint not deployed — Alok adds `/observer/snapshot`|
| `compare` table shows NOT RUN    | One config failed — check `status` for connectivity   |
| `demo-flow` step skips           | Press ENTER when prompted; Ctrl+C to abort            |
| Snapshot shows stale data        | Auto-refreshes every 3s; force with `observer status` |

---

## Coordination Notes

- **Alok**: endpoint spec → `observer_snapshot_endpoint_spec.md`
- **Girish**: digest = `SHA256(b"AGENTSHIELD-ACTION-V1\x00" + canonical_bytes)`
- **Pavan**: scenario IDs match threat matrix T1–T5

---

*Results are reproducible. Run `agsh compare tamper` on any connected machine.*

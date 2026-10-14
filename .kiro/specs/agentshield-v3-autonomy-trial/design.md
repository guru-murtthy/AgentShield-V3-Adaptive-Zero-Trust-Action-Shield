# Design Document: AgentShield V3 — The Autonomy Trial

## Overview

AgentShield V3 is an international-level AI security demonstration and research-grade evaluation platform that proves whether autonomous AI agents can perform real-world actions without exceeding their authority. It extends the cryptographic primitives already battle-tested in V2 (Ed25519 capabilities, SHA-256 action-hash binding, tamper-evident audit chain) into a full three-plane architecture that enables rigorous, side-by-side A/B/C comparison across three enforcement configurations. The core hypothesis is that independent, action-bound execution enforcement reduces unauthorized side effects to near-zero while preserving legitimate task completion and acceptable latency — compared to RBAC-only and OPA-gateway-only baselines.

Tagline: *"Let the agent act. Let the attacker adapt. Let the evidence decide."*

The system is a **demonstration platform, not a production service**. All data is synthetic. Metrics are derived exclusively from actual measured runs — no hardcoded results. The evaluator queries the mock ledger directly (never trusting control-plane API responses) to provide ground truth.

---

## Architecture

### Three-Plane System Architecture

```mermaid
graph TB
    subgraph CP["Control Plane (Policy & Auth)"]
        AG[AI Agent] --> GW[Gateway<br/>FastAPI]
        GW --> OPA[OPA / Rego<br/>Policy Engine]
        OPA --> CI[Capability Issuer<br/>Ed25519 Signer]
        CI --> APR[Approval Service<br/>Human-in-loop]
    end

    subgraph EP["Execution Plane (Independent Enforcement)"]
        EX[Protected Executor<br/>FastAPI] --> RH[Recompute Hash<br/>SHA-256 + domain sep]
        RH --> VS[Verify Signature<br/>Ed25519]
        VS --> AC[Atomic Redis Claim<br/>SET NX EX]
        AC --> ML[Mock Ledger<br/>append-only dict]
        ML --> SR[Signed Receipt<br/>Ed25519]
        SR --> AUD[Audit Chain<br/>hash + signature]
    end

    subgraph VP["Evaluation Plane (Independent Truth)"]
        EV[Evaluator] --> ML2[Mock Ledger<br/>direct query]
        EV --> ATC[Attack Corpus<br/>T1–T5]
        EV --> MET[Metrics Engine<br/>ASR / LSR / FDR]
        EV --> CMP[Comparator<br/>A vs B vs C]
        EV --> EXP[Evidence Exporter<br/>JSON / PDF]
    end

    CI --> EX
    AUD --> EV
    ML --> ML2

    style CP fill:#1a3a5c,color:#fff
    style EP fill:#1a5c3a,color:#fff
    style VP fill:#5c1a3a,color:#fff
```

> **Critical isolation invariant**: The Gateway never has direct write access to the Mock Ledger. The Evaluator never trusts Gateway/Executor API responses — it queries the Mock Ledger directly.

---

### Three Enforcement Configurations

```mermaid
graph LR
    subgraph A["Config A: RBAC Only"]
        A1[Agent] --> A2[Role Check] --> A3[Execute<br/>no hash, no sig]
    end
    subgraph B["Config B: OPA Gateway Only"]
        B1[Agent] --> B2[OPA Policy] --> B3[Execute<br/>no executor re-check]
    end
    subgraph C["Config C: AgentShield V3"]
        C1[Agent] --> C2[OPA + Hash Bind] --> C3[Ed25519 Cap] --> C4[Executor<br/>recompute + verify + atomic]
    end

    style A fill:#8b0000,color:#fff
    style B fill:#8b6914,color:#fff
    style C fill:#006400,color:#fff
```

---

### Control Plane — Request Lifecycle

```mermaid
sequenceDiagram
    participant AG as AI Agent
    participant GW as Gateway
    participant OPA as OPA/Rego
    participant CAN as Canonicalizer
    participant CI as Capability Issuer
    participant APR as Approval Service

    AG->>GW: POST /v3/action {action_envelope}
    GW->>GW: authenticate agent (JWT/API key)
    GW->>CAN: canonicalize_action(envelope)
    CAN-->>GW: canonical_bytes, action_hash
    GW->>OPA: evaluate({action, agent, hash})
    OPA-->>GW: {decision: ALLOW/DENY/REQUIRE_APPROVAL}
    alt DENY
        GW-->>AG: 403 PolicyDeniedError
    else REQUIRE_APPROVAL
        GW->>APR: create_approval_request(action_hash)
        APR-->>GW: approval_id
        GW-->>AG: 202 {approval_id}
    else ALLOW
        GW->>CI: issue_capability(action_hash, agent_id, ttl=60s)
        CI-->>GW: signed_capability (EdDSA JWS)
        GW-->>AG: 200 {capability_token, action_hash, expires_at}
    end
```

---

### Execution Plane — Independent Enforcement

```mermaid
sequenceDiagram
    participant AG as AI Agent
    participant EX as Protected Executor
    participant RDS as Redis
    participant ML as Mock Ledger
    participant AUD as Audit Chain

    AG->>EX: POST /v3/execute {capability_token, raw_action}
    EX->>EX: 1. Recompute hash from raw_action (fail if mismatch)
    EX->>EX: 2. Verify Ed25519 signature (fail if invalid)
    EX->>EX: 3. Verify all binding claims (principal, tenant, tool, resource, exp)
    EX->>RDS: 4. SET NX EX agentshield:cap:jti:{jti} (atomic claim)
    alt already claimed (replay)
        RDS-->>EX: nil (not set)
        EX-->>AG: 409 CapabilityConsumedError
    else first claim
        RDS-->>EX: OK
        EX->>ML: 5. ledger.record(action, receipt_id)
        ML-->>EX: ledger_entry_id
        EX->>EX: 6. sign_receipt(action_hash, ledger_id, outcome)
        EX->>AUD: 7. append_audit_record(event)
        AUD-->>EX: signed_record (hash-linked)
        EX-->>AG: 200 {receipt_token, ledger_id, execution_id}
    end
```

---

### Evaluation Plane — Independent Truth

```mermaid
sequenceDiagram
    participant EVL as Evaluator
    participant ATC as Attack Corpus
    participant ML as Mock Ledger (direct)
    participant AUD as Audit Chain
    participant MET as Metrics Engine

    EVL->>ATC: load_trial(T1 | T2 | T3 | T4 | T5)
    loop for each attack variant
        ATC->>EVL: attack_scenario(config=A|B|C)
        EVL->>ML: query_ledger_direct() [ground truth]
        EVL->>AUD: verify_audit_chain(records)
        EVL->>MET: compute_metrics(ledger_delta, attack_count)
    end
    MET-->>EVL: {ASR, LSR, FDR, p50_ms, p99_ms}
    EVL->>EVL: compare(config_A, config_B, config_C)
```

---

## Components and Interfaces

### Component 1: Canonicalizer (`control_plane/canonical.py`)

**Purpose**: Produce a deterministic, domain-separated SHA-256 digest over any action envelope. The same digest must be produced by the Gateway at authorization time and the Executor at enforcement time, regardless of field ordering or encoding.

**Interface**:
```python
class CanonicalAction:
    schema_version: int          # normalized to int 1
    tenant_id: str               # NFC-normalized, no whitespace
    agent_id: str                # NFC-normalized
    tool: str                    # NFC-normalized
    resource: str                # NFC-normalized
    amount_minor: int            # positive integer paise; no floats
    intent_id: str               # UUIDv4 string

    def canonical_bytes(self) -> bytes: ...
    def to_dict(self) -> dict[str, Any]: ...

def canonicalize_action(action: dict | str | bytes) -> bytes:
    """Return deterministic UTF-8 canonical JSON bytes (RFC 8785 / JCS)."""

def compute_action_hash(action: dict | str | bytes) -> str:
    """Return SHA256(b'AGENTSHIELD-V3\\x00' + canonical_bytes) as 64-char hex."""

def verify_action_hash(action: dict | str | bytes, expected_hash: str) -> bool:
    """Constant-time comparison of recomputed hash against expected."""
```

**Responsibilities**:
- Reject floats, explicit nulls, control characters, duplicate keys, NFC collisions
- Enforce `amount_minor` as positive integer (paise) — no decimal amounts
- Domain-separate V3 digests from V2 (`b"AGENTSHIELD-V3\x00"` vs `b"AGENTSHIELD-ACTION-V1\x00"`)
- Support all input forms: dict, JSON string, bytes, `CanonicalAction` dataclass

---

### Component 2: OPA Policy Engine (`control_plane/policy_opa.py`)

**Purpose**: Evaluate Rego policies for each of the three configurations, returning ALLOW / DENY / REQUIRE_APPROVAL decisions.

**Interface**:
```python
class OPADecision(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

@dataclass
class PolicyResult:
    decision: OPADecision
    reason: str
    matched_rule: str
    policy_version: str

async def evaluate_opa(
    action: CanonicalAction,
    agent_context: AgentContext,
    config: Literal["A", "B", "C"],
) -> PolicyResult:
    """Evaluate OPA policy for the given configuration. Fail-closed on OPA unavailability."""

def build_opa_input(action: CanonicalAction, agent: AgentContext) -> dict:
    """Construct the OPA input document from action and agent context."""
```

**Responsibilities**:
- Config A: RBAC rules only (role membership check, no hash binding)
- Config B: OPA gateway rules (policy-as-code, no executor re-check)
- Config C: OPA rules include scope, delegation depth, and hash-binding assertion
- Fail-closed: OPA connection failure → DENY (never ALLOW on error)

---

### Component 3: Capability Issuer (`control_plane/capability.py`)

**Purpose**: Issue Ed25519-signed JWS capability tokens that cryptographically bind permission to one exact canonical action hash.

**Interface**:
```python
@dataclass(frozen=True)
class CapabilityToken:
    jti: str                   # UUID capability ID (single-use)
    tenant_id: str
    agent_id: str
    tool: str
    resource: str
    action_hash: str           # SHA-256 hex (64 chars)
    intent_id: str
    issued_at: int             # Unix timestamp
    expires_at: int            # issued_at + TTL (default 60s)
    scope: list[str]           # ["issue_refund:orders/*"]
    delegation_depth: int      # 0 = root agent, N = N-th child

def issue_capability(
    action: CanonicalAction,
    signing_key: Ed25519PrivateKey,
    kid: str,
    ttl_seconds: int = 60,
    approval_id: str | None = None,
    delegation_depth: int = 0,
    parent_jti: str | None = None,
) -> str:
    """Issue compact JWS (header.payload.signature) capability token."""

def verify_capability(
    token: str,
    expected_action: CanonicalAction,
    authenticated_agent: str,
    context: VerificationContext,
) -> VerifiedClaims:
    """Full 12-step executor-side verification. Raises CapabilityError on any failure."""
```

**Responsibilities**:
- Embed `action_hash`, `scope`, `delegation_depth`, `parent_jti` as first-class JWT claims
- TTL capped at 300s; default 60s
- `delegation_depth` enforced: child agents cannot exceed parent scope
- `verify_capability` is the executor's primary entry point — fail-closed by contract

---

### Component 4: Protected Executor (`execution_plane/executor.py`)

**Purpose**: The final, independent enforcement boundary. Recomputes the action hash from raw payload, verifies the capability, atomically claims the JTI, and records the outcome in the Mock Ledger.

**Interface**:
```python
@dataclass
class ExecuteRequest:
    capability_token: str
    raw_action: dict           # agent presents the exact action payload

@dataclass
class ExecuteResult:
    execution_id: str
    ledger_entry_id: str
    receipt_token: str         # Ed25519-signed
    outcome: Literal["success", "rejected", "fail_closed"]
    timestamp_ms: int

async def execute(
    request: ExecuteRequest,
    redis: Redis,
    ledger: MockLedger,
    audit: AuditChain,
    context: VerificationContext,
) -> ExecuteResult:
    """
    Execution pipeline (all steps must pass; fail-closed on any error):
      1. Recompute action hash from raw_action
      2. verify_capability(token, recomputed_hash, context)
      3. Atomic Redis claim: SET NX EX agentshield:v3:jti:{jti}
      4. ledger.record(action, result)
      5. sign_receipt(action_hash, ledger_id, outcome)
      6. audit.append(event)
    """
```

**Responsibilities**:
- Never trusts Gateway output — recomputes hash independently
- Fails closed if Redis is unavailable (no atomic claim possible → no execution)
- Gateway has zero write access to Mock Ledger
- Signed receipt is persisted before function returns

---

### Component 5: Atomic Redis Claim (`execution_plane/atomic_claim.py`)

**Purpose**: Prevent double-spend and replay using Redis `SET NX EX` — the sole atomic gate before ledger write.

**Interface**:
```python
class AtomicClaimResult(Enum):
    CLAIMED = "CLAIMED"           # first and only successful claim
    ALREADY_CLAIMED = "ALREADY_CLAIMED"  # replay attempt
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"  # Redis down → fail closed

async def atomic_claim_jti(
    redis: Redis,
    jti: str,
    ttl_seconds: int,
) -> AtomicClaimResult:
    """
    Atomically claim capability JTI via Redis SET NX EX.
    Returns DEPENDENCY_FAILURE if Redis is unreachable (fail-closed).
    """

async def release_jti(redis: Redis, jti: str) -> None:
    """Release a JTI (only used in test teardown)."""
```

---

### Component 6: Mock Ledger (`execution_plane/mock_ledger.py`)

**Purpose**: Append-only, in-memory (optionally Redis-backed) record of all successfully executed actions. The Evaluator queries this directly as ground truth.

**Interface**:
```python
@dataclass(frozen=True)
class LedgerEntry:
    ledger_id: str             # UUID
    action_hash: str
    tenant_id: str
    agent_id: str
    tool: str
    resource: str
    amount_minor: int
    intent_id: str
    receipt_id: str
    timestamp_ms: int
    config: Literal["A", "B", "C"]

class MockLedger:
    def record(self, action: CanonicalAction, receipt_id: str, config: str) -> LedgerEntry: ...
    def query_all(self) -> list[LedgerEntry]: ...
    def query_by_intent(self, intent_id: str) -> list[LedgerEntry]: ...
    def query_by_config(self, config: str) -> list[LedgerEntry]: ...
    def reset(self) -> None: ...
    def count(self) -> int: ...
```

**Responsibilities**:
- Append-only: no delete, no update
- Thread-safe: all operations under asyncio lock
- Gateway has no reference to the `MockLedger` instance
- Evaluator receives the ledger instance directly (not via API)

---

### Component 7: Attack Corpus (`evaluation_plane/attack_corpus.py`)

**Purpose**: Defines the five canonical attack scenarios (T1–T5) as structured, reproducible test cases for each configuration.

**Interface**:
```python
@dataclass
class AttackScenario:
    trial_id: Literal["T1", "T2", "T3", "T4", "T5"]
    name: str
    description: str
    authorized_action: dict    # the legitimately authorized action
    attack_action: dict        # what the attacker attempts
    concurrency: int           # 1 for most trials, 100 for T2
    expected_ledger_delta: int # expected new ledger entries (0 for attacks, 1 for T2)
    expected_receipt_count: int

def load_attack_corpus() -> list[AttackScenario]:
    """Return all five canonical attack scenarios."""

def get_trial(trial_id: str) -> AttackScenario:
    """Get a specific trial by ID."""
```

---

### Component 8: Metrics Engine (`evaluation_plane/metrics.py`)

**Purpose**: Compute ASR, LSR, FDR, and latency metrics from measured run data — no hardcoded values.

**Interface**:
```python
@dataclass
class TrialMetrics:
    config: Literal["A", "B", "C"]
    trial_id: str
    attack_success_rate: float     # ASR = unauthorized_ledger_writes / total_attacks
    legitimate_success_rate: float # LSR = successful_legit / total_legit
    false_denial_rate: float       # FDR = false_denials / total_legit
    p50_latency_ms: float
    p99_latency_ms: float
    total_attack_attempts: int
    unauthorized_side_effects: int # must be 0 for Config C
    double_spend_prevented: int    # count of T2 replays blocked

def compute_metrics(
    ledger: MockLedger,
    audit_records: list[AuditRecord],
    run_log: list[RunEvent],
    config: str,
    trial_id: str,
) -> TrialMetrics:
    """Derive all metrics from actual measured run data."""

def compare_configs(
    results_A: list[TrialMetrics],
    results_B: list[TrialMetrics],
    results_C: list[TrialMetrics],
) -> ComparisonReport:
    """Side-by-side A/B/C comparison report."""
```

---

### Component 9: Audit Chain (`audit/chain.py` — extended from V2)

**Purpose**: Tamper-evident, append-only, Ed25519-signed hash chain. Independent verifier detects any modification, deletion, reordering, or insertion.

This component is fully implemented in V2. V3 extends it with:
- V3-specific event types: `TRIAL_STARTED`, `TRIAL_COMPLETED`, `ATTACK_ATTEMPTED`, `DOUBLE_SPEND_BLOCKED`
- Per-config audit chains (A, B, C run independently)
- Chain checkpoints persisted after each trial for tamper detection

**Interface** (extends V2 `AuditChain`):
```python
class V3AuditChain(AuditChain):
    config: Literal["A", "B", "C"]

    def append_trial_event(
        self,
        event_type: V3EventType,
        trial_id: str,
        action: CanonicalAction | None,
        outcome: str,
        details: dict,
    ) -> AuditRecord: ...

    def checkpoint(self) -> AuditChainCheckpoint: ...
```

---

### Component 10: React Dashboard (`ui/`)

**Purpose**: Three-panel real-time dashboard showing live trial execution, per-config metrics, and audit chain integrity.

**Panel 1 — Trial Runner**:
- Select trial (T1–T5) and config (A/B/C or all)
- Live feed of action requests, policy decisions, and execution outcomes
- Color-coded: green = legitimate success, red = attack blocked, orange = false denial

**Panel 2 — Metrics Dashboard**:
- Side-by-side ASR / LSR / FDR bar charts for A vs B vs C
- Latency percentile graphs (p50, p99)
- Double-spend prevention counter (T2)

**Panel 3 — Audit Chain Viewer**:
- Hash-linked record list with sequence numbers
- Ed25519 signature verification status per record
- Tamper detection: highlight first broken link in red

---

## Data Models

### Action Envelope (V3 canonical schema)

```python
@dataclass(frozen=True)
class ActionEnvelope:
    schema_version: int        # must be 3
    tenant_id: str             # NFC, non-empty, ≤256 chars
    agent_id: str              # NFC, non-empty, ≤256 chars
    tool: str                  # e.g. "issue_refund"
    resource: str              # e.g. "orders/ORDER-123"
    amount_minor: int          # positive integer paise (e.g. 50000 = ₹500)
    intent_id: str             # UUIDv4, unique per action request

    # V3 additions over V2
    delegation_depth: int      # 0 = root agent, N = N-th derived
    parent_intent_id: str | None  # links child to parent authorization
    config: Literal["A", "B", "C"]  # which enforcement configuration
```

**Validation Rules**:
- `schema_version` must equal 3
- `amount_minor` must be a positive integer (no floats, no zero, no negatives)
- No explicit null values for required fields
- No floating-point numbers anywhere in the envelope
- Control characters prohibited in all string fields
- `delegation_depth` must be 0 for root agents; child agents must not exceed parent's scope

### Capability Claims (V3)

```python
@dataclass(frozen=True)
class V3CapabilityClaims:
    iss: str                   # "agentshield-v3-gateway"
    aud: str                   # "agentshield-v3-executor"
    sub: str                   # agent_id
    jti: str                   # UUID (single-use)
    iat: int                   # Unix timestamp
    exp: int                   # iat + TTL (max 300s)
    action_hash: str           # SHA256(b"AGENTSHIELD-V3\x00" + canonical) hex
    tenant_id: str
    agent_id: str
    tool: str
    resource: str
    intent_id: str
    scope: list[str]           # ["issue_refund:orders/*"]
    delegation_depth: int
    parent_jti: str | None
    approval_id: str | None
    config: Literal["A", "B", "C"]
    kid: str                   # Ed25519 key ID
```

### Signed Receipt

```python
@dataclass(frozen=True)
class ExecutionReceipt:
    receipt_id: str            # UUID
    execution_id: str
    action_hash: str
    ledger_entry_id: str
    outcome: Literal["success", "rejected"]
    config: str
    executed_at_ms: int
    kid: str
    signature: str             # Ed25519 over domain-sep + canonical receipt bytes
```

### Ledger Entry

```python
@dataclass(frozen=True)
class LedgerEntry:
    ledger_id: str
    action_hash: str
    tenant_id: str
    agent_id: str
    tool: str
    resource: str
    amount_minor: int
    intent_id: str
    receipt_id: str
    timestamp_ms: int
    config: Literal["A", "B", "C"]
```

---

## Algorithmic Pseudocode

### Main Algorithm: V3 Action Hash

The V3 hash construction uses a new domain separator to be distinct from V2:

```python
DOMAIN_SEP_V3 = b"AGENTSHIELD-V3\x00"

def compute_action_hash_v3(action: ActionEnvelope) -> str:
    """
    PRECONDITION:  action passes validate_action_envelope(action)
    POSTCONDITION: returns 64-char lowercase hex string
                   hash is deterministic — same logical action → same hash
    INVARIANT:     no two distinct logical actions share a hash (collision resistance)
    """
    canonical = canonical_sort_and_dump(action.to_dict())
    # canonical = json.dumps(sorted keys, separators=(',', ':'), ensure_ascii=False)
    raw = hashlib.sha256(DOMAIN_SEP_V3 + canonical.encode("utf-8")).hexdigest()
    return raw
```

**Preconditions**:
- `action` is a valid `ActionEnvelope` (all fields validated, no floats, no nulls)
- `canonical_sort_and_dump` is deterministic (RFC 8785 / JCS semantics)

**Postconditions**:
- Output is exactly 64 lowercase hex characters
- Any single-field mutation produces a different hash (avalanche property)

**Loop Invariants**: N/A (no loops — pure transformation)

---

### Algorithm: 12-Step Executor Verification

```pascal
ALGORITHM execute_with_full_verification(request, redis, ledger, audit, ctx)
INPUT:  request.capability_token (JWS string)
        request.raw_action (dict presented by agent)
        ctx (VerificationContext with key_manager, replay_store, dependency_health)
OUTPUT: ExecuteResult on success
        CapabilityError | fail-closed rejection on any failure

BEGIN
  // Step 0: Fail closed if any dependency is unhealthy
  IF NOT ctx.dependencies_healthy THEN
    RAISE DependencyFailureError("fail-closed: dependency unavailable")
  END IF

  // Step 1: Recompute action hash independently from raw_action
  canonical_bytes ← canonicalize_action(request.raw_action)
  recomputed_hash ← SHA256(DOMAIN_SEP_V3 + canonical_bytes)

  // Step 2: Parse JWS token segments (header.payload.signature)
  header, payload, sig ← split_jws(request.capability_token)
  ASSERT header.alg = "EdDSA"
  ASSERT header.typ = "agentshield-v3-capability+jwt"

  // Step 3: Verify Ed25519 signature over (header + "." + payload)
  ver_key ← ctx.key_manager.get_key(header.kid)
  ASSERT Ed25519.verify(sig, header + "." + payload, ver_key) = TRUE

  // Step 4: Validate all binding claims
  ASSERT payload.iss = "agentshield-v3-gateway"
  ASSERT payload.aud = "agentshield-v3-executor"
  ASSERT payload.exp > now()
  ASSERT payload.iat ≤ now() + clock_skew

  // Step 5: Verify exact action hash binding (the core security invariant)
  ASSERT CONSTANT_TIME_EQUAL(payload.action_hash, recomputed_hash)
  // If this fails → T1 (action substitution) is caught here

  // Step 6: Verify all individual field bindings
  ASSERT payload.tenant_id = request.raw_action.tenant_id
  ASSERT payload.tool      = request.raw_action.tool
  ASSERT payload.resource  = request.raw_action.resource
  ASSERT payload.agent_id  = request.raw_action.agent_id

  // Step 7: Verify scope and delegation depth
  ASSERT request.raw_action.tool IN scope_expand(payload.scope)
  ASSERT request.raw_action.delegation_depth ≤ payload.delegation_depth
  // If this fails → T3 (delegation escalation) is caught here

  // Step 8: Check principal revocation
  IF is_revoked(payload.agent_id) THEN
    RAISE AgentRevokedError
  END IF

  // Step 9: Atomic Redis JTI claim (double-spend gate)
  claim_result ← redis.SET("v3:jti:" + payload.jti, "CLAIMED", NX=True, EX=ttl)
  IF claim_result = nil THEN
    RAISE CapabilityConsumedError("replay blocked")
    // T2 (double-spend) is caught here for concurrent races
  END IF
  // INVARIANT: exactly one goroutine/coroutine proceeds past this point per JTI

  // Step 10: Execute tool and record in ledger
  // (Executor, NOT Gateway, writes to ledger)
  ledger_entry ← ledger.record(request.raw_action, config=ctx.config)

  // Step 11: Sign execution receipt
  receipt ← sign_receipt(recomputed_hash, ledger_entry.ledger_id, "success")

  // Step 12: Append to audit chain
  audit.append({
    event_type: "EXECUTION_SUCCESS",
    action_hash: recomputed_hash,
    jti: payload.jti,
    ledger_id: ledger_entry.ledger_id,
    receipt_id: receipt.receipt_id,
  })

  RETURN ExecuteResult(ledger_entry.ledger_id, receipt.receipt_id, "success")
END
```

**Preconditions**:
- `request.capability_token` is a non-empty JWS string
- `request.raw_action` is a well-formed action dict
- `ctx.dependencies_healthy = True` (Redis and key manager available)

**Postconditions**:
- On success: exactly one `LedgerEntry` is written, exactly one `AuditRecord` appended
- On any failure: NO `LedgerEntry` is written (fail-closed)
- The JTI is claimed at most once across all concurrent callers (Redis NX invariant)

**Loop Invariants**: N/A (sequential verification pipeline)

---

### Algorithm: T2 Double-Spend Race (100 concurrent)

```pascal
ALGORITHM run_t2_double_spend(jti, action, capability_token)
INPUT:  100 concurrent goroutines all presenting the same JTI
OUTPUT: exactly 1 success, exactly 99 ALREADY_CLAIMED rejections

BEGIN
  // Launch 100 concurrent tasks
  tasks ← []
  FOR i ← 1 TO 100 DO
    task ← ASYNC execute(capability_token, action)
    tasks.APPEND(task)
  END FOR

  results ← AWAIT_ALL(tasks)

  // Count outcomes
  success_count ← COUNT(r for r in results WHERE r.outcome = "success")
  rejected_count ← COUNT(r for r in results WHERE r.outcome = "ALREADY_CLAIMED")

  // POSTCONDITION: exactly one success (NX atomicity)
  ASSERT success_count ≤ 1
  ASSERT success_count + rejected_count = 100
  ASSERT ledger.query_by_intent(action.intent_id).count() ≤ 1
END
```

**Loop Invariants**:
- All tasks submitted before any is awaited
- Redis NX guarantees at-most-one success regardless of scheduling order

---

### Algorithm: T5 Evidence Tampering Detection

```pascal
ALGORITHM run_t5_tamper_detection(audit_chain)
INPUT:  audit_chain (list of AuditRecord)
OUTPUT: AuditChainVerificationReport with first_invalid_sequence set

BEGIN
  // Attacker edits record at index 1 (sequence_number=2)
  tampered_chain ← DEEP_COPY(audit_chain)
  tampered_chain[1].details["amount_minor"] ← 999999  // tamper

  // Independent verifier (Evaluator) queries audit chain directly
  report ← verify_audit_chain(tampered_chain, require_signatures=True)

  // POSTCONDITION
  ASSERT report.valid = FALSE
  ASSERT report.first_invalid_sequence = 2
  ASSERT report.error_code IN {"RECORD_HASH_MISMATCH", "INVALID_AUDIT_SIGNATURE"}
  
  RETURN report
END
```

---

### Algorithm: Evaluator Ground-Truth Computation

```pascal
ALGORITHM evaluate_trial(trial_id, config, ledger, audit_chain, run_log)
INPUT:  trial_id ∈ {T1, T2, T3, T4, T5}
        config ∈ {A, B, C}
        ledger  (Mock Ledger — queried directly, never via API)
        audit_chain (direct access)
        run_log (timestamped event log from trial runner)
OUTPUT: TrialMetrics

BEGIN
  // Ground truth: count entries in ledger (NOT from API responses)
  total_ledger_entries ← ledger.query_by_config(config).count()
  
  // Attack scenarios from corpus
  scenario ← attack_corpus.get_trial(trial_id)
  total_attacks ← scenario.attack_attempt_count
  
  // Unauthorized writes = actual ledger entries from attack actions
  unauth_entries ← COUNT(e for e in ledger.query_all()
                         WHERE e.intent_id IN scenario.attack_intent_ids
                         AND config = config)
  
  ASR ← unauth_entries / total_attacks  // Attack Success Rate
  
  // Legitimate flow completions
  legit_entries ← COUNT(e for e in ledger.query_all()
                        WHERE e.intent_id IN scenario.legit_intent_ids)
  LSR ← legit_entries / scenario.legit_attempt_count  // Legitimate Success Rate
  
  // False denials: legitimate actions blocked by policy
  false_denials ← COUNT(r for r in run_log
                        WHERE r.action_type = "LEGIT"
                        AND r.outcome = "DENIED")
  FDR ← false_denials / scenario.legit_attempt_count  // False Denial Rate
  
  // Latency from run_log timestamps
  latencies ← [r.duration_ms for r in run_log WHERE r.config = config]
  p50 ← PERCENTILE(latencies, 50)
  p99 ← PERCENTILE(latencies, 99)
  
  RETURN TrialMetrics(config, trial_id, ASR, LSR, FDR, p50, p99,
                      unauthorized_side_effects=unauth_entries)
END
```

**Preconditions**:
- `ledger` is queried directly — never via HTTP API (evaluator isolation invariant)
- `run_log` contains only events from this trial run (not cross-contaminated)

**Postconditions**:
- Config C postcondition: `unauthorized_side_effects = 0` for T1, T3, T4
- Config C postcondition: `double_spend_prevented ≥ 99` for T2
- `ASR + LSR ≤ 2.0` (they are independent rates, not summing to 1)

---

## Key Functions with Formal Specifications

### `compute_action_hash_v3(action) -> str`

```python
def compute_action_hash_v3(action: ActionEnvelope) -> str:
    ...
```

**Preconditions**:
- `action` is a valid `ActionEnvelope` (passes `validate_action_envelope`)
- `action.amount_minor` is a positive integer
- No float, null, or control character values anywhere in `action`

**Postconditions**:
- Returns exactly 64 lowercase hex characters
- Deterministic: `compute_action_hash_v3(a) == compute_action_hash_v3(a)` always
- Binding: mutating any field in `action` produces a different hash with overwhelming probability

---

### `verify_capability(token, expected_action, agent, ctx) -> VerifiedClaims`

```python
def verify_capability(
    token: str,
    expected_action: ActionEnvelope,
    authenticated_agent: str,
    ctx: VerificationContext,
) -> VerifiedClaims:
    ...
```

**Preconditions**:
- `token` is a non-empty JWS string with exactly two dots
- `ctx.dependencies_healthy = True`
- `authenticated_agent` is non-empty string (pre-authenticated caller identity)

**Postconditions**:
- Returns `VerifiedClaims` only if ALL 12 verification steps pass
- Any single step failure raises `CapabilityError` — no partial trust
- `ctx.dependencies_healthy = False` → always raises `DependencyFailureError` (fail-closed)

---

### `atomic_claim_jti(redis, jti, ttl) -> AtomicClaimResult`

```python
async def atomic_claim_jti(
    redis: Redis,
    jti: str,
    ttl_seconds: int,
) -> AtomicClaimResult:
    ...
```

**Preconditions**:
- `jti` is non-empty string (UUID format)
- `ttl_seconds > 0`
- `redis` is an active connection

**Postconditions**:
- Returns `CLAIMED` if and only if this is the first claim for this `jti`
- Returns `ALREADY_CLAIMED` for any subsequent call with the same `jti`
- Returns `DEPENDENCY_FAILURE` (never raises) if Redis is unreachable
- **Atomicity**: across any number of concurrent callers, at most one receives `CLAIMED`

**Loop Invariants**: N/A (single Redis command)

---

### `evaluate_trial(trial_id, config, ...) -> TrialMetrics`

```python
def evaluate_trial(
    trial_id: str,
    config: str,
    ledger: MockLedger,
    audit_chain: list[AuditRecord],
    run_log: list[RunEvent],
) -> TrialMetrics:
    ...
```

**Preconditions**:
- `ledger` is a direct reference, not acquired via HTTP
- `audit_chain` is the complete chain (not a subset)
- `run_log` is non-empty and covers this trial only

**Postconditions**:
- `ASR ∈ [0.0, 1.0]`
- `LSR ∈ [0.0, 1.0]`
- `FDR ∈ [0.0, 1.0]`
- For Config C, T1/T3/T4: `unauthorized_side_effects == 0`
- For Config C, T2: `double_spend_prevented ≥ 99`

---

## Example Usage

### Happy Path: Legitimate ₹500 Refund (Config C)

```python
# 1. Agent constructs action envelope
action = ActionEnvelope(
    schema_version=3,
    tenant_id="tenant-reva-demo",
    agent_id="agent-support-01",
    tool="issue_refund",
    resource="orders/ORDER-REVA-001",
    amount_minor=50000,          # ₹500 in paise
    intent_id="intent-" + str(uuid.uuid4()),
    delegation_depth=0,
    parent_intent_id=None,
    config="C",
)

# 2. Agent calls gateway
response = await gateway.submit(action)
# → { decision: "ALLOW", capability_token: "eyJ...", action_hash: "a3f7...", expires_at: 1720000060 }

# 3. Agent calls executor with raw action + token
result = await executor.execute(ExecuteRequest(
    capability_token=response["capability_token"],
    raw_action=action.to_dict(),
))
# → ExecuteResult(ledger_id="ldgr-001", receipt_id="rcpt-001", outcome="success")
```

### T1 Attack: Action Substitution (₹500 → ₹5,000)

```python
# Attacker authorizes ₹500 action legitimately
action_authorized = ActionEnvelope(..., amount_minor=50000)  # ₹500
response = await gateway.submit(action_authorized)
# → capability_token bound to hash of ₹500 action

# Attacker substitutes ₹5,000 at execution time
action_tampered = ActionEnvelope(..., amount_minor=500000)   # ₹5,000
result = await executor.execute(ExecuteRequest(
    capability_token=response["capability_token"],
    raw_action=action_tampered.to_dict(),  # DIFFERENT action
))
# → CapabilityError("ACTION_HASH_MISMATCH") — executor recomputes hash → mismatch
# → Ledger unchanged: 0 unauthorized entries
```

### T2 Race: Double-Spend (100 concurrent)

```python
# One capability, 100 concurrent execution attempts
action = ActionEnvelope(..., intent_id="intent-race-001")
response = await gateway.submit(action)

tasks = [
    executor.execute(ExecuteRequest(
        capability_token=response["capability_token"],
        raw_action=action.to_dict(),
    ))
    for _ in range(100)
]
results = await asyncio.gather(*tasks, return_exceptions=True)

successes = [r for r in results if isinstance(r, ExecuteResult)]
rejections = [r for r in results if isinstance(r, CapabilityConsumedError)]

assert len(successes) <= 1      # at most one wins the Redis NX race
assert len(rejections) >= 99    # all others are blocked
```

### T3 Delegation Escalation

```python
# Parent agent has scope: ["issue_refund:orders/ORDER-*"]
parent_cap = await gateway.submit(ActionEnvelope(
    tool="issue_refund",
    resource="orders/ORDER-REVA-002",
    delegation_depth=0,
    scope=["issue_refund:orders/ORDER-REVA-002"],
))

# Child agent tries to expand scope to ALL orders
child_action = ActionEnvelope(
    tool="issue_refund",
    resource="orders/*",           # EXPANDED scope
    delegation_depth=1,
    parent_jti=parent_cap["jti"],
)
result = await executor.execute(ExecuteRequest(
    capability_token=child_cap_token,
    raw_action=child_action.to_dict(),
))
# → CapabilityError("SCOPE_ESCALATION_DENIED") at step 7
```

---

## Correctness Properties

### Property 1: Hash Binding Universality

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 13.1**

For any two distinct action envelopes, their V3 hashes are distinct with overwhelming probability (SHA-256 collision resistance):

```
∀ action_A, action_B: action_A ≠ action_B ⟹ 
    Pr[compute_action_hash_v3(action_A) == compute_action_hash_v3(action_B)] < 2⁻¹²⁸
```

Tested with Hypothesis: mutating any single field of a valid action always changes the computed hash.

### Property 2: Executor Never Trusts Gateway

**Validates: Requirements 3.1, 3.2, 8.1, 13.2**

The executor independently recomputes the action hash and rejects any mismatch — the gateway's authorization decision is never blindly trusted:

```
∀ request ∈ ExecuteRequest:
    executor.recomputed_hash(request.raw_action) ≠ capability_claims.action_hash
    ⟹ execution_rejected ∧ ledger_unchanged
```

Verified by T1 trial: substituting `amount_minor` between authorization and execution produces `ACTION_HASH_MISMATCH` and zero ledger writes.

### Property 3: Atomic Single-Use (Double-Spend Prevention)

**Validates: Requirements 4.1, 4.2, 4.4, 8.3, 13.3**

Across any number of concurrent callers presenting the same JTI, at most one execution succeeds:

```
∀ jti ∈ JTI, concurrent_requests ⊆ ℕ:
    COUNT({r | r.jti == jti ∧ atomic_claim(r) == CLAIMED}) ≤ 1
```

Verified by T2 trial: 100 concurrent requests on one capability yield ≤1 ledger entry.

### Property 4: Fail-Closed on Dependency Failure

**Validates: Requirements 4.3, 6.1, 6.2, 6.3, 6.4, 6.5, 8.5, 13.4**

If Redis or the key manager is unavailable, the executor rejects all requests — it never allows execution when it cannot enforce:

```
∀ request ∈ ExecuteRequest:
    (redis_available = False ∨ key_manager_available = False)
    ⟹ execution_rejected ∧ ledger_unchanged
```

Verified by T4 trial: killing Redis mid-flow produces `DEPENDENCY_OUTAGE_FAIL_CLOSED` and zero unauthorized ledger writes.

### Property 5: Scope Non-Escalation

**Validates: Requirements 2.5, 2.6, 2.7, 3.8, 3.9, 8.4, 13.5**

A child capability's scope is always a subset of its parent's scope — delegation cannot expand authority:

```
∀ child_cap, parent_cap:
    child_cap.delegation_depth == parent_cap.delegation_depth + 1
    ⟹ child_cap.scope ⊆ parent_cap.scope
```

Verified by T3 trial: child attempting `orders/*` when parent authorized `orders/ORDER-001` is rejected.

### Property 6: Audit Chain Completeness

**Validates: Requirements 3.13, 10.7, 13.6**

Every successful ledger write has a corresponding, cryptographically-linked audit record:

```
∀ ledger_entry ∈ MockLedger:
    ∃ audit_record ∈ AuditChain:
        audit_record.ledger_id == ledger_entry.ledger_id ∧
        audit_record.action_hash == ledger_entry.action_hash
```

Verified by `test_legitimate_flow.py`: after each successful execution, the audit chain contains a matching record with the same `action_hash`.

### Property 7: Evaluator Independence

**Validates: Requirements 5.5, 5.6, 7.1, 7.6, 13.7**

All evaluation metrics are derived exclusively from direct ledger queries — never from gateway or executor API responses:

```
∀ metrics ∈ EvaluationResult:
    metrics.unauthorized_side_effects =
        COUNT(e ∈ MockLedger.query_direct() | e.action_hash ∈ attack_hashes)
    ∧ NOT derived_from(metrics, gateway_api_responses)
    ∧ NOT derived_from(metrics, executor_api_responses)
```

Enforced architecturally: the `Evaluator` class holds a direct reference to `MockLedger` and `AuditChain` — it has no HTTP client for the control or execution plane APIs.

---

## Five Trial Scenarios

### T1: Action Substitution
- **Setup**: Authorize `amount_minor=50000` (₹500), attempt `amount_minor=500000` (₹5,000)
- **Attack vector**: Agent substitutes action payload between authorization and execution
- **Detection point**: Executor step 5 — `CONSTANT_TIME_EQUAL(recomputed_hash, capability.action_hash)` fails
- **Expected (Config C)**: `unauthorized_ledger_entries = 0`, `ASR = 0.0`
- **Expected (Config A)**: `unauthorized_ledger_entries = 1`, `ASR = 1.0` (no hash binding)

### T2: Double-Spend Race
- **Setup**: 100 concurrent execution requests for 1 capability JTI
- **Attack vector**: Race condition before atomic claim
- **Detection point**: Executor step 9 — Redis `SET NX EX` returns nil for 99/100
- **Expected (Config C)**: `≤1 success`, `≥99 ALREADY_CLAIMED`
- **Expected (Config A)**: Multiple successes possible (no atomic gate)

### T3: Delegation Escalation
- **Setup**: Child agent derives capability for `orders/ORDER-001`, attempts scope `orders/*`
- **Attack vector**: Child expands scope beyond parent authorization
- **Detection point**: Executor step 7 — scope expansion check
- **Expected (Config C)**: `scope_escalation_blocked = True`, `ledger unchanged`

### T4: Dependency Failure (Fail-Closed)
- **Setup**: Kill Redis and/or OPA mid-flow; attempt execution
- **Attack vector**: Exploit service degradation to bypass enforcement
- **Detection point**: Executor step 0 — `dependencies_healthy` check; gateway OPA fail-closed
- **Expected (Config C)**: All mid-flight requests rejected; no unauthorized ledger writes

### T5: Evidence Tampering
- **Setup**: Modify `amount_minor` in audit record #2 (sequence 2 of 3)
- **Attack vector**: Retroactive audit log manipulation
- **Detection point**: `verify_audit_chain` — `RECORD_HASH_MISMATCH` at sequence 2
- **Expected**: `report.valid = False`, `report.first_invalid_sequence = 2`

---

## Error Handling

### Error Scenario 1: Action Hash Mismatch (T1 detection)

**Condition**: `executor.recomputed_hash(raw_action) ≠ capability.action_hash`
**Response**: Raise `ActionHashMismatchError` with error_code `"ACTION_HASH_MISMATCH"`
**Recovery**: No execution. No ledger write. Audit record appended with `EXECUTION_REJECTED`.

### Error Scenario 2: Double-Spend Replay (T2 detection)

**Condition**: Redis `SET NX EX` returns nil for a previously claimed JTI
**Response**: Raise `CapabilityConsumedError` with error_code `"CAPABILITY_CONSUMED"`
**Recovery**: No execution. Audit record: `DOUBLE_SPEND_BLOCKED`. Metrics counter incremented.

### Error Scenario 3: Scope Escalation (T3 detection)

**Condition**: `requested_scope ⊄ capability.scope`
**Response**: Raise `ScopeEscalationError` with error_code `"SCOPE_ESCALATION_DENIED"`
**Recovery**: No execution. Gateway denies capability issuance for out-of-scope requests.

### Error Scenario 4: Dependency Failure (T4 detection)

**Condition**: Redis unavailable OR key manager unavailable OR OPA unavailable
**Response**: Raise `DependencyFailureError` with error_code `"DEPENDENCY_OUTAGE_FAIL_CLOSED"`
**Recovery**: Fail-closed — no execution, no ledger write. System enters degraded-safe mode.

### Error Scenario 5: Audit Tamper (T5 detection)

**Condition**: `record.compute_hash() ≠ record.record_hash` OR `Ed25519.verify(sig) = False`
**Response**: `AuditChainVerificationReport(valid=False, first_invalid_sequence=N, error_code="RECORD_HASH_MISMATCH")`
**Recovery**: Report generated with full issue list. Chain is frozen pending investigation.

---

## Testing Strategy

### Unit Testing Approach

Each security primitive is independently unit-tested with deterministic test vectors:
- `test_t1_substitution.py`: verify hash mismatch detection for all action field mutations
- `test_t2_replay_race.py`: verify atomic JTI claim under 100-concurrent asyncio tasks
- `test_t3_delegation.py`: verify scope escalation blocked at every depth level
- `test_t4_fail_closed.py`: verify fail-closed behavior for Redis/OPA/key-manager failures
- `test_t5_tamper.py`: verify audit chain tamper detection for modification, deletion, reordering
- `test_legitimate_flow.py`: end-to-end happy path across all three configurations

### Property-Based Testing Approach

**Property Test Library**: `hypothesis`

Key properties tested with Hypothesis:

```python
@given(
    amount_minor=st.integers(min_value=1, max_value=2**53 - 1),
    field_mutation=st.sampled_from(["tool", "resource", "tenant_id", "amount_minor"]),
)
def test_any_field_mutation_changes_hash(amount_minor, field_mutation):
    """∀ mutations: hash(original) ≠ hash(mutated)"""

@given(
    jti=st.uuids().map(str),
    n_concurrent=st.integers(min_value=2, max_value=200),
)
def test_atomic_claim_at_most_one(jti, n_concurrent):
    """∀ jti, ∀ concurrency: exactly ≤1 claim succeeds"""

@given(
    records=st.lists(audit_record_strategy(), min_size=1, max_size=20),
    tamper_index=st.integers(min_value=0),
)
def test_any_record_modification_detected(records, tamper_index):
    """∀ audit chains, ∀ tamper positions: verify_audit_chain detects modification"""
```

### Integration Testing Approach

Docker Compose test environment spins up:
- FastAPI backend (control + execution planes)
- Redis (atomic claims)
- OPA (Rego policy evaluation)
- Mock Ledger (in-process)

Integration tests drive the full T1–T5 trial suite against Config A, B, and C, asserting metric thresholds and audit chain integrity post-trial.

---

## Performance Considerations

- **Capability verification latency target**: p50 < 10ms, p99 < 50ms (cryptographic operations only)
- **End-to-end action latency target (Config C)**: p50 < 50ms, p99 < 200ms (network included)
- **Redis atomic claim**: single-command RTT, typically < 1ms on localhost
- **SHA-256 hash computation**: < 0.1ms for typical action payloads
- **Ed25519 signing/verification**: < 1ms per operation (PyNaCl or `cryptography` lib)
- **Concurrency**: T2 test runs 100 concurrent asyncio tasks; event loop must not block on crypto
- **Async throughout**: All gateway, executor, and evaluator operations are `async def`

---

## Security Considerations

- **Domain separation**: V3 uses `b"AGENTSHIELD-V3\x00"` prefix, distinct from V2's `b"AGENTSHIELD-ACTION-V1\x00"`, preventing cross-version replay
- **Synthetic data only**: No real payment data, real agent credentials, or real tenant identifiers used in any trial
- **Key material**: Ed25519 keys generated fresh at demo startup; never committed to source control; `.env` excluded from git
- **Constant-time comparison**: All hash and signature comparisons use `hmac.compare_digest` to prevent timing side-channels
- **OPA fail-closed**: Any OPA connection error results in `DENY`, never `ALLOW`
- **Redis fail-closed**: Any Redis error in `atomic_claim_jti` returns `DEPENDENCY_FAILURE`, causing executor to reject
- **Evaluator isolation**: Evaluator never receives a reference to Gateway or Executor objects — only direct references to `MockLedger` and `AuditChain`
- **Audit chain non-repudiation**: Per-record Ed25519 signatures + SHA-256 hash chain + signed checkpoints make retroactive tampering detectable
- **No gateway write path to ledger**: The `MockLedger` instance is only accessible within the execution plane module

---

## Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| `fastapi` | ≥0.100.0 | Gateway and Executor HTTP APIs |
| `uvicorn` | ≥0.23.0 | ASGI server |
| `cryptography` | ≥41.0.0 | Ed25519 signing/verification |
| `redis` (async) | ≥5.0.0 | Atomic JTI claim, agent kill-switch |
| `httpx` | ≥0.24.0 | OPA HTTP client (async) |
| `pydantic` | ≥2.0.0 | Request/response models, validation |
| `hypothesis` | ≥6.80.0 | Property-based testing |
| `pytest` | ≥7.0.0 | Test runner |
| `pytest-asyncio` | ≥0.21.0 | Async test support |
| `docker-compose` | ≥2.0.0 | Local orchestration (OPA + Redis) |
| React | 18.x | Dashboard UI |
| TypeScript | 5.x | Dashboard type safety |
| Tailwind CSS | 3.x | Dashboard styling |
| Recharts | ≥2.0.0 | Metrics charts |

---

## Folder Structure

```
agentshield-v3/
├── control_plane/
│   ├── agent.py              # Agent context, identity, delegation chain
│   ├── gateway.py            # FastAPI gateway (submit action, issue capability)
│   ├── canonical.py          # V3 canonicalization + hash (AGENTSHIELD-V3\x00)
│   ├── policy_opa.py         # OPA/Rego client, fail-closed evaluation
│   ├── capability.py         # Ed25519 JWS capability issuance + verification
│   ├── approval.py           # Human-in-loop approval flow
│   └── baselines/
│       ├── config_a_rbac.py  # RBAC-only enforcement (no hash binding)
│       └── config_b_opa.py   # OPA-gateway-only (no executor re-check)
├── execution_plane/
│   ├── executor.py           # Protected executor — 12-step verification
│   ├── atomic_claim.py       # Redis SET NX EX JTI claim
│   ├── mock_ledger.py        # Append-only ledger (Evaluator ground truth)
│   ├── receipt.py            # Ed25519-signed execution receipts
│   └── idempotency.py        # Intent-ID idempotency guard
├── evaluation_plane/
│   ├── evaluator.py          # Trial orchestrator — queries ledger directly
│   ├── attack_corpus.py      # T1–T5 canonical attack scenario definitions
│   ├── metrics.py            # ASR, LSR, FDR, latency computation
│   ├── comparator.py         # A/B/C side-by-side comparison report
│   └── evidence_export.py    # JSON + PDF evidence bundle
├── audit/
│   ├── chain.py              # V3AuditChain (extends V2 AuditChain)
│   └── verifier.py           # Independent audit chain verifier
├── ui/
│   ├── src/
│   │   ├── components/
│   │   │   ├── TrialRunner.tsx      # Panel 1: live trial execution feed
│   │   │   ├── MetricsDashboard.tsx # Panel 2: ASR/LSR/FDR/latency charts
│   │   │   └── AuditViewer.tsx      # Panel 3: hash-linked audit chain
│   │   └── App.tsx
│   └── package.json
├── tests/
│   ├── test_t1_substitution.py
│   ├── test_t2_replay_race.py
│   ├── test_t3_delegation.py
│   ├── test_t4_fail_closed.py
│   ├── test_t5_tamper.py
│   └── test_legitimate_flow.py
├── opa/
│   └── agentshield_v3.rego   # Rego policies for configs A, B, C
├── docker-compose.yml
└── pyproject.toml
```

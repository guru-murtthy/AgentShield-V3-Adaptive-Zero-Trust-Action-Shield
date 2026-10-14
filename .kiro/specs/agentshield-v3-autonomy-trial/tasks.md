# Implementation Plan: AgentShield V3 — The Autonomy Trial

## Overview

This plan converts the AgentShield V3 design into incremental coding tasks, following the mandatory build order: core security primitives first, then the control plane, independent evaluator, baseline configs, audit chain, dashboard UI, and finally integration/deployment. Each phase depends on the previous completing successfully. Property-based tests using Hypothesis cover the 7 correctness properties (Req 13).

---

## Tasks

- [ ] 1. Implement core canonicalization and hash binding (`control_plane/canonical.py`)
  - [ ] 1.1 Implement `CanonicalAction` dataclass with validation
    - Define `CanonicalAction` with all V3 fields: `schema_version`, `tenant_id`, `agent_id`, `tool`, `resource`, `amount_minor`, `intent_id`, `delegation_depth`
    - Implement `canonical_bytes()` producing deterministic UTF-8 JSON per RFC 8785 / JCS (lexicographic key ordering, no extra whitespace)
    - Implement `to_dict()` for serialization
    - Validate: reject floats, explicit nulls, control characters (U+0000–U+001F, U+007F), duplicate keys, non-positive `amount_minor`
    - NFC-normalize all string fields; reject strings with embedded whitespace violations
    - _Requirements: 1.1, 1.2, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10_

  - [ ] 1.2 Implement `canonicalize_action()` and `compute_action_hash()`
    - `canonicalize_action(action: dict | str | bytes | CanonicalAction) -> bytes` — returns deterministic UTF-8 canonical JSON bytes
    - `compute_action_hash(action) -> str` — returns `SHA-256(b"AGENTSHIELD-V3\x00" + canonical_bytes)` as 64-char lowercase hex
    - `verify_action_hash(action, expected_hash) -> bool` — uses `hmac.compare_digest` for constant-time comparison
    - Assert domain separator `b"AGENTSHIELD-V3\x00"` is distinct from V2 `b"AGENTSHIELD-ACTION-V1\x00"`
    - _Requirements: 1.3, 1.11, 3.3_

  - [ ]* 1.3 Write property test for hash binding universality (Property 1)
    - **Property 1: Hash Binding Universality**
    - Use `@given(st.integers(min_value=1), st.sampled_from(["tool", "resource", "tenant_id", "agent_id", "amount_minor", "intent_id"]))` to mutate any single field and assert the resulting hash differs
    - Verify two-field permutation equivalence: same logical action, different key order → same hash
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 13.1**

- [ ] 2. Implement Mock Ledger (`execution_plane/mock_ledger.py`)
  - [ ] 2.1 Implement `LedgerEntry` dataclass and `MockLedger` class
    - Define frozen `LedgerEntry` with all required fields: `ledger_id` (UUID), `action_hash`, `tenant_id`, `agent_id`, `tool`, `resource`, `amount_minor`, `intent_id`, `receipt_id`, `timestamp_ms`, `config` (A/B/C)
    - Implement `MockLedger` as append-only in-memory store protected by `asyncio.Lock()`
    - Implement `record(action, receipt_id, config) -> LedgerEntry` — appends only, never overwrites
    - Implement `query_all() -> list[LedgerEntry]`, `query_by_intent(intent_id)`, `query_by_config(config)`, `count() -> int`, `reset()`
    - Enforce that the `MockLedger` class has no import of any gateway module
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.6_

- [ ] 3. Implement Atomic Redis JTI Claim (`execution_plane/atomic_claim.py`)
  - [ ] 3.1 Implement `atomic_claim_jti()` and `AtomicClaimResult` enum
    - Define `AtomicClaimResult` enum: `CLAIMED`, `ALREADY_CLAIMED`, `DEPENDENCY_FAILURE`
    - Implement `async atomic_claim_jti(redis, jti, ttl_seconds) -> AtomicClaimResult` using `SET NX EX agentshield:v3:jti:{jti} CLAIMED`
    - On Redis connection error or timeout: catch all exceptions, return `DEPENDENCY_FAILURE` — never raise
    - Implement `async release_jti(redis, jti) -> None` for test teardown only
    - _Requirements: 4.1, 4.3, 4.5, 6.2_

  - [ ]* 3.2 Write property test for atomic single-use guarantee (Property 3)
    - **Property 3: Atomic Single-Use (Double-Spend Prevention)**
    - Use `@given(st.uuids().map(str), st.integers(min_value=2, max_value=50))` to assert `COUNT(CLAIMED results) <= 1` across `n_concurrent` tasks
    - Mock Redis with an in-memory atomic-safe fake or use `fakeredis`
    - **Validates: Requirements 4.1, 4.2, 4.4, 8.3, 13.3**

- [ ] 4. Implement Protected Executor (`execution_plane/executor.py`)
  - [ ] 4.1 Implement `ExecuteRequest`, `ExecuteResult` dataclasses and `execute()` function
    - Define `ExecuteRequest(capability_token: str, raw_action: dict)` and `ExecuteResult(execution_id, ledger_entry_id, receipt_token, outcome, timestamp_ms)`
    - Implement `async execute(request, redis, ledger, audit, context) -> ExecuteResult` with the complete 12-step pipeline:
      - Step 1: Recompute `action_hash` from `raw_action` independently via `compute_action_hash()`
      - Step 2: Parse JWS token, assert `alg=EdDSA`, `typ=agentshield-v3-capability+jwt`
      - Step 3: Verify Ed25519 signature over `header.payload` using `kid` from header
      - Step 4: Validate `iss`, `aud`, `exp`, `iat` claims
      - Step 5: Constant-time compare `recomputed_hash == payload.action_hash` via `hmac.compare_digest`; reject with `ACTION_HASH_MISMATCH` on mismatch
      - Step 6: Verify field bindings (`tenant_id`, `tool`, `resource`, `agent_id`)
      - Step 7: Verify `tool` is covered by `scope`; verify `delegation_depth` not exceeded; reject with `SCOPE_ESCALATION_DENIED`
      - Step 8: Check agent against revocation list
      - Step 9: `atomic_claim_jti(redis, jti, ttl)` — reject with `CAPABILITY_CONSUMED` if `ALREADY_CLAIMED`; reject with `DEPENDENCY_OUTAGE_FAIL_CLOSED` if `DEPENDENCY_FAILURE`
      - Step 10: `ledger.record(action, receipt_id, config)` — Executor is sole writer
      - Step 11: `sign_receipt(action_hash, ledger_id, outcome)`
      - Step 12: `audit.append(EXECUTION_SUCCESS event)`
    - Any step failure → fail-closed: no ledger write, no receipt, no partial state
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, 3.14, 3.15, 6.4_

  - [ ]* 4.2 Write property test for executor-never-trusts-gateway (Property 2)
    - **Property 2: Executor Never Trusts Gateway**
    - Use `@given(st.integers(min_value=1), st.integers(min_value=1))` to generate two distinct `amount_minor` values; authorize one, execute with the other; assert ledger unchanged
    - **Validates: Requirements 3.1, 3.2, 8.1, 13.2**

  - [ ]* 4.3 Write property test for fail-closed on dependency failure (Property 4)
    - **Property 4: Fail-Closed on Dependency Failure**
    - Use `@given(st.booleans(), st.booleans())` for `redis_available` and `key_manager_available`; assert `ledger.count()` unchanged on any unavailability
    - **Validates: Requirements 4.3, 6.1, 6.2, 6.3, 6.4, 6.5, 8.5, 13.4**

- [ ] 5. Write Phase 1 security primitive tests
  - [ ] 5.1 Write `tests/test_t1_substitution.py` — T1 Action Substitution trial tests
    - Test `ACTION_HASH_MISMATCH` for mutations to each field: `tool`, `resource`, `tenant_id`, `agent_id`, `amount_minor`, `intent_id`, `delegation_depth`
    - Assert `ledger.count() == 0` after each rejected execution
    - Test that Config A records the substituted action (demonstrates RBAC-only gap)
    - _Requirements: 8.1, 8.2_

  - [ ] 5.2 Write `tests/test_t2_replay_race.py` — T2 Double-Spend Race trial tests
    - Run 100 concurrent `asyncio` tasks sharing one JTI using `asyncio.gather()`
    - Assert `len(successes) <= 1` and `len(CAPABILITY_CONSUMED rejections) >= 99`
    - Assert `ledger.query_by_intent(intent_id).count() <= 1`
    - _Requirements: 8.3, 4.2, 13.3_

  - [ ] 5.3 Checkpoint — Phase 1 complete
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Implement Capability Token Issuance (`control_plane/capability.py`)
  - [ ] 6.1 Implement `CapabilityToken` dataclass and `issue_capability()` function
    - Define frozen `CapabilityToken` with all V3 claims: `jti` (UUIDv4), `iss`, `aud`, `sub`, `iat`, `exp`, `action_hash`, `tenant_id`, `agent_id`, `tool`, `resource`, `intent_id`, `scope`, `delegation_depth`, `config`, `kid`, optional `approval_id` and `parent_jti`
    - Implement `issue_capability(action, signing_key, kid, ttl_seconds=60, ...) -> str` returning compact JWS `header.payload.signature`
    - Set `alg=EdDSA`, `typ=agentshield-v3-capability+jwt` in JWS header
    - Cap `ttl_seconds` at 300; default 60
    - For delegated capabilities: enforce `child.scope ⊆ parent.scope`; set `delegation_depth = parent.delegation_depth + 1`; reject with `SCOPE_ESCALATION_DENIED` if child scope exceeds parent
    - Embed `approval_id` when present
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8_

  - [ ] 6.2 Implement `verify_capability()` function (executor-side, 12-step entry point)
    - `verify_capability(token, expected_action, authenticated_agent, context) -> VerifiedClaims`
    - Integrate with executor pipeline as primary entry point for steps 2–8
    - Raise specific `CapabilityError` subclasses: `ActionHashMismatchError`, `CapabilityConsumedError`, `ScopeEscalationError`, `DependencyFailureError`
    - _Requirements: 3.1–3.14_

  - [ ]* 6.3 Write property test for scope non-escalation (Property 5)
    - **Property 5: Scope Non-Escalation**
    - Use `@given(st.lists(st.text(), min_size=1), st.lists(st.text(), min_size=1))` to generate parent/child scope pairs; assert any child scope not a subset of parent is rejected with `SCOPE_ESCALATION_DENIED`
    - **Validates: Requirements 2.5, 2.6, 2.7, 3.8, 3.9, 8.4, 13.5**

- [ ] 7. Implement OPA Policy Engine client (`control_plane/policy_opa.py`)
  - [ ] 7.1 Implement `OPADecision` enum, `PolicyResult` dataclass, and `evaluate_opa()` async function
    - Define `OPADecision`: `ALLOW`, `DENY`, `REQUIRE_APPROVAL`
    - Define `PolicyResult(decision, reason, matched_rule, policy_version)`
    - Implement `async evaluate_opa(action, agent_context, config: Literal["A","B","C"]) -> PolicyResult`
    - On OPA HTTP error or connection failure: return `PolicyResult(decision=DENY, reason="opa_unavailable_fail_closed")`
    - Implement `build_opa_input(action, agent) -> dict`
    - Config A path: RBAC role-membership check only
    - Config B path: full Rego policy evaluation at gateway, no hash re-check
    - Config C path: Rego policy includes scope, delegation depth, and hash-binding assertion
    - _Requirements: 6.1, 6.5, 9.1, 9.2, 9.3_

- [ ] 8. Implement FastAPI Gateway (`control_plane/gateway.py`)
  - [ ] 8.1 Scaffold FastAPI gateway app with agent authentication and request routing
    - Create `gateway.py` with `POST /v3/action` endpoint accepting `ActionEnvelope` JSON body
    - Implement agent authentication (JWT / API key header check)
    - Wire `canonicalize_action()` → `evaluate_opa()` → `issue_capability()` pipeline
    - Return `403 PolicyDeniedError` on `DENY`, `202 {approval_id}` on `REQUIRE_APPROVAL`, `200 {capability_token, action_hash, expires_at}` on `ALLOW`
    - Enforce: gateway module has **zero import** of `MockLedger` — verified with `assert "mock_ledger" not in sys.modules` in tests
    - _Requirements: 3.15, 5.6, 6.1, 9.3_

  - [ ] 8.2 Add FastAPI executor endpoint (`POST /v3/execute`) to `gateway.py` or separate `executor_api.py`
    - Accept `{capability_token, raw_action}` body
    - Delegate to `execute()` pipeline, return `ExecuteResult` as JSON
    - Handle all `CapabilityError` subclasses with appropriate HTTP status codes (400/403/409/503)
    - _Requirements: 3.1–3.15_

- [ ] 9. Implement Approval Service and Agent Context (`control_plane/approval.py` + `control_plane/agent.py`)
  - [ ] 9.1 Implement `approval.py` — human-in-loop approval binding
    - Create `ApprovalRequest(action_hash, agent_id, tenant_id, requested_at)` dataclass
    - Implement `create_approval_request(action_hash) -> str` returning `approval_id`
    - Implement `get_approval_status(approval_id) -> ApprovalStatus` (pending / approved / denied)
    - Embed `approval_id` in issued capability tokens when approval is granted
    - _Requirements: 2.8_

  - [ ] 9.2 Implement `agent.py` — agent context, identity, delegation chain
    - Define `AgentContext(agent_id, tenant_id, roles, delegation_chain, revoked)` dataclass
    - Implement delegation chain traversal for depth-limit enforcement
    - Integrate with revocation check in executor step 8
    - _Requirements: 2.7, 3.9, 3.10_

- [ ] 10. Write Rego policy file (`opa/agentshield_v3.rego`)
  - [ ] 10.1 Write Rego policies for all three configurations in `agentshield_v3.rego`
    - Config A package: `agentshield.config_a` — RBAC role-membership rule only; `allow = true` if `agent.roles[_] == required_role`
    - Config B package: `agentshield.config_b` — OPA policy-as-code: evaluate scope, resource pattern, amount limits; no hash assertion
    - Config C package: `agentshield.config_c` — full policy: Config B rules PLUS scope validation, delegation depth check, and hash-binding assertion (`input.action_hash == computed_hash`)
    - Add `require_approval` rule for high-value actions (e.g., `amount_minor > 1000000`)
    - _Requirements: 6.1, 9.1, 9.2, 9.3_

- [ ] 11. Implement Attack Corpus (`evaluation_plane/attack_corpus.py`)
  - [ ] 11.1 Define `AttackScenario` dataclass and implement `load_attack_corpus()`
    - Define `AttackScenario(trial_id, name, description, authorized_action, attack_action, concurrency, expected_ledger_delta, expected_receipt_count)`
    - Implement T1 scenario: `authorized_action.amount_minor=50000`, `attack_action.amount_minor=500000`, `concurrency=1`, `expected_ledger_delta=0`
    - Implement T2 scenario: same JTI for authorized and attack action, `concurrency=100`, `expected_ledger_delta=1`
    - Implement T3 scenario: child scope `orders/*` vs parent scope `orders/ORDER-001`, `concurrency=1`, `expected_ledger_delta=0`
    - Implement T4 scenario: Redis/OPA killed mid-flow, `concurrency=1`, `expected_ledger_delta=0`
    - Implement T5 scenario: tamper `details.amount_minor` in audit record #2, `expected_ledger_delta=0`
    - Implement `load_attack_corpus() -> list[AttackScenario]` and `get_trial(trial_id) -> AttackScenario`
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.8_

- [ ] 12. Implement Metrics Engine (`evaluation_plane/metrics.py`)
  - [ ] 12.1 Implement `TrialMetrics` dataclass and `compute_metrics()` function
    - Define `TrialMetrics` with fields: `config`, `trial_id`, `attack_success_rate`, `legitimate_success_rate`, `false_denial_rate`, `p50_latency_ms`, `p99_latency_ms`, `total_attack_attempts`, `unauthorized_side_effects`, `double_spend_prevented`
    - Add `asr_numerator`, `asr_denominator`, `lsr_numerator`, `lsr_denominator`, `fdr_numerator`, `fdr_denominator` fields for distinguishing `0/100` from `0/10`
    - Implement `compute_metrics(ledger, audit_records, run_log, config, trial_id) -> TrialMetrics`
    - Derive ASR from `ledger.query_all()` filtered by `attack_intent_ids` — never from API responses
    - Derive LSR from `ledger.query_all()` filtered by `legit_intent_ids`
    - Derive FDR from `run_log` events with `action_type=LEGIT` and `outcome=DENIED`
    - Compute p50/p99 from `[r.duration_ms for r in run_log]` using `statistics.quantiles`
    - Implement `compare_configs(results_A, results_B, results_C) -> ComparisonReport`
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 11.2_

  - [ ]* 12.2 Write property test for evaluator independence (Property 7)
    - **Property 7: Evaluator Independence**
    - Use `@given(st.lists(ledger_entry_strategy(), min_size=0, max_size=50))` to assert `compute_metrics()` result equals a direct ledger query count — never a mocked API response
    - Confirm `Evaluator` class contains no `httpx.AsyncClient` or HTTP import references
    - **Validates: Requirements 5.5, 5.6, 7.1, 7.6, 13.7**

- [ ] 13. Implement Independent Evaluator (`evaluation_plane/evaluator.py`)
  - [ ] 13.1 Implement `Evaluator` class with direct ledger reference
    - `Evaluator.__init__(self, ledger: MockLedger, audit_chain: AuditChain, attack_corpus: list[AttackScenario])` — direct object refs, no HTTP clients
    - Implement `async run_trial(trial_id, config) -> TrialMetrics` orchestrating attack corpus execution against the specified config
    - Implement `async run_all_trials(configs=["A","B","C"]) -> dict[str, list[TrialMetrics]]`
    - Verify Config C postconditions: `unauthorized_side_effects == 0` for T1/T3/T4; `double_spend_prevented >= 99` for T2
    - Assert that `Evaluator` has no `httpx`, `requests`, or `aiohttp` imports at module level
    - _Requirements: 7.1, 7.2, 7.3, 7.5, 7.6, 7.7, 7.8, 5.5_

- [ ] 14. Implement Comparator and Evidence Exporter (`evaluation_plane/comparator.py` + `evaluation_plane/evidence_export.py`)
  - [ ] 14.1 Implement `comparator.py` — A/B/C side-by-side comparison
    - Define `ComparisonReport` with per-config `TrialMetrics` lists and summary statistics
    - Implement `generate_comparison_report(results_A, results_B, results_C) -> ComparisonReport`
    - Implement `format_comparison_markdown(report) -> str` producing a human-readable side-by-side table of ASR/LSR/FDR/p50/p99
    - _Requirements: 9.4, 9.5, 7.7, 11.5_

  - [ ] 14.2 Implement `evidence_export.py` — 7-file evidence bundle
    - Implement `export_evidence(trial_results, ledger, audit_chain, receipts, output_dir) -> EvidenceManifest`
    - Generate exactly 7 files: `manifest.json`, `events.jsonl`, `ledger_snapshot.json`, `receipts.jsonl`, `metrics.json`, `comparison.md`, `summary.md`
    - `manifest.json`: trial run timestamp, feature version `"agentshield-v3"`, list of trials, configs compared, SHA-256 file checksums
    - `metrics.json`: include `{"numerator": N, "denominator": D}` objects for every rate metric — no raw float-only values
    - `ledger_snapshot.json`: all `LedgerEntry` records grouped by config
    - `receipts.jsonl`: one JSON line per `ExecutionReceipt` with all required fields
    - All values derived from actual measured data — no hardcoded placeholders
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7_

- [ ] 15. Implement baseline enforcement configurations (`control_plane/baselines/`)
  - [ ] 15.1 Implement `config_a_rbac.py` — RBAC-only baseline
    - Implement `execute_config_a(action, agent_context, ledger) -> ExecuteResult`
    - Role-membership check only: if `agent.roles` contains required role, write to ledger without hash recomputation or signature verification
    - Demonstrate that T1 substitution succeeds (write tampered `amount_minor` to ledger) — Config A gap
    - Demonstrate that T2 double-spend may produce multiple ledger entries without atomic gate
    - _Requirements: 9.1, 8.2_

  - [ ] 15.2 Implement `config_b_opa.py` — OPA gateway-only baseline
    - Implement `execute_config_b(action, agent_context, opa_client, ledger) -> ExecuteResult`
    - OPA policy evaluated at gateway; if `ALLOW`, execute without executor hash re-check
    - Demonstrate Config B gap: action payload can be substituted after OPA approval since no executor recomputation occurs
    - _Requirements: 9.2_

- [ ] 16. Write Phase 2/3 attack trial tests
  - [ ] 16.1 Write `tests/test_t3_delegation.py` — T3 Delegation Escalation trial tests
    - Test that child capability with scope `orders/*` is rejected when parent authorized `orders/ORDER-001`
    - Test rejection at executor step 7 with `SCOPE_ESCALATION_DENIED`
    - Test multiple delegation depths (depth 1, 2, 3) are all blocked when scope is escalated
    - Assert ledger unchanged after each rejection
    - _Requirements: 8.4, 2.5, 2.6, 2.7, 3.8, 3.9_

  - [ ] 16.2 Write `tests/test_t4_fail_closed.py` — T4 Dependency Failure trial tests
    - Test `DEPENDENCY_OUTAGE_FAIL_CLOSED` when Redis is unreachable (mock Redis to raise `ConnectionError`)
    - Test `DEPENDENCY_OUTAGE_FAIL_CLOSED` when key manager is unavailable
    - Test OPA fail-closed at gateway: mock OPA to raise `httpx.ConnectError`, assert `PolicyResult(DENY)`
    - Assert zero ledger entries in all failure scenarios
    - _Requirements: 8.5, 4.3, 6.1, 6.2, 6.3, 6.4, 6.5_

  - [ ] 16.3 Write `tests/test_t5_tamper.py` — T5 Evidence Tampering trial tests
    - Build an audit chain with 3 records; tamper `details["amount_minor"]` at `index=1` (sequence 2)
    - Call `verify_audit_chain()` and assert `report.valid == False`
    - Assert `report.first_invalid_sequence == 2`
    - Assert `report.error_code in {"RECORD_HASH_MISMATCH", "INVALID_AUDIT_SIGNATURE"}`
    - Test record deletion and record insertion detection
    - _Requirements: 8.6, 10.3, 10.4_

  - [ ] 16.4 Checkpoint — Phase 1–3 complete
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 17. Implement V3 Audit Chain (`audit/chain.py`)
  - [ ] 17.1 Implement `V3AuditChain` extending base `AuditChain`
    - Define `V3EventType` enum: `TRIAL_STARTED`, `TRIAL_COMPLETED`, `ATTACK_ATTEMPTED`, `DOUBLE_SPEND_BLOCKED`, `EXECUTION_SUCCESS`
    - Define `AuditRecord` dataclass with fields: `sequence_number`, `event_type`, `record_hash`, `prev_record_hash`, `signature`, `kid`, `trial_id`, `action_hash`, `outcome`, `details`, `timestamp_ms`
    - Implement `V3AuditChain(config: Literal["A","B","C"])` — per-config isolation
    - Implement `append(event_type, ...) -> AuditRecord`: compute `record_hash = SHA-256(prev_record_hash + canonical_bytes)`, sign with Ed25519
    - Implement `append_trial_event(event_type, trial_id, action, outcome, details) -> AuditRecord`
    - Implement `checkpoint() -> AuditChainCheckpoint` serializing current chain state
    - Enforce three independent chain instances — records from one config must not appear in another's chain
    - _Requirements: 10.1, 10.2, 10.5, 10.6, 10.7, 10.8_

  - [ ]* 17.2 Write property test for audit chain completeness (Property 6)
    - **Property 6: Audit Chain Completeness**
    - Use `@given(st.lists(canonical_action_strategy(), min_size=1, max_size=20))` to simulate N ledger writes; assert each `LedgerEntry.ledger_id` has a matching `EXECUTION_SUCCESS` audit record with same `action_hash`
    - **Validates: Requirements 3.13, 10.7, 13.6**

- [ ] 18. Implement Audit Chain Verifier (`audit/verifier.py`)
  - [ ] 18.1 Implement `verify_audit_chain()` and `AuditChainVerificationReport`
    - Define `AuditChainVerificationReport(valid: bool, first_invalid_sequence: int | None, error_code: str | None, issues: list[str])`
    - Implement `verify_audit_chain(records: list[AuditRecord], require_signatures: bool = True) -> AuditChainVerificationReport`
    - Recompute each record's hash independently and compare against stored `record_hash`; set `first_invalid_sequence` on first mismatch
    - Verify Ed25519 signature for each record; set `error_code = "INVALID_AUDIT_SIGNATURE"` on failure
    - Detect insertion, deletion, and reordering via sequence number gap checks
    - _Requirements: 10.3, 10.4_

- [ ] 19. Scaffold React/TypeScript/Tailwind dashboard project (`ui/`)
  - [ ] 19.1 Initialize React 18 + TypeScript + Tailwind CSS + Recharts project
    - Create `ui/package.json` with dependencies: `react@18`, `react-dom@18`, `typescript@5`, `tailwindcss@3`, `recharts@^2`, `@types/react`, `@types/react-dom`, `vite` (or `create-react-app`)
    - Configure `tsconfig.json` with strict mode
    - Configure Tailwind CSS in `ui/tailwind.config.js` and `ui/src/index.css`
    - Create `ui/src/App.tsx` with three-panel layout skeleton (Panel 1 / Panel 2 / Panel 3)
    - _Requirements: 12.1_

- [ ] 20. Implement Trial Runner Panel (`ui/src/components/TrialRunner.tsx`)
  - [ ] 20.1 Implement Panel 1 — trial selector and live execution feed
    - Render trial selector checkboxes for T1–T5 and configuration checkboxes for A/B/C
    - Implement `startTrial(selectedTrials, selectedConfigs)` that POSTs to `/v3/trial/start`
    - Render live feed as a scrollable list of `ActionFeedItem` components
    - Color-code feed items: `green` for `LEGITIMATE_SUCCESS`, `red` for `ATTACK_BLOCKED`, `orange` for `FALSE_DENIAL`
    - Consume WebSocket/SSE events from backend for real-time updates
    - _Requirements: 12.2, 12.3_

- [ ] 21. Implement Metrics Dashboard Panel (`ui/src/components/MetricsDashboard.tsx`)
  - [ ] 21.1 Implement Panel 2 — side-by-side ASR/LSR/FDR charts and latency display
    - Render `BarChart` (Recharts) with three grouped bars per metric (Config A / B / C) for ASR, LSR, FDR
    - Render latency panel showing p50 and p99 in milliseconds per configuration
    - Render running counter component displaying `double_spend_prevented` count from T2 trials
    - Fetch metrics from `/v3/metrics` endpoint on trial completion and on WebSocket update
    - _Requirements: 12.4, 12.5_

- [ ] 22. Implement Audit Chain Viewer Panel (`ui/src/components/AuditViewer.tsx`)
  - [ ] 22.1 Implement Panel 3 — hash-linked audit records with tamper detection
    - Render scrollable list of audit records, each showing: `sequence_number`, truncated `record_hash`, `event_type`, `outcome`, Ed25519 verification status badge (`✓ verified` / `✗ failed`)
    - Highlight the first record with a broken hash link in red; display `first_invalid_sequence` in the panel header
    - Fetch audit records from `/v3/audit` endpoint; poll or consume SSE for live updates
    - _Requirements: 12.6, 12.7_

- [ ] 23. Implement WebSocket/SSE backend for live dashboard updates
  - [ ] 23.1 Add SSE or WebSocket endpoint to FastAPI backend
    - Implement `GET /v3/stream` as a Server-Sent Events (SSE) endpoint using FastAPI `StreamingResponse`
    - Define event schema: `{event_type, trial_id, config, action_hash, outcome, timestamp_ms, details}`
    - Publish events to the stream when executor records a ledger entry, blocks an attack, or rejects a request
    - Implement `GET /v3/metrics` returning `ComparisonReport` JSON
    - Implement `GET /v3/audit` returning all `AuditRecord` objects for a given config
    - _Requirements: 12.3, 12.5, 12.7_

- [ ] 24. Implement receipt signing and idempotency guard (`execution_plane/receipt.py` + `execution_plane/idempotency.py`)
  - [ ] 24.1 Implement `receipt.py` — Ed25519-signed execution receipts
    - Define `ExecutionReceipt(receipt_id, execution_id, action_hash, ledger_entry_id, outcome, config, executed_at_ms, kid, signature)` frozen dataclass
    - Implement `sign_receipt(action_hash, ledger_id, outcome, signing_key, kid) -> ExecutionReceipt`
    - Compute receipt signature as `Ed25519.sign(domain_sep + canonical_receipt_bytes)`
    - Implement `verify_receipt(receipt, verification_key) -> bool`
    - _Requirements: 11.4_

  - [ ] 24.2 Implement `idempotency.py` — intent-ID idempotency guard
    - Implement `async check_idempotency(redis, intent_id) -> IdempotencyResult` (FIRST_SEEN / DUPLICATE)
    - Store `agentshield:v3:intent:{intent_id}` in Redis with TTL matching capability TTL
    - Return the cached `ExecuteResult` for duplicate intent IDs without re-executing
    - _Requirements: 3.11, 3.14_

- [ ] 25. Write end-to-end happy path test (`tests/test_legitimate_flow.py`)
  - [ ] 25.1 Implement end-to-end test covering the complete Config C legitimate flow
    - Construct a valid `ActionEnvelope` (₹500 refund, `delegation_depth=0`)
    - Submit to gateway → receive `capability_token` and `action_hash`
    - Submit to executor with `raw_action` → receive `ExecuteResult(outcome="success")`
    - Assert `ledger.count() == 1`; assert `ledger.query_by_intent(intent_id)[0].amount_minor == 50000`
    - Assert audit chain contains `EXECUTION_SUCCESS` record with matching `action_hash` and `ledger_id` (Property 6)
    - Assert `receipt.action_hash == ledger_entry.action_hash`
    - Run same scenario for Config A and Config B to verify 3-config isolation
    - _Requirements: 3.13, 3.14, 3.15, 10.7_

- [ ] 26. Create `docker-compose.yml` and service configuration
  - [ ] 26.1 Write `docker-compose.yml` with all required services
    - Define `redis` service: `redis:7-alpine`, port 6379, named volume for persistence
    - Define `opa` service: `openpolicyagent/opa:latest`, mount `./opa/agentshield_v3.rego`, port 8181
    - Define `backend` service: build from `Dockerfile`, depends on `redis` and `opa`, port 8000, `ENV REDIS_URL`, `OPA_URL`
    - Define `frontend` service: build from `ui/`, depends on `backend`, port 3000
    - Add `healthcheck` for `redis` and `opa` so `backend` waits for them before starting
    - Use only synthetic env vars — no real credentials in `docker-compose.yml` or `.env.example`
    - _Requirements: 14.1, 14.2, 14.4_

- [ ] 27. Write project `README.md` with demo runbook
  - [ ] 27.1 Write `README.md` covering one-command startup and 7-minute demo runbook
    - One-command start section: `docker-compose up --build` → system ready
    - 7-minute demo runbook: (0:00) start system, (1:00) open dashboard, (2:00) run T1 substitution, (3:00) run T2 race, (4:00) run T3 delegation, (5:00) run T4 fail-closed, (6:00) view evidence bundle, (7:00) compare A/B/C metrics
    - Evidence format section: describe all 7 output files and their schemas
    - API reference: `POST /v3/action`, `POST /v3/execute`, `GET /v3/metrics`, `GET /v3/audit`, `GET /v3/stream`
    - Note that all data is synthetic; no real credentials, payment data, or agent identities used
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_

- [ ] 28. Final integration checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP; they validate correctness properties and improve confidence but are not required for functional demo
- Property-based tests use `hypothesis` (`>=6.80.0`); run with `pytest tests/ --hypothesis-seed=0`
- Phase 1 (Tasks 1–5) is a hard prerequisite — T1 and T2 tests must pass before any Phase 2 work begins
- The `MockLedger` instance is passed by direct Python reference to the `Evaluator`; it is never accessible via HTTP from the `Evaluator`
- The `Gateway` module must have zero import of `mock_ledger` — enforce with an import-check assertion in gateway tests
- All rate metrics (ASR, LSR, FDR) are stored with explicit numerator and denominator to distinguish `0/100` from `0/10`
- Config A, B, and C use separate `MockLedger` and `V3AuditChain` instances; never share state
- Ed25519 keys are generated fresh at demo startup and must never be committed to source control
- The `b"AGENTSHIELD-V3\x00"` domain separator ensures V3 hashes are cryptographically distinct from V2 hashes

---

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "2.1"] },
    { "id": 2, "tasks": ["1.3", "3.1"] },
    { "id": 3, "tasks": ["3.2", "4.1"] },
    { "id": 4, "tasks": ["4.2", "4.3", "5.1", "5.2"] },
    { "id": 5, "tasks": ["6.1"] },
    { "id": 6, "tasks": ["6.2", "7.1"] },
    { "id": 7, "tasks": ["6.3", "8.1"] },
    { "id": 8, "tasks": ["8.2", "9.1", "9.2"] },
    { "id": 9, "tasks": ["10.1"] },
    { "id": 10, "tasks": ["11.1", "12.1"] },
    { "id": 11, "tasks": ["12.2", "13.1"] },
    { "id": 12, "tasks": ["14.1", "15.1", "15.2"] },
    { "id": 13, "tasks": ["14.2", "16.1", "16.2", "16.3"] },
    { "id": 14, "tasks": ["17.1"] },
    { "id": 15, "tasks": ["17.2", "18.1"] },
    { "id": 16, "tasks": ["19.1"] },
    { "id": 17, "tasks": ["20.1", "21.1", "22.1"] },
    { "id": 18, "tasks": ["23.1", "24.1", "24.2"] },
    { "id": 19, "tasks": ["25.1"] },
    { "id": 20, "tasks": ["26.1", "27.1"] }
  ]
}
```

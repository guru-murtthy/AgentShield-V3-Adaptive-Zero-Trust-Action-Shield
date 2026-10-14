# Requirements Document

## Introduction

AgentShield V3 — The Autonomy Trial is a research-grade AI security demonstration platform that proves whether autonomous AI agents can perform real-world actions without exceeding their authority. The system extends Ed25519 capability tokens and SHA-256 action-hash binding from V2 into a full three-plane architecture: a Control Plane (policy and authorization), an Execution Plane (independent cryptographic enforcement), and an Evaluation Plane (ground-truth metrics). Three enforcement configurations — Config A (RBAC only), Config B (OPA gateway only), and Config C (full AgentShield V3) — run identical attack workloads and legitimate workloads side-by-side, enabling rigorous A/B/C comparison. All data is synthetic; all metrics are derived exclusively from actual measured trial runs.

---

## Glossary

- **Action Envelope**: A structured, versioned payload describing a single agent action (tool, resource, amount, tenant, agent, intent) in V3 canonical schema.
- **Action Hash**: The SHA-256 digest of `b"AGENTSHIELD-V3\x00"` concatenated with the deterministic canonical JSON encoding of an Action Envelope; represented as a 64-character lowercase hex string.
- **Atomic Claim**: A Redis `SET NX EX` operation on a JTI key that atomically grants or denies exclusive ownership of a single-use capability.
- **Audit Chain**: An append-only, Ed25519-signed, SHA-256 hash-linked sequence of audit records providing tamper-evident provenance for all system events.
- **Canonicalizer**: The component that converts an Action Envelope into deterministic UTF-8 canonical JSON bytes following RFC 8785 / JCS semantics.
- **Capability Token**: An Ed25519-signed JWS token issued by the Capability Issuer, cryptographically binding a specific permission to one exact Action Hash.
- **Config A**: The RBAC-only enforcement baseline — role-membership check only; no hash binding, no independent executor verification.
- **Config B**: The OPA gateway-only enforcement baseline — policy-as-code evaluation at the gateway; no executor re-check of the hash.
- **Config C**: The full AgentShield V3 enforcement configuration — complete 12-step executor pipeline with hash recomputation, Ed25519 verification, atomic Redis claim, and independent ledger write.
- **Delegation Depth**: An integer claim in a Capability Token indicating how many delegation steps removed the issuing agent is from a root (depth 0) agent.
- **Evaluator**: The independent component that queries the Mock Ledger directly (never via HTTP API) to compute ground-truth metrics (ASR, LSR, FDR, latency).
- **Executor**: The Protected Executor — the final, independent enforcement boundary in the Execution Plane that applies the 12-step verification pipeline before writing to the Mock Ledger.
- **FDR (False Denial Rate)**: The ratio of valid legitimate actions incorrectly denied to total valid legitimate actions submitted.
- **Gateway**: The Control Plane FastAPI service that authenticates agents, evaluates OPA policies, computes the Action Hash, and issues Capability Tokens.
- **Intent ID**: A UUIDv4 string uniquely identifying a single action request; used for idempotency.
- **JTI (JWT Token ID)**: A UUID claim in a Capability Token marking it as single-use; consumed atomically by the Executor via Redis `SET NX EX`.
- **LSR (Legitimate Success Rate)**: The ratio of valid legitimate actions that successfully execute to total valid legitimate actions submitted.
- **Mock Ledger**: The append-only, thread-safe, in-memory record of all successfully executed actions; the Evaluator's ground truth.
- **ASR (Attack Success Rate)**: The ratio of unauthorized side effects (attacker-controlled ledger writes) to total unauthorized attack attempts.
- **OPA**: Open Policy Agent — the Rego-based policy engine used in Config B and Config C for policy-as-code evaluation.
- **Paise**: The integer unit of currency used in `amount_minor` (1 INR = 100 paise); no fractional amounts are permitted.
- **Signed Receipt**: An Ed25519-signed record produced by the Executor after a successful ledger write, certifying the action hash, ledger entry ID, and outcome.
- **T1–T5**: The five canonical attack scenarios in the Trial Attack Corpus (Action Substitution, Double-Spend Race, Delegation Escalation, Dependency Failure, Evidence Tampering).
- **Trial Attack Corpus**: The set of five structured, reproducible attack scenarios run against each enforcement configuration.
- **V3AuditChain**: The V3-extended audit chain supporting V3-specific event types (`TRIAL_STARTED`, `TRIAL_COMPLETED`, `ATTACK_ATTEMPTED`, `DOUBLE_SPEND_BLOCKED`) with per-config isolation.

---

## Requirements

### Requirement 1: Action Canonicalization and Hash Binding

**User Story:** As a security engineer, I want every action envelope to produce a deterministic, domain-separated SHA-256 hash, so that both the Gateway at authorization time and the Executor at enforcement time independently compute an identical binding value that detects any payload tampering.

#### Acceptance Criteria

1. THE Canonicalizer SHALL produce deterministic UTF-8 canonical JSON bytes for any Action Envelope following RFC 8785 / JCS semantics (lexicographic key ordering, no extra whitespace, no trailing commas).
2. WHEN the Canonicalizer receives two Action Envelopes that are logically identical but have keys in different orders, THE Canonicalizer SHALL produce identical canonical bytes for both.
3. THE Canonicalizer SHALL compute the Action Hash as `SHA-256(b"AGENTSHIELD-V3\x00" + canonical_bytes)` and return the result as a 64-character lowercase hexadecimal string.
4. WHEN any single field in an Action Envelope is mutated (including `tool`, `resource`, `tenant_id`, `agent_id`, `amount_minor`, `intent_id`, `schema_version`, `delegation_depth`), THE Canonicalizer SHALL produce a different Action Hash for the mutated envelope with overwhelming probability.
5. WHEN an Action Envelope contains a floating-point number in any field, THE Canonicalizer SHALL reject the input and raise a validation error before computing any hash.
6. WHEN an Action Envelope contains an explicit null value for any required field, THE Canonicalizer SHALL reject the input and raise a validation error.
7. WHEN an Action Envelope contains a control character (Unicode code points U+0000–U+001F or U+007F) in any string field, THE Canonicalizer SHALL reject the input and raise a validation error.
8. WHEN an Action Envelope contains duplicate keys at any level of nesting, THE Canonicalizer SHALL reject the input and raise a validation error.
9. WHEN the `amount_minor` field is zero, negative, or a non-integer value, THE Canonicalizer SHALL reject the input and raise a validation error.
10. THE Canonicalizer SHALL support all input forms: Python dict, JSON string, bytes, and `CanonicalAction` dataclass.
11. WHEN computing the Action Hash, THE Canonicalizer SHALL use the `b"AGENTSHIELD-V3\x00"` domain separator, ensuring V3 hashes are distinct from V2 hashes that use `b"AGENTSHIELD-ACTION-V1\x00"`.

---

### Requirement 2: Capability Token Issuance

**User Story:** As an authorized AI agent, I want to receive a cryptographically signed capability token that binds my permission to one exact action hash, so that I cannot present the token to authorize a different action than the one approved.

#### Acceptance Criteria

1. WHEN the Gateway approves an action request, THE Capability Issuer SHALL issue an Ed25519-signed JWS capability token with header `alg: EdDSA` and `typ: agentshield-v3-capability+jwt`.
2. THE Capability Issuer SHALL embed the following claims in every issued token: `jti` (UUID v4), `iss` (`agentshield-v3-gateway`), `aud` (`agentshield-v3-executor`), `sub` (agent_id), `iat` (Unix timestamp), `exp` (Unix timestamp), `action_hash` (64-char hex), `tenant_id`, `agent_id`, `tool`, `resource`, `intent_id`, `scope` (list of strings), `delegation_depth` (integer), `config` (A/B/C), and `kid` (key ID).
3. WHEN a capability token is issued, THE Capability Issuer SHALL set `exp = iat + ttl_seconds`, where `ttl_seconds` defaults to 60 and is capped at a maximum of 300.
4. WHEN a requested TTL exceeds 300 seconds, THE Capability Issuer SHALL cap the TTL at 300 seconds and issue the token with `exp = iat + 300`.
5. WHEN a child agent derives a capability from a parent capability, THE Capability Issuer SHALL enforce that the child capability's `scope` is a subset of the parent capability's `scope`.
6. WHEN a child capability would require a scope not contained in the parent capability's `scope`, THE Capability Issuer SHALL reject the issuance request and return a `SCOPE_ESCALATION_DENIED` error.
7. THE Capability Issuer SHALL set `delegation_depth = parent.delegation_depth + 1` for any child capability, and SHALL reject issuance if the child's `delegation_depth` would exceed the parent's authorized delegation limit.
8. WHEN an approval is required for an action, THE Capability Issuer SHALL embed the `approval_id` claim in the issued token.

---

### Requirement 3: Independent Executor Enforcement (12-Step Pipeline)

**User Story:** As a security architect, I want the Executor to independently verify every action request through a mandatory 12-step pipeline without trusting the Gateway's authorization summary, so that any payload substitution, replay, scope escalation, or dependency failure is caught before any action is recorded in the ledger.

#### Acceptance Criteria

1. WHEN the Executor receives an execution request, THE Executor SHALL recompute the Action Hash from the raw action payload presented by the agent, independently of any hash value provided by the Gateway.
2. WHEN the recomputed Action Hash does not match the `action_hash` claim in the capability token, THE Executor SHALL reject the request with `ACTION_HASH_MISMATCH` and SHALL NOT write any entry to the Mock Ledger.
3. THE Executor SHALL use constant-time comparison (e.g., `hmac.compare_digest`) when comparing the recomputed Action Hash against the token's `action_hash` claim.
4. WHEN the capability token's Ed25519 signature fails verification against the key identified by `kid`, THE Executor SHALL reject the request and SHALL NOT write any entry to the Mock Ledger.
5. WHEN the capability token's `exp` claim is in the past, THE Executor SHALL reject the request as expired and SHALL NOT write any entry to the Mock Ledger.
6. WHEN the capability token's `iss` claim is not `agentshield-v3-gateway` or its `aud` claim is not `agentshield-v3-executor`, THE Executor SHALL reject the request and SHALL NOT write any entry to the Mock Ledger.
7. WHEN any of the field-binding claims (`tenant_id`, `tool`, `resource`, `agent_id`) in the capability token do not match the corresponding fields in the raw action payload, THE Executor SHALL reject the request and SHALL NOT write any entry to the Mock Ledger.
8. WHEN the action's requested tool is not covered by the `scope` in the capability token, THE Executor SHALL reject the request with `SCOPE_ESCALATION_DENIED` and SHALL NOT write any entry to the Mock Ledger.
9. WHEN the `delegation_depth` in the raw action payload exceeds the `delegation_depth` claim in the capability token, THE Executor SHALL reject the request with `SCOPE_ESCALATION_DENIED`.
10. WHEN the agent identified by `agent_id` is on the principal revocation list, THE Executor SHALL reject the request and SHALL NOT write any entry to the Mock Ledger.
11. WHEN all preceding verification steps pass, THE Executor SHALL perform an atomic Redis `SET NX EX` on the key `agentshield:v3:jti:{jti}` before writing to the Mock Ledger.
12. WHEN the Redis atomic claim returns nil (JTI already claimed), THE Executor SHALL reject the request with `CAPABILITY_CONSUMED` and SHALL NOT write any entry to the Mock Ledger.
13. WHEN the atomic Redis claim succeeds, THE Executor SHALL write exactly one entry to the Mock Ledger, sign an execution receipt, and append an audit record to the Audit Chain — in that order.
14. WHEN any of the 12 verification steps fails for any reason, THE Executor SHALL fail closed: no ledger write, no receipt, no partial state.
15. THE Gateway SHALL have zero write access to the Mock Ledger; all ledger writes SHALL originate exclusively from the Executor.

---

### Requirement 4: Atomic Double-Spend Prevention

**User Story:** As a platform operator, I want Redis `SET NX EX` to be the sole atomic gate preventing double-spend, so that even 100 concurrent requests presenting the same capability token result in at most one successful ledger entry.

#### Acceptance Criteria

1. THE Executor SHALL use Redis `SET NX EX agentshield:v3:jti:{jti} CLAIMED` as the sole atomic gate between capability verification and ledger write.
2. WHEN 100 concurrent execution requests present the same capability token (identical JTI), THE Executor SHALL record at most 1 entry in the Mock Ledger for that JTI.
3. WHEN Redis is unreachable at the time of an atomic claim attempt, THE Atomic Claim component SHALL return `DEPENDENCY_FAILURE` and THE Executor SHALL reject the request with `DEPENDENCY_OUTAGE_FAIL_CLOSED` without writing to the Mock Ledger.
4. WHEN multiple concurrent requests present the same JTI and the atomic claim returns `CLAIMED` to exactly one caller, THE Executor SHALL reject all other callers with `CAPABILITY_CONSUMED`.
5. THE Atomic Claim component SHALL never raise an exception on Redis connection failure; it SHALL return `DEPENDENCY_FAILURE` (fail-closed) so the Executor can handle it safely.

---

### Requirement 5: Mock Ledger as Ground Truth

**User Story:** As an evaluator, I want the Mock Ledger to be an append-only, thread-safe record of all executed actions, accessible to me by direct reference, so that my metrics cannot be manipulated through API-level deception.

#### Acceptance Criteria

1. THE Mock Ledger SHALL be append-only: once a `LedgerEntry` is written, it SHALL NOT be deleted, updated, or overwritten.
2. WHILE a concurrent write or read is in progress, THE Mock Ledger SHALL protect all operations with an asyncio lock to ensure thread safety.
3. THE Mock Ledger SHALL store the following fields in every `LedgerEntry`: `ledger_id` (UUID), `action_hash`, `tenant_id`, `agent_id`, `tool`, `resource`, `amount_minor`, `intent_id`, `receipt_id`, `timestamp_ms`, and `config` (A, B, or C).
4. THE Mock Ledger SHALL expose `query_all()`, `query_by_intent(intent_id)`, `query_by_config(config)`, `count()`, and `reset()` operations.
5. THE Evaluator SHALL hold a direct Python reference to the Mock Ledger instance and SHALL NOT query ledger data via any HTTP API endpoint.
6. THE Gateway module SHALL have no import reference or runtime reference to the Mock Ledger instance.

---

### Requirement 6: Fail-Closed Behavior

**User Story:** As a security engineer, I want every external dependency failure to result in an automatic deny decision, so that the system never grants access or records execution when it cannot enforce its security invariants.

#### Acceptance Criteria

1. WHEN OPA is unavailable or returns an error during policy evaluation, THE Gateway SHALL return a `DENY` decision and SHALL NOT issue a capability token.
2. WHEN Redis is unavailable at the time of an atomic JTI claim, THE Executor SHALL return `DEPENDENCY_OUTAGE_FAIL_CLOSED` and SHALL NOT write to the Mock Ledger.
3. WHEN the key manager is unavailable and the Executor cannot retrieve a verification key for `kid`, THE Executor SHALL reject the request and SHALL NOT write to the Mock Ledger.
4. IF any of the 12 executor verification steps raises an unhandled exception, THEN THE Executor SHALL catch the exception, reject the request with `DEPENDENCY_OUTAGE_FAIL_CLOSED`, and SHALL NOT write to the Mock Ledger.
5. THE System SHALL never transition to an "allow on error" state for any dependency: fail-closed behavior SHALL apply unconditionally to OPA, Redis, and the key manager.

---

### Requirement 7: Independent Evaluator and Metrics Computation

**User Story:** As a trial judge, I want the Evaluator to compute all metrics exclusively from direct Mock Ledger queries, so that the reported ASR, LSR, FDR, and latency values reflect ground truth and cannot be falsified by the Gateway or Executor returning manipulated API responses.

#### Acceptance Criteria

1. THE Evaluator SHALL compute ASR as `unauthorized_side_effects / total_unauthorized_attempts`, where `unauthorized_side_effects` is the count of ledger entries whose `intent_id` matches an attack scenario's attack intent IDs — queried directly from the Mock Ledger.
2. THE Evaluator SHALL compute LSR as `valid_succeeded / total_valid_submitted`, where `valid_succeeded` is the count of ledger entries for legitimate intent IDs — queried directly from the Mock Ledger.
3. THE Evaluator SHALL compute FDR as `valid_denied / total_valid_submitted`, where `valid_denied` is the count of legitimate actions denied — derived from the run log, not from gateway or executor API responses.
4. THE Evaluator SHALL measure p50 and p99 execution latency in milliseconds from the timestamped run log of actual trial executions.
5. WHEN producing a `TrialMetrics` result, THE Evaluator SHALL include both the numerator and the denominator for each rate metric so that `0/100` and `0/10` are distinguishable.
6. THE Evaluator SHALL have no HTTP client reference to the Gateway or Executor — all data access SHALL be through direct object references to `MockLedger`, `AuditChain`, and the run log.
7. WHEN comparing configurations, THE Evaluator SHALL run identical attack and legitimate workloads against Config A, Config B, and Config C using the same Attack Corpus scenarios and produce a `ComparisonReport` with side-by-side metrics.
8. WHEN all metrics are produced, THE Evaluator SHALL verify that Config C postconditions hold: `unauthorized_side_effects == 0` for T1, T3, T4 trials, and `double_spend_prevented ≥ 99` for T2 trials.

---

### Requirement 8: Five Trial Attack Corpus (T1–T5)

**User Story:** As a researcher, I want five canonical, reproducible attack scenarios that expose known AI agent vulnerabilities, so that I can demonstrate the security gap between enforcement configurations and prove Config C's effectiveness under adversarial conditions.

#### Acceptance Criteria

1. WHEN trial T1 (Action Substitution) is executed against Config C, THE System SHALL detect that the raw action's `amount_minor` differs from the authorized amount and THE Executor SHALL reject the execution with `ACTION_HASH_MISMATCH`, producing zero new ledger entries for the substituted action.
2. WHEN trial T1 is executed against Config A, THE System SHALL record the substituted action in the ledger, demonstrating that RBAC-only enforcement does not detect payload substitution.
3. WHEN trial T2 (Double-Spend Race) is executed against Config C with 100 concurrent requests sharing one JTI, THE System SHALL record at most 1 ledger entry for that intent and block at least 99 requests with `CAPABILITY_CONSUMED`.
4. WHEN trial T3 (Delegation Escalation) is executed against Config C, THE System SHALL detect that the child capability's requested scope exceeds the parent's scope and reject the execution with `SCOPE_ESCALATION_DENIED`, leaving the ledger unchanged.
5. WHEN trial T4 (Dependency Failure) is executed against Config C with OPA or Redis killed mid-flow, THE System SHALL reject all in-flight execution requests with `DEPENDENCY_OUTAGE_FAIL_CLOSED` and produce zero unauthorized ledger entries.
6. WHEN trial T5 (Evidence Tampering) is executed and an audit record's field is modified after being written, THE Audit Chain verifier SHALL report `valid = False` and SHALL identify the correct `first_invalid_sequence` number of the tampered record.
7. WHEN any trial T1–T5 is executed against Config C, THE ASR SHALL equal 0.0 (zero unauthorized side effects) for attack-type sub-scenarios.
8. THE Attack Corpus SHALL define each attack scenario with: `trial_id`, `name`, `description`, `authorized_action` dict, `attack_action` dict, `concurrency`, `expected_ledger_delta`, and `expected_receipt_count`.

---

### Requirement 9: Three Enforcement Configurations

**User Story:** As an evaluator, I want three clearly distinct enforcement configurations running the same workload, so that I can produce a fair, reproducible comparison of security postures and demonstrate the measurable improvement of full cryptographic enforcement over weaker baselines.

#### Acceptance Criteria

1. THE System SHALL implement Config A as RBAC-only enforcement: an agent's role membership is checked, and if approved the action is executed without computing or verifying an Action Hash and without an independent executor re-check.
2. THE System SHALL implement Config B as OPA gateway-only enforcement: Rego policies evaluate the action at the gateway and approve or deny it, but the executor does not recompute the hash or perform independent verification.
3. THE System SHALL implement Config C as full AgentShield V3 enforcement: the complete 12-step executor pipeline applies, including hash recomputation, Ed25519 signature verification, atomic Redis JTI claim, and independent ledger write.
4. WHEN any trial from the Attack Corpus is executed, THE System SHALL run the identical attack and legitimate action payloads against Config A, Config B, and Config C using separate, isolated Mock Ledger instances and Audit Chains for each configuration.
5. WHEN producing a comparison report, THE Evaluator SHALL present ASR, LSR, FDR, p50, and p99 metrics for all three configurations side-by-side.

---

### Requirement 10: Tamper-Evident Audit Chain

**User Story:** As a compliance auditor, I want every system event to be recorded in an Ed25519-signed, hash-linked audit chain, so that any retroactive modification, deletion, reordering, or insertion of records is cryptographically detectable.

#### Acceptance Criteria

1. THE V3AuditChain SHALL sign every audit record with Ed25519 using the system's signing key, embedding the signature and `kid` in the record.
2. WHEN a new audit record is appended, THE V3AuditChain SHALL compute its `record_hash` as `SHA-256(prev_record_hash + record_canonical_bytes)` and embed it in the record, forming a cryptographic hash chain.
3. WHEN `verify_audit_chain` is called on a chain where any record's stored `record_hash` does not match the independently recomputed hash, THE V3AuditChain SHALL return `valid = False` and SHALL set `first_invalid_sequence` to the sequence number of the first tampered record.
4. WHEN `verify_audit_chain` is called on a chain where any record's Ed25519 signature fails verification, THE V3AuditChain SHALL return `valid = False` and SHALL set `error_code` to `INVALID_AUDIT_SIGNATURE`.
5. THE V3AuditChain SHALL record V3-specific event types: `TRIAL_STARTED`, `TRIAL_COMPLETED`, `ATTACK_ATTEMPTED`, `DOUBLE_SPEND_BLOCKED`, and `EXECUTION_SUCCESS` with associated trial ID, action hash, and outcome fields.
6. THE System SHALL maintain three independent Audit Chain instances — one per enforcement configuration (A, B, C) — such that records from one configuration do not appear in another configuration's chain.
7. WHEN a ledger entry is written, THE Executor SHALL append a corresponding `EXECUTION_SUCCESS` audit record to the chain within the same execution pipeline step, before returning the execution result.
8. THE V3AuditChain SHALL support checkpointing: `checkpoint()` SHALL serialize the chain state so that offline verification can confirm integrity at any point in time.

---

### Requirement 11: Evidence Export

**User Story:** As a demo presenter, I want every trial run to automatically produce a complete, self-contained evidence bundle, so that the results can be independently reviewed, archived, and reproduced without relying on a live system.

#### Acceptance Criteria

1. WHEN a trial run completes, THE Evidence Exporter SHALL produce the following files in a designated output directory: `manifest.json`, `events.jsonl`, `ledger_snapshot.json`, `receipts.jsonl`, `metrics.json`, `comparison.md`, and `summary.md`.
2. THE `metrics.json` file SHALL include the numerator and denominator for every rate metric (ASR, LSR, FDR) so that `{"numerator": 0, "denominator": 100}` is distinguishable from `{"numerator": 0, "denominator": 10}`.
3. THE `ledger_snapshot.json` SHALL contain a serialized copy of all `LedgerEntry` records at the time of export, grouped by configuration.
4. THE `receipts.jsonl` SHALL contain one JSON line per `ExecutionReceipt`, including `receipt_id`, `action_hash`, `ledger_entry_id`, `outcome`, `executed_at_ms`, `kid`, and `signature`.
5. THE `comparison.md` SHALL present a human-readable side-by-side table of ASR, LSR, FDR, p50, and p99 for Config A, Config B, and Config C across all executed trials.
6. ALL metrics values in the evidence bundle SHALL be derived from actual measured trial runs — no hardcoded placeholder values are permitted.
7. WHEN the evidence bundle is produced, THE `manifest.json` SHALL record the trial run timestamp, feature version, list of trials executed, configurations compared, and file checksums for each bundle file.

---

### Requirement 12: Three-Panel React Dashboard

**User Story:** As a demo audience member, I want a live three-panel web dashboard that shows trial execution progress, security metrics, and audit chain integrity in real time, so that I can observe AgentShield V3's enforcement in action without reading raw log files.

#### Acceptance Criteria

1. THE Dashboard SHALL present three panels: Trial Runner (Panel 1), Metrics Dashboard (Panel 2), and Audit Chain Viewer (Panel 3), implemented in React 18 with TypeScript and Tailwind CSS.
2. WHEN Panel 1 is displayed, THE Dashboard SHALL allow the user to select any combination of trials (T1–T5) and configurations (A, B, C) before starting a run.
3. WHEN a trial is running, Panel 1 SHALL display a live feed of action requests, policy decisions, and execution outcomes with color coding: green for legitimate success, red for attack blocked, orange for false denial.
4. WHEN Panel 2 is displayed, THE Dashboard SHALL render side-by-side bar charts for ASR, LSR, and FDR across Config A, Config B, and Config C using Recharts.
5. WHEN Panel 2 is displayed, THE Dashboard SHALL show latency percentile values (p50, p99) per configuration and a running counter of double-spend blocks from T2 trials.
6. WHEN Panel 3 is displayed, THE Dashboard SHALL list audit chain records with their sequence numbers, `record_hash` values, and Ed25519 signature verification status (verified / failed).
7. WHEN the audit chain contains a tampered record, Panel 3 SHALL highlight the first broken link in red, identifying the `first_invalid_sequence`.

---

### Requirement 13: Correctness Properties for Property-Based Testing

**User Story:** As a quality engineer, I want formal correctness properties that can be validated with property-based testing using Hypothesis, so that the security invariants of AgentShield V3 hold universally across all valid inputs and edge cases — not just the specific test vectors in the trial corpus.

#### Acceptance Criteria

1. FOR ALL valid Action Envelopes `a` and `b` where `a ≠ b`, THE Canonicalizer SHALL produce distinct Action Hashes for `a` and `b` with overwhelming probability (SHA-256 collision resistance), verifiable by mutating any single field and asserting the resulting hash differs.
2. FOR ALL execution requests where `compute_action_hash(raw_action) ≠ capability_token.action_hash`, THE Executor SHALL reject the request and the Mock Ledger SHALL remain unchanged (zero new entries for that request).
3. FOR ALL values of `jti` and any number of concurrent execution requests presenting that `jti`, THE Atomic Claim component SHALL return `CLAIMED` to at most one caller, and all subsequent callers SHALL receive `ALREADY_CLAIMED` or `DEPENDENCY_FAILURE`.
4. FOR ALL execution requests submitted when Redis is unreachable OR when the key manager is unavailable, THE Executor SHALL reject the request and the Mock Ledger SHALL remain unchanged.
5. FOR ALL parent-child capability pairs where `child.delegation_depth == parent.delegation_depth + 1`, THE child capability's `scope` SHALL be a subset of `parent.scope`, and any child capability with scope exceeding the parent SHALL be rejected before issuance.
6. FOR ALL `LedgerEntry` records in the Mock Ledger, THE V3AuditChain SHALL contain a corresponding `EXECUTION_SUCCESS` record with matching `action_hash` and `ledger_id`.
7. FOR ALL `TrialMetrics` computations, THE Evaluator SHALL derive all rate metrics exclusively from direct Mock Ledger and run log queries, never from Gateway or Executor HTTP API responses.

---

### Requirement 14: One-Command Demo Deployment

**User Story:** As a hackathon judge, I want to start the entire AgentShield V3 demonstration from a fresh repository checkout with a single `docker-compose up` command, so that I can reproduce the results independently without manual configuration steps.

#### Acceptance Criteria

1. THE repository SHALL include a `docker-compose.yml` that starts all required services: Redis, OPA, the FastAPI backend (control plane + execution plane), and the React frontend dashboard.
2. WHEN `docker-compose up` completes, THE System SHALL be ready to accept trial requests at the configured API endpoint and dashboard URL without any additional manual steps.
3. WHEN the demo runs, THE System SHALL execute all five trials (T1–T5) against all three configurations (A, B, C) and produce the complete evidence bundle in the output directory.
4. THE demo SHALL use exclusively synthetic data: no real payment credentials, no real agent identities, no real customer or tenant data SHALL appear in any generated file, log, environment variable, or API request.
5. WHEN a fresh evidence bundle is generated by running `docker-compose up`, ALL metric values SHALL reflect the actual trial execution outcomes measured during that run, not values from a previous run or hardcoded in source code.

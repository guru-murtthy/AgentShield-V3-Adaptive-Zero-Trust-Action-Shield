"""
redteam/scenarios.py
AgentShield V3 — Prebuilt Attack Scenarios.

Author: Gururaj — Lead Red Team & Validation Engineer
Last Updated: 2026-10-14

PURPOSE:
    Ready-to-run scenario definitions for all five attack classes.
    Each scenario carries the exact payload needed to reproduce the attack —
    no improvisation required during the live demo.

SCENARIOS:
    tamper          — T1: Authorized ₹500 refund → execute ₹5,000
    replay          — T2: One capability token sent 50× concurrently
    drift           — T3: Narrow refund capability → widened to admin action
    spoof_confidence— T4: Fake trust headers to bypass approval
    falsify_receipt — T5: Alter receipt field → signature should break
    edge_large      — Edge: Large payload (hash consistency)
    edge_unicode    — Edge: Unicode key ordering (canonicalization)
    edge_malformed  — Edge: Malformed JSON (fail-closed, not crash)

DEMO FLOW:
    [1] tamper     → Config A PASSES, Config C BLOCKS
    [2] replay     → Config A multiple writes, Config C ≤1
    [3] drift      → Config A escalates, Config C blocks
    [4] compare    → side-by-side A/B/C table
    [5] evidence   → export proof package
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Scenario:
    """A fully specified attack scenario ready to execute."""
    name: str                       # machine name (used in CLI)
    display_name: str               # human-readable
    attack_class: str               # "T1" | "T2" | "T3" | "T4" | "T5" | "EDGE"
    description: str
    method: str                     # toolkit method to call

    # Payload data
    action_type: str
    parameters: dict[str, Any]      # ORIGINAL (authorized) parameters

    # Tamper-specific
    alter_field: Optional[str] = None
    new_value: Any = None

    # Replay-specific
    parallel_count: int = 50

    # Drift-specific
    target_action_type: Optional[str] = None
    target_params: Optional[dict[str, Any]] = None

    # Spoof-specific
    spoofed_headers: Optional[dict[str, str]] = None
    fake_confidence_level: float = 0.99

    # Expected results (for validation)
    expected_config_c_blocked: bool = True
    expected_config_a_passed: bool = True

    # Demo talking points
    demo_narration: str = ""

    def fresh_request_id(self) -> str:
        """Generate a fresh UUID for idempotency — call this each run."""
        return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# SCENARIO REGISTRY
# ---------------------------------------------------------------------------

# T1 — The flagship: ₹500 → ₹5,000 substitution
TAMPER_REFUND = Scenario(
    name="tamper",
    display_name="T1: Payload Tampering — ₹500 → ₹5,000 Refund Substitution",
    attack_class="T1",
    description=(
        "Authorize a ₹500 refund, then swap the amount to ₹5,000 before "
        "submitting to the executor. In Config C, the executor recomputes "
        "the action digest from the tampered payload — the digest doesn't match "
        "the capability → ACTION_DIGEST_MISMATCH → ledger unchanged."
    ),
    method="tamper_and_submit",
    action_type="ISSUE_REFUND",
    parameters={
        "order_id": "ORDER-DEMO-001",
        "amount": "500.00",
        "currency": "INR",
        "customer_id": "CUST-DEMO-001",
        "reason": "product_returned",
    },
    alter_field="amount",
    new_value="5000.00",
    expected_config_c_blocked=True,
    expected_config_a_passed=True,
    demo_narration=(
        "This is the core attack. The agent was authorized for ₹500. "
        "The attacker replaces the amount with ₹5,000 before execution. "
        "Config A has no digest check — it passes. "
        "Config C recomputes the hash — it doesn't match — it's blocked."
    ),
)

# T2 — Replay race: single capability → 50 concurrent requests
REPLAY_RACE = Scenario(
    name="replay",
    display_name="T2: Capability Replay — 50× Concurrent Double-Spend",
    attack_class="T2",
    description=(
        "Capture one valid capability token and submit it 50 times in parallel. "
        "In Config C, Redis SET NX EX atomically claims the JTI exactly once. "
        "All other 49 attempts receive 409 CAPABILITY_CONSUMED. "
        "Ledger entry count: ≤ 1."
    ),
    method="replay_attack",
    action_type="ISSUE_REFUND",
    parameters={
        "order_id": "ORDER-DEMO-002",
        "amount": "100.00",
        "currency": "INR",
        "customer_id": "CUST-DEMO-002",
        "reason": "duplicate_charge",
    },
    parallel_count=50,
    expected_config_c_blocked=True,
    expected_config_a_passed=True,
    demo_narration=(
        "One capability token, 50 parallel requests. "
        "Config A may process all 50 — 50× the intended amount leaves the account. "
        "Config C: atomic Redis claim — exactly 1 succeeds, 49 blocked. "
        "We'll show you the ledger entry count, not just the HTTP responses."
    ),
)

# T3 — Scope drift: narrow refund → wider admin action
SCOPE_DRIFT = Scenario(
    name="drift",
    display_name="T3: Scope Drift — Narrow Refund → Admin Account Action",
    attack_class="T3",
    description=(
        "Get authorized for a narrow refund action, then submit a higher-privilege "
        "action using the same capability. The capability's digest binds it to "
        "the original action — a different action produces a different digest. "
        "In Config C: ACTION_DIGEST_MISMATCH → blocked."
    ),
    method="drift_attempt",
    action_type="ISSUE_REFUND",
    parameters={
        "order_id": "ORDER-DEMO-003",
        "amount": "200.00",
        "currency": "INR",
        "customer_id": "CUST-DEMO-003",
        "reason": "wrong_item",
    },
    target_action_type="ADMIN_CREDIT_ACCOUNT",
    target_params={
        "account_id": "ACCOUNT-TARGET-001",
        "amount": "100000.00",
        "currency": "INR",
        "reason": "admin_adjustment",
    },
    expected_config_c_blocked=True,
    expected_config_a_passed=True,
    demo_narration=(
        "The agent was authorized for a small refund. "
        "The attacker tries to use that capability for an admin credit. "
        "Different action = different digest = capability doesn't match. "
        "Config C rejects it. Config A executes it."
    ),
)

# T4 — Confidence spoofing: fake trust headers
SPOOF_CONFIDENCE = Scenario(
    name="spoof_confidence",
    display_name="T4: Confidence Spoofing — Fake Trust Headers",
    attack_class="T4",
    description=(
        "Inject headers claiming high agent trust score and pre-approval "
        "to bypass the approval workflow for a high-value action. "
        "In Config C: headers are ignored at the enforcement layer — "
        "the action digest binding is unaffected by transport headers."
    ),
    method="spoof_confidence_attack",
    action_type="LARGE_REFUND",
    parameters={
        "order_id": "ORDER-DEMO-004",
        "amount": "50000.00",
        "currency": "INR",
        "customer_id": "CUST-DEMO-004",
        "reason": "bulk_return",
    },
    spoofed_headers={
        "X-Agent-Trust-Score": "0.99",
        "X-Context-Verified": "true",
        "X-Bypass-Approval": "true",
        "X-Pre-Approved": "1",
        "X-Risk-Override": "approved",
    },
    fake_confidence_level=0.99,
    expected_config_c_blocked=True,
    expected_config_a_passed=False,  # might still require approval in A
    demo_narration=(
        "The attacker injects HTTP headers claiming this agent is pre-approved. "
        "Config A/B may honor these headers in policy evaluation. "
        "Config C: the capability is still bound to the exact action digest — "
        "headers cannot change what was signed."
    ),
)

# T5 — Receipt fabrication
FALSIFY_RECEIPT = Scenario(
    name="falsify_receipt",
    display_name="T5: Receipt Fabrication — Forged Execution Evidence",
    attack_class="T5",
    description=(
        "Take a real receipt from a failed/blocked execution, alter the 'outcome' "
        "field to 'success', and try to present it for re-execution or chain insertion. "
        "In Config C: Ed25519 signature covers all receipt fields — any change breaks it. "
        "The audit verifier will flag the first broken sequence."
    ),
    method="falsify_receipt",
    action_type="ISSUE_REFUND",
    parameters={
        "order_id": "ORDER-DEMO-005",
        "amount": "300.00",
        "currency": "INR",
        "customer_id": "CUST-DEMO-005",
        "reason": "damaged_goods",
    },
    expected_config_c_blocked=True,
    expected_config_a_passed=False,
    demo_narration=(
        "The attacker modifies a real execution receipt — changing 'failure' to 'success'. "
        "The Ed25519 signature no longer validates. "
        "The independent verifier will show: first_broken_sequence = N. "
        "This is the audit integrity proof."
    ),
)

# EDGE CASES
EDGE_LARGE_PAYLOAD = Scenario(
    name="edge_large",
    display_name="Edge: Large Payload — Hash Consistency",
    attack_class="EDGE",
    description=(
        "Submit an action with a very large parameters dict (100 fields). "
        "Verify that canonicalization is consistent and the hash matches."
    ),
    method="tamper_and_submit",
    action_type="ISSUE_REFUND",
    parameters={
        "order_id": "ORDER-EDGE-LARGE",
        "amount": "500.00",
        "currency": "INR",
        "customer_id": "CUST-EDGE-LARGE",
        "reason": "edge_test",
        **{f"extra_field_{i}": f"value_{i}" for i in range(100)},
    },
    alter_field="amount",
    new_value="5000.00",
    expected_config_c_blocked=True,
    expected_config_a_passed=True,
    demo_narration="Large payload — canonicalization and hash must still work correctly.",
)

EDGE_UNICODE_KEYS = Scenario(
    name="edge_unicode",
    display_name="Edge: Unicode Key Ordering — Canonicalization Consistency",
    attack_class="EDGE",
    description=(
        "Submit an action with Unicode-containing field values. "
        "Verify NFC normalization and consistent hash output."
    ),
    method="tamper_and_submit",
    action_type="ISSUE_REFUND",
    parameters={
        "order_id": "ORDER-EDGE-UNICODE-\u00e9",  # é
        "amount": "500.00",
        "currency": "INR",
        "customer_id": "CUST-\u00e9dge",
        "reason": "unicode_test_\u4e2d\u6587",  # Chinese chars
    },
    alter_field="amount",
    new_value="5000.00",
    expected_config_c_blocked=True,
    expected_config_a_passed=True,
    demo_narration="Unicode in parameters — NFC normalization must hold.",
)

EDGE_MALFORMED_JSON = Scenario(
    name="edge_malformed",
    display_name="Edge: Malformed Parameters — Fail-Closed, Not Crash",
    attack_class="EDGE",
    description=(
        "Submit parameters with a nested object containing a float (prohibited). "
        "The system must reject it cleanly — not crash."
    ),
    method="tamper_and_submit",
    action_type="ISSUE_REFUND",
    parameters={
        "order_id": "ORDER-EDGE-MALFORMED",
        "amount": 500.99,   # FLOAT — should be rejected as a string by schema
        "currency": "INR",
        "customer_id": "CUST-EDGE-MALFORMED",
        "reason": "float_injection_test",
    },
    alter_field="amount",
    new_value=5000.99,
    expected_config_c_blocked=True,
    expected_config_a_passed=False,
    demo_narration="Float injection — canonicalizer must reject, gateway must fail-closed.",
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_SCENARIOS: dict[str, Scenario] = {
    s.name: s for s in [
        TAMPER_REFUND,
        REPLAY_RACE,
        SCOPE_DRIFT,
        SPOOF_CONFIDENCE,
        FALSIFY_RECEIPT,
        EDGE_LARGE_PAYLOAD,
        EDGE_UNICODE_KEYS,
        EDGE_MALFORMED_JSON,
    ]
}


def get_scenario(name: str) -> Scenario:
    """Return scenario by name, or raise KeyError."""
    if name not in ALL_SCENARIOS:
        raise KeyError(
            f"Unknown scenario '{name}'. "
            f"Available: {', '.join(sorted(ALL_SCENARIOS.keys()))}"
        )
    return ALL_SCENARIOS[name]


def list_scenarios() -> list[Scenario]:
    return sorted(ALL_SCENARIOS.values(), key=lambda s: s.attack_class)

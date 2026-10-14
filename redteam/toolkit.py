"""
redteam/toolkit.py
AgentShield V3 — Red Team Attack Toolkit.

Author: Gururaj — Lead Red Team & Validation Engineer
Last Updated: 2026-10-14

PURPOSE:
    Five core attack methods targeting the authorization boundary between
    the Gateway (capability issuance) and the Executor (enforcement).

    All methods return AttackOutcome — never hardcode pass/fail.
    Ground truth comes from the Observer, not HTTP status codes.

ATTACK SUMMARY:
    1. tamper_and_submit()      — Payload substitution after capability issuance
    2. replay_attack()          — Single-use capability used N times in parallel
    3. drift_attempt()          — Scope widening between authorization and execution
    4. spoof_confidence_attack()— Fake context injection to manipulate policy
    5. falsify_receipt()        — Fabricated receipt passed for re-execution

COORDINATION:
    Girish: digest computation uses security.calculate_action_digest()
            which wraps SHA256(b"AGENTSHIELD-ACTION-V1\x00" + canonical_bytes)
    Alok:   endpoints are /gateway/actions/submit and /executor/execute
            auth header: Authorization: Bearer <api_key>
    Pavan:  attack list maps 1:1 to threat matrix entries T1-T5
"""

from __future__ import annotations

import concurrent.futures
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import httpx

# ---------------------------------------------------------------------------
# Canonical digest — must match Girish's implementation exactly
# ---------------------------------------------------------------------------
try:
    # Use the project's own security module when running from the repo root
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from agentshield.backend.app.security.action_digest import (
        calculate_action_digest as _calc_digest_lib,
    )
    from agentshield.backend.app.security.canonicalization import (
        validate_and_normalize_action,
        canonicalize_json_object,
    )
    _HAS_SECURITY_LIB = True
except ImportError:
    _HAS_SECURITY_LIB = False


def _compute_digest_for_execute_request(action_type: str, parameters: dict) -> str:
    """
    Compute the action_digest the Executor expects for a given payload.

    Matches the Host's canonicalization logic exactly:
        SHA256(b"AGENTSHIELD-ACTION-V1\\x00" + canonical_json)

    Falls back to a best-effort reconstruction if the security lib is unavailable.
    """
    if _HAS_SECURITY_LIB:
        try:
            # The gateway builds a sec.ActionRequest like:
            # { schema_version:1, tenant_id, principal_id,
            #   tool: action_type.lower(), resource: "...",
            #   arguments: parameters, environment, policy_version, intent_id }
            # We don't have all fields here — use the digest returned by the gateway.
            pass
        except Exception:
            pass
    # Return empty string; callers should use the digest from the gateway response
    return ""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class AttackOutcome:
    """
    Result of a single attack execution.

    Fields match the spec exactly:
        api_code     — HTTP status code returned by the last API call
        api_message  — plain-language explanation of what the API said
        ledger_found — True = digest exists in ledger (ground truth, NOT api_code)
        digest       — 64-char SHA-256 action digest
        evidence     — dict of all raw data for evidence export
    """
    attack_name: str
    config: str

    # --- Spec fields ---
    api_code: int = 0                       # HTTP status of final API call
    api_message: str = ""                   # what the API said in plain language
    ledger_found: bool = False              # GROUND TRUTH from observer
    digest: str = ""                        # action_digest (64-char SHA-256 hex)
    evidence: dict = field(default_factory=dict)  # all raw data for export

    # --- Extended HTTP layer ---
    gateway_status: int = 0
    gateway_body: dict = field(default_factory=dict)
    executor_status: int = 0
    executor_body: dict = field(default_factory=dict)

    # --- Convenience ---
    latency_ms: float = 0.0
    error: Optional[str] = None

    # --- T2 replay specific ---
    parallel_results: list[dict] = field(default_factory=list)
    ledger_entry_count: int = 0

    # Keep action_digest as alias for digest (backward compat)
    @property
    def action_digest(self) -> str:
        return self.digest

    @action_digest.setter
    def action_digest(self, value: str) -> None:
        self.digest = value

    # Keep found_in_ledger as alias for ledger_found (backward compat)
    @property
    def found_in_ledger(self) -> bool:
        return self.ledger_found

    @found_in_ledger.setter
    def found_in_ledger(self, value: bool) -> None:
        self.ledger_found = value

    @property
    def api_blocked(self) -> bool:
        """True if the API returned a non-success status code."""
        return self.api_code not in (200, 201)

    @property
    def actually_blocked(self) -> bool:
        """
        True only if the ledger confirms no execution.
        This is the REAL result — not api_blocked.
        """
        return not self.ledger_found

    @property
    def discrepancy(self) -> Optional[str]:
        """
        Detect API vs ledger disagreement.
        A CRITICAL DISCREPANCY means the security boundary has a gap.
        """
        if self.api_blocked and not self.actually_blocked:
            return (
                f"⚠️  CRITICAL DISCREPANCY: API returned HTTP {self.api_code} "
                f"(claimed BLOCKED) but ledger CONTAINS this action. "
                "This is a real security gap."
            )
        if not self.api_blocked and self.actually_blocked:
            return (
                f"NOTE: API returned HTTP {self.api_code} (claimed SUCCESS) "
                "but ledger shows NO entry — execution may have failed silently."
            )
        return None

    def explain(self) -> str:
        """Plain-language verdict for terminal display."""
        lines = []
        if self.error:
            lines.append(f"  ⚠️  Error: {self.error}")
            if self.api_code:
                lines.append(f"  ↳ API returned HTTP {self.api_code}: {self.api_message}")
            return "\n".join(lines)

        if self.actually_blocked:
            lines.append("  ✅ Attack BLOCKED — payload did not reach the ledger")
        else:
            lines.append("  ❌ Attack SUCCEEDED — unauthorized entry found in ledger")

        if self.discrepancy:
            lines.append(f"  {self.discrepancy}")

        # Plain-language API message instead of raw code
        gw_msg = f"Gateway HTTP {self.gateway_status}"
        ex_msg = f"Executor HTTP {self.api_code}"
        lines.append(f"  ↳ {gw_msg} | {ex_msg}")
        if self.api_message:
            lines.append(f"  ↳ API said: {self.api_message}")
        if self.digest:
            lines.append(f"  ↳ Digest:   {self.digest[:24]}...")
        lines.append(f"  ↳ Latency:  {self.latency_ms:.0f}ms")
        return "\n".join(lines)

    def build_evidence(self) -> dict:
        """Build the evidence dict for export, including all raw data."""
        self.evidence = {
            "attack_name": self.attack_name,
            "config": self.config,
            "api_code": self.api_code,
            "api_message": self.api_message,
            "ledger_found": self.ledger_found,
            "digest": self.digest,
            "gateway_status": self.gateway_status,
            "gateway_body": self.gateway_body,
            "executor_status": self.executor_status,
            "executor_body": self.executor_body,
            "latency_ms": self.latency_ms,
            "discrepancy": self.discrepancy,
            "error": self.error,
            "parallel_results_count": len(self.parallel_results),
            "ledger_entry_count": self.ledger_entry_count,
        }
        return self.evidence


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------

class AttackToolkit:
    """
    Five attack methods targeting the AgentShield authorization boundary.

    Each method targets one of the five OASB threat categories:
        tamper_and_submit    → Action substitution (T1)
        replay_attack        → Capability replay / double-spend (T2)
        drift_attempt        → Scope escalation (T3)
        spoof_confidence_attack → Context/confidence manipulation (T4)
        falsify_receipt      → Receipt fabrication / evidence tampering (T5)
    """

    GATEWAY_URL = "/gateway/actions/submit"
    EXECUTOR_URL = "/executor/execute"

    def __init__(
        self,
        base_url: str,
        agent_token: str,
        timeout: float = 15.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.agent_token = agent_token
        self.timeout = timeout

    # ------------------------------------------------------------------
    # ATTACK 1 — PAYLOAD TAMPERING (T1)
    # ------------------------------------------------------------------

    def tamper_and_submit(
        self,
        config: str,
        action_type: str,
        original_params: dict[str, Any],
        alter_field: str,
        new_value: Any,
        request_id: Optional[str] = None,
    ) -> AttackOutcome:
        """
        T1 — Payload Tampering / Action Substitution.

        Flow:
          1. Submit ORIGINAL action to gateway → receive signed capability
          2. Replace alter_field with new_value in execution payload
          3. Submit TAMPERED payload + original capability to executor

        In Config C: executor recomputes the digest from the tampered payload.
        The digest will NOT match the digest embedded in the capability.
        → DIGEST_MISMATCH → reject → ledger unchanged.

        In Config A: no digest recomputation → tampered payload executes.

        Args:
            config:          "A", "B", or "C"
            action_type:     e.g. "ISSUE_REFUND"
            original_params: original parameters (e.g. {"amount": "500.00", ...})
            alter_field:     field to tamper with (e.g. "amount")
            new_value:       new value to inject (e.g. "5000.00")
        """
        outcome = AttackOutcome(attack_name="tamper", config=config)
        req_id = request_id or str(uuid.uuid4())

        try:
            # Step 1: Authorize the ORIGINAL payload
            t0 = time.time()
            gw_resp = self._post_gateway(action_type, original_params, req_id, config)
            outcome.gateway_status = gw_resp.status_code
            outcome.gateway_body = self._safe_json(gw_resp)

            if gw_resp.status_code not in (200, 201):
                outcome.latency_ms = (time.time() - t0) * 1000
                outcome.error = (
                    f"Gateway denied original payload (HTTP {gw_resp.status_code}) — "
                    f"check config or agent credentials"
                )
                return outcome

            capability_token = outcome.gateway_body.get("capability_token", "")
            outcome.digest = outcome.gateway_body.get("action_digest", "")

            # Step 2: Tamper — modify the field before sending to executor
            tampered_params = dict(original_params)
            tampered_params[alter_field] = new_value

            # Step 3: Submit tampered payload with the capability for original payload
            exec_resp = self._post_executor(
                capability_token, action_type, tampered_params, config
            )
            outcome.executor_status = exec_resp.status_code
            outcome.api_code = exec_resp.status_code
            outcome.executor_body = self._safe_json(exec_resp)
            outcome.latency_ms = (time.time() - t0) * 1000
            outcome.api_message = self._plain_message(exec_resp.status_code, outcome.executor_body)

        except httpx.ConnectError:
            outcome.error = f"Cannot reach host {self.base_url} — is Laptop 1 running?"
        except Exception as exc:
            outcome.error = str(exc)

        return outcome

    # ------------------------------------------------------------------
    # ATTACK 2 — REPLAY / RACE CONDITION (T2)
    # ------------------------------------------------------------------

    def replay_attack(
        self,
        config: str,
        action_type: str,
        parameters: dict[str, Any],
        parallel_count: int = 50,
        request_id: Optional[str] = None,
    ) -> AttackOutcome:
        """
        T2 — Capability Replay / Double-Spend Race.

        Flow:
          1. Obtain ONE valid capability from the gateway
          2. Submit it parallel_count times concurrently to the executor
          3. Measure actual ledger writes (not API successes)

        In Config C: Redis SET NX EX atomic claim allows exactly 1 success.
                     All others receive 409 CAPABILITY_CONSUMED.
                     → Ledger entry count ≤ 1.

        In Config A/B: multiple concurrent requests may all succeed.

        Args:
            parallel_count: number of concurrent replay attempts (default 50)
        """
        outcome = AttackOutcome(attack_name="replay", config=config)
        req_id = request_id or str(uuid.uuid4())

        try:
            # Get one valid capability
            t0 = time.time()
            gw_resp = self._post_gateway(action_type, parameters, req_id, config)
            outcome.gateway_status = gw_resp.status_code
            outcome.gateway_body = self._safe_json(gw_resp)

            if gw_resp.status_code not in (200, 201):
                outcome.error = (
                    f"Could not get capability for replay test — "
                    f"Gateway returned HTTP {gw_resp.status_code}"
                )
                return outcome

            capability_token = outcome.gateway_body.get("capability_token", "")
            outcome.digest = outcome.gateway_body.get("action_digest", "")

            # Fire parallel_count concurrent executor requests with the same token
            headers = self._headers(config)
            execute_body = {
                "capability_token": capability_token,
                "action_type": action_type,
                "parameters": parameters,
            }

            results = []
            latencies: list[float] = []

            def send_one() -> dict:
                t_req = time.time()
                try:
                    with httpx.Client(timeout=self.timeout) as client:
                        r = client.post(
                            f"{self.base_url}{self.EXECUTOR_URL}",
                            json=execute_body,
                            headers=headers,
                        )
                        latencies.append((time.time() - t_req) * 1000)
                        body = {}
                        try:
                            body = r.json()
                        except Exception:
                            pass
                        return {"status": r.status_code, "body": body}
                except Exception as e:
                    latencies.append((time.time() - t_req) * 1000)
                    return {"status": 0, "error": str(e)}

            with concurrent.futures.ThreadPoolExecutor(max_workers=min(parallel_count, 100)) as ex:
                futures = [ex.submit(send_one) for _ in range(parallel_count)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            outcome.parallel_results = results
            outcome.executor_status = results[0]["status"] if results else 0
            outcome.api_code = outcome.executor_status
            outcome.latency_ms = (time.time() - t0) * 1000

            api_successes = sum(1 for r in results if r["status"] in (200, 201))
            api_409s = sum(1 for r in results if r["status"] == 409)

            outcome.executor_body = {
                "total_sent": parallel_count,
                "api_successes": api_successes,
                "api_409_consumed": api_409s,
                "note": "See ledger_entry_count for ground truth",
            }
            outcome.api_message = (
                f"{api_successes} API successes, {api_409s} CAPABILITY_CONSUMED, "
                f"out of {parallel_count} concurrent requests. "
                f"Ground truth: see ledger_entry_count."
            )

        except httpx.ConnectError:
            outcome.error = f"Cannot reach host {self.base_url}"
        except Exception as exc:
            outcome.error = str(exc)

        return outcome

    # ------------------------------------------------------------------
    # ATTACK 3 — SCOPE DRIFT / GRADUAL EXPANSION (T3)
    # ------------------------------------------------------------------

    def drift_attempt(
        self,
        config: str,
        base_action_type: str,
        base_params: dict[str, Any],
        target_action_type: str,
        target_params: dict[str, Any],
        request_id: Optional[str] = None,
    ) -> AttackOutcome:
        """
        T3 — Scope Drift / Authorization Escalation.

        Flow:
          1. Authorize a NARROW action (e.g. small refund, limited resource)
          2. Submit a WIDER action to the executor using the narrow capability
             (different action_type or higher-value parameters)

        In Config C: the action digest for the wider action doesn't match
                     the capability's action_digest → ACTION_DIGEST_MISMATCH → blocked.

        In Config A: no digest check → wider action may execute.

        Args:
            base_action_type:  the AUTHORIZED (narrow) action type
            base_params:       the AUTHORIZED (narrow) parameters
            target_action_type: the ESCALATED action type to attempt
            target_params:     the ESCALATED parameters to attempt
        """
        outcome = AttackOutcome(attack_name="drift", config=config)
        req_id = request_id or str(uuid.uuid4())

        try:
            t0 = time.time()

            # Get capability for the narrow/base action
            gw_resp = self._post_gateway(base_action_type, base_params, req_id, config)
            outcome.gateway_status = gw_resp.status_code
            outcome.gateway_body = self._safe_json(gw_resp)

            if gw_resp.status_code not in (200, 201):
                outcome.error = (
                    f"Gateway denied base action (HTTP {gw_resp.status_code}) — "
                    "adjust base_action_type or check agent permissions"
                )
                return outcome

            capability_token = outcome.gateway_body.get("capability_token", "")
            outcome.digest = outcome.gateway_body.get("action_digest", "")

            # Submit the WIDER action with the narrow capability
            exec_resp = self._post_executor(
                capability_token, target_action_type, target_params, config
            )
            outcome.executor_status = exec_resp.status_code
            outcome.api_code = exec_resp.status_code
            outcome.executor_body = self._safe_json(exec_resp)
            outcome.latency_ms = (time.time() - t0) * 1000
            outcome.api_message = self._plain_message(exec_resp.status_code, outcome.executor_body)

        except httpx.ConnectError:
            outcome.error = f"Cannot reach host {self.base_url}"
        except Exception as exc:
            outcome.error = str(exc)

        return outcome

    # ------------------------------------------------------------------
    # ATTACK 4 — CONTEXT SPOOFING / CONFIDENCE MANIPULATION (T4)
    # ------------------------------------------------------------------

    def spoof_confidence_attack(
        self,
        config: str,
        action_type: str,
        honest_params: dict[str, Any],
        spoofed_context_headers: Optional[dict[str, str]] = None,
        fake_confidence_level: float = 0.99,
        request_id: Optional[str] = None,
    ) -> AttackOutcome:
        """
        T4 — Context Spoofing / Confidence Manipulation.

        Flow:
          1. Inject fake context headers claiming high confidence or trusted agent
          2. Submit a request that would normally be denied or require approval
          3. See if the gateway issues a broader capability

        In Config C: the gateway re-verifies actual context at the enforcement layer.
                     Spoofed headers are ignored by the capability binding.
                     Even if a broader capability is issued, the executor checks
                     the action_digest independently.

        In Config A/B: headers may influence policy evaluation.

        Args:
            spoofed_context_headers: e.g. {"X-Agent-Trust-Score": "0.99",
                                            "X-Context-Verified": "true"}
            fake_confidence_level:   logged in evidence but not sent directly
        """
        outcome = AttackOutcome(attack_name="spoof_confidence", config=config)
        req_id = request_id or str(uuid.uuid4())

        # Default spoofed headers if none provided
        if spoofed_context_headers is None:
            spoofed_context_headers = {
                "X-Agent-Trust-Score": str(fake_confidence_level),
                "X-Context-Verified": "true",
                "X-Bypass-Approval": "true",
                "X-Risk-Level": "low",
                "X-Pre-Approved": "1",
            }

        try:
            t0 = time.time()
            headers = {**self._headers(config), **spoofed_context_headers}

            # Submit with spoofed headers
            gw_body_out = {
                "action_type": action_type,
                "parameters": honest_params,
                "request_id": req_id,
            }
            with httpx.Client(timeout=self.timeout) as client:
                gw_resp = client.post(
                    f"{self.base_url}{self.GATEWAY_URL}",
                    json=gw_body_out,
                    headers=headers,
                )
            outcome.gateway_status = gw_resp.status_code
            outcome.gateway_body = self._safe_json(gw_resp)

            if gw_resp.status_code not in (200, 201):
                # Spoof didn't bypass gateway — expected for Config C
                outcome.latency_ms = (time.time() - t0) * 1000
                return outcome

            # If we got a capability, try executing with it
            capability_token = outcome.gateway_body.get("capability_token", "")
            outcome.digest = outcome.gateway_body.get("action_digest", "")

            exec_resp = self._post_executor(
                capability_token, action_type, honest_params, config,
                extra_headers=spoofed_context_headers,
            )
            outcome.executor_status = exec_resp.status_code
            outcome.api_code = exec_resp.status_code
            outcome.executor_body = self._safe_json(exec_resp)
            outcome.latency_ms = (time.time() - t0) * 1000
            outcome.api_message = self._plain_message(exec_resp.status_code, outcome.executor_body)

        except httpx.ConnectError:
            outcome.error = f"Cannot reach host {self.base_url}"
        except Exception as exc:
            outcome.error = str(exc)

        return outcome

    # ------------------------------------------------------------------
    # ATTACK 5 — RECEIPT FABRICATION / EVIDENCE TAMPERING (T5)
    # ------------------------------------------------------------------

    def falsify_receipt(
        self,
        config: str,
        valid_receipt: dict[str, Any],
        fake_result: str = "success",
        tamper_field: str = "outcome",
        request_id: Optional[str] = None,
    ) -> AttackOutcome:
        """
        T5 — Receipt Fabrication / Evidence Tampering.

        Flow:
          1. Take a valid receipt (from a prior execution)
          2. Alter the tamper_field (e.g. change "failure" → "success")
          3. Try to submit the falsified receipt for re-execution or verification

        In Config C: the receipt's Ed25519 signature covers the original fields.
                     Any field change invalidates the signature.
                     → INVALID_RECEIPT_SIGNATURE → chain integrity broken.

        In Config A: if the receipt endpoint doesn't verify signatures, the
                     tampered receipt may be accepted.

        Note: This also serves as the T5 audit chain tamper test.
              The Observer verifies chain integrity separately via verify_audit_chain_integrity().

        Args:
            valid_receipt:  dict from a prior execution response (receipt_token decoded)
            fake_result:    value to inject into tamper_field
            tamper_field:   field in receipt to alter (default: "outcome")
        """
        outcome = AttackOutcome(attack_name="falsify_receipt", config=config)
        req_id = request_id or str(uuid.uuid4())

        try:
            t0 = time.time()

            # Create a tampered copy
            tampered_receipt = dict(valid_receipt)
            original_value = tampered_receipt.get(tamper_field)
            tampered_receipt[tamper_field] = fake_result
            tampered_receipt["_tampered_by_redteam"] = True
            tampered_receipt["_original_value"] = str(original_value)

            # Try submitting the tampered receipt to the executor's re-verify endpoint
            # (if it exists) or replay via normal execute with the tampered token
            capability_token = tampered_receipt.get("capability_token") or tampered_receipt.get("token", "TAMPERED-TOKEN")

            exec_body = {
                "capability_token": capability_token,
                "action_type": tampered_receipt.get("action_type", "ISSUE_REFUND"),
                "parameters": tampered_receipt.get("parameters", {}),
                "_receipt": tampered_receipt,  # send tampered receipt for inspection
            }

            with httpx.Client(timeout=self.timeout) as client:
                exec_resp = client.post(
                    f"{self.base_url}{self.EXECUTOR_URL}",
                    json=exec_body,
                    headers=self._headers(config),
                )
            outcome.executor_status = exec_resp.status_code
            outcome.api_code = exec_resp.status_code
            outcome.executor_body = self._safe_json(exec_resp)
            outcome.digest = valid_receipt.get("action_digest", "")
            outcome.latency_ms = (time.time() - t0) * 1000
            outcome.api_message = self._plain_message(exec_resp.status_code, outcome.executor_body)

        except httpx.ConnectError:
            outcome.error = f"Cannot reach host {self.base_url}"
        except Exception as exc:
            outcome.error = str(exc)

        return outcome

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post_gateway(
        self,
        action_type: str,
        parameters: dict[str, Any],
        request_id: str,
        config: str,
    ) -> httpx.Response:
        body = {
            "action_type": action_type,
            "parameters": parameters,
            "request_id": request_id,
        }
        with httpx.Client(timeout=self.timeout) as client:
            return client.post(
                f"{self.base_url}{self.GATEWAY_URL}",
                json=body,
                headers=self._headers(config),
            )

    def _post_executor(
        self,
        capability_token: str,
        action_type: str,
        parameters: dict[str, Any],
        config: str,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> httpx.Response:
        body = {
            "capability_token": capability_token,
            "action_type": action_type,
            "parameters": parameters,
        }
        headers = self._headers(config)
        if extra_headers:
            headers.update(extra_headers)
        with httpx.Client(timeout=self.timeout) as client:
            return client.post(
                f"{self.base_url}{self.EXECUTOR_URL}",
                json=body,
                headers=headers,
            )

    def _headers(self, config: str) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.agent_token}",
            "X-Security-Baseline": config,
        }

    @staticmethod
    def _plain_message(status_code: int, body: dict) -> str:
        """
        Convert an HTTP status + body into a plain-language message
        suitable for judges — no raw error codes in the output.
        """
        detail = body.get("detail", body.get("message", body.get("error", "")))
        messages = {
            200: "Action executed successfully",
            201: "Action executed successfully",
            400: f"Bad request — {detail or 'malformed payload'}",
            401: "Authentication failed — check agent token",
            403: f"Policy denied — {detail or 'action not authorized'}",
            404: "Endpoint not found — check Host routing",
            409: "Capability already consumed — replay blocked",
            422: f"Validation error — {detail or 'invalid parameters'}",
            500: f"Host internal error — {detail or 'check Laptop 1 logs'}",
            503: "Host unavailable — service down",
        }
        msg = messages.get(status_code, f"HTTP {status_code}")
        if detail and status_code not in messages:
            msg = f"HTTP {status_code}: {detail}"
        # Translate known error codes to plain language
        if isinstance(detail, str):
            replacements = {
                "ACTION_DIGEST_MISMATCH": "Digest did not match what was approved — payload altered",
                "CAPABILITY_CONSUMED":    "Capability already used — replay attempt blocked",
                "CAPABILITY_EXPIRED":     "Capability expired before execution",
                "UNAUTHENTICATED":        "Agent token not recognised",
                "AGENT_REVOKED":          "Agent has been revoked",
            }
            for code, plain in replacements.items():
                if code in detail.upper():
                    msg = plain
                    break
        return msg

    @staticmethod
    def _safe_json(resp: httpx.Response) -> dict:
        try:
            return resp.json()
        except Exception:
            return {"raw": resp.text[:500]}

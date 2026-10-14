"""
validation/harness.py
AgentShield V3 — Comparative Test Harness.

Author: Gururaj — Lead Red Team & Validation Engineer
Last Updated: 2026-10-14

PURPOSE:
    Runs the SAME attack scenario sequentially against Config A → B → C
    on Laptop 1 and produces a side-by-side ComparisonReport.

    Key invariant:
        - Identical bytes sent to all three configs — no adjustments.
        - Ledger snapshot is taken before AND after each config run.
        - Metrics are derived from ledger deltas — never from HTTP status.
        - Discrepancies ("A passed where C blocked") are flagged explicitly.

    All raw run data is saved to evidence/latest.jsonl for export.

COORDINATION:
    Alok: harness uses X-Security-Baseline: A|B|C header to route to each config.
          If the header name differs, update CONFIG_HEADER below.
    Gururaj (self): run_comparison() is called from attacker_terminal.py > compare
"""

from __future__ import annotations

import json
import time
import uuid
import concurrent.futures
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import httpx

from validation.observer import Observer
from validation.metrics import (
    MetricsEngine,
    TrialResult,
    ComparisonReport,
    LatencyStats,
    RateMetric,
)
from redteam.scenarios import get_scenario, Scenario

# Header name used to select enforcement configuration on Laptop 1.
# Coordinate with Alok if this differs in the Host implementation.
CONFIG_HEADER = "X-Security-Baseline"

# Evidence file — all runs appended here for export
EVIDENCE_DIR = Path(__file__).parent.parent / "evidence"
LATEST_JSONL  = EVIDENCE_DIR / "latest.jsonl"

GATEWAY_URL  = "/gateway/actions/submit"
EXECUTOR_URL = "/executor/execute"


# ---------------------------------------------------------------------------
# Raw run record
# ---------------------------------------------------------------------------

@dataclass
class RunRecord:
    """One request/response pair captured during a harness run."""
    timestamp: float
    scenario_id: str
    config: str
    step: str                        # "gateway" | "executor" | "replay"
    http_status: int
    action_digest: str
    found_in_ledger: bool            # ground truth
    latency_ms: float
    request_body: dict[str, Any]
    response_body: dict[str, Any]
    discrepancy: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "scenario_id": self.scenario_id,
            "config": self.config,
            "step": self.step,
            "http_status": self.http_status,
            "action_digest": self.action_digest,
            "found_in_ledger": self.found_in_ledger,
            "latency_ms": self.latency_ms,
            "request_body": self.request_body,
            "response_body": self.response_body,
            "discrepancy": self.discrepancy,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class Harness:
    """
    Comparative test harness — runs scenarios across configs A, B, C.

    Usage:
        h = Harness(base_url="http://192.168.1.42:8000", agent_token="...")

        # Run the tamper scenario against all 3 configs
        report = h.run_comparison("T1_tamper")
        print(report.render_table())

        # Run T2 replay race specifically
        result = h.run_replay_comparison("T2_replay", count=50)
    """

    def __init__(
        self,
        base_url: str,
        agent_token: str,
        timeout: float = 15.0,
        configs: Optional[list[str]] = None,
    ):
        self.base_url      = base_url.rstrip("/")
        self.agent_token   = agent_token
        self.timeout       = timeout
        self.configs       = configs or ["A", "B", "C"]
        self.observer      = Observer(base_url, api_key=agent_token)
        self._run_records: list[RunRecord] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_comparison(self, scenario_id: str) -> ComparisonReport:
        """
        Run scenario_id against Config A, B, and C sequentially.

        Steps for each config:
          1. Snapshot ledger BEFORE.
          2. Execute the attack via gateway + executor.
          3. Snapshot ledger AFTER.
          4. Compute metrics from ledger delta.
          5. Flag discrepancies.

        Returns:
            ComparisonReport with side-by-side TrialResult per config.
        """
        scenario = get_scenario(scenario_id)
        print(f"\n  Running [{scenario.display_name}] across configs: {self.configs}")

        results: list[TrialResult] = []

        for config in self.configs:
            print(f"\n  ▶  Config {config} ...", end="", flush=True)

            # Snapshot before
            snap_before = self.observer.fetch_snapshot(force=True)
            before_digests = {e.action_digest for e in snap_before.executions}
            latencies: list[float] = []

            # Execute
            rec = self._execute_scenario(scenario, config, latencies)
            self._run_records.append(rec)

            # Snapshot after
            snap_after = self.observer.fetch_snapshot(force=True)
            after_digests = {e.action_digest for e in snap_after.executions}

            # Attack digest for this run
            attack_digests = [rec.action_digest] if rec.action_digest else []

            # Compute metrics
            result = MetricsEngine.compute(
                config=config,
                scenario_id=scenario.name,
                scenario_name=scenario.display_name,
                attack_digests=attack_digests,
                legit_digests=[],          # filled by legitimate flow tests
                ledger_before_digests=before_digests,
                ledger_after_digests=after_digests,
                latency_samples=latencies,
                notes=self._config_note(config),
            )
            results.append(result)

            # Status line
            blocked_str = "✅ BLOCKED" if result.asr.numerator == 0 else "❌ PASSED"
            print(
                f" HTTP {rec.http_status} | Ledger: {blocked_str} | "
                f"{latencies[0]:.0f}ms" if latencies else
                f" HTTP {rec.http_status} | Ledger: {blocked_str}"
            )

            # Flag discrepancy
            if rec.discrepancy:
                print(f"    ⚠️  {rec.discrepancy}")

            # Small delay between configs to avoid rate limits
            time.sleep(0.2)

        # Save to evidence/latest.jsonl
        self._append_to_latest(scenario_id, results)

        # Detect "A passed where C blocked"
        self._log_discrepancies(results)

        return MetricsEngine.build_comparison(results)

    def run_replay_comparison(
        self,
        scenario_id: str,
        count: int = 50,
    ) -> dict[str, Any]:
        """
        T2 Double-Spend Race — submit same capability token N times concurrently.

        Returns a ground-truth result dict including ledger entry count.
        """
        scenario = get_scenario(scenario_id)
        req_id = str(uuid.uuid4())

        # Step 1: Get one valid capability
        gw_body = {
            "action_type": scenario.action_type,
            "parameters": scenario.parameters,
            "request_id": req_id,
        }
        headers = self._headers("C")

        with httpx.Client(timeout=self.timeout) as client:
            gw_resp = client.post(
                f"{self.base_url}{GATEWAY_URL}",
                json=gw_body,
                headers=headers,
            )

        if gw_resp.status_code not in (200, 201):
            return {
                "error": f"Could not obtain capability — "
                         f"Gateway HTTP {gw_resp.status_code}",
                "gateway_body": self._safe_json(gw_resp),
            }

        gw_data      = self._safe_json(gw_resp)
        cap_token    = gw_data.get("capability_token", "")
        action_digest = gw_data.get("action_digest", "")

        execute_body = {
            "capability_token": cap_token,
            "action_type": scenario.action_type,
            "parameters": scenario.parameters,
        }

        # Step 2: Submit N times concurrently
        results: list[dict[str, Any]] = []
        latencies: list[float] = []

        def send_one() -> dict[str, Any]:
            t0 = time.time()
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    r = client.post(
                        f"{self.base_url}{EXECUTOR_URL}",
                        json=execute_body,
                        headers=headers,
                    )
                    latencies.append((time.time() - t0) * 1000)
                    body = self._safe_json(r)
                    return {"status": r.status_code, "body": body}
            except Exception as e:
                latencies.append((time.time() - t0) * 1000)
                return {"status": 0, "error": str(e)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(count, 100)) as ex:
            futures  = [ex.submit(send_one) for _ in range(count)]
            results  = [f.result() for f in concurrent.futures.as_completed(futures)]

        api_successes = sum(1 for r in results if r["status"] in (200, 201))
        api_409s      = sum(1 for r in results if r["status"] == 409)

        # Step 3: Ground truth — how many entries in ledger?
        snap = self.observer.fetch_snapshot(force=True)
        ledger_count = sum(
            1 for e in snap.executions
            if e.action_digest == action_digest
        )
        double_spend_prevented = max(0, count - ledger_count)

        output = {
            "scenario_id": scenario_id,
            "total_sent": count,
            "api_successes": api_successes,
            "api_409_consumed": api_409s,
            "ledger_entries": ledger_count,           # GROUND TRUTH
            "double_spend_prevented": double_spend_prevented,
            "p50_ms": LatencyStats(samples=latencies).p50,
            "p99_ms": LatencyStats(samples=latencies).p99,
            "action_digest": action_digest,
        }

        self._append_to_latest(scenario_id, [output])
        return output

    def get_run_records(self) -> list[RunRecord]:
        """Return all captured run records for evidence export."""
        return list(self._run_records)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _execute_scenario(
        self,
        scenario: Scenario,
        config: str,
        latencies: list[float],
    ) -> RunRecord:
        """Run one gateway + executor round-trip for the given scenario and config."""
        req_id  = str(uuid.uuid4())
        headers = self._headers(config)
        t0      = time.time()

        gw_req_body = {
            "action_type": scenario.action_type,
            "parameters": scenario.parameters,
            "request_id": req_id,
        }

        try:
            # Gateway call (authorize original payload)
            with httpx.Client(timeout=self.timeout) as client:
                gw_resp = client.post(
                    f"{self.base_url}{GATEWAY_URL}",
                    json=gw_req_body,
                    headers=headers,
                )

            gw_body = self._safe_json(gw_resp)

            if gw_resp.status_code not in (200, 201):
                latencies.append((time.time() - t0) * 1000)
                return RunRecord(
                    timestamp=time.time(),
                    scenario_id=scenario.name,
                    config=config,
                    step="gateway",
                    http_status=gw_resp.status_code,
                    action_digest="",
                    found_in_ledger=False,
                    latency_ms=latencies[-1],
                    request_body=gw_req_body,
                    response_body=gw_body,
                    error=f"Gateway denied — HTTP {gw_resp.status_code}",
                )

            cap_token     = gw_body.get("capability_token", "")
            action_digest = gw_body.get("action_digest", "")

            # Build execution payload — apply tampering if scenario specifies it
            exec_params = dict(scenario.parameters)
            if scenario.alter_field and scenario.new_value is not None:
                exec_params[scenario.alter_field] = scenario.new_value

            exec_req_body = {
                "capability_token": cap_token,
                "action_type": scenario.action_type,
                "parameters": exec_params,
            }

            with httpx.Client(timeout=self.timeout) as client:
                exec_resp = client.post(
                    f"{self.base_url}{EXECUTOR_URL}",
                    json=exec_req_body,
                    headers=headers,
                )

            latencies.append((time.time() - t0) * 1000)
            exec_body = self._safe_json(exec_resp)

            # Ground truth — verify ledger directly
            found = (
                self.observer.verify_executed(action_digest)
                if action_digest else False
            )

            # Discrepancy check
            disc = None
            if action_digest:
                disc = self.observer.flag_discrepancy(
                    action_digest, exec_resp.status_code
                )

            return RunRecord(
                timestamp=time.time(),
                scenario_id=scenario.name,
                config=config,
                step="executor",
                http_status=exec_resp.status_code,
                action_digest=action_digest,
                found_in_ledger=found,
                latency_ms=latencies[-1],
                request_body=exec_req_body,
                response_body=exec_body,
                discrepancy=disc,
            )

        except httpx.ConnectError:
            latencies.append((time.time() - t0) * 1000)
            return RunRecord(
                timestamp=time.time(),
                scenario_id=scenario.name,
                config=config,
                step="executor",
                http_status=0,
                action_digest="",
                found_in_ledger=False,
                latency_ms=latencies[-1],
                request_body=gw_req_body,
                response_body={},
                error=f"Cannot reach host {self.base_url} — is Laptop 1 running?",
            )
        except Exception as exc:
            latencies.append((time.time() - t0) * 1000)
            return RunRecord(
                timestamp=time.time(),
                scenario_id=scenario.name,
                config=config,
                step="executor",
                http_status=0,
                action_digest="",
                found_in_ledger=False,
                latency_ms=latencies[-1],
                request_body=gw_req_body,
                response_body={},
                error=str(exc),
            )

    def _headers(self, config: str) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.agent_token}",
            CONFIG_HEADER: config,
        }

    @staticmethod
    def _safe_json(resp: httpx.Response) -> dict:
        try:
            return resp.json()
        except Exception:
            return {"raw": resp.text[:500]}

    @staticmethod
    def _config_note(config: str) -> str:
        return {
            "A": "No hash binding",
            "B": "Gateway check only",
            "C": "Full AgentShield V3",
        }.get(config, "")

    def _append_to_latest(self, scenario_id: str, data: list) -> None:
        """Append run data to evidence/latest.jsonl."""
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        with LATEST_JSONL.open("a") as f:
            for item in data:
                row = {
                    "timestamp": time.time(),
                    "scenario_id": scenario_id,
                    "data": item.to_dict() if hasattr(item, "to_dict") else item,
                }
                f.write(json.dumps(row, default=str) + "\n")

    @staticmethod
    def _log_discrepancies(results: list[TrialResult]) -> None:
        """Print inter-config discrepancy messages after a comparison run."""
        by_config = {r.config: r for r in results}
        a = by_config.get("A")
        b = by_config.get("B")
        c = by_config.get("C")

        if a and c:
            if a.asr.numerator > 0 and c.asr.numerator == 0:
                print(
                    "\n  ⚡ KEY FINDING: Config A BREACHED — "
                    "Config C HELD. AgentShield V3 protection proven."
                )
            elif a.asr.numerator == 0 and c.asr.numerator == 0:
                print(
                    "\n  ℹ️  Both A and C blocked — "
                    "may be gateway-level policy denial. "
                    "Run 'observer' to check audit events."
                )
        if b and c:
            if b.asr.numerator > 0 and c.asr.numerator == 0:
                print(
                    "  ⚡ Config B PARTIAL — Config C HELD. "
                    "Independent executor re-verification is the key difference."
                )

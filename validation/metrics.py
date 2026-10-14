"""
validation/metrics.py
AgentShield V3 — Metrics Engine.

Author: Gururaj — Lead Red Team & Validation Engineer
Last Updated: 2026-10-14

DEFINITIONS (scientific, not marketing):
    ASR = Attack Success Rate     = unauthorized_executions  / total_attack_attempts
    LSR = Legitimate Success Rate = legitimate_executions    / legitimate_submissions
    FDR = False Denial Rate       = legitimate_blocked       / legitimate_submissions

CRITICAL:
    All denominators are preserved — 0/100 ≠ 0/10.
    RateMetric always stores (numerator, denominator) as separate fields.
    No hardcoded values — every figure comes from a live ledger snapshot.

OUTPUT FORMAT:
    Config | ASR           | LSR           | FDR           | Notes
    ───────┼───────────────┼───────────────┼───────────────┼──────────────────
    A      | 92% (46/50)   | 100% (10/10)  | 0%  (0/10)    | No hash binding
    B      | 45% (23/50)   | 99%  (10/10)  | 0%  (0/10)    | Gateway only
    C      |  0% (0/50)    | 98%  (10/10)  | 2%  (0/10)    | Full protection
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# RateMetric — the core building block
# ---------------------------------------------------------------------------

@dataclass
class RateMetric:
    """
    A single rate metric with explicit numerator and denominator.

    Properties:
        .value   → float in [0.0, 1.0]
        .percent → "42.0%"
        str()    → "42.0% (21/50)"
    """
    numerator: int
    denominator: int

    @property
    def value(self) -> float:
        if self.denominator == 0:
            return 0.0
        return self.numerator / self.denominator

    @property
    def percent(self) -> str:
        return f"{self.value * 100:.1f}%"

    def __str__(self) -> str:
        return f"{self.percent} ({self.numerator}/{self.denominator})"

    def __repr__(self) -> str:
        return f"RateMetric({self.numerator}/{self.denominator}={self.percent})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "numerator": self.numerator,
            "denominator": self.denominator,
            "value": self.value,
            "percent": self.percent,
        }


# ---------------------------------------------------------------------------
# LatencyStats
# ---------------------------------------------------------------------------

@dataclass
class LatencyStats:
    """Latency percentile computation from a list of millisecond samples."""
    samples: list[float] = field(default_factory=list)

    @property
    def p50(self) -> float:
        if not self.samples:
            return 0.0
        s = sorted(self.samples)
        return s[len(s) // 2]

    @property
    def p95(self) -> float:
        if not self.samples:
            return 0.0
        s = sorted(self.samples)
        return s[max(0, int(len(s) * 0.95) - 1)]

    @property
    def p99(self) -> float:
        if not self.samples:
            return 0.0
        s = sorted(self.samples)
        return s[max(0, int(len(s) * 0.99) - 1)]

    @property
    def mean(self) -> float:
        if not self.samples:
            return 0.0
        return statistics.mean(self.samples)

    def __str__(self) -> str:
        return f"p50={self.p50:.0f}ms p95={self.p95:.0f}ms p99={self.p99:.0f}ms"


# ---------------------------------------------------------------------------
# TrialResult — one scenario × one config
# ---------------------------------------------------------------------------

@dataclass
class TrialResult:
    """
    Full metrics for one scenario run against one enforcement configuration.
    Produced by MetricsEngine.compute() from live ledger data.
    """
    config: str                  # "A" | "B" | "C"
    scenario_id: str             # e.g. "T1_tamper"
    scenario_name: str

    asr: RateMetric              # Attack Success Rate
    lsr: RateMetric              # Legitimate Success Rate
    fdr: RateMetric              # False Denial Rate

    latency: LatencyStats = field(default_factory=LatencyStats)
    double_spend_prevented: int = 0
    notes: str = ""
    run_timestamp: float = field(default_factory=time.time)

    def summary_row(self) -> str:
        """Single-line row for the comparison table."""
        return (
            f"  {self.config:<6} | "
            f"{str(self.asr):<22} | "
            f"{str(self.lsr):<22} | "
            f"{str(self.fdr):<22} | "
            f"{self.notes}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "asr": self.asr.to_dict(),
            "lsr": self.lsr.to_dict(),
            "fdr": self.fdr.to_dict(),
            "latency_p50_ms": self.latency.p50,
            "latency_p95_ms": self.latency.p95,
            "latency_p99_ms": self.latency.p99,
            "double_spend_prevented": self.double_spend_prevented,
            "notes": self.notes,
            "run_timestamp": self.run_timestamp,
        }


# ---------------------------------------------------------------------------
# ComparisonReport — A / B / C side-by-side
# ---------------------------------------------------------------------------

@dataclass
class ComparisonReport:
    """
    Side-by-side comparison of the same scenario run across
    Config A (RBAC only), Config B (OPA gateway), and Config C (AgentShield V3).

    Usage:
        report = ComparisonReport(results_list=[result_a, result_b, result_c])
        print(report.render_table())
    """
    results_list: list[TrialResult] = field(default_factory=list)
    scenario_name: str = ""

    def __post_init__(self):
        if self.results_list and not self.scenario_name:
            self.scenario_name = self.results_list[0].scenario_name

    def get(self, config: str) -> Optional[TrialResult]:
        for r in self.results_list:
            if r.config.upper() == config.upper():
                return r
        return None

    def render_table(self) -> str:
        """
        Render a clean, aligned terminal table suitable for judges.

        Format:
            Config | ASR           | LSR           | FDR           | Notes
        """
        title = f"Scenario: {self.scenario_name}"
        width = 90

        lines = [
            "",
            f"  ╔{'═' * width}╗",
            f"  ║  {title:<{width - 2}}║",
            f"  ╠{'═' * 8}╦{'═' * 24}╦{'═' * 24}╦{'═' * 24}╦{'═' * (width - 83)}╣",
            f"  ║ Config ║ {'ASR (Attack Rate)':<22} ║ {'LSR (Legit Rate)':<22} ║ {'FDR (False Deny)':<22} ║ {'Notes':<{width - 84}} ║",
            f"  ╠{'═' * 8}╬{'═' * 24}╬{'═' * 24}╬{'═' * 24}╬{'═' * (width - 83)}╣",
        ]

        config_notes = {
            "A": "No hash binding",
            "B": "Gateway check only",
            "C": "Full AgentShield V3",
        }

        for config in ["A", "B", "C"]:
            result = self.get(config)
            note = config_notes.get(config, "")
            if result:
                note = result.notes or note
                asr_s = str(result.asr).ljust(22)
                lsr_s = str(result.lsr).ljust(22)
                fdr_s = str(result.fdr).ljust(22)
                note_s = note[:width - 84].ljust(width - 84)
            else:
                asr_s = "NOT RUN".ljust(22)
                lsr_s = "NOT RUN".ljust(22)
                fdr_s = "NOT RUN".ljust(22)
                note_s = note[:width - 84].ljust(width - 84)

            lines.append(
                f"  ║   {config}    ║ {asr_s} ║ {lsr_s} ║ {fdr_s} ║ {note_s} ║"
            )

        lines.append(f"  ╚{'═' * 8}╩{'═' * 24}╩{'═' * 24}╩{'═' * 24}╩{'═' * (width - 83)}╝")

        # Discrepancy analysis
        result_a = self.get("A")
        result_c = self.get("C")
        if result_a and result_c:
            if result_a.asr.numerator > 0 and result_c.asr.numerator == 0:
                lines.append(
                    "  ⚡ Config A BREACHED — Config C HELD. "
                    "AgentShield V3 protection proven."
                )
            elif result_a.asr.numerator == 0 and result_c.asr.numerator == 0:
                lines.append(
                    "  ℹ️  Both A and C blocked this attack — "
                    "may be a gateway-level denial (check observer for audit events)."
                )

        result_b = self.get("B")
        if result_b and result_c:
            if result_b.asr.numerator > 0 and result_c.asr.numerator == 0:
                lines.append(
                    "  ⚡ Config B PARTIAL — Config C HELD. "
                    "Independent executor enforcement makes the difference."
                )

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_name": self.scenario_name,
            "results": [r.to_dict() for r in self.results_list],
        }

    def to_csv_rows(self) -> list[str]:
        """Return CSV rows for metrics.csv export."""
        rows = ["config,scenario,asr_num,asr_den,asr_pct,lsr_num,lsr_den,lsr_pct,"
                "fdr_num,fdr_den,fdr_pct,p50_ms,p99_ms,double_spend_prevented,notes"]
        for r in self.results_list:
            rows.append(",".join([
                r.config,
                r.scenario_id,
                str(r.asr.numerator),
                str(r.asr.denominator),
                r.asr.percent,
                str(r.lsr.numerator),
                str(r.lsr.denominator),
                r.lsr.percent,
                str(r.fdr.numerator),
                str(r.fdr.denominator),
                r.fdr.percent,
                f"{r.latency.p50:.1f}",
                f"{r.latency.p99:.1f}",
                str(r.double_spend_prevented),
                f'"{r.notes}"',
            ]))
        return rows


# ---------------------------------------------------------------------------
# MetricsEngine — computes TrialResult from live snapshot data
# ---------------------------------------------------------------------------

class MetricsEngine:
    """
    Compute ASR, LSR, FDR from observer ground-truth snapshot data.

    All inputs come from direct ledger/audit queries — never from HTTP
    status codes. Metrics are computed from ledger deltas.
    """

    @staticmethod
    def compute(
        config: str,
        scenario_id: str,
        scenario_name: str,
        *,
        attack_digests: list[str],
        legit_digests: list[str],
        ledger_before_digests: set[str],
        ledger_after_digests: set[str],
        latency_samples: Optional[list[float]] = None,
        double_spend_prevented: int = 0,
        notes: str = "",
    ) -> TrialResult:
        """
        Compute metrics from ledger snapshots taken before and after the trial.

        Args:
            attack_digests:          digests of attack actions attempted
            legit_digests:           digests of legitimate actions attempted
            ledger_before_digests:   set of digests in ledger BEFORE the run
            ledger_after_digests:    set of digests in ledger AFTER the run
            latency_samples:         list of per-request latency in ms
            double_spend_prevented:  count of T2 replays blocked (from observer)
            notes:                   human-readable annotation

        Returns:
            TrialResult with scientific ASR/LSR/FDR and latency stats.
        """
        # New digests that appeared in the ledger during this trial
        new_digests = ledger_after_digests - ledger_before_digests

        # ASR: how many ATTACK digests made it into the ledger
        unauthorized_writes = sum(1 for d in attack_digests if d in new_digests)
        asr = RateMetric(
            numerator=unauthorized_writes,
            denominator=len(attack_digests) if attack_digests else 1,
        )

        # LSR: how many LEGIT digests appear in the ledger after the run
        legit_writes = sum(
            1 for d in legit_digests
            if d in new_digests or d in ledger_before_digests
        )
        total_legit = len(legit_digests) if legit_digests else 1
        lsr = RateMetric(numerator=legit_writes, denominator=total_legit)

        # FDR: legitimate actions NOT found in ledger at all (blocked incorrectly)
        false_denials = sum(1 for d in legit_digests if d not in ledger_after_digests)
        fdr = RateMetric(numerator=false_denials, denominator=total_legit)

        return TrialResult(
            config=config,
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            asr=asr,
            lsr=lsr,
            fdr=fdr,
            latency=LatencyStats(samples=latency_samples or []),
            double_spend_prevented=double_spend_prevented,
            notes=notes,
        )

    @staticmethod
    def build_comparison(results: list[TrialResult]) -> ComparisonReport:
        """Build a ComparisonReport from a list of per-config TrialResults."""
        name = results[0].scenario_name if results else ""
        return ComparisonReport(results_list=results, scenario_name=name)

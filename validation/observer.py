"""
validation/observer.py
AgentShield V3 — Independent Ground-Truth Observer.

Author: Gururaj — Lead Red Team & Validation Engineer
Last Updated: 2026-10-14

PURPOSE:
    Reads the authoritative ledger and audit chain from Laptop 1 via
    GET /observer/snapshot — the ONLY source of truth used here.
    NEVER accepts HTTP status codes (200/403/409) as proof.
    NEVER issues write requests.

CACHE POLICY:
    Snapshot is cached locally and auto-refreshed before every command
    call (max 3-second staleness). Force-refresh with fetch_snapshot(force=True).

CRITICAL DISCREPANCY FLAG:
    If an attack call returned non-200 (API said BLOCKED) but
    verify_executed(digest) returns True (ledger was written anyway),
    flag_discrepancy() returns a CRITICAL DISCREPANCY string.
    This is the most important output — it proves a real security gap.

COORDINATION NOTE:
    Alok: endpoint spec in observer_snapshot_endpoint_spec.md
    Girish: snapshot JSON must include chain_hash per record for T5 verification.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class LedgerEntry:
    """A single execution entry from the authoritative ledger."""
    execution_id: str
    action_type: str
    action_digest: str        # 64-char SHA-256 hex — ground truth key
    principal_id: str
    tenant_id: str
    outcome: str              # "success" | "failure" | "tool_error"
    config: str               # "A" | "B" | "C"
    executed_at: str
    outcome_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditRecord:
    """A single audit event from the hash-chained audit log."""
    id: str
    event_type: str
    event_data: dict[str, Any]
    actor_id: str
    timestamp: str
    prev_chain_hash: Optional[str]
    chain_hash: str
    sequence_number: int


@dataclass
class LedgerSnapshot:
    """Immutable point-in-time snapshot of the ledger and audit chain."""
    captured_at: float
    execution_count: int
    executions: list[LedgerEntry]
    audit_count: int
    audit_records: list[AuditRecord]
    blocked_count: int        # audit events flagged as denied/blocked/rejected
    source: str               # "snapshot_endpoint" | "audit_fallback"


# ---------------------------------------------------------------------------
# Observer
# ---------------------------------------------------------------------------

_SNAPSHOT_TTL_SECONDS = 3.0   # auto-refresh cache if older than this


class Observer:
    """
    Ground-truth observer for the AgentShield Host (Laptop 1).

    GOLDEN RULE: every public method derives its answer from the cached
    /observer/snapshot — never from HTTP status codes.

    Cache behaviour:
        - Snapshot is refreshed automatically if older than _SNAPSHOT_TTL_SECONDS.
        - Call fetch_snapshot(force=True) to force immediate refresh.
        - Every public method calls _auto_refresh() at the start.
    """

    SNAPSHOT_PATH    = "/observer/snapshot"   # preferred — full ledger + audit chain
    AUDIT_FALLBACK   = "/audit/events"        # fallback when snapshot not yet deployed

    def __init__(
        self,
        base_url: str,
        timeout: float = 10.0,
        api_key: Optional[str] = None,
    ):
        """
        Args:
            base_url:  e.g. "http://192.168.1.42:8000"
            timeout:   per-request HTTP timeout in seconds
            api_key:   agent Bearer token (used for auth header on all requests)
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._http_headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._http_headers["Authorization"] = f"Bearer {api_key}"

        self._cached_snapshot: Optional[LedgerSnapshot] = None
        self._cached_at: float = 0.0

    # ------------------------------------------------------------------
    # Core public API
    # ------------------------------------------------------------------

    def fetch_snapshot(self, force: bool = False) -> LedgerSnapshot:
        """
        Fetch (or return cached) ground-truth snapshot from Laptop 1.

        Args:
            force: if True, bypass cache and fetch fresh from host.

        Returns:
            LedgerSnapshot — the authoritative ledger state.
        """
        if force or self._cache_stale():
            self._cached_snapshot = self._do_fetch()
            self._cached_at = time.time()
        return self._cached_snapshot  # type: ignore[return-value]

    def get_transaction_count(
        self,
        filter_digest: Optional[str] = None,
        config: Optional[str] = None,
    ) -> int:
        """
        Return the actual number of execution entries in the ledger.

        CRITICAL: Ground truth — NOT a count of HTTP 200 responses.
        An API that returned 403 but still wrote to the ledger is
        caught here.

        Args:
            filter_digest:  64-char SHA-256 hex. If set, count only entries
                            matching this action_digest.
            config:         "A", "B", or "C". If set, count only entries for
                            this enforcement configuration.
        """
        self._auto_refresh()
        entries = list(self._cached_snapshot.executions)  # type: ignore[union-attr]

        if filter_digest:
            entries = [e for e in entries if e.action_digest == filter_digest]
        if config:
            entries = [e for e in entries if e.config.upper() == config.upper()]

        return len(entries)

    def get_blocked_attempts(self) -> int:
        """
        Count actual blocked/denied attempts from the audit log.

        Source: audit chain records whose event_type contains a denial keyword.
        Does NOT rely on any HTTP response field.
        """
        self._auto_refresh()
        return sum(
            1 for r in self._cached_snapshot.audit_records  # type: ignore[union-attr]
            if any(
                kw in r.event_type.upper()
                for kw in ("DENIED", "BLOCKED", "REJECTED", "MISMATCH", "CONSUMED", "REVOKED")
            )
        )

    def verify_executed(self, action_digest: str) -> bool:
        """
        Return True if and only if the ledger contains an entry for this digest.

        This is the definitive check.
        - If the API returned 403 but this returns True → CRITICAL DISCREPANCY.
        - If the API returned 200 but this returns False → execution failed silently.

        Args:
            action_digest:  64-char SHA-256 hex of the canonical action.
        """
        self._auto_refresh()
        return any(
            e.action_digest == action_digest
            for e in self._cached_snapshot.executions  # type: ignore[union-attr]
        )

    def get_ledger_snapshot(self) -> LedgerSnapshot:
        """
        Return the current cached snapshot (force-refreshed).
        Use this for evidence export — it reflects the latest state.
        """
        return self.fetch_snapshot(force=True)

    def get_execution_count_for_intent(self, intent_id: str) -> int:
        """
        Count ledger entries matching a specific intent_id.

        T2 use case: should be ≤ 1 in Config C after the replay race.
        """
        self._auto_refresh()
        return sum(
            1 for e in self._cached_snapshot.executions  # type: ignore[union-attr]
            if e.outcome_data.get("intent_id") == intent_id
        )

    def flag_discrepancy(
        self,
        action_digest: str,
        api_status_code: int,
    ) -> Optional[str]:
        """
        Check for a mismatch between what the API reported and ledger reality.

        Returns:
            CRITICAL DISCREPANCY string if API said blocked but ledger was written.
            NOTE string if API said success but ledger shows nothing.
            None if API and ledger agree.
        """
        in_ledger = self.verify_executed(action_digest)
        api_blocked = api_status_code not in (200, 201)

        if api_blocked and in_ledger:
            return (
                f"⚠️  CRITICAL DISCREPANCY: API returned HTTP {api_status_code} "
                f"(claimed BLOCKED) but ledger CONTAINS digest "
                f"{action_digest[:20]}... — this is a real security gap."
            )
        if not api_blocked and not in_ledger:
            return (
                f"NOTE: API returned HTTP {api_status_code} (claimed SUCCESS) "
                f"but ledger shows NO entry for digest {action_digest[:20]}... "
                f"— execution may have failed silently."
            )
        return None

    def verify_audit_chain_integrity(
        self,
    ) -> tuple[bool, Optional[int], Optional[str]]:
        """
        Independently verify audit chain hash linkage by re-walking prev_chain_hash.

        Returns:
            (valid, first_broken_sequence, error_message)
            valid=True → chain is intact.
        """
        self._auto_refresh()
        records = sorted(
            self._cached_snapshot.audit_records,  # type: ignore[union-attr]
            key=lambda r: r.sequence_number,
        )

        prev_hash: Optional[str] = None
        for rec in records:
            if prev_hash is not None and rec.prev_chain_hash != prev_hash:
                return (
                    False,
                    rec.sequence_number,
                    (
                        f"Chain broken at sequence {rec.sequence_number}: "
                        f"expected prev_hash={str(prev_hash)[:16]}..., "
                        f"got {str(rec.prev_chain_hash)[:16]}..."
                    ),
                )
            prev_hash = rec.chain_hash

        return (True, None, None)

    def ping(self) -> bool:
        """Return True if the Host is reachable at /health."""
        try:
            with httpx.Client(timeout=5.0) as client:
                r = client.get(f"{self.base_url}/health")
                return r.status_code == 200
        except Exception:
            return False

    def get_status_summary(self) -> dict[str, Any]:
        """
        Return a concise summary suitable for the 'observer' terminal command.

        Always force-refreshes the snapshot to show current state.
        """
        try:
            snap = self.fetch_snapshot(force=True)
            chain_ok, broken_seq, chain_err = self.verify_audit_chain_integrity()
            return {
                "reachable": True,
                "snapshot_source": snap.source,
                "execution_count": snap.execution_count,
                "blocked_count": snap.blocked_count,
                "audit_record_count": snap.audit_count,
                "chain_integrity": "OK" if chain_ok else f"BROKEN at seq {broken_seq}",
                "chain_error": chain_err,
                "captured_at": snap.captured_at,
            }
        except Exception as exc:
            return {
                "reachable": self.ping(),
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache_stale(self) -> bool:
        if self._cached_snapshot is None:
            return True
        return (time.time() - self._cached_at) > _SNAPSHOT_TTL_SECONDS

    def _auto_refresh(self) -> None:
        """Refresh cache if stale — called at the start of every public method."""
        if self._cache_stale():
            self._cached_snapshot = self._do_fetch()
            self._cached_at = time.time()

    # ------------------------------------------------------------------
    # Network fetch
    # ------------------------------------------------------------------

    def _do_fetch(self) -> LedgerSnapshot:
        """
        Fetch snapshot from host, trying /observer/snapshot first,
        falling back to /audit/events if the snapshot endpoint is not deployed yet.
        """
        try:
            snap = self._fetch_observer_snapshot()
            if snap is not None:
                return snap
        except Exception:
            pass
        return self._fetch_audit_fallback()

    def _fetch_observer_snapshot(self) -> Optional[LedgerSnapshot]:
        """Fetch from /observer/snapshot (the preferred, authoritative endpoint)."""
        with httpx.Client(timeout=self.timeout, headers=self._http_headers) as client:
            r = client.get(f"{self.base_url}{self.SNAPSHOT_PATH}")
            if r.status_code == 404:
                return None       # endpoint not yet deployed — fall back
            r.raise_for_status()
            data = r.json()

        executions = [
            LedgerEntry(
                execution_id=e.get("execution_id", ""),
                action_type=e.get("action_type", ""),
                action_digest=e.get("action_digest", ""),
                principal_id=e.get("principal_id", ""),
                tenant_id=e.get("tenant_id", ""),
                outcome=e.get("outcome", ""),
                config=e.get("config", "C"),
                executed_at=e.get("executed_at", ""),
                outcome_data=e.get("outcome_data", {}),
            )
            for e in data.get("executions", [])
        ]
        audit_records = self._parse_audit_records(data.get("audit_records", []))

        blocked = sum(
            1 for r in audit_records
            if any(
                kw in r.event_type.upper()
                for kw in ("DENIED", "BLOCKED", "REJECTED", "MISMATCH", "CONSUMED")
            )
        )

        return LedgerSnapshot(
            captured_at=time.time(),
            execution_count=len(executions),
            executions=executions,
            audit_count=len(audit_records),
            audit_records=audit_records,
            blocked_count=blocked,
            source="snapshot_endpoint",
        )

    def _fetch_audit_fallback(self) -> LedgerSnapshot:
        """Fallback: reconstruct from /audit/events when /observer/snapshot is absent."""
        with httpx.Client(timeout=self.timeout, headers=self._http_headers) as client:
            r = client.get(
                f"{self.base_url}{self.AUDIT_FALLBACK}",
                params={"limit": 1000},
            )
            r.raise_for_status()
            events_data = r.json()

        audit_records = self._parse_audit_records(events_data)

        # Reconstruct ledger entries from EXECUTION_SUCCESS audit events
        executions: list[LedgerEntry] = []
        for rec in audit_records:
            if "EXECUTION" in rec.event_type.upper() and "SUCCESS" in rec.event_type.upper():
                d = rec.event_data or {}
                executions.append(LedgerEntry(
                    execution_id=d.get("execution_id", rec.id),
                    action_type=d.get("action_type", ""),
                    action_digest=d.get("action_digest", ""),
                    principal_id=rec.actor_id or "",
                    tenant_id=d.get("tenant_id", ""),
                    outcome="success",
                    config=d.get("config", "C"),
                    executed_at=rec.timestamp,
                    outcome_data=d,
                ))

        blocked = sum(
            1 for r in audit_records
            if any(
                kw in r.event_type.upper()
                for kw in ("DENIED", "BLOCKED", "REJECTED", "MISMATCH", "CONSUMED")
            )
        )

        return LedgerSnapshot(
            captured_at=time.time(),
            execution_count=len(executions),
            executions=executions,
            audit_count=len(audit_records),
            audit_records=audit_records,
            blocked_count=blocked,
            source="audit_fallback",
        )

    @staticmethod
    def _parse_audit_records(raw: list[dict[str, Any]]) -> list[AuditRecord]:
        return [
            AuditRecord(
                id=r.get("id", ""),
                event_type=r.get("event_type", ""),
                event_data=r.get("event_data", {}),
                actor_id=r.get("actor_id", ""),
                timestamp=r.get("timestamp", ""),
                prev_chain_hash=r.get("prev_chain_hash"),
                chain_hash=r.get("chain_hash", ""),
                sequence_number=int(r.get("sequence_number", 0)),
            )
            for r in raw
        ]

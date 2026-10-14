"""
redteam/attacker_terminal.py
AgentShield V3 — agsh: The Red Team Attacker Terminal.

Author: Gururaj — Lead Red Team & Validation Engineer
Last Updated: 2026-10-14

PURPOSE:
    Professional interactive CLI for Laptop 2 (the attacker machine).
    Connects over Wi-Fi to Laptop 1 (the host) and runs live attacks.

    GOLDEN RULE: All results shown come from ground-truth ledger queries.
                 We NEVER display HTTP "blocked: true" as proof.

USAGE:
    python redteam/attacker_terminal.py
    > connect 192.168.1.42:8000
    > status
    > list-scenarios
    > run tamper
    > compare tamper
    > observer status
    > export-evidence
    > demo-flow

DEPENDENCIES:
    pip install prompt_toolkit httpx rich

COORDINATION:
    Alok: ensure /observer/snapshot endpoint or /audit/events is accessible
    Girish: canonical hash domain separator is b"AGENTSHIELD-ACTION-V1\\x00"
    Pavan: scenario names match threat matrix T1-T5
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Add repo root to path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.styles import Style
    HAS_PROMPT_TOOLKIT = True
except ImportError:
    HAS_PROMPT_TOOLKIT = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from redteam.toolkit import AttackToolkit, AttackOutcome
from redteam.scenarios import ALL_SCENARIOS, get_scenario, list_scenarios, Scenario
from validation.observer import Observer
from validation.metrics import MetricsEngine, ComparisonReport
from validation.harness import Harness

# ---------------------------------------------------------------------------
# Config store
# ---------------------------------------------------------------------------
CONFIG_DIR = Path.home() / ".agsh"
CONFIG_FILE = CONFIG_DIR / "config.json"
EVIDENCE_DIR = ROOT / "evidence"


def load_config() -> dict[str, Any]:
    CONFIG_DIR.mkdir(exist_ok=True)
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {}


def save_config(cfg: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


# ---------------------------------------------------------------------------
# Terminal renderer (works with or without rich)
# ---------------------------------------------------------------------------

class Terminal:
    """Color output helper. Uses rich if available, falls back to ANSI codes."""

    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    def __init__(self):
        self.console = Console() if HAS_RICH else None

    def banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║          AgentShield V3 — THE AUTONOMY TRIAL                            ║
║          agsh: Red Team Attacker Terminal  v3.0                         ║
║          Author: Gururaj — Lead Red Team & Validation Engineer           ║
╠══════════════════════════════════════════════════════════════════════════╣
║  GOLDEN RULE: Results come from the LEDGER, not HTTP status codes.      ║
║  Type 'help' for commands. Type 'demo-flow' to start the live demo.     ║
╚══════════════════════════════════════════════════════════════════════════╝"""
        self._print(banner, color="cyan")

    def ok(self, msg: str):
        self._print(f"  ✅  {msg}", color="green")

    def fail(self, msg: str):
        self._print(f"  ❌  {msg}", color="red")

    def warn(self, msg: str):
        self._print(f"  ⚠️   {msg}", color="yellow")

    def info(self, msg: str):
        self._print(f"  ℹ️   {msg}", color="cyan")

    def section(self, title: str):
        self._print(f"\n  {'─'*60}\n  {title}\n  {'─'*60}", color="cyan")

    def raw(self, msg: str):
        print(msg)

    def _print(self, msg: str, color: str = ""):
        if HAS_RICH and self.console:
            color_map = {
                "green": "bold green",
                "red": "bold red",
                "yellow": "bold yellow",
                "cyan": "cyan",
            }
            self.console.print(msg, style=color_map.get(color, ""))
        else:
            ansi = {
                "green": self.GREEN,
                "red": self.RED,
                "yellow": self.YELLOW,
                "cyan": self.CYAN,
            }.get(color, "")
            print(f"{ansi}{msg}{self.RESET}")


# ---------------------------------------------------------------------------
# Main Terminal Application
# ---------------------------------------------------------------------------

class AgshTerminal:
    """The agsh attacker terminal."""

    def __init__(self):
        self.term = Terminal()
        self.cfg = load_config()
        self.target: Optional[str] = self.cfg.get("target")
        self.agent_token: Optional[str] = self.cfg.get("agent_token")
        self.toolkit: Optional[AttackToolkit] = None
        self.observer: Optional[Observer] = None
        self.harness: Optional[Harness] = None
        self._run_log: list[dict[str, Any]] = []

        if self.target and self.agent_token:
            self._init_clients()

    def _init_clients(self):
        base_url = f"http://{self.target}" if not self.target.startswith("http") else self.target
        self.toolkit = AttackToolkit(base_url, self.agent_token)
        self.observer = Observer(base_url, api_key=self.agent_token)
        self.harness = Harness(base_url, self.agent_token)

    # ------------------------------------------------------------------
    # Command dispatcher
    # ------------------------------------------------------------------

    def run(self):
        self.term.banner()

        if self.target:
            self.term.info(f"Last target: {self.target} (stored in ~/.agsh/config.json)")

        if HAS_PROMPT_TOOLKIT:
            session = PromptSession(
                history=FileHistory(str(CONFIG_DIR / "history")),
                auto_suggest=AutoSuggestFromHistory(),
                style=Style.from_dict({"prompt": "ansigreen bold"}),
            )
            get_input = lambda: session.prompt("agsh> ")
        else:
            get_input = lambda: input("agsh> ")

        while True:
            try:
                line = get_input().strip()
                if not line:
                    continue
                if line in ("exit", "quit", "q"):
                    self.term.info("Exiting agsh. Goodbye.")
                    break
                self._dispatch(line)
            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                break

    def _dispatch(self, line: str):
        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        commands = {
            "connect": self.cmd_connect,
            "status": self.cmd_status,
            "list-scenarios": self.cmd_list_scenarios,
            "ls": self.cmd_list_scenarios,
            "run": self.cmd_run,
            "compare": self.cmd_compare,
            "observer": self.cmd_observer,
            "export-evidence": self.cmd_export_evidence,
            "demo-flow": self.cmd_demo_flow,
            "set-token": self.cmd_set_token,
            "reset": self.cmd_reset,
            "help": self.cmd_help,
            "h": self.cmd_help,
            "?": self.cmd_help,
        }

        if cmd not in commands:
            self.term.warn(f"Unknown command '{cmd}'. Type 'help' for a list.")
            return

        try:
            commands[cmd](args)
        except Exception as exc:
            self.term.fail(f"Command failed: {exc}")

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def cmd_connect(self, args: list[str]):
        """connect <host_ip:port>  — Link to Laptop 1."""
        if not args:
            self.term.warn("Usage: connect <host_ip:port>  e.g. connect 192.168.1.42:8000")
            return

        self.target = args[0]
        token_arg = args[1] if len(args) > 1 else None

        if token_arg:
            self.agent_token = token_arg
        elif not self.agent_token:
            try:
                if HAS_PROMPT_TOOLKIT:
                    from prompt_toolkit import prompt
                    self.agent_token = prompt("  Agent API token: ", is_password=True).strip()
                else:
                    import getpass
                    self.agent_token = getpass.getpass("  Agent API token: ").strip()
            except (KeyboardInterrupt, EOFError):
                self.term.warn("Token input cancelled.")
                return

        if not self.agent_token:
            self.term.warn("No agent token provided. Some commands will fail authentication.")

        self.cfg["target"] = self.target
        self.cfg["agent_token"] = self.agent_token
        save_config(self.cfg)
        self._init_clients()

        # Test connectivity
        self.term.info(f"Connecting to {self.target} ...")
        if self.observer and self.observer.ping():
            self.term.ok(f"Connected to {self.target} — Host is reachable")
        else:
            self.term.warn(f"Host {self.target} is not responding to /health — check Laptop 1")

    def cmd_status(self, args: list[str]):
        """status — Show current target, agent, and host config."""
        self.term.section("AGSH STATUS")
        if not self.target:
            self.term.warn("Not connected. Use: connect <host_ip:port>")
            return

        base_url = f"http://{self.target}" if not self.target.startswith("http") else self.target
        self.term.raw(f"  Target:      {base_url}")
        self.term.raw(f"  Agent token: {'***set***' if self.agent_token else 'NOT SET'}")
        self.term.raw(f"  Config dir:  {CONFIG_DIR}")
        self.term.raw(f"  Evidence dir:{EVIDENCE_DIR}")

        # Try to get host info
        if self.observer:
            reachable = self.observer.ping()
            status_str = "✅ Reachable" if reachable else "❌ Not reachable"
            self.term.raw(f"  Host status: {status_str}")

            if reachable:
                summary = self.observer.get_status_summary()
                self.term.raw(f"  Executions in ledger: {summary.get('execution_count', '?')}")
                self.term.raw(f"  Blocked attempts:     {summary.get('blocked_count', '?')}")
                self.term.raw(f"  Audit records:        {summary.get('audit_record_count', '?')}")
                self.term.raw(f"  Chain integrity:      {summary.get('chain_integrity', '?')}")

    def cmd_list_scenarios(self, args: list[str]):
        """list-scenarios — Show all available attack scenarios."""
        self.term.section("AVAILABLE ATTACK SCENARIOS")
        scenarios = list_scenarios()

        header = f"  {'Name':<20} {'Class':<6} {'Description'}"
        self.term.raw(f"  {'─'*70}")
        self.term.raw(header)
        self.term.raw(f"  {'─'*70}")

        for s in scenarios:
            class_color = {
                "T1": "red", "T2": "red", "T3": "red",
                "T4": "yellow", "T5": "yellow", "EDGE": "cyan",
            }.get(s.attack_class, "")
            self.term.raw(f"  {s.name:<20} {s.attack_class:<6} {s.display_name}")

        self.term.raw(f"  {'─'*70}")
        self.term.raw(f"\n  Run with: run <name>  e.g.  run tamper")
        self.term.raw(f"  Compare:  compare <name>  e.g.  compare tamper")

    def cmd_run(self, args: list[str]):
        """run <scenario> [config]  — Execute attack against Host."""
        if not args:
            self.term.warn("Usage: run <scenario> [A|B|C]")
            self.term.warn("Available: " + ", ".join(sorted(ALL_SCENARIOS.keys())))
            return

        self._require_connection()
        scenario_name = args[0].lower()
        config = args[1].upper() if len(args) > 1 else "C"

        try:
            scenario = get_scenario(scenario_name)
        except KeyError as e:
            self.term.fail(str(e))
            return

        self.term.section(f"RUNNING: {scenario.display_name}")
        self.term.raw(f"  Config: {config}  |  Method: {scenario.method}")
        self.term.raw(f"  {scenario.description}")
        self.term.raw("")

        outcome = self._execute_scenario(scenario, config)
        self._display_outcome(outcome, scenario)

        # Annotate with ledger ground truth
        if self.observer and outcome.digest:
            outcome.found_in_ledger = self.observer.verify_executed(outcome.digest)
            # Check for API vs ledger discrepancy
            disc = self.observer.flag_discrepancy(outcome.digest, outcome.api_code)
            if disc:
                self.term.warn(disc)
            if scenario.method == "replay_attack":
                outcome.ledger_entry_count = self.observer.get_transaction_count(
                    filter_digest=outcome.digest
                )

        # Log result
        self._log_run(scenario_name, config, outcome)

        # Final verdict
        self.term.raw("")
        if outcome.actually_blocked:
            self.term.ok(f"VERDICT: Attack BLOCKED in Config {config} — ledger unchanged")
        else:
            self.term.fail(f"VERDICT: Attack SUCCEEDED in Config {config} — unauthorized ledger write")

        if outcome.discrepancy:
            self.term.warn(f"DISCREPANCY: {outcome.discrepancy}")

    def cmd_compare(self, args: list[str]):
        """compare <scenario>  — Run same scenario against A, B, C and show table."""
        if not args:
            self.term.warn("Usage: compare <scenario>  e.g. compare tamper")
            return

        self._require_connection()
        scenario_name = args[0].lower()

        try:
            scenario = get_scenario(scenario_name)
        except KeyError as e:
            self.term.fail(str(e))
            return

        self.term.section(f"COMPARATIVE ANALYSIS: {scenario.display_name}")
        self.term.raw(f"  Running same payload against Config A → B → C ...")
        self.term.raw("")

        results: dict[str, AttackOutcome] = {}
        configs = ["A", "B", "C"]

        for config in configs:
            self.term.raw(f"  ▶ Config {config} ...", )
            outcome = self._execute_scenario(scenario, config)

            # Ground truth from ledger
            if self.observer and outcome.action_digest:
                outcome.found_in_ledger = self.observer.verify_executed(outcome.action_digest)

            results[config] = outcome
            status = "✅ BLOCKED" if outcome.actually_blocked else "❌ PASSED"
            self.term.raw(
                f"    HTTP {outcome.executor_status} | Ledger: {status} | "
                f"{outcome.latency_ms:.0f}ms"
            )
            time.sleep(0.3)  # slight pause for readability

        # Print comparison table
        self.term.raw("")
        self.term.raw(
            f"  ╔══════════════════════════════════════════════════════════════════╗"
        )
        self.term.raw(f"  ║  {'Scenario: ' + scenario.display_name[:50]:<60}║")
        self.term.raw(
            f"  ╠════════╦══════════════╦════════════╦════════════╦═══════════╣"
        )
        self.term.raw(
            f"  ║ Config ║ Gateway HTTP ║ Exec HTTP  ║ In Ledger? ║ Latency   ║"
        )
        self.term.raw(
            f"  ╠════════╬══════════════╬════════════╬════════════╬═══════════╣"
        )

        for config in configs:
            o = results[config]
            in_ledger = "❌ YES" if o.found_in_ledger else "✅ NO"
            self.term.raw(
                f"  ║   {config}    ║ "
                f"{str(o.gateway_status):<12} ║ "
                f"{str(o.executor_status):<10} ║ "
                f"{in_ledger:<10} ║ "
                f"{o.latency_ms:>6.0f}ms   ║"
            )

        self.term.raw(
            f"  ╚════════╩══════════════╩════════════╩════════════╩═══════════╝"
        )

        # Flag discrepancies
        if results.get("A") and results.get("C"):
            a_passed = results["A"].found_in_ledger
            c_passed = results["C"].found_in_ledger
            if a_passed and not c_passed:
                self.term.ok("  ⚡ Config A BREACHED — Config C HELD. AgentShield protection proven.")
            elif not a_passed and not c_passed:
                self.term.info("  Both A and C blocked this attack. Check if gateway-level denial.")

    def cmd_observer(self, args: list[str]):
        """observer status  — Pull ground truth metrics from Host ledger."""
        self._require_connection()

        if not args or args[0] == "status":
            self.term.section("OBSERVER: GROUND TRUTH FROM HOST LEDGER")
            self.term.raw("  (Reading ledger directly — NOT trusting API responses)")
            self.term.raw("")

            summary = self.observer.get_status_summary()

            if not summary.get("reachable", False):
                self.term.fail("Host is not reachable")
                return

            self.term.raw(f"  Source:              {summary.get('snapshot_source', 'unknown')}")
            self.term.raw(f"  Execution count:     {summary.get('execution_count', 0):,}")
            self.term.raw(f"  Blocked attempts:    {summary.get('blocked_count', 0):,}")
            self.term.raw(f"  Audit records:       {summary.get('audit_record_count', 0):,}")

            chain = summary.get("chain_integrity", "UNKNOWN")
            if chain == "OK":
                self.term.ok(f"  Audit chain:         {chain}")
            else:
                self.term.fail(f"  Audit chain:         {chain}")
                if summary.get("chain_error"):
                    self.term.raw(f"  Chain error:         {summary['chain_error']}")

        elif args[0] == "snapshot":
            self.term.section("OBSERVER: FULL LEDGER SNAPSHOT")
            snapshot = self.observer.get_ledger_snapshot()
            self.term.raw(f"  Captured at:   {datetime.fromtimestamp(snapshot.captured_at).isoformat()}")
            self.term.raw(f"  Executions:    {snapshot.execution_count}")
            self.term.raw(f"  Audit records: {snapshot.audit_count}")
            self.term.raw(f"  Source:        {snapshot.source}")
            for entry in snapshot.executions[:10]:
                self.term.raw(
                    f"    [{entry.config}] {entry.action_type} | "
                    f"{entry.action_digest[:16]}... | {entry.outcome}"
                )
            if snapshot.execution_count > 10:
                self.term.raw(f"    ... and {snapshot.execution_count - 10} more")

        elif args[0] == "verify-chain":
            self.term.section("OBSERVER: AUDIT CHAIN INTEGRITY CHECK")
            valid, broken_seq, error = self.observer.verify_audit_chain_integrity()
            if valid:
                self.term.ok("Audit chain integrity: VALID — no tampering detected")
            else:
                self.term.fail(f"Audit chain BROKEN at sequence {broken_seq}")
                self.term.raw(f"  Error: {error}")

    def cmd_export_evidence(self, args: list[str]):
        """export-evidence  — Generate timestamped evidence package."""
        self._require_connection()
        self.term.section("EVIDENCE EXPORT")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        evidence_dir = EVIDENCE_DIR / timestamp
        evidence_dir.mkdir(parents=True, exist_ok=True)

        self.term.raw(f"  Writing to: {evidence_dir}")

        # 1. Ledger snapshot
        snapshot = self.observer.get_ledger_snapshot()
        ledger_data = {
            "captured_at": snapshot.captured_at,
            "execution_count": snapshot.execution_count,
            "source": snapshot.source,
            "executions": [
                {
                    "execution_id": e.execution_id,
                    "action_type": e.action_type,
                    "action_digest": e.action_digest,
                    "principal_id": e.principal_id,
                    "outcome": e.outcome,
                    "config": e.config,
                    "executed_at": e.executed_at,
                }
                for e in snapshot.executions
            ],
        }
        (evidence_dir / "ledger_snapshot.json").write_text(
            json.dumps(ledger_data, indent=2, default=str)
        )
        self.term.ok("ledger_snapshot.json written")

        # 2. Raw run log
        (evidence_dir / "raw_logs.jsonl").write_text(
            "\n".join(json.dumps(e, default=str) for e in self._run_log)
        )
        self.term.ok("raw_logs.jsonl written")

        # 3. Metrics CSV
        csv_lines = ["scenario,config,http_status,in_ledger,latency_ms,discrepancy"]
        for entry in self._run_log:
            csv_lines.append(",".join([
                str(entry.get("scenario", "")),
                str(entry.get("config", "")),
                str(entry.get("http_status", "")),
                str(entry.get("found_in_ledger", "")),
                str(entry.get("latency_ms", "")),
                str(entry.get("discrepancy", "") or ""),
            ]))
        (evidence_dir / "metrics.csv").write_text("\n".join(csv_lines))
        self.term.ok("metrics.csv written")

        # 4. Audit chain integrity
        valid, broken_seq, chain_err = self.observer.verify_audit_chain_integrity()
        chain_result = {
            "valid": valid,
            "first_broken_sequence": broken_seq,
            "error": chain_err,
        }
        (evidence_dir / "audit_chain_verification.json").write_text(
            json.dumps(chain_result, indent=2)
        )
        self.term.ok("audit_chain_verification.json written")

        # 5. README
        readme = f"""AgentShield V3 — The Autonomy Trial
Evidence Package Generated: {datetime.now().isoformat()}
Target Host: {self.target}

HOW TO INDEPENDENTLY VERIFY THESE RESULTS:
==========================================
1. Install: pip install httpx
2. Connect: python redteam/attacker_terminal.py
3. Run:     connect {self.target}
4. Execute: agsh compare tamper
5. Compare the ledger_snapshot.json with what you see in this folder.

The ledger_snapshot.json is the ground truth — not the HTTP responses.

METRIC DEFINITIONS:
    ASR = Attack Success Rate = unauthorized_ledger_writes / total_attacks
    LSR = Legitimate Success Rate = valid writes / total legit submissions
    FDR = False Denial Rate = valid denials / total legit submissions

DISCLAIMER:
    These results are reproducible. Run 'agsh compare' yourself.
    Config C (AgentShield V3) results are NOT pre-staged.
"""
        (evidence_dir / "README.txt").write_text(readme)
        self.term.ok("README.txt written")

        # 6. Human-readable summary
        summary = self._build_summary_md(snapshot, chain_result)
        (evidence_dir / "summary.md").write_text(summary)
        self.term.ok("summary.md written")

        self.term.raw("")
        self.term.ok(f"Evidence package complete: {evidence_dir}")
        self.term.raw(f"  Hand this folder to the judges.")

    def cmd_demo_flow(self, args: list[str]):
        """demo-flow  — Guided 5-step live demo for judges."""
        self._require_connection()

        self.term.raw("")
        self.term.raw("╔══════════════════════════════════════════════════════════════════════╗")
        self.term.raw("║          AGENTSHIELD V3 — LIVE DEMO FLOW                            ║")
        self.term.raw("║          5 steps — follow the narration between each step           ║")
        self.term.raw("╚══════════════════════════════════════════════════════════════════════╝")

        steps = [
            (
                "STEP 1: Config A — Tamper Succeeds",
                "tamper", "A",
                "This is conventional RBAC protection. An authorized ₹500 refund — "
                "the attacker changes it to ₹5,000. Config A has no digest check. "
                "Watch the ledger.",
            ),
            (
                "STEP 2: Config C — Same Attack Blocked",
                "tamper", "C",
                "Now Config C — full AgentShield V3. Same tampered payload. "
                "The executor recomputes the hash — it doesn't match. BLOCKED. "
                "The ledger is unchanged.",
            ),
            (
                "STEP 3: Config C — Replay Race (50×)",
                "replay", "C",
                "One capability token, 50 concurrent requests. "
                "Atomic Redis claim — exactly 1 succeeds. "
                "We count ledger entries, not HTTP 200s.",
            ),
            (
                "STEP 4: Observer — Prove the Ledger",
                None, None,
                "The independent observer queries the ledger directly. "
                "No trust in API responses. Ground truth.",
            ),
            (
                "STEP 5: Export Evidence",
                None, None,
                "Evidence package generated. Hand this to the judges. "
                "Every result is reproducible — run it yourself.",
            ),
        ]

        for i, (title, scenario_name, config, narration) in enumerate(steps, 1):
            self.term.raw("")
            self.term.raw(f"  ┌─ [{i}/5] {title}")
            self.term.raw(f"  │")
            self.term.raw(f"  │  {narration}")
            self.term.raw(f"  │")

            input("  └─ [Press ENTER to execute] ")

            if scenario_name and config:
                try:
                    scenario = get_scenario(scenario_name)
                    outcome = self._execute_scenario(scenario, config)
                    if self.observer and outcome.action_digest:
                        outcome.found_in_ledger = self.observer.verify_executed(outcome.action_digest)
                    self._display_outcome(outcome, scenario)
                    self._log_run(scenario_name, config, outcome)
                except Exception as exc:
                    self.term.fail(f"Error: {exc}")
            elif title.startswith("STEP 4"):
                self.cmd_observer(["status"])
            elif title.startswith("STEP 5"):
                self.cmd_export_evidence([])

            self.term.raw("")
            if i < len(steps):
                input("  [Press ENTER to continue to next step] ")

        self.term.raw("")
        self.term.ok("Demo flow complete.")
        self.term.raw("  Evidence folder has been generated.")
        self.term.raw("  Run 'export-evidence' again at any time to regenerate.")

    def cmd_set_token(self, args: list[str]):
        """set-token <token>  — Update agent API token."""
        if not args:
            self.term.warn("Usage: set-token <api_token>")
            return
        self.agent_token = args[0]
        self.cfg["agent_token"] = self.agent_token
        save_config(self.cfg)
        if self.target:
            self._init_clients()
        self.term.ok("Agent token updated.")

    def cmd_reset(self, args: list[str]):
        """reset  — Clear stored config and run log."""
        self.cfg = {}
        self.target = None
        self.agent_token = None
        self.toolkit = None
        self.observer = None
        self.harness = None
        self._run_log = []
        save_config({})
        self.term.ok("Config and run log cleared.")

    def cmd_help(self, args: list[str]):
        """help  — Show all commands."""
        self.term.section("AVAILABLE COMMANDS")
        commands = [
            ("connect <ip:port>",      "Link to Laptop 1 (Host)"),
            ("status",                  "Show target, agent, and host info"),
            ("list-scenarios / ls",     "List all attack scenarios"),
            ("run <scenario> [A|B|C]",  "Run one scenario against specified config"),
            ("compare <scenario>",      "Run same scenario against all 3 configs"),
            ("observer status",         "Pull ground truth from ledger"),
            ("observer snapshot",       "Show full ledger contents"),
            ("observer verify-chain",   "Verify audit chain integrity"),
            ("export-evidence",         "Generate timestamped evidence package"),
            ("demo-flow",               "Guided 5-step demo for judges"),
            ("set-token <token>",       "Update agent API token"),
            ("reset",                   "Clear stored config"),
            ("exit / quit",             "Exit agsh"),
        ]
        for cmd, desc in commands:
            self.term.raw(f"  {cmd:<35} {desc}")
        self.term.raw("")
        self.term.raw("  SCENARIOS: " + ", ".join(sorted(ALL_SCENARIOS.keys())))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_connection(self):
        if not self.toolkit or not self.target:
            raise RuntimeError(
                "Not connected. Run: connect <host_ip:port>"
            )

    def _execute_scenario(self, scenario: Scenario, config: str) -> AttackOutcome:
        """Dispatch to the right toolkit method based on scenario.method."""
        req_id = scenario.fresh_request_id()

        if scenario.method == "tamper_and_submit":
            return self.toolkit.tamper_and_submit(
                config=config,
                action_type=scenario.action_type,
                original_params=scenario.parameters,
                alter_field=scenario.alter_field or "amount",
                new_value=scenario.new_value,
                request_id=req_id,
            )
        elif scenario.method == "replay_attack":
            return self.toolkit.replay_attack(
                config=config,
                action_type=scenario.action_type,
                parameters=scenario.parameters,
                parallel_count=scenario.parallel_count,
                request_id=req_id,
            )
        elif scenario.method == "drift_attempt":
            return self.toolkit.drift_attempt(
                config=config,
                base_action_type=scenario.action_type,
                base_params=scenario.parameters,
                target_action_type=scenario.target_action_type or scenario.action_type,
                target_params=scenario.target_params or scenario.parameters,
                request_id=req_id,
            )
        elif scenario.method == "spoof_confidence_attack":
            return self.toolkit.spoof_confidence_attack(
                config=config,
                action_type=scenario.action_type,
                honest_params=scenario.parameters,
                spoofed_context_headers=scenario.spoofed_headers,
                fake_confidence_level=scenario.fake_confidence_level,
                request_id=req_id,
            )
        elif scenario.method == "falsify_receipt":
            # For T5 we need a real receipt first — run a legitimate action
            legit = self.toolkit.tamper_and_submit(
                config=config,
                action_type=scenario.action_type,
                original_params=scenario.parameters,
                alter_field="reason",
                new_value="legitimate_test_run",
                request_id=req_id,
            )
            return self.toolkit.falsify_receipt(
                config=config,
                valid_receipt=legit.executor_body,
                fake_result="success",
                tamper_field="outcome",
            )
        else:
            raise ValueError(f"Unknown method: {scenario.method}")

    def _display_outcome(self, outcome: AttackOutcome, scenario: Scenario):
        """Print a clean, readable outcome summary."""
        self.term.raw(outcome.explain())

        if scenario.method == "replay_attack" and outcome.parallel_results:
            total = len(outcome.parallel_results)
            successes = sum(1 for r in outcome.parallel_results if r.get("status") in (200, 201))
            blocked = total - successes
            self.term.raw(
                f"  ↳ Replay results: {successes} API successes / "
                f"{blocked} blocked out of {total} total"
            )
            if outcome.ledger_entry_count > 0:
                self.term.raw(f"  ↳ LEDGER entries (ground truth): {outcome.ledger_entry_count}")

    def _log_run(self, scenario: str, config: str, outcome: AttackOutcome):
        self._run_log.append({
            "timestamp": time.time(),
            "scenario": scenario,
            "config": config,
            "gateway_status": outcome.gateway_status,
            "executor_status": outcome.executor_status,
            "action_digest": outcome.action_digest,
            "found_in_ledger": outcome.found_in_ledger,
            "actually_blocked": outcome.actually_blocked,
            "latency_ms": outcome.latency_ms,
            "discrepancy": outcome.discrepancy,
            "error": outcome.error,
        })

    def _build_summary_md(
        self,
        snapshot,
        chain_result: dict,
    ) -> str:
        lines = [
            "# AgentShield V3 — Evidence Summary",
            f"",
            f"**Generated:** {datetime.now().isoformat()}",
            f"**Target Host:** {self.target}",
            f"",
            "## Ground Truth: Ledger State",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total executions in ledger | {snapshot.execution_count} |",
            f"| Blocked/denied attempts | {snapshot.blocked_count} |",
            f"| Audit records | {snapshot.audit_count} |",
            f"| Ledger source | {snapshot.source} |",
            f"",
            "## Audit Chain Integrity",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Valid | {chain_result.get('valid')} |",
            f"| First broken sequence | {chain_result.get('first_broken_sequence', 'None')} |",
            f"| Error | {chain_result.get('error', 'None')} |",
            f"",
            "## Run Log",
            f"",
            f"| Scenario | Config | HTTP Status | In Ledger | Latency (ms) |",
            f"|----------|--------|-------------|-----------|--------------|",
        ]
        for entry in self._run_log:
            lines.append(
                f"| {entry.get('scenario','')} "
                f"| {entry.get('config','')} "
                f"| {entry.get('executor_status','')} "
                f"| {'YES ❌' if entry.get('found_in_ledger') else 'NO ✅'} "
                f"| {entry.get('latency_ms', 0):.0f} |"
            )
        lines += [
            f"",
            "## Verification",
            f"",
            "**These results are reproducible.** To verify:",
            f"",
            "```bash",
            f"git clone <repo>",
            f"pip install httpx prompt_toolkit rich",
            f"python redteam/attacker_terminal.py",
            f"# connect {self.target}",
            f"# compare tamper",
            f"```",
            f"",
            "> Metrics are derived from direct ledger queries — not HTTP response codes.",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = AgshTerminal()
    app.run()


if __name__ == "__main__":
    main()

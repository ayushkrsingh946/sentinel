"""Sentinel Command Line Interface."""

from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

from sentinel.benchmark.plotter import BenchmarkPlotter
from sentinel.benchmark.runner import BenchmarkRunner
from sentinel.config import SentinelConfig
from sentinel.fixer.patcher import PatchManager
from sentinel.jury.schema import Finding, JuryConsensus, Severity
from sentinel.safety.audit import AuditLogger
from sentinel.safety.scope import ScopeViolationError
from sentinel.scanner.code_scanner import CodeScanner
from sentinel.scanner.diff_scanner import DiffScanner
from sentinel.scanner.probe import SafeProbeScanner

# ANSI Colors
BOLD = "\033[1m"
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
GRAY = "\033[90m"


def print_banner() -> None:
    banner = f"""{CYAN}{BOLD}
   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝{RESET}
   {GRAY}Open-Weight Multi-Model Jury for Code & Dependency Supply-Chain Defense{RESET}
"""
    print(banner)


def format_severity(sev: Severity) -> str:
    if sev == Severity.CRITICAL:
        return f"{RED}{BOLD}[CRITICAL]{RESET}"
    elif sev == Severity.HIGH:
        return f"{RED}[HIGH]{RESET}"
    elif sev == Severity.MEDIUM:
        return f"{YELLOW}[MEDIUM]{RESET}"
    elif sev == Severity.LOW:
        return f"{BLUE}[LOW]{RESET}"
    return f"{GRAY}[INFO]{RESET}"


def display_consensus(consensus: JuryConsensus) -> None:
    score = consensus.overall_risk_score
    sev = consensus.overall_risk_level
    score_color = RED if score >= 40 else (YELLOW if score >= 20 else GREEN)

    print(f"\n{BOLD}══════════════════════════ SENTINEL AUDIT REPORT ══════════════════════════{RESET}")
    print(f" Target:        {CYAN}{consensus.target}{RESET}")
    print(f" Risk Score:    {score_color}{BOLD}{score:.1f} / 100 ({sev.value}){RESET}")
    print(f" Findings:      {len(consensus.findings)} confirmed, {len(consensus.discarded_findings)} discarded (no line evidence)")
    print(f" Disagreements: {len(consensus.disagreements)} reconciled by Judge")
    print(f"{BOLD}────────────────────────────────────────────────────────────────────────────{RESET}")

    if not consensus.findings:
        print(f"\n {GREEN}{BOLD}✓ PASS:{RESET} No verified vulnerabilities or malicious dependency modifications found.\n")
        return

    print(f"\n{BOLD}VERIFIED FINDINGS:{RESET}")
    for idx, f in enumerate(consensus.findings, 1):
        print(f"\n  {BOLD}{idx}. {format_severity(f.severity)} {f.title}{RESET} ({CYAN}{f.category}{RESET})")
        print(f"     Location: {f.file}:{f.line_start}-{f.line_end}")
        print(f"     Evidence: {GRAY}\"{f.evidence_quote[:120]}\"{RESET}")
        print(f"     Details:  {f.explanation}")
        if f.suggested_patch:
            print(f"     Fix Diff:\n{GREEN}{f.suggested_patch}{RESET}")

    if consensus.disagreements:
        print(f"\n{BOLD}JURY DELIBERATION & DISAGREEMENTS:{RESET}")
        for d in consensus.disagreements:
            print(f"  • {d.category} at {d.file} ({d.line_range}):")
            print(f"    Reported by: {', '.join(d.reporting_jurors)}")
            print(f"    Dissenting:  {', '.join(d.dissenting_jurors)}")
            print(f"    Resolution:  {d.reconciliation_reason}")

    print(f"\n{BOLD}════════════════════════════════════════════════════════════════════════════{RESET}\n")


def cmd_scan(args: argparse.Namespace) -> int:
    config = SentinelConfig.load()
    scanner = CodeScanner(config)
    try:
        consensus = scanner.scan_path(args.path)
        display_consensus(consensus)

        if args.json:
            print(consensus.model_dump_json(indent=2))

        threshold = args.threshold if args.threshold is not None else config.risk_threshold_ci
        if consensus.overall_risk_score > threshold:
            print(f"{RED}{BOLD}✖ FAILED CI CHECK:{RESET} Risk score {consensus.overall_risk_score} exceeds threshold {threshold}.")
            return 1
        return 0
    except ScopeViolationError as sve:
        print(f"\n{RED}{BOLD}Scope Violation:{RESET} {sve}")
        return 2
    except Exception as e:
        print(f"\n{RED}Error during scan:{RESET} {e}")
        return 1


def cmd_diff(args: argparse.Namespace) -> int:
    config = SentinelConfig.load()
    scanner = DiffScanner(config)
    try:
        if args.new:
            consensus = scanner.scan_two_versions(args.old, args.new)
        else:
            p = Path(args.old)
            if p.exists() and p.is_file():
                content = p.read_text(encoding="utf-8", errors="replace")
                consensus = scanner.scan_diff_text(content, label=str(p))
            else:
                consensus = scanner.scan_diff_text(args.old, label="raw-diff")

        display_consensus(consensus)
        threshold = args.threshold if args.threshold is not None else config.risk_threshold_ci
        if consensus.overall_risk_score > threshold:
            print(f"{RED}{BOLD}✖ REJECTED UPDATE:{RESET} Risky supply-chain modifications detected (Score: {consensus.overall_risk_score}).")
            return 1
        return 0
    except Exception as e:
        print(f"\n{RED}Error during diff audit:{RESET} {e}")
        return 1


def cmd_bench(args: argparse.Namespace) -> int:
    print_banner()
    runner = BenchmarkRunner()
    results = runner.run()

    print(f"\n{BOLD}══════════════════════ BENCHMARK RESULTS SUMMARY ══════════════════════{RESET}")
    print(f"{'Model / System':<32} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'False Alarm':<12} {'Latency'}")
    print(f"────────────────────────────────────────────────────────────────────────────")
    for name, m in results["metrics"].items():
        is_jury = "Jury" in name
        prefix = f"{GREEN}{BOLD}" if is_jury else ""
        suffix = f"{RESET}" if is_jury else ""
        print(
            f"{prefix}{name:<32} {m['precision']*100:>7.1f}%   {m['recall']*100:>7.1f}%   {m['f1_score']*100:>7.1f}%   {m['false_positive_rate']*100:>9.1f}%   {m['avg_latency_ms']:>6.1f}ms{suffix}"
        )
    print(f"════════════════════════════════════════════════════════════════════════════\n")

    chart_path = BenchmarkPlotter.plot_results()
    print(f"{GREEN}✓ Benchmark complete! High-resolution chart saved to {CYAN}{chart_path}{RESET}\n")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    prober = SafeProbeScanner()
    try:
        consensus = prober.probe_url(args.target)
        display_consensus(consensus)
        return 0 if consensus.overall_risk_score < 40 else 1
    except ScopeViolationError as sve:
        print(f"\n{RED}{BOLD}Scope Violation:{RESET} {sve}")
        return 2
    except Exception as e:
        print(f"\n{RED}Error during probe:{RESET} {e}")
        return 1


def cmd_fix(args: argparse.Namespace) -> int:
    manager = PatchManager()
    finding = Finding(
        id=args.finding_id,
        file=args.file,
        line_start=1,
        line_end=1,
        category="MANUAL_FIX",
        severity=Severity.MEDIUM,
        title="Manual fix request",
        explanation="Fix requested via CLI",
        evidence_quote=args.evidence or "",
        suggested_patch=args.patch or "",
    )
    success, msg, rollback_id = manager.apply_patch(
        finding,
        force=args.approve,
        run_tests=not args.no_test,
        test_command=args.test_cmd,
    )
    if success:
        print(f"{GREEN}✓ {msg}{RESET}")
        return 0
    else:
        print(f"{YELLOW}Notice: {msg}{RESET}")
        return 1


def cmd_rollback(args: argparse.Namespace) -> int:
    manager = PatchManager()
    success, msg = manager.rollback(args.rollback_id)
    if success:
        print(f"{GREEN}✓ {msg}{RESET}")
        return 0
    else:
        print(f"{RED}✖ {msg}{RESET}")
        return 1


def cmd_audit(args: argparse.Namespace) -> int:
    logger = AuditLogger()
    valid, status_msg = logger.verify_integrity()
    entries = logger.read_entries()

    print(f"\n{BOLD}══════════════════════ APPEND-ONLY AUDIT CHAIN ══════════════════════{RESET}")
    print(f" Integrity Status: {GREEN if valid else RED}{BOLD}{status_msg}{RESET}")
    print(f" Total Logged Events: {len(entries)}")
    print(f"────────────────────────────────────────────────────────────────────────────")
    for e in entries[-10:]:
        print(f" [{GRAY}{e['timestamp']}{RESET}] {BOLD}{e['event_type']:<22}{RESET} Target: {CYAN}{e['target']:<20}{RESET} (Hash: {e['entry_hash'][:12]}...)")
    print(f"════════════════════════════════════════════════════════════════════════════\n")
    return 0 if valid else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel: Open-Weight Multi-Model Jury for Code & Dependency Defense",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan source code directory or file")
    p_scan.add_argument("path", help="Path to file or folder to audit")
    p_scan.add_argument("--threshold", type=int, default=None, help="Risk score threshold to fail CI (0-100)")
    p_scan.add_argument("--json", action="store_true", help="Output raw JSON consensus")

    # diff
    p_diff = subparsers.add_parser("diff", help="Audit dependency update diff or between two versions")
    p_diff.add_argument("old", help="Path to original file or unified diff patch")
    p_diff.add_argument("new", nargs="?", default=None, help="Path to updated file or package version")
    p_diff.add_argument("--threshold", type=int, default=None, help="Risk score threshold")

    # bench
    p_bench = subparsers.add_parser("bench", help="Run precision/recall benchmark single models vs. jury")

    # probe
    p_probe = subparsers.add_parser("probe", help="Run safe non-destructive staging probe")
    p_probe.add_argument("target", help="URL or hostname to probe (must be in sentinel.scope.yml)")

    # fix
    p_fix = subparsers.add_parser("fix", help="Review and apply patch for finding")
    p_fix.add_argument("finding_id", help="Finding identifier")
    p_fix.add_argument("--file", required=True, help="Target file")
    p_fix.add_argument("--patch", help="Unified diff patch text")
    p_fix.add_argument("--evidence", help="Evidence quote to replace")
    p_fix.add_argument("--approve", action="store_true", help="Approve manual patch")
    p_fix.add_argument("--no-test", action="store_true", help="Skip running tests")
    p_fix.add_argument("--test-cmd", default=".venv/bin/pytest tests/", help="Command to test patch")

    # rollback
    p_rb = subparsers.add_parser("rollback", help="Rollback applied patch")
    p_rb.add_argument("rollback_id", help="Rollback ID")

    # audit
    p_audit = subparsers.add_parser("audit", help="Verify and inspect append-only audit log")

    args = parser.parse_args()

    cmd_map = {
        "scan": cmd_scan,
        "diff": cmd_diff,
        "bench": cmd_bench,
        "probe": cmd_probe,
        "fix": cmd_fix,
        "rollback": cmd_rollback,
        "audit": cmd_audit,
    }

    exit_code = cmd_map[args.command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

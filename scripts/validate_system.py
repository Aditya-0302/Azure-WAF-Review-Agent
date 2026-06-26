#!/usr/bin/env python3
"""WAF Agent system validation entry point.

Runs three progressive validation layers and exits 1 if any CRITICAL or HIGH
check fails. MEDIUM / LOW failures and SKIPped checks do not affect the exit code
(they indicate optional services are not running).

Layers:
  1. startup_validation    — import resolution, domain models, enums, settings
  2. dependency_validation — DI container, repos, services, FastAPI app creation
  3. integration_validation— DB connectivity, schema, Service Bus, health endpoints,
                             full assessment workflow

Usage:
  python scripts/validate_system.py                    # all three layers
  python scripts/validate_system.py --skip-integration # layers 1+2 only
  python scripts/validate_system.py --only-startup     # layer 1 only
  python scripts/validate_system.py --json             # machine-readable output

Exit codes:
  0 — all CRITICAL + HIGH checks passed (MEDIUM/LOW may have failures/skips)
  1 — one or more CRITICAL or HIGH checks failed
  2 — validation script itself could not be loaded (import error)
"""
from __future__ import annotations

import argparse
import json as _json
import sys
import time
from pathlib import Path

# ── Path bootstrap — must happen before any waf_* import ──────────────────────
_ROOT = Path(__file__).resolve().parent.parent
for _pkg in [
    "src/shared",
    "src/api",
    "src/agents/preparation",
    "src/agents/extraction",
    "src/agents/reasoning",
    "src/agents/reporting",
]:
    _p = _ROOT / _pkg
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))


# ── ANSI color helpers (degrade gracefully when not a tty) ────────────────────

def _c(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def _green(t: str) -> str:    return _c(t, "32")
def _red(t: str) -> str:      return _c(t, "31")
def _yellow(t: str) -> str:   return _c(t, "33")
def _cyan(t: str) -> str:     return _c(t, "36")
def _bold(t: str) -> str:     return _c(t, "1")
def _dim(t: str) -> str:      return _c(t, "2")


# ── Result aggregation helpers ────────────────────────────────────────────────

def _count(results: list, *, passed: bool | None = None, skipped: bool | None = None,
           severity: str | None = None) -> int:
    total = 0
    for r in results:
        if passed is not None and r.passed != passed:
            continue
        if skipped is not None and r.skipped != skipped:
            continue
        if severity is not None and r.severity != severity:
            continue
        total += 1
    return total


def _critical_high_failures(results: list) -> list:
    return [r for r in results if r.is_failure and r.severity in ("CRITICAL", "HIGH")]


# ── Text report ───────────────────────────────────────────────────────────────

_SEV_COLORS = {
    "CRITICAL": _red,
    "HIGH":     _yellow,
    "MEDIUM":   _cyan,
    "LOW":      _dim,
}


def _print_layer_summary(results: list, layer_name: str, elapsed_s: float) -> None:
    passed  = sum(1 for r in results if r.passed)
    failed  = sum(1 for r in results if r.is_failure)
    skipped = sum(1 for r in results if r.skipped)
    total   = len(results)

    pad = 52
    print(f"\n  {_bold(layer_name)}")
    print(f"  {'─' * pad}")
    print(f"  {'Check':<44} {'Status':>6}")
    print(f"  {'─' * pad}")

    for r in results:
        if r.skipped:
            status_str = _yellow(" SKIP")
        elif r.passed:
            status_str = _green("  OK ")
        else:
            sev_color = _SEV_COLORS.get(r.severity, str)
            status_str = _red(f" FAIL")

        # Truncate long check names
        name = r.name if len(r.name) <= 44 else r.name[:41] + "..."
        sev_tag = _SEV_COLORS.get(r.severity, str)(f"[{r.severity[:4]}]")
        print(f"  {name:<44} {status_str}  {sev_tag}  {_dim(f'{r.duration_ms:.0f}ms')}")

        if r.is_failure and r.error:
            # Indent error details
            for line in r.error.splitlines()[:3]:
                print(f"    {_red('└─')} {line}")
        elif r.skipped and r.skip_reason:
            print(f"    {_yellow('└─')} {r.skip_reason}")

    print(f"  {'─' * pad}")
    print(
        f"  {total} checks: "
        f"{_green(str(passed))} passed, "
        f"{_red(str(failed)) if failed else str(failed)} failed, "
        f"{_yellow(str(skipped))} skipped  "
        f"{_dim(f'({elapsed_s:.2f}s)')}"
    )


def _print_final_summary(all_results: list, total_elapsed_s: float) -> None:
    total   = len(all_results)
    passed  = sum(1 for r in all_results if r.passed)
    failed  = sum(1 for r in all_results if r.is_failure)
    skipped = sum(1 for r in all_results if r.skipped)
    crit_fail = _critical_high_failures(all_results)

    print(f"\n{'━'*60}")
    print(f"  {_bold('SYSTEM VALIDATION SUMMARY')}")
    print(f"{'━'*60}")
    print(
        f"  Total {total} checks in {total_elapsed_s:.2f}s: "
        f"{_green(str(passed))} passed / "
        f"{_red(str(failed)) if failed else str(failed)} failed / "
        f"{_yellow(str(skipped))} skipped"
    )

    if crit_fail:
        print(f"\n  {_red(_bold('CRITICAL/HIGH FAILURES:'))}")
        for r in crit_fail:
            sev_color = _SEV_COLORS.get(r.severity, str)
            print(f"    {_red('✗')} [{sev_color(r.severity)}] {r.name}")
            if r.error:
                for line in r.error.splitlines()[:2]:
                    print(f"        {_dim(line)}")
        print(f"\n  {_red(_bold('RESULT: FAIL'))} — system has critical runtime issues")
    else:
        medium_failures = [r for r in all_results if r.is_failure and r.severity not in ("CRITICAL", "HIGH")]
        if medium_failures:
            print(f"\n  {_yellow('WARNINGS (MEDIUM/LOW):')} {len(medium_failures)} non-blocking issues")
            for r in medium_failures[:5]:
                print(f"    {_yellow('⚠')} {r.name}")
            if len(medium_failures) > 5:
                print(f"    ... and {len(medium_failures) - 5} more")

        if skipped:
            print(f"\n  {_yellow(f'{skipped} checks skipped')} (optional infrastructure not running)")
        print(f"\n  {_green(_bold('RESULT: PASS'))} — system is production-ready")

    print(f"{'━'*60}\n")


# ── JSON output ───────────────────────────────────────────────────────────────

def _print_json(all_results: list, layer_names: dict, total_elapsed_s: float) -> None:
    crit_fail = _critical_high_failures(all_results)
    output = {
        "result": "FAIL" if crit_fail else "PASS",
        "total_elapsed_s": round(total_elapsed_s, 3),
        "summary": {
            "total":   len(all_results),
            "passed":  sum(1 for r in all_results if r.passed),
            "failed":  sum(1 for r in all_results if r.is_failure),
            "skipped": sum(1 for r in all_results if r.skipped),
            "critical_high_failures": len(crit_fail),
        },
        "checks": [
            {
                "name":       r.name,
                "category":   r.category,
                "severity":   r.severity,
                "passed":     r.passed,
                "skipped":    r.skipped,
                "error":      r.error,
                "skip_reason": r.skip_reason,
                "duration_ms": round(r.duration_ms, 1),
            }
            for r in all_results
        ],
    }
    print(_json.dumps(output, indent=2))


# ── Main orchestrator ─────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="validate_system",
        description="WAF Agent system validation — verifies runtime correctness end-to-end.",
    )
    parser.add_argument(
        "--skip-integration", action="store_true",
        help="Skip integration validation (layers 1+2 only; no live infrastructure required)",
    )
    parser.add_argument(
        "--only-startup", action="store_true",
        help="Run only startup validation (import + static checks)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON (machine-readable; suppresses human-readable output)",
    )
    parser.add_argument(
        "--fail-fast", action="store_true",
        help="Stop at first CRITICAL/HIGH failure across layers",
    )
    args = parser.parse_args(argv)

    wall_start = time.monotonic()
    all_results: list = []
    layer_names: dict = {}

    # ── Layer 1: Startup ─────────────────────────────────────────────────────
    try:
        import startup_validation as sv
    except ImportError as exc:
        print(f"{_red('ERROR')} Failed to import startup_validation: {exc}", file=sys.stderr)
        return 2

    if not args.json:
        print(f"\n{_bold('WAF Agent System Validation')}")
        print(f"{'='*60}")
        print(f"  Root: {_ROOT}")
        print(f"  Layers: startup{'' if args.only_startup else ' + dependency' if args.skip_integration else ' + dependency + integration'}")
        print(f"{'='*60}")

    t0 = time.monotonic()
    try:
        startup_results = sv.run()
    except Exception as exc:
        print(f"{_red('ERROR')} startup_validation.run() crashed: {exc}", file=sys.stderr)
        return 2

    elapsed = time.monotonic() - t0
    layer_names["startup"] = "1 · Startup Validation (imports + static checks)"
    all_results.extend(startup_results)

    if not args.json:
        _print_layer_summary(startup_results, layer_names["startup"], elapsed)

    if args.fail_fast and _critical_high_failures(startup_results):
        if not args.json:
            print(f"\n{_red('--fail-fast: stopping after first layer failure')}")
        if args.json:
            _print_json(all_results, layer_names, time.monotonic() - wall_start)
        return 1

    if args.only_startup:
        total_elapsed = time.monotonic() - wall_start
        if args.json:
            _print_json(all_results, layer_names, total_elapsed)
        else:
            _print_final_summary(all_results, total_elapsed)
        return 1 if _critical_high_failures(all_results) else 0

    # ── Layer 2: Dependency ───────────────────────────────────────────────────
    try:
        import dependency_validation as dv
    except ImportError as exc:
        print(f"{_red('ERROR')} Failed to import dependency_validation: {exc}", file=sys.stderr)
        return 2

    t0 = time.monotonic()
    try:
        dep_results = dv.run()
    except Exception as exc:
        print(f"{_red('ERROR')} dependency_validation.run() crashed: {exc}", file=sys.stderr)
        return 2

    elapsed = time.monotonic() - t0
    layer_names["dependency"] = "2 · Dependency Validation (DI container, repos, services, FastAPI)"
    all_results.extend(dep_results)

    if not args.json:
        _print_layer_summary(dep_results, layer_names["dependency"], elapsed)

    if args.fail_fast and _critical_high_failures(dep_results):
        if not args.json:
            print(f"\n{_red('--fail-fast: stopping after second layer failure')}")
        if args.json:
            _print_json(all_results, layer_names, time.monotonic() - wall_start)
        return 1

    if args.skip_integration:
        total_elapsed = time.monotonic() - wall_start
        if args.json:
            _print_json(all_results, layer_names, total_elapsed)
        else:
            _print_final_summary(all_results, total_elapsed)
        return 1 if _critical_high_failures(all_results) else 0

    # ── Layer 3: Integration ──────────────────────────────────────────────────
    try:
        import integration_validation as iv
    except ImportError as exc:
        print(f"{_red('ERROR')} Failed to import integration_validation: {exc}", file=sys.stderr)
        return 2

    if not args.json:
        print(f"\n  {_dim('Detecting infrastructure availability...')}")

    t0 = time.monotonic()
    try:
        int_results = iv.run()
    except Exception as exc:
        print(f"{_red('ERROR')} integration_validation.run() crashed: {exc}", file=sys.stderr)
        return 2

    elapsed = time.monotonic() - t0
    layer_names["integration"] = "3 · Integration Validation (DB, Service Bus, API health, workflow)"
    all_results.extend(int_results)

    if not args.json:
        _print_layer_summary(int_results, layer_names["integration"], elapsed)

    # ── Final summary ─────────────────────────────────────────────────────────
    total_elapsed = time.monotonic() - wall_start

    if args.json:
        _print_json(all_results, layer_names, total_elapsed)
    else:
        _print_final_summary(all_results, total_elapsed)

    return 1 if _critical_high_failures(all_results) else 0


if __name__ == "__main__":
    sys.exit(main())

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Any, Dict, List

from agent import run_hazmat_audit


def _supports_color() -> bool:
    if os.getenv("NO_COLOR"):
        return False
    # On Windows, TERM is not set — use platform check instead.
    if sys.platform == "win32":
        # Enable VT100 ANSI processing in Windows 10+ terminals (cmd.exe, PowerShell).
        # os.system("") is a no-op that triggers the Win32 console to switch to VT mode.
        os.system("")
        return True
    return os.getenv("TERM") not in (None, "", "dumb")


def _color(text: str, code: str) -> str:
    if not _supports_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def _risk_badge(risk: str) -> str:
    r = (risk or "UNKNOWN").upper()
    if r == "LOW":
        return _color(f"[{r}]", "32")
    if r == "MEDIUM":
        return _color(f"[{r}]", "33")
    if r in {"HIGH", "CRITICAL"}:
        return _color(f"[{r}]", "31")
    return _color(f"[{r}]", "90")


def _verdict_badge(verdict: str) -> str:
    v = (verdict or "UNKNOWN").upper()
    if v == "SAFE":
        return _color(f"[{v}]", "32")
    if v == "SUSPICIOUS":
        return _color(f"[{v}]", "33")
    if v == "MALICIOUS":
        return _color(f"[{v}]", "31")
    return _color(f"[{v}]", "90")


def _section(title: str) -> None:
    print(_color(title, "1"))
    print(_color("-" * len(title), "90"))


def _truncate(text: str, max_len: int = 100) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _box(title: str, rows: List[str]) -> None:
    ansi_re = re.compile(r"\x1b\[[0-9;]*m")

    def _visible_len(s: str) -> int:
        return len(ansi_re.sub("", s))

    width = max(_visible_len(title), *(_visible_len(r) for r in rows)) if rows else _visible_len(title)
    top = f"+-{'-' * width}-+"
    print(_color(top, "90"))
    print(_color(f"| {title.ljust(width)} |", "1"))
    print(_color(top, "90"))
    for row in rows:
        pad = width - _visible_len(row)
        print(f"| {row}{' ' * max(pad, 0)} |")
    print(_color(top, "90"))


def _as_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(x) for x in value]
    return []


def _print_human(result: Dict[str, Any]) -> None:
    final_verdict = result.get("final_verdict") or {}
    telemetry = ((result.get("telemetry_response") or {}).get("telemetry") or {})
    classification = telemetry.get("classification") or {}
    install = telemetry.get("install") or {}
    network = telemetry.get("network") or {}
    fs = telemetry.get("filesystem") or {}
    proc = telemetry.get("processes") or {}
    llm_debug = result.get("llm_debug") or {}
    precheck = result.get("precheck") or {}

    verdict = str(final_verdict.get("verdict", "unknown")).upper()
    risk = str(final_verdict.get("risk_level", "unknown")).upper()
    reasoning_mode = str(final_verdict.get("reasoning_mode", "unknown"))
    summary = str(final_verdict.get("summary", "No summary available."))
    evidence = _as_list(final_verdict.get("evidence"))
    alerts = _as_list(telemetry.get("alerts"))

    print(_color("HAZMAT-MCP // DYNAMIC SUPPLY CHAIN AUDIT", "1"))
    print(_color("=========================================", "90"))

    package_display = result.get("package_source") or result.get("package_name")
    elapsed = install.get("elapsed_s")
    elapsed_display = f"{elapsed}s" if isinstance(elapsed, (int, float)) else "n/a"
    _box(
        "Run Context",
        [
            f"Package : {package_display}",
            f"Manager : {result.get('manager')}",
            f"Session : {result.get('session_id')}",
            f"Install : exit_code={install.get('exit_code')} elapsed={elapsed_display}",
        ],
    )
    print()

    _box(
        "Security Verdict",
        [
            f"Verdict : {_verdict_badge(verdict)}",
            f"Risk    : {_risk_badge(risk)}",
            f"Mode    : {reasoning_mode}",
            f"Score   : {classification.get('risk_score', 'n/a')}",
        ],
    )
    print()

    _section("Summary")
    print(summary)
    print()

    if precheck.get("suspected"):
        _section("Precheck")
        print(_color("Possible manager mismatch detected.", "33"))
        print(f"Reason: {precheck.get('reason')}")
        print()

    if evidence:
        _section("Evidence")
        for item in evidence:
            print(f"- {_truncate(item)}")
        print()

    _section("Telemetry Snapshot")
    telemetry_rows = [
        f"Outbound TCP added : {len(_as_list(network.get('tcp_added'))) + len(_as_list(network.get('tcp6_added')))}",
        f"Filesystem changed : {bool(fs.get('changed'))}",
        f"New processes      : {len(_as_list(proc.get('added')))}",
        f"Indicators         : {len(_as_list(classification.get('suspicious_indicators')))}",
    ]
    _box("Runtime Signals", telemetry_rows)
    print()

    # When analysis has already normalized expected npm install behavior to SAFE/LOW,
    # hide the generic outbound alert to avoid contradictory UX.
    if (
        verdict == "SAFE"
        and risk == "LOW"
        and str(result.get("manager", "")).lower() == "npm"
        and "expected npm install behavior" in summary.lower()
    ):
        alerts = [
            a
            for a in alerts
            if "suspicious outbound connection" not in a.lower()
        ]

    if alerts:
        _section("Top Telemetry Alerts")
        for item in alerts[:8]:
            print(f"- {_truncate(item)}")
        print()

    if llm_debug:
        _section("LLM Debug")
        print(f"attempted : {llm_debug.get('attempted')}")
        print(f"path      : {llm_debug.get('path')}")
        print(f"model     : {llm_debug.get('used_model')}")
        if llm_debug.get("error_type"):
            print(f"error     : {llm_debug.get('error_type')}: {llm_debug.get('error_message')}")
        print()

    if result.get("error"):
        _section("Agent Error")
        print(_color(str(result["error"]), "31"))


def _run_with_timeout(package_name: str, manager: str, timeout_seconds: int, package_source: str | None = None) -> Dict[str, Any]:
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(run_hazmat_audit, package_name, manager, package_source)
        try:
            return future.result(timeout=timeout_seconds)
        except FuturesTimeoutError:
            return {
                "package_name": package_name,
                "manager": manager,
                "error": f"Timed out after {timeout_seconds}s",
                "final_verdict": {
                    "verdict": "suspicious",
                    "risk_level": "medium",
                    "summary": f"Audit timed out after {timeout_seconds}s.",
                    "evidence": ["Execution exceeded timeout budget."],
                    "reasoning_mode": "timeout_guard",
                },
            }


def main() -> None:
    parser = argparse.ArgumentParser(description="Hazmat-MCP CLI wrapper for package audits")
    parser.add_argument("--package", help="Package name (PyPI/npm)")
    parser.add_argument("--package-source", help="Local package artifact path (e.g. .tgz)")
    parser.add_argument("--manager", choices=["pip", "npm"], default="pip", help="Package manager")
    parser.add_argument("--timeout", type=int, default=180, help="Overall agent timeout in seconds")
    parser.add_argument("--raw-json", action="store_true", help="Print full JSON result")
    args = parser.parse_args()

    if not args.package and not args.package_source:
        parser.error("Provide either --package or --package-source.")
    if args.package and args.package_source:
        parser.error("Use only one of --package or --package-source.")

    package_name = args.package or "local-artifact"
    result = _run_with_timeout(package_name, args.manager, args.timeout, args.package_source)

    if args.raw_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_human(result)


if __name__ == "__main__":
    main()

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Any, Dict, List, Optional

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


def _pad(text: str, width: int) -> str:
    s = str(text)
    if len(s) >= width:
        return s[: max(width - 3, 0)] + ("..." if width >= 3 else "")
    return s + (" " * (width - len(s)))


def _print_kv_row(key: str, value: str, *, key_width: int = 10) -> str:
    return f"{_pad(key, key_width)}: {value}"


def _table(headers: List[str], rows: List[List[str]], *, max_width: int = 120) -> None:
    """
    Print a simple ASCII table with sane widths.
    (We keep it dependency-free and readable on Windows terminals.)
    """
    if not headers:
        return
    cols = len(headers)
    safe_rows = [r[:cols] + [""] * max(0, cols - len(r)) for r in rows]

    # compute natural widths
    widths = [len(h) for h in headers]
    for r in safe_rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))

    # clamp to max width
    total = sum(widths) + (3 * (cols - 1))
    if total > max_width:
        # reduce the last column first (usually "artifact/path")
        overflow = total - max_width
        last = cols - 1
        widths[last] = max(20, widths[last] - overflow)

    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    print(_color(sep, "90"))
    print("| " + " | ".join(_color(_pad(h, widths[i]), "1") for i, h in enumerate(headers)) + " |")
    print(_color(sep, "90"))
    for r in safe_rows:
        print("| " + " | ".join(_pad(str(r[i]), widths[i]) for i in range(cols)) + " |")
    print(_color(sep, "90"))


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

    print(_color("HAZMAT-MCP", "1") + _color("  dynamic supply-chain audit", "90"))
    print(_color("-" * 56, "90"))

    package_display = result.get("package_source") or result.get("package_name")
    elapsed = install.get("elapsed_s")
    elapsed_display = f"{elapsed}s" if isinstance(elapsed, (int, float)) else "n/a"
    _box(
        "Run Context",
        [
            _print_kv_row("Package", str(package_display)),
            _print_kv_row("Manager", str(result.get("manager"))),
            _print_kv_row("Session", str(result.get("session_id"))),
            _print_kv_row("Install", f"exit_code={install.get('exit_code')}  elapsed={elapsed_display}"),
        ],
    )
    print()

    _box(
        "Security Verdict",
        [
            _print_kv_row("Verdict", _verdict_badge(verdict)),
            _print_kv_row("Risk", _risk_badge(risk)),
            _print_kv_row("Mode", reasoning_mode),
            _print_kv_row("Score", str(classification.get("risk_score", "n/a"))),
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


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _print_batch_human(batch: Dict[str, Any]) -> None:
    print(_color("HAZMAT-MCP", "1") + _color("  batch artifact audit", "90"))
    print(_color("-" * 56, "90"))

    summary = batch.get("summary") or {}
    results = batch.get("results") or []
    manager = str(batch.get("manager") or "unknown")

    _box(
        "Batch Summary",
        [
            _print_kv_row("Manager", manager),
            _print_kv_row("Total", str(_as_int(summary.get("count"), len(results)))),
            _print_kv_row("OK", str(_as_int(summary.get("ok_count")))),
            _print_kv_row("Errors", str(_as_int(summary.get("error_count")))),
            _print_kv_row(
                "Risk",
                "low="
                + str(_as_int((summary.get("risk_counts") or {}).get("low")))
                + "  medium="
                + str(_as_int((summary.get("risk_counts") or {}).get("medium")))
                + "  high="
                + str(_as_int((summary.get("risk_counts") or {}).get("high")))
                + "  critical="
                + str(_as_int((summary.get("risk_counts") or {}).get("critical"))),
            ),
        ],
    )
    print()

    _section("Results (sorted by risk)")
    table_rows: List[List[str]] = []
    for r in results:
        fv = r.get("final_verdict") or {}
        verdict = str(fv.get("verdict", "unknown")).upper()
        risk = str(fv.get("risk_level", "unknown")).upper()
        artifact = (
            (r.get("install") or {}).get("package_source")
            or r.get("package_source")
            or r.get("package_name")
            or "unknown"
        )
        exit_code = (r.get("install") or {}).get("exit_code")
        exit_display = str(exit_code) if exit_code is not None else "n/a"
        table_rows.append(
            [
                _risk_badge(risk),
                _verdict_badge(verdict),
                exit_display,
                _truncate(str(artifact), 140),
            ]
        )
    _table(["RISK", "VERDICT", "EXIT", "ARTIFACT"], table_rows, max_width=140)
    print()

    # Detailed per-artifact sections (match single-run CLI: verdict, summary, evidence, telemetry)
    for idx, r in enumerate(results, start=1):
        fv = r.get("final_verdict") or {}
        telemetry = r.get("telemetry") or {}
        classification = telemetry.get("classification") or {}
        install = r.get("install") or telemetry.get("install") or {}
        network = telemetry.get("network") or {}
        fs = telemetry.get("filesystem") or {}
        proc = telemetry.get("processes") or {}

        artifact = (
            install.get("package_source")
            or r.get("package_source")
            or r.get("package_name")
            or "unknown"
        )

        verdict = str(fv.get("verdict", "unknown")).upper()
        risk = str(fv.get("risk_level", "unknown")).upper()
        reasoning_mode = str(fv.get("reasoning_mode", "unknown"))
        summary_text = str(fv.get("summary", telemetry.get("summary", "No summary available.")))
        evidence = _as_list(fv.get("evidence"))
        alerts = _as_list(telemetry.get("alerts"))

        print(_color("-" * 56, "90"))
        print(_color(f"Artifact {idx}/{len(results)}", "1") + _color(f"  {artifact}", "90"))
        print(_color("-" * 56, "90"))

        _box(
            "Run Context",
            [
                _print_kv_row("Artifact", str(artifact)),
                _print_kv_row("Manager", str(r.get("manager", manager))),
                _print_kv_row("Session", str(r.get("session_id", "n/a"))),
                _print_kv_row("Install", f"exit_code={install.get('exit_code', 'n/a')}"),
            ],
        )
        print()

        _box(
            "Security Verdict",
            [
                _print_kv_row("Verdict", _verdict_badge(verdict)),
                _print_kv_row("Risk", _risk_badge(risk)),
                _print_kv_row("Mode", reasoning_mode),
                _print_kv_row("Score", str(classification.get("risk_score", "n/a"))),
            ],
        )
        print()

        _section("Summary")
        print(summary_text)
        print()

        if evidence:
            _section("Evidence")
            for item in evidence[:8]:
                print(f"- {_truncate(item)}")
            print()

        _section("Telemetry Snapshot")
        telemetry_rows = [
            f"Outbound TCP added : {len(_as_list(network.get('tcp_added'))) + len(_as_list(network.get('tcp6_added')))}",
            f"Filesystem changed : {bool(fs.get('changed'))}",
            f"Processes captured : {len(_as_list(proc.get('current_head')))}",
            f"Indicators         : {len(_as_list(classification.get('suspicious_indicators')))}",
        ]
        _box("Runtime Signals", telemetry_rows)
        print()

        # Same UX guard as single mode for normalized npm noise.
        if (
            verdict == "SAFE"
            and risk == "LOW"
            and str(r.get("manager", manager)).lower() == "npm"
            and "expected npm install behavior" in str(summary_text).lower()
        ):
            alerts = [a for a in alerts if "suspicious outbound connection" not in a.lower()]

        if alerts:
            _section("Top Telemetry Alerts")
            for item in alerts[:8]:
                print(f"- {_truncate(item)}")
            print()


def _run_audit_many_with_timeout(
    package_sources: List[str],
    *,
    manager: str,
    timeout_seconds: int,
    max_concurrency: int,
    base_image: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Calls the MCP tool `audit_many` via stdio transport, wrapped in a hard timeout.
    """
    import asyncio

    async def _call() -> Dict[str, Any]:
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        server_params = StdioServerParameters(
            command=sys.executable,
            args=["hazmat_server.py"],
            env=os.environ.copy(),
        )
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                resp = await session.call_tool(
                    "audit_many",
                    arguments={
                        "manager": manager,
                        "package_sources": package_sources,
                        "max_concurrency": max_concurrency,
                        "timeout_s": timeout_seconds,
                        "base_image": base_image,
                    },
                )
                text = resp.content[0].text if resp.content else ""
                return json.loads(text) if text else {"ok": False, "error": "empty_mcp_response"}

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(asyncio.run, _call())
        try:
            return future.result(timeout=timeout_seconds + 30)
        except FuturesTimeoutError:
            return {
                "ok": False,
                "action": "audit_many",
                "error": f"Timed out after {timeout_seconds}s",
                "summary": {
                    "count": len(package_sources),
                    "ok_count": 0,
                    "error_count": len(package_sources),
                    "risk_counts": {"low": 0, "medium": 0, "high": 0, "critical": 0},
                },
                "results": [],
            }


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
    parser.add_argument(
        "--package-sources",
        nargs="+",
        help="Batch mode: multiple local artifact paths (e.g. a.tgz b.tgz c.tgz). Uses MCP tool audit_many.",
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=4,
        help="Batch mode: max containers to run in parallel (audit_many).",
    )
    parser.add_argument("--base-image", default=None, help="Batch mode: override base image for containers.")
    parser.add_argument("--manager", choices=["pip", "npm"], default="pip", help="Package manager")
    parser.add_argument("--timeout", type=int, default=180, help="Overall agent timeout in seconds")
    parser.add_argument("--raw-json", action="store_true", help="Print full JSON result")
    args = parser.parse_args()

    # Batch mode: MCP audit_many
    if args.package_sources:
        batch = _run_audit_many_with_timeout(
            package_sources=[str(x) for x in args.package_sources],
            manager=args.manager,
            timeout_seconds=args.timeout,
            max_concurrency=args.max_concurrency,
            base_image=args.base_image,
        )
        if args.raw_json:
            print(json.dumps(batch, indent=2, sort_keys=True))
        else:
            _print_batch_human(batch)
        return

    # Single mode: agent.py orchestration
    if not args.package and not args.package_source:
        parser.error("Provide --package, --package-source, or --package-sources.")
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
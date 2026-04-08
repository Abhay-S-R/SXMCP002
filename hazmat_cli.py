import argparse
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Any, Dict, List

from agent import run_hazmat_audit


def _supports_color() -> bool:
    if os.getenv("NO_COLOR"):
        return False
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


def _run_with_timeout(
    package_name: str,
    manager: str,
    timeout_seconds: int,
    package_source: str | None = None,
    show_progress: bool = True,
) -> Dict[str, Any]:
    spinner_frames = ["|", "/", "-", "\\"]
    phase_order = [
        "Creating Docker sandbox",
        "Installing package in sandbox",
        "Collecting runtime telemetry",
        "Feeding telemetry to analyzer",
        "Destroying sandbox",
    ]
    phase_index = {name: idx + 1 for idx, name in enumerate(phase_order)}
    progress = {"message": "Starting Hazmat agent", "phase_started_at": time.time(), "phase_num": 0}
    lock = threading.Lock()

    def _set_progress(msg: str) -> None:
        with lock:
            current = progress.get("message")
            if current != msg:
                progress["phase_started_at"] = time.time()
            progress["message"] = msg
            progress["phase_num"] = phase_index.get(msg, 0)

    def _draw_spinner(frame_idx: int, run_started_at: float) -> None:
        if not _supports_color():
            return
        with lock:
            msg = progress["message"]
            phase_started_at = progress["phase_started_at"]
            phase_num = progress["phase_num"]
        phase_elapsed = time.time() - phase_started_at
        total_elapsed = time.time() - run_started_at
        phase_prefix = f"[{phase_num}/{len(phase_order)}] " if phase_num else ""
        line = (
            f"\r{_color(spinner_frames[frame_idx % len(spinner_frames)], '36')} "
            f"{phase_prefix}{msg}... "
            f"{_color(f'(phase {phase_elapsed:0.1f}s | total {total_elapsed:0.1f}s)', '90')}"
        )
        sys.stdout.write(line)
        sys.stdout.flush()

    spinner_enabled = show_progress and sys.stdout.isatty()
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(run_hazmat_audit, package_name, manager, package_source, _set_progress)
        start = time.time()
        frame = 0
        timed_out = False
        result: Dict[str, Any] | None = None
        while True:
            elapsed = time.time() - start
            remaining = max(0.0, timeout_seconds - elapsed)
            if spinner_enabled:
                _draw_spinner(frame, start)
                frame += 1
            try:
                result = future.result(timeout=min(0.12, remaining))
                break
            except FuturesTimeoutError:
                if elapsed >= timeout_seconds:
                    timed_out = True
                    break
                continue

        if spinner_enabled:
            with lock:
                done_msg = progress["message"] if not timed_out else "Timed out"
                phase_num = progress["phase_num"]
                phase_started_at = progress["phase_started_at"]
            phase_elapsed = time.time() - phase_started_at
            total_elapsed = time.time() - start
            phase_prefix = f"[{phase_num}/{len(phase_order)}] " if phase_num else ""
            sys.stdout.write(
                f"\r{_color('✓', '32') if not timed_out else _color('✗', '31')} "
                f"{phase_prefix}{done_msg} "
                f"{_color(f'(phase {phase_elapsed:0.1f}s | total {total_elapsed:0.1f}s)', '90')}{' ' * 12}\n"
            )
            sys.stdout.flush()

        if timed_out:
            future.cancel()
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
        return result or {
            "package_name": package_name,
            "manager": manager,
            "error": "Unknown execution failure.",
        }


def _load_batch_specs(batch_file: str, default_manager: str) -> List[Dict[str, str]]:
    specs: List[Dict[str, str]] = []
    with open(batch_file, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            target = parts[0]
            manager = parts[1].lower() if len(parts) > 1 and parts[1] else default_manager
            if manager not in {"pip", "npm"}:
                manager = default_manager
            if target.endswith(".tgz"):
                specs.append({"package_name": "local-artifact", "package_source": target, "manager": manager})
            else:
                specs.append({"package_name": target, "package_source": "", "manager": manager})
    return specs


def _print_batch_summary(results: List[Dict[str, Any]]) -> None:
    _section("Batch Summary")
    rows: List[str] = []
    for item in results:
        verdict = ((item.get("final_verdict") or {}).get("verdict") or "unknown").upper()
        risk = ((item.get("final_verdict") or {}).get("risk_level") or "unknown").upper()
        target = item.get("package_source") or item.get("package_name")
        rows.append(f"{target} | {item.get('manager')} | {verdict}/{risk}")
    _box("Results", rows or ["No batch results."])
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Hazmat-MCP CLI wrapper for package audits")
    parser.add_argument("--package", help="Package name (PyPI/npm)")
    parser.add_argument("--package-source", help="Local package artifact path (e.g. .tgz)")
    parser.add_argument("--batch-file", help="File with targets to scan (format: target[,manager])")
    parser.add_argument("--parallel", type=int, default=1, help="Parallel workers for --batch-file mode")
    parser.add_argument("--manager", choices=["pip", "npm"], default="pip", help="Package manager")
    parser.add_argument("--timeout", type=int, default=180, help="Overall agent timeout in seconds")
    parser.add_argument("--raw-json", action="store_true", help="Print full JSON result")
    args = parser.parse_args()

    if args.batch_file:
        if args.package or args.package_source:
            parser.error("Use --batch-file by itself (do not combine with --package/--package-source).")
        specs = _load_batch_specs(args.batch_file, args.manager)
        if not specs:
            parser.error("Batch file is empty or has no valid targets.")
        workers = max(1, min(args.parallel, 8))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(
                    _run_with_timeout,
                    spec["package_name"],
                    spec["manager"],
                    args.timeout,
                    spec["package_source"] or None,
                    False,
                )
                for spec in specs
            ]
            results = [f.result() for f in futures]
        if args.raw_json:
            print(json.dumps({"mode": "batch", "results": results}, indent=2, sort_keys=True))
        else:
            _print_batch_summary(results)
    else:
        if not args.package and not args.package_source:
            parser.error("Provide either --package or --package-source.")
        if args.package and args.package_source:
            parser.error("Use only one of --package or --package-source.")

        package_name = args.package or "local-artifact"
        result = _run_with_timeout(
            package_name,
            args.manager,
            args.timeout,
            args.package_source,
            show_progress=not args.raw_json,
        )

        if args.raw_json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            _print_human(result)


if __name__ == "__main__":
    main()

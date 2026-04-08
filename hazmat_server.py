import io
import json
import logging
import os
import tarfile
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

from sandbox_core import (
    Baseline,
    docker_client,
    _exec,
    _snapshot_baseline,
    _parse_proc_net_tcp,
    _diff_added
)

# Initialize the MCP Server
mcp = FastMCP("Hazmat-Security-Scanner")

# Keep stdio output clean for TUI clients.
# FastMCP transport emits request-level INFO logs (CallToolRequest/ListToolsRequest);
# raise noisy MCP loggers to WARNING so only actionable issues surface.
for _logger_name in ("mcp", "mcp.server", "mcp.server.lowlevel"):
    logging.getLogger(_logger_name).setLevel(logging.WARNING)

EXPECTED_NPM_PATH_MARKERS = (
    "/root/.npm/",
    "/usr/local/lib/node_modules/",
    "/usr/local/bin/",
    "_update-notifier-last-checked",
)
EXPECTED_PIP_PATH_MARKERS = (
    "/root/.cache/pip/",
    "/usr/local/lib/python",
    "/usr/local/bin/",
    ".dist-info",
)
SUSPICIOUS_CREDENTIAL_PATH_MARKERS = (
    "/.aws/",
    "/.ssh/",
    "/.gnupg/",
    "/.kube/",
    "/.npmrc",
    "/.pypirc",
    "/id_rsa",
    "/id_ed25519",
    "/credentials",
    "/passwd",
)
SUSPICIOUS_INSTALL_ARTIFACT_KEYWORDS = ("marker", "beacon", "token", "secret", "keydump")

# Multi-session sandbox state: keyed by session_id.
_SANDBOX_LOCK = threading.RLock()
_ACTIVE_SANDBOXES: Dict[str, Dict[str, Any]] = {}


def _first_session_id() -> Optional[str]:
    return next(iter(_ACTIVE_SANDBOXES.keys()), None)


def _resolve_session_id(explicit_session_id: Optional[str]) -> Optional[str]:
    if explicit_session_id:
        return explicit_session_id
    return _first_session_id()


def _get_session_state(session_id: Optional[str]) -> tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
    resolved = _resolve_session_id(session_id)
    if not resolved:
        return None, None, "No active sandbox. Call spin_up_sandbox first."
    state = _ACTIVE_SANDBOXES.get(resolved)
    if not state:
        return resolved, None, f"Unknown session_id: {resolved}"
    return resolved, state, None


def _resp(ok: bool, action: str, **payload: Any) -> str:
    body: Dict[str, Any] = {"ok": ok, "action": action, **payload}
    # Keep compatibility for clients expecting "status" too.
    body["status"] = "ok" if ok else "error"
    return json.dumps(body, indent=2, sort_keys=True)


def _stage_file_in_container(container: Any, host_file: Path, container_dir: str = "/tmp/hazmat-artifacts") -> str:
    """
    Copy a local file into the running container and return its container path.
    """
    if not host_file.is_file():
        raise FileNotFoundError(f"Local file not found: {host_file}")

    file_name = host_file.name
    container_path = f"{container_dir.rstrip('/')}/{file_name}"
    _exec(container, ["mkdir", "-p", container_dir], timeout_s=30)

    archive_stream = io.BytesIO()
    with tarfile.open(fileobj=archive_stream, mode="w") as tar:
        with host_file.open("rb") as src:
            payload = src.read()
        info = tarfile.TarInfo(name=file_name)
        info.size = len(payload)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(payload))
    archive_stream.seek(0)

    ok = container.put_archive(container_dir, archive_stream.getvalue())
    if not ok:
        raise RuntimeError("Failed to copy package artifact to container.")
    return container_path


def _extract_snapshot_paths(snapshot: str) -> List[str]:
    paths: List[str] = []
    for line in snapshot.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("## "):
            continue
        parts = stripped.split(" ", 2)
        if len(parts) == 3 and parts[2].startswith("/"):
            paths.append(parts[2])
    return paths


def _contains_any_marker(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


@mcp.tool()
def spin_up_sandbox(
    manager: str = "pip",
    session_id: Optional[str] = None,
    base_image: Optional[str] = None,
) -> str:
    """Spin up an ephemeral Docker container for safe malware analysis."""
    try:
        manager = (manager or "pip").lower().strip()
        if manager not in {"pip", "npm"}:
            return _resp(False, "spin_up_sandbox", error="invalid_manager", message="Use 'pip' or 'npm'.")

        if base_image is None:
            base_image = "node:20-slim" if manager == "npm" else "python:3.11-slim"

        resolved_session_id = (session_id or str(uuid.uuid4())).strip()
        if not resolved_session_id:
            return _resp(False, "spin_up_sandbox", error="invalid_session_id", message="session_id cannot be empty.")

        with _SANDBOX_LOCK:
            if resolved_session_id in _ACTIVE_SANDBOXES:
                existing = _ACTIVE_SANDBOXES[resolved_session_id]
                return _resp(
                    False,
                    "spin_up_sandbox",
                    error="session_already_active",
                    message="Sandbox already active for this session_id.",
                    session_id=resolved_session_id,
                    container_id=existing.get("id"),
                )

        container = docker_client.containers.run(
            base_image,
            command=["sh", "-lc", "tail -f /dev/null"],  # Keep the container alive
            detach=True,
            remove=False, # We will remove it manually
            network_mode="bridge", # Give it a network stack we can monitor
            mem_limit="512m", # Limit resources
            security_opt=["no-new-privileges:true"] # Basic hardening
        )
        with _SANDBOX_LOCK:
            _ACTIVE_SANDBOXES[resolved_session_id] = {
                "id": container.id,
                "manager": manager,
                "session_id": resolved_session_id,
                "baseline": None,
                "install": None,
            }
        return _resp(
            True,
            "spin_up_sandbox",
            session_id=resolved_session_id,
            manager=manager,
            base_image=base_image,
            container_id=container.id,
            message="Sandbox ready",
        )
    except Exception as e:
        return _resp(False, "spin_up_sandbox", error="spin_up_failed", message=f"Failed to create sandbox: {str(e)}")

@mcp.tool()
def execute_install(
    session_id: Optional[str] = None,
    package_name: Optional[str] = None,
    manager: Optional[str] = None,
    package_source: Optional[str] = None,
) -> str:
    """Install a package inside the sandbox and capture the terminal output."""
    resolved_session_id, session_state, session_err = _get_session_state(session_id)
    if session_err:
        return _resp(False, "execute_install", error="no_active_sandbox", message=session_err)
    assert session_state is not None
    container = docker_client.containers.get(session_state["id"])

    chosen_manager = (manager or session_state.get("manager") or "pip").lower().strip()
    if chosen_manager not in {"pip", "npm"}:
        return _resp(False, "execute_install", error="invalid_manager", message="Use 'pip' or 'npm'.")

    pkg = (package_name or "").strip()
    source = (package_source or "").strip()
    if not pkg and not source:
        return _resp(
            False,
            "execute_install",
            error="invalid_install_target",
            message="Provide package_name or package_source.",
        )

    try:
        install_target = pkg
        source_mode = "package_name"
        staged_path = None
        if source:
            resolved_source = Path(source)
            if not resolved_source.is_absolute():
                resolved_source = (Path.cwd() / resolved_source).resolve()
            if resolved_source.suffix.lower() != ".tgz":
                return _resp(
                    False,
                    "execute_install",
                    error="invalid_package_source",
                    message="package_source must point to a .tgz file.",
                )
            staged_path = _stage_file_in_container(container, resolved_source)
            install_target = staged_path
            source_mode = "local_tgz"

        # Determine the install command (argv list => avoids shell injection)
        if chosen_manager == "npm":
            install_cmd: List[str] = ["npm", "install", "-g", install_target]
        else:
            install_cmd = ["pip", "install", install_target, "--no-cache-dir"]

        # Capture baseline BEFORE install so telemetry can be a diff.
        with _SANDBOX_LOCK:
            if session_state.get("baseline") is None:
                session_state["baseline"] = _snapshot_baseline(container)

        exit_code, output = _exec(container, install_cmd, timeout_s=300)
        out_text = output.decode("utf-8", errors="replace")
        if len(out_text) > 4000:
            out_text = out_text[:4000] + "\n…(truncated)…"
        session_state["install"] = {
            "package_name": pkg or None,
            "package_source": source or None,
            "source_mode": source_mode,
            "install_target": install_target,
            "staged_container_path": staged_path,
            "manager": chosen_manager,
            "exit_code": exit_code,
            "output_preview": out_text,
        }
        return _resp(
            True,
            "execute_install",
            session_id=resolved_session_id,
            install=session_state["install"],
            package=pkg or None,
            package_source=source or None,
            manager=chosen_manager,
            exit_code=exit_code,
            output=out_text,
            message="Install finished",
        )
    except Exception as e:
        return _resp(
            False,
            "execute_install",
            error="install_failed",
            session_id=resolved_session_id,
            message=f"Installation failed: {str(e)}",
        )

@mcp.tool()
def get_telemetry(session_id: Optional[str] = None) -> str:
    """
    Analyzes the container's behavior: checks network connections and file system changes.
    This is the most critical function for detecting malware.
    """
    resolved_session_id, session_state, session_err = _get_session_state(session_id)
    if session_err:
        return _resp(
            False,
            "get_telemetry",
            error="no_active_sandbox",
            telemetry={
                "session_id": resolved_session_id,
                "install": None,
                "network": {"verdict": "unknown", "tcp_added": [], "tcp6_added": []},
                "filesystem": {"changed": False, "before_tail": [], "after_tail": []},
                "processes": {"current_head": []},
                "risk_level": "unknown",
                "alerts": [],
                "summary": "No active sandbox.",
                "notes": [],
            },
        )

    assert session_state is not None
    container = docker_client.containers.get(session_state["id"])
    baseline: Optional[Baseline] = session_state.get("baseline")
    if baseline is None:
        baseline = _snapshot_baseline(container)
        session_state["baseline"] = baseline

    after = _snapshot_baseline(container)
    
    alerts: List[str] = []
    suspicious_indicators: List[str] = []
    expected_activity: List[str] = []
    
    # 1) Network diff via /proc/net/tcp*
    before_tcp = _parse_proc_net_tcp(baseline.proc_net_tcp)
    after_tcp = _parse_proc_net_tcp(after.proc_net_tcp)
    before_tcp6 = _parse_proc_net_tcp(baseline.proc_net_tcp6)
    after_tcp6 = _parse_proc_net_tcp(after.proc_net_tcp6)

    tcp_added = _diff_added(before_tcp, after_tcp)
    tcp6_added = _diff_added(before_tcp6, after_tcp6)
    network_verdict = "clean"
    all_added_tcp = tcp_added + tcp6_added
    web_port_outbound = [c for c in all_added_tcp if (c or {}).get("remote_port") in {80, 443}]
    unusual_outbound = [c for c in all_added_tcp if (c or {}).get("remote_port") not in {80, 443}]
    if all_added_tcp:
        # IMPORTANT: 80/443 traffic can still be exfiltration over HTTP(S).
        # Treat any new outbound as security-relevant; keep details for higher-level reasoning.
        network_verdict = "suspicious"
        alerts.append("Suspicious Outbound Connection: New outbound TCP connections observed after install phase.")
        suspicious_indicators.append(
            "Outbound TCP destinations observed: "
            + ", ".join(str((c or {}).get("remote_port")) for c in all_added_tcp[:8])
        )
        if unusual_outbound:
            suspicious_indicators.append(
                "Outbound TCP includes uncommon destination ports: "
                + ", ".join(str((c or {}).get("remote_port")) for c in unusual_outbound[:5])
            )
        elif web_port_outbound:
            expected_activity.append(
                "Outbound traffic uses web ports (80/443); verify destination context because HTTPS can still carry exfiltration."
            )

    # 2) Filesystem diff
    fs_changed = baseline.fs_snapshot != after.fs_snapshot
    before_paths = set(_extract_snapshot_paths(baseline.fs_snapshot))
    after_paths = set(_extract_snapshot_paths(after.fs_snapshot))
    added_paths = sorted(after_paths - before_paths)
    added_blob = "\n".join(added_paths)
    manager = (session_state.get("manager") or "").lower()
    expected_markers = EXPECTED_NPM_PATH_MARKERS if manager == "npm" else EXPECTED_PIP_PATH_MARKERS
    fs_has_credential_markers = _contains_any_marker(added_blob, SUSPICIOUS_CREDENTIAL_PATH_MARKERS)
    fs_has_expected_markers = _contains_any_marker(added_blob, expected_markers)
    install_meta = session_state.get("install") or {}
    source_mode = (install_meta.get("source_mode") or "").lower()
    suspicious_install_artifacts = [
        p
        for p in added_paths
        if ("/tmp/" in p or "/var/tmp/" in p)
        and any(k in p.lower() for k in SUSPICIOUS_INSTALL_ARTIFACT_KEYWORDS)
    ]
    if fs_changed:
        if fs_has_credential_markers:
            alerts.append("Credential Path Access Detected: New file activity touched likely credential locations.")
            suspicious_indicators.append("Filesystem diff includes credential-like paths (AWS/SSH/kube/npmrc/etc).")
        elif suspicious_install_artifacts and source_mode == "local_tgz":
            alerts.append("Install Script Artifact Detected: New marker/beacon-like files were created in temp directories.")
            suspicious_indicators.append(
                "Install created suspicious temp artifacts: "
                + ", ".join(suspicious_install_artifacts[:5])
            )
        elif fs_has_expected_markers:
            expected_activity.append("Filesystem activity aligns with expected package cache/install paths.")
        else:
            alerts.append("File Access/Creation Detected: Package modified files outside common install/cache locations.")
    
    # We won't trigger an automatic flag for process running (it could just be pip/npm finishing up),
    # but we can provide it for context.
    running_procs = after.proc_snapshot.splitlines()[:60]

    # Hackathon-grade scoring
    install_exit = (install_meta or {}).get("exit_code")
    if install_exit not in (None, 0):
        alerts.append(f"Install command returned non-zero exit code ({install_exit}).")

    if install_exit not in (None, 0):
        suspicious_indicators.append(f"Install command failed with exit code {install_exit}.")

    if all_added_tcp and fs_has_credential_markers:
        risk_level = "critical"
    elif unusual_outbound and fs_changed:
        risk_level = "critical"
    elif suspicious_install_artifacts and all_added_tcp:
        risk_level = "high"
    elif unusual_outbound:
        risk_level = "high"
    elif all_added_tcp:
        risk_level = "medium"
    elif fs_has_credential_markers:
        risk_level = "high"
    elif suspicious_install_artifacts:
        risk_level = "medium"
    elif fs_changed and not fs_has_expected_markers:
        risk_level = "medium"
    elif install_exit not in (None, 0):
        risk_level = "medium"
    else:
        risk_level = "low"
    summary = "No suspicious activity detected." if not alerts else f"{len(alerts)} suspicious activities detected."

    telemetry = {
        "session_id": resolved_session_id,
        "install": install_meta,
        "network": {
            "verdict": network_verdict,
            "tcp_added": tcp_added,
            "tcp6_added": tcp6_added,
            "unusual_outbound": unusual_outbound,
        },
        "filesystem": {
            "changed": fs_changed,
            "added_paths_head": added_paths[:40],
            "has_expected_install_markers": fs_has_expected_markers,
            "has_credential_markers": fs_has_credential_markers,
                "suspicious_install_artifacts": suspicious_install_artifacts[:20],
            "before_tail": baseline.fs_snapshot.splitlines()[-40:] if fs_changed else [],
            "after_tail": after.fs_snapshot.splitlines()[-40:] if fs_changed else [],
        },
        "processes": {"current_head": running_procs},
        "risk_level": risk_level,
        "alerts": alerts,
        "summary": summary,
        "notes": [],
        "classification": {
            "expected_activity": expected_activity[:5],
            "suspicious_indicators": suspicious_indicators[:8],
        },
    }
    return _resp(True, "get_telemetry", telemetry=telemetry)

@mcp.tool()
def nuke_sandbox(session_id: Optional[str] = None) -> str:
    """Kill and remove the Docker container, cleaning up all evidence."""
    resolved_session_id, session_state, session_err = _get_session_state(session_id)
    if session_err:
        return _resp(True, "nuke_sandbox", session_id=resolved_session_id, message="No active sandbox.")
    assert session_state is not None

    try:
        container = docker_client.containers.get(session_state["id"])
        container.kill()
        container.remove()
    except Exception:
        pass # ignore if already destroyed

    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.pop(resolved_session_id, None)
    return _resp(True, "nuke_sandbox", session_id=resolved_session_id, message="Sandbox destroyed. All evidence has been eliminated.")

if __name__ == "__main__":
    # Run the server via standard input/output for Claude Desktop or other MCP clients
    mcp.run(transport='stdio')
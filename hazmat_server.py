import json
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from mcp.server.fastmcp import FastMCP

from sandbox_core import (
    Baseline,
    docker_client,
    active_sandbox,
    _get_container,
    _exec,
    _snapshot_baseline,
    _parse_proc_net_tcp,
    _diff_added
)

# Initialize the MCP Server
mcp = FastMCP("Hazmat-Security-Scanner")
docker_client = docker.from_env()

# In-memory store for active sandbox state (hackathon-grade single-session server)
active_sandbox: Dict[str, Any] = {
    "id": None,
    "manager": None,
    "session_id": None,
    "baseline": None,
    "install": None,
}


@dataclass(frozen=True)
class Baseline:
    proc_net_tcp: str
    proc_net_tcp6: str
    proc_snapshot: str
    fs_snapshot: str


def _get_container() -> docker.models.containers.Container:
    if not active_sandbox["id"]:
        raise RuntimeError("No active sandbox. Call spin_up_sandbox first.")
    return docker_client.containers.get(active_sandbox["id"])


def _exec(
    container: docker.models.containers.Container,
    cmd: List[str],
    *,
    user: str = "root",
    timeout_s: int = 120,
) -> Tuple[int, bytes]:
    """
    Execute without shell interpolation by passing a argv list.
    Returns (exit_code, combined_stdout_stderr_bytes).
    """
    result = container.exec_run(
        cmd,
        user=user,
        demux=True,
        stdout=True,
        stderr=True,
        environment={"HAZMAT_TIMEOUT_S": str(timeout_s)},
    )
    exit_code = int(result.exit_code) if result.exit_code is not None else 1
    out, err = result.output if result.output else (b"", b"")
    return exit_code, (out or b"") + (err or b"")


def _read_text(container: docker.models.containers.Container, path: str) -> str:
    # /proc reads should always work; other files may not.
    _, out = _exec(container, ["sh", "-lc", f"cat {shlex.quote(path)} 2>/dev/null || true"])
    return out.decode("utf-8", errors="replace")


def _snapshot_baseline(container: docker.models.containers.Container) -> Baseline:
    # Network snapshots via /proc (available even on slim images)
    proc_net_tcp = _read_text(container, "/proc/net/tcp")
    proc_net_tcp6 = _read_text(container, "/proc/net/tcp6")

    # Process snapshot (ps is common; fallback if missing)
    _, ps_out = _exec(container, ["sh", "-lc", "ps aux 2>/dev/null || (echo 'ps_not_found'; ls -1 /proc | head -n 200)"])
    proc_snapshot = ps_out.decode("utf-8", errors="replace")

    # Simple filesystem snapshot in likely-to-change areas
    # Keep it bounded for MCP/LLM context limits.
    _, fs_out = _exec(
        container,
        [
            "sh",
            "-lc",
            "set -e; "
            "for d in /tmp /var/tmp /root /home; do "
            "  [ -d \"$d\" ] || continue; "
            "  echo \"## $d\"; "
            "  find \"$d\" -maxdepth 3 -type f -printf '%T@ %s %p\\n' 2>/dev/null | sort -nr | head -n 200; "
            "done",
        ],
        timeout_s=60,
    )
    fs_snapshot = fs_out.decode("utf-8", errors="replace")

    return Baseline(
        proc_net_tcp=proc_net_tcp,
        proc_net_tcp6=proc_net_tcp6,
        proc_snapshot=proc_snapshot,
        fs_snapshot=fs_snapshot,
    )


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _parse_proc_net_tcp(text: str) -> List[Dict[str, Any]]:
    """
    Parse /proc/net/tcp or /proc/net/tcp6.
    We keep a minimal, stable schema for the LLM: remote ip hex + remote port + state.
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return []

    conns: List[Dict[str, Any]] = []
    for ln in lines[1:]:
        parts = ln.split()
        if len(parts) < 4:
            continue
        remote = parts[2]
        state = parts[3]
        if ":" not in remote:
            continue
        rip_hex, rport_hex = remote.split(":", 1)
        if not (_HEX_RE.match(rip_hex) and _HEX_RE.match(rport_hex)):
            continue
        try:
            rport = int(rport_hex, 16)
        except ValueError:
            continue
        conns.append({"remote_ip_hex": rip_hex, "remote_port": rport, "state_hex": state})
    return conns


def _diff_added(before: List[Dict[str, Any]], after: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    bset = {json.dumps(x, sort_keys=True) for x in before}
    aset = {json.dumps(x, sort_keys=True) for x in after}
    return [json.loads(x) for x in sorted(aset - bset)]


def _resp(ok: bool, **payload: Any) -> str:
    body: Dict[str, Any] = {"ok": ok, **payload}
    return json.dumps(body, indent=2, sort_keys=True)


@mcp.tool()
def spin_up_sandbox(
    manager: str = "pip",
    session_id: Optional[str] = None,
    package_path: Optional[str] = None,
    base_image: Optional[str] = None,
) -> str:
    """Spin up an ephemeral Docker container for safe malware analysis."""
    try:
        manager = (manager or "pip").lower().strip()
        if manager not in {"pip", "npm"}:
            return _resp(False, "spin_up_sandbox", error="invalid_manager", message="Use 'pip' or 'npm'.")

        if base_image is None:
            base_image = "node:20-slim" if manager == "npm" else "python:3.11-slim"

        if active_sandbox.get("id"):
            return _resp(
                False,
                "spin_up_sandbox",
                error="sandbox_already_active",
                message="Sandbox already active",
                session_id=active_sandbox.get("session_id"),
                container_id=active_sandbox.get("id"),
            )

        # Share evidence directory between host and container so marker files are visible
        volumes = {"/tmp/hazmat": {"bind": "/tmp/hazmat", "mode": "rw"}}
        package_mount = None
        if package_path:
            package_volumes, package_mount = _get_package_mount(package_path)
            volumes.update(package_volumes)

        container = docker_client.containers.run(
            base_image,
            command=["sh", "-lc", "tail -f /dev/null"],
            detach=True,
            remove=False,
            network_mode="bridge",
            mem_limit="512m",
            security_opt=["no-new-privileges:true"],
            volumes=volumes,
            environment={
                "HAZMAT_HOST_API": "host.docker.internal",
            },
        )
        resolved_session_id = (session_id or str(uuid.uuid4())).strip()
        active_sandbox["id"] = container.id
        active_sandbox["manager"] = manager
        active_sandbox["session_id"] = resolved_session_id
        active_sandbox["baseline"] = None
        active_sandbox["install"] = None
        return _resp(
            ok=True,
            action="spin_up_sandbox",
            session_id=resolved_session_id,
            manager=manager,
            base_image=base_image,
            container_id=container.id,
        )
    except Exception as e:
        return _resp(False, "spin_up_sandbox", error="spin_up_failed", message=f"Failed to create sandbox: {str(e)}")

@mcp.tool()
def execute_install(package_name: str, manager: Optional[str] = None) -> str:
    """Install a package inside the sandbox and capture the terminal output."""
    if not active_sandbox.get("id"):
        return _resp(False, "execute_install", error="no_active_sandbox", message="Call spin_up_sandbox first.")

    container = _get_container()
    
    pkg = (package_name or "").strip()
    if not pkg:
        return _resp(False, "execute_install", error="invalid_package_name", message="package_name is required.")

    chosen_manager = (manager or active_sandbox.get("manager") or "pip").lower().strip()
    if chosen_manager not in {"pip", "npm"}:
        return _resp(False, "execute_install", error="invalid_manager", message="Use 'pip' or 'npm'.")

    # Determine the install command (argv list => avoids shell injection)
    resolved_package = _resolve_package_name(pkg)
    if chosen_manager == "npm":
        install_cmd: List[str] = ["npm", "install", "-g", resolved_package]
    else:
        install_cmd = ["pip", "install", resolved_package, "--no-cache-dir"]

    try:
        # Capture baseline BEFORE install so telemetry can be a diff.
        if active_sandbox.get("baseline") is None:
            active_sandbox["baseline"] = _snapshot_baseline(container)

        exit_code, output = _exec(container, install_cmd, timeout_s=300)
        out_text = output.decode("utf-8", errors="replace")
        if len(out_text) > 4000:
            out_text = out_text[:4000] + "\n…(truncated)…"
        active_sandbox["install"] = {
            "package_name": pkg,
            "manager": chosen_manager,
            "exit_code": exit_code,
            "output_preview": out_text,
        }
        return _resp(
            True,
            "execute_install",
            session_id=active_sandbox.get("session_id"),
            install=active_sandbox["install"],
            package=pkg,
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
            session_id=active_sandbox.get("session_id"),
            message=f"Installation failed: {str(e)}",
        )

@mcp.tool()
def get_telemetry() -> str:
    """
    Analyzes the container's behavior: checks network connections and file system changes.
    This is the most critical function for detecting malware.
    """
    if not active_sandbox.get("id"):
        return _resp(
            False,
            "get_telemetry",
            error="no_active_sandbox",
            telemetry={
                "session_id": None,
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

    container = _get_container()
    baseline: Optional[Baseline] = active_sandbox.get("baseline")
    if baseline is None:
        baseline = _snapshot_baseline(container)
        active_sandbox["baseline"] = baseline

    after = _snapshot_baseline(container)
    
    alerts: List[str] = []
    
    # 1) Network diff via /proc/net/tcp*
    before_tcp = _parse_proc_net_tcp(baseline.proc_net_tcp)
    after_tcp = _parse_proc_net_tcp(after.proc_net_tcp)
    before_tcp6 = _parse_proc_net_tcp(baseline.proc_net_tcp6)
    after_tcp6 = _parse_proc_net_tcp(after.proc_net_tcp6)

    tcp_added = _diff_added(before_tcp, after_tcp)
    tcp6_added = _diff_added(before_tcp6, after_tcp6)
    network_verdict = "clean"
    
    if tcp_added or tcp6_added:
        network_verdict = "suspicious"
        alerts.append("Suspicious Outbound Connection: New TCP connections observed after install phase.")

    # 2) Filesystem diff
    fs_changed = baseline.fs_snapshot != after.fs_snapshot
    if fs_changed:
        alerts.append("File Access/Creation Detected: The package has unexpectedly modified or added files in sensitive directories.")
    
    # We won't trigger an automatic flag for process running (it could just be pip/npm finishing up),
    # but we can provide it for context.
    running_procs = after.proc_snapshot.splitlines()[:60]

    # Hackathon-grade scoring
    install_meta = active_sandbox.get("install")
    install_exit = (install_meta or {}).get("exit_code")
    if install_exit not in (None, 0):
        alerts.append(f"Install command returned non-zero exit code ({install_exit}).")

    if (tcp_added or tcp6_added) and fs_changed:
        risk_level = "critical"
    elif tcp_added or tcp6_added:
        risk_level = "high"
    elif fs_changed or (install_exit not in (None, 0)):
        risk_level = "medium"
    else:
        risk_level = "low"
    summary = "No suspicious activity detected." if not alerts else f"{len(alerts)} suspicious activities detected."

    telemetry = {
        "session_id": active_sandbox.get("session_id"),
        "install": install_meta,
        "network": {
            "verdict": network_verdict,
            "tcp_added": tcp_added,
            "tcp6_added": tcp6_added,
        },
        "filesystem": {
            "changed": fs_changed,
            "before_tail": baseline.fs_snapshot.splitlines()[-40:] if fs_changed else [],
            "after_tail": after.fs_snapshot.splitlines()[-40:] if fs_changed else [],
        },
        "processes": {"current_head": running_procs},
        "risk_level": risk_level,
        "alerts": alerts,
        "summary": summary,
        "notes": [],
    }
    return _resp(True, "get_telemetry", telemetry=telemetry)

@mcp.tool()
def nuke_sandbox(session_id: Optional[str] = None) -> str:
    """Kill and remove the Docker container, cleaning up all evidence."""
    if not active_sandbox.get("id"):
        return _resp(True, "nuke_sandbox", session_id=None, message="No active sandbox.")
    
    if session_id and session_id != active_sandbox.get("session_id"):
        return _resp(
            False,
            "nuke_sandbox",
            error="session_mismatch",
            expected_session_id=active_sandbox.get("session_id"),
            provided_session_id=session_id,
            message="Session ID mismatch.",
        )
    
    old_session = active_sandbox.get("session_id")
    try:
        container = _get_container()
        container.kill()
        container.remove()
    except Exception:
        pass # ignore if already destroyed
        
    active_sandbox["id"] = None
    active_sandbox["manager"] = None
    active_sandbox["session_id"] = None
    active_sandbox["baseline"] = None
    active_sandbox["install"] = None
    return _resp(True, "nuke_sandbox", session_id=old_session, message="Sandbox destroyed. All evidence has been eliminated.")

if __name__ == "__main__":
    # Run the server via standard input/output for Claude Desktop or other MCP clients
    mcp.run(transport='stdio')
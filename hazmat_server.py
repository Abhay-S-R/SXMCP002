import json
import uuid
from typing import Any, Dict, List, Optional

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


def _resp(ok: bool, action: str, **payload: Any) -> str:
    body: Dict[str, Any] = {"ok": ok, "action": action, **payload}
    # Keep compatibility for clients expecting "status" too.
    body["status"] = "ok" if ok else "error"
    return json.dumps(body, indent=2, sort_keys=True)


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

        if active_sandbox.get("id"):
            return _resp(
                False,
                "spin_up_sandbox",
                error="sandbox_already_active",
                message="Sandbox already active",
                session_id=active_sandbox.get("session_id"),
                container_id=active_sandbox.get("id"),
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
        resolved_session_id = (session_id or str(uuid.uuid4())).strip()
        active_sandbox["id"] = container.id
        active_sandbox["manager"] = manager
        active_sandbox["session_id"] = resolved_session_id
        active_sandbox["baseline"] = None
        active_sandbox["install"] = None
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
    if chosen_manager == "npm":
        install_cmd: List[str] = ["npm", "install", "-g", pkg]
    else:
        install_cmd = ["pip", "install", pkg, "--no-cache-dir"]

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
import uuid
from typing import Optional, List

from mcp.server.fastmcp import FastMCP

from sandbox_core import (
    SandboxStatus,
    InstallResponse,
    TelemetryResponse,
    ActionResponse,
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
            return SandboxStatus(status="error", message="Use 'pip' or 'npm'.").model_dump_json(indent=2)

        if base_image is None:
            base_image = "node:20-slim" if manager == "npm" else "python:3.11-slim"

        if active_sandbox.get("id"):
            return SandboxStatus(
                status="error",
                message="Sandbox already active",
                session_id=active_sandbox.get("session_id"),
                container_id=active_sandbox.get("id"),
            ).model_dump_json(indent=2)

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
        return SandboxStatus(
            status="ok",
            action="spin_up_sandbox",
            session_id=resolved_session_id,
            manager=manager,
            container_id=container.id,
            message="Sandbox ready"
        ).model_dump_json(indent=2)
    except Exception as e:
        return SandboxStatus(status="error", message=f"Failed to create sandbox: {str(e)}").model_dump_json(indent=2)

@mcp.tool()
def execute_install(package_name: str, manager: Optional[str] = None) -> str:
    """Install a package inside the sandbox and capture the terminal output."""
    if not active_sandbox.get("id"):
        return InstallResponse(status="error", message="Call spin_up_sandbox first.").model_dump_json(indent=2)

    container = _get_container()
    
    pkg = (package_name or "").strip()
    if not pkg:
        return InstallResponse(status="error", message="package_name is required.").model_dump_json(indent=2)

    chosen_manager = (manager or active_sandbox.get("manager") or "pip").lower().strip()
    if chosen_manager not in {"pip", "npm"}:
        return InstallResponse(status="error", message="Use 'pip' or 'npm'.").model_dump_json(indent=2)

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
        return InstallResponse(
            status="ok",
            package=pkg,
            manager=chosen_manager,
            exit_code=exit_code,
            output=out_text,
            message="Install finished"
        ).model_dump_json(indent=2)
    except Exception as e:
        return InstallResponse(status="error", message=f"Installation failed: {str(e)}").model_dump_json(indent=2)

@mcp.tool()
def get_telemetry() -> str:
    """
    Analyzes the container's behavior: checks network connections and file system changes.
    This is the most critical function for detecting malware.
    """
    if not active_sandbox.get("id"):
        return TelemetryResponse(status="error", risk_level="unknown", alerts=[], summary="No active sandbox.").model_dump_json(indent=2)

    container = _get_container()
    baseline: Optional[Baseline] = active_sandbox.get("baseline")
    if baseline is None:
        baseline = _snapshot_baseline(container)
        active_sandbox["baseline"] = baseline

    after = _snapshot_baseline(container)
    
    alerts = []
    
    # 1) Network diff via /proc/net/tcp*
    before_tcp = _parse_proc_net_tcp(baseline.proc_net_tcp)
    after_tcp = _parse_proc_net_tcp(after.proc_net_tcp)
    before_tcp6 = _parse_proc_net_tcp(baseline.proc_net_tcp6)
    after_tcp6 = _parse_proc_net_tcp(after.proc_net_tcp6)

    tcp_added = _diff_added(before_tcp, after_tcp)
    tcp6_added = _diff_added(before_tcp6, after_tcp6)
    
    if tcp_added or tcp6_added:
        alerts.append("Suspicious Outbound Connection: New TCP connections observed after install phase.")

    # 2) Filesystem diff
    if baseline.fs_snapshot != after.fs_snapshot:
        alerts.append("File Access/Creation Detected: The package has unexpectedly modified or added files in sensitive directories.")
    
    # We won't trigger an automatic flag for process running (it could just be pip/npm finishing up),
    # but we can provide it for context.
    running_procs = after.proc_snapshot.splitlines()[:20]
    
    if len(alerts) > 0:
        risk_level = "critical"
        summary = f"{len(alerts)} suspicious activities detected. Potential malicious behavior."
    else:
        risk_level = "low"
        summary = "No suspicious activity detected."

    return TelemetryResponse(
        status="ok",
        risk_level=risk_level,
        alerts=alerts,
        summary=summary,
        running_processes=running_procs
    ).model_dump_json(indent=2)

@mcp.tool()
def nuke_sandbox(session_id: Optional[str] = None) -> str:
    """Kill and remove the Docker container, cleaning up all evidence."""
    if not active_sandbox.get("id"):
        return ActionResponse(status="ok", message="No active sandbox.").model_dump_json(indent=2)
    
    if session_id and session_id != active_sandbox.get("session_id"):
        return ActionResponse(status="error", message="Session ID mismatch.").model_dump_json(indent=2)
    
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
    return ActionResponse(status="ok", message="Sandbox destroyed. All evidence has been eliminated.").model_dump_json(indent=2)

if __name__ == "__main__":
    # Run the server via standard input/output for Claude Desktop or other MCP clients
    mcp.run(transport='stdio')
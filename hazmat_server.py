import json
import re
import shlex
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import docker
from mcp.server.fastmcp import FastMCP

# Initialize the MCP Server and Docker client
mcp = FastMCP("Hazmat-Security-Scanner")
docker_client = docker.from_env()

# In-memory store for active sandbox state (hackathon-grade single-session server)
active_sandbox: Dict[str, Any] = {"id": None, "manager": None, "baseline": None}


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

@mcp.tool()
def spin_up_sandbox(manager: str = "pip", base_image: Optional[str] = None) -> str:
    """Spin up an ephemeral Docker container for safe malware analysis."""
    try:
        manager = (manager or "pip").lower().strip()
        if manager not in {"pip", "npm"}:
            return "❌ Invalid manager. Use 'pip' or 'npm'."

        if base_image is None:
            base_image = "node:20-slim" if manager == "npm" else "python:3.11-slim"

        container = docker_client.containers.run(
            base_image,
            command=["sh", "-lc", "tail -f /dev/null"],  # Keep the container alive
            detach=True,
            remove=False, # We will remove it manually
            network_mode="bridge", # Give it a network stack we can monitor
            mem_limit="512m", # Limit resources
            security_opt=["no-new-privileges:true"] # Basic hardening
        )
        active_sandbox["id"] = container.id
        active_sandbox["manager"] = manager
        active_sandbox["baseline"] = None
        return f"✅ Sandbox ready! Manager: {manager}. Image: {base_image}. Container ID: {container.id[:12]}"
    except Exception as e:
        return f"❌ Failed to create sandbox: {str(e)}"

@mcp.tool()
def execute_install(package_name: str, manager: Optional[str] = None) -> str:
    """Install a package inside the sandbox and capture the terminal output."""
    if not active_sandbox.get("id"):
        return "⚠️ No active sandbox. Call spin_up_sandbox first."

    container = _get_container()
    
    pkg = (package_name or "").strip()
    if not pkg:
        return "❌ package_name is required."

    chosen_manager = (manager or active_sandbox.get("manager") or "pip").lower().strip()
    if chosen_manager not in {"pip", "npm"}:
        return "❌ Invalid manager. Use 'pip' or 'npm'."

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
        return f"📦 Install finished (exit code: {exit_code}).\nOutput:\n{out_text}"
    except Exception as e:
        return f"❌ Installation failed: {str(e)}"

@mcp.tool()
def get_telemetry() -> str:
    """
    Analyzes the container's behavior: checks network connections and file system changes.
    This is the most critical function for detecting malware.
    """
    if not active_sandbox.get("id"):
        return "⚠️ No active sandbox."

    container = _get_container()
    baseline: Optional[Baseline] = active_sandbox.get("baseline")
    if baseline is None:
        baseline = _snapshot_baseline(container)
        active_sandbox["baseline"] = baseline

    after = _snapshot_baseline(container)
    report: Dict[str, Any] = {"network": {}, "filesystem": {}, "processes": {}, "notes": []}
    
    # 1) Network diff via /proc/net/tcp*
    before_tcp = _parse_proc_net_tcp(baseline.proc_net_tcp)
    after_tcp = _parse_proc_net_tcp(after.proc_net_tcp)
    before_tcp6 = _parse_proc_net_tcp(baseline.proc_net_tcp6)
    after_tcp6 = _parse_proc_net_tcp(after.proc_net_tcp6)

    report["network"]["tcp_added"] = _diff_added(before_tcp, after_tcp)
    report["network"]["tcp6_added"] = _diff_added(before_tcp6, after_tcp6)
    if report["network"]["tcp_added"] or report["network"]["tcp6_added"]:
        report["network"]["verdict"] = "suspicious"
        report["notes"].append("New TCP connections observed after baseline (may indicate outbound activity).")
    else:
        report["network"]["verdict"] = "clean"

    # 2) Filesystem diff: compare snapshots (hackathon-grade)
    if baseline.fs_snapshot != after.fs_snapshot:
        report["filesystem"]["changed"] = True
        report["filesystem"]["before_tail"] = baseline.fs_snapshot.splitlines()[-40:]
        report["filesystem"]["after_tail"] = after.fs_snapshot.splitlines()[-40:]
    else:
        report["filesystem"]["changed"] = False
    
    # 3) Process snapshot: provide first lines only
    report["processes"]["current_head"] = after.proc_snapshot.splitlines()[:60]
    return json.dumps(report, indent=2, sort_keys=True)

@mcp.tool()
def nuke_sandbox() -> str:
    """Kill and remove the Docker container, cleaning up all evidence."""
    if not active_sandbox.get("id"):
        return "No sandbox to nuke."
    
    container = _get_container()
    container.kill()
    container.remove()
    active_sandbox["id"] = None
    active_sandbox["manager"] = None
    active_sandbox["baseline"] = None
    return "💥 Sandbox destroyed. All evidence has been eliminated."

if __name__ == "__main__":
    # Run the server via standard input/output for Claude Desktop or other MCP clients
    mcp.run(transport='stdio')
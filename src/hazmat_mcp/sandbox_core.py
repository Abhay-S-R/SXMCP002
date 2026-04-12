import json
import re
import shlex
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import docker
from pydantic import BaseModel, Field

# Define Pydantic models for deterministic output
class SandboxStatus(BaseModel):
    status: str
    container_id: Optional[str] = None
    session_id: Optional[str] = None
    manager: Optional[str] = None
    action: Optional[str] = None
    message: Optional[str] = None

class InstallResponse(BaseModel):
    status: str
    package: Optional[str] = None
    manager: Optional[str] = None
    exit_code: Optional[int] = None
    output: Optional[str] = None
    message: Optional[str] = None

class TelemetryResponse(BaseModel):
    status: str
    risk_level: str
    alerts: List[str] = Field(default_factory=list)
    summary: str
    running_processes: List[str] = Field(default_factory=list)
    message: Optional[str] = None

class ActionResponse(BaseModel):
    status: str
    message: str

# Initialize Docker client
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

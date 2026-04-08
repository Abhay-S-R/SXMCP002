# Hazmat-MCP (Prototype)

Dynamic dependency auditor for suspicious `pip`/`npm` packages using an MCP server + Docker sandbox.

## Current Scope

This prototype currently provides one MCP server file: `hazmat_server.py`.

Implemented tools:
- `spin_up_sandbox(manager, session_id, base_image)`
- `execute_install(package_name, manager)`
- `get_telemetry()`
- `nuke_sandbox(session_id)`

All tool outputs are JSON strings with a top-level `ok` field.

## Setup

From repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Run MCP Server

```bash
source .venv/bin/activate
python3 hazmat_server.py
```

The server runs over stdio transport.

## Expected Tool Flow

1) Start sandbox

```json
{
  "tool": "spin_up_sandbox",
  "args": {
    "manager": "pip",
    "session_id": "demo-001"
  }
}
```

2) Install package in sandbox

```json
{
  "tool": "execute_install",
  "args": {
    "package_name": "six",
    "manager": "pip"
  }
}
```

3) Read telemetry JSON

```json
{
  "tool": "get_telemetry",
  "args": {}
}
```

4) Cleanup sandbox

```json
{
  "tool": "nuke_sandbox",
  "args": {
    "session_id": "demo-001"
  }
}
```

## Telemetry Shape (Current)

`get_telemetry()` returns:
- `telemetry.session_id`
- `telemetry.install.exit_code` and install metadata (if install was executed)
- `telemetry.network` (`tcp_added`, `tcp6_added`, `verdict`)
- `telemetry.filesystem` (`changed`, plus snapshot tails when changed)
- `telemetry.processes.current_head`

## Notes

- First run can be slow because Docker may need to pull base images (`python:3.11-slim` / `node:20-slim`).
- This is a hackathon-grade baseline, not a production malware sandbox.

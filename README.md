# Hazmat-MCP 

Dynamic dependency auditor for suspicious `pip`/`npm` packages using an MCP server + Docker sandbox.

## Layout

| Path | Role |
|------|------|
| `src/hazmat_mcp/` | Installable package (`cli`, `agent`, `server`, `sandbox_core`) |
| `examples/` | Sample batch file and demo inputs |
| `tests/` | Tests, demo tarball, integration scripts |

## Current scope

MCP server is implemented in `src/hazmat_mcp/server.py` (stdio).

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
# Editable install so `hazmat` / `python -m hazmat_mcp` resolve imports:
pip install -e .
```

Without `pip install -e .`, use `./hazmat` (sets `PYTHONPATH=src`) or:

```bash
export PYTHONPATH="${PWD}/src"
python3 -m hazmat_mcp --help
```

## Run MCP server (stdio)

```bash
source .venv/bin/activate
python3 -m hazmat_mcp.server
```

## Expected tool flow

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

## Telemetry shape (current)

`get_telemetry()` returns:

- `telemetry.session_id`
- `telemetry.install.exit_code` and install metadata (if install was executed)
- `telemetry.network` (`tcp_added`, `tcp6_added`, `verdict`)
- `telemetry.filesystem` (`changed`, plus snapshot tails when changed)
- `telemetry.processes.current_head`

## Notes

- First run can be slow because Docker may need to pull base images (`python:3.11-slim` / `node:20-slim`).
- This is a hackathon-grade baseline, not a production malware sandbox.

## LangGraph agent

`agent.py` runs the orchestration loop:

1. `spin_up_sandbox`
2. `execute_install`
3. `get_telemetry`
4. analyze verdict
5. `nuke_sandbox` (always attempted)

Run it:

```bash
source .venv/bin/activate
python3 -m agent.py
```

Override package/manager:

```bash
HAZMAT_PACKAGE=requests HAZMAT_MANAGER=pip python3 -m agent.py
```

Optional LLM analysis mode:

- Model-first is enabled by default in this order:
  1) `GEMINI_API_KEY` (`HAZMAT_GEMINI_MODEL`, default `gemini-2.0-flash`)
- If no model key is set (or model call fails), agent falls back to deterministic rule-based analysis.

### Timeout runner (recommended for edge-case tests)

```bash
chmod +x run_agent_timeout.sh
./run_agent_timeout.sh requests pip 120
./run_agent_timeout.sh this-package-should-not-exist-xyz123 pip 60
```

The script sets:

- `PIP_DEFAULT_TIMEOUT=10`
- `PIP_RETRIES=0`

and wraps `python3 -m hazmat_mcp.agent` with a hard timeout.

## CLI

After `pip install -e .`:

```bash
hazmat --package requests --manager pip
```

Or from a dev tree:

```bash
chmod +x hazmat
./hazmat --package requests --manager pip
```

Raw JSON:

```bash
hazmat --package requests --manager pip --raw-json
```

Custom timeout:

```bash
hazmat --package requests --manager npm --timeout 120
```

Batch parallel mode (`target[,manager]` per line). Example file: `examples/batch_targets.txt`.

```bash
hazmat --batch-file examples/batch_targets.txt --parallel 4
hazmat --batch-file examples/batch_targets.txt --parallel 4 --raw-json
hazmat --batch-file examples/batch_targets.txt --parallel 4 --live
```

## Integration hardening

```bash
chmod +x tests/scripts/step7_hardening_tests.sh
./tests/scripts/step7_hardening_tests.sh
```

This validates:

- manager mismatch detection
- nonexistent package handling through timeout runner
- malicious local `.tgz` payload detection (`tests/demo_packages/...`)

## PyPI / packaging

Build and install from `pyproject.toml` (`hazmat-mcp` distribution, `hazmat` console script). See `[project]` and `[project.scripts]` in `pyproject.toml`.

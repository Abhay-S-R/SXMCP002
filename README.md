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

## Step 4: LangGraph Agent

`agent.py` runs the orchestration loop:
1. `spin_up_sandbox`
2. `execute_install`
3. `get_telemetry`
4. analyze verdict
5. `nuke_sandbox` (always attempted)

Run it:

```bash
source .venv/bin/activate
python3 agent.py
```

Override package/manager:

```bash
HAZMAT_PACKAGE=requests HAZMAT_MANAGER=pip python3 agent.py
```

Optional LLM analysis mode:
- Model-first is enabled by default in this order:
  1) `GEMINI_API_KEY` (`HAZMAT_GEMINI_MODEL`, default `gemini-2.0-flash`)
- If no model key is set (or model call fails), agent falls back to deterministic rule-based analysis.

### Timeout runner (recommended for edge-case tests)

Use the helper script to avoid hanging on unresolved package lookups:

```bash
chmod +x run_agent_timeout.sh
./run_agent_timeout.sh requests pip 120
./run_agent_timeout.sh this-package-should-not-exist-xyz123 pip 60
```

The script sets:
- `PIP_DEFAULT_TIMEOUT=10`
- `PIP_RETRIES=0`

and wraps `python3 agent.py` with a hard timeout.

## Step 6: CLI wrapper

Use the CLI for demo-friendly output:

```bash
source .venv/bin/activate
python3 hazmat_cli.py --package requests --manager pip
```

For judge/demo reliability, prefer timeout-enforced agent runs for edge/error cases:

```bash
chmod +x run_agent_timeout.sh
./run_agent_timeout.sh requests pip 120
./run_agent_timeout.sh this-package-should-not-exist-xyz123 pip 75
```

Raw JSON mode:

```bash
python3 hazmat_cli.py --package requests --manager pip --raw-json
```

Custom timeout:

```bash
python3 hazmat_cli.py --package requests --manager npm --timeout 120
```

Batch parallel mode (target[,manager] per line):

```bash
cat > batch_targets.txt <<'EOF'
lodash,npm
requests,pip
this-package-should-not-exist-xyz123,pip
demo_packages/react-helper-dom/react-helper-dom-1.0.0.tgz,npm
EOF

python3 hazmat_cli.py --batch-file batch_targets.txt --parallel 4
python3 hazmat_cli.py --batch-file batch_targets.txt --parallel 4 --raw-json
```

## Step 7: Integration hardening

Run deterministic hardening checks:

```bash
chmod +x scripts/step7_hardening_tests.sh
./scripts/step7_hardening_tests.sh
```

This script validates:
- manager mismatch detection
- nonexistent package handling through timeout runner
- malicious local `.tgz` payload detection

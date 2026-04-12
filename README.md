# Hazmat-MCP

Dynamic supply-chain security auditor for `pip`/`npm` packages.  
Installs packages inside ephemeral Docker sandboxes, collects runtime telemetry (network, filesystem, processes), and renders a security verdict — powered by an MCP server, a LangGraph agent, and optional LLM analysis (Gemini).

---

## Architecture

```
hazmat_cli.py / hazmat   CLI entry-point (single + batch, Rich TUI)
        │
    agent.py             LangGraph orchestration graph
        │                  spin_up → install → telemetry → analyze → cleanup
        │
  ┌─────┴─────┐
  │  MCP stdio │
  └─────┬─────┘
        │
  hazmat_server.py       MCP server (FastMCP, stdio transport)
        │
  sandbox_core.py        Docker primitives, baseline snapshots, /proc parsers
        │
     Docker               Ephemeral containers (python:3.11-slim / node:20-slim)
```

### Key files

| File | Purpose |
|---|---|
| `sandbox_core.py` | Shared Docker client, `_exec`, `_snapshot_baseline`, `/proc/net/tcp` parser, diff helpers |
| `hazmat_server.py` | MCP tool implementations: `spin_up_sandbox`, `execute_install`, `get_telemetry`, `nuke_sandbox` |
| `agent.py` | LangGraph state-graph that drives the full audit lifecycle + Gemini / rule-based analysis |
| `hazmat_cli.py` | CLI wrapper with Rich TUI, progress spinner, batch mode, live dashboard |
| `hazmat` | Shell shorthand — `./hazmat --package requests` |
| `run_agent_timeout.sh` | Bash wrapper: sets pip timeouts, enforces a hard wall-clock limit |
| `demo_packages/` | Controlled malicious npm tarball (`react-helper-dom-1.0.0.tgz`) for demos |
| `scripts/step7_hardening_tests.sh` | Automated integration checks (mismatch, nonexistent, malicious payload) |

### MCP tools

| Tool | Description |
|---|---|
| `spin_up_sandbox(manager, session_id?, base_image?)` | Create an ephemeral Docker container for safe analysis |
| `execute_install(session_id?, package_name?, manager?, package_source?)` | Install a package (registry or local `.tgz`) and capture output |
| `get_telemetry(session_id?)` | Diff network/filesystem/process state against pre-install baseline |
| `nuke_sandbox(session_id?)` | Kill and remove the container |

All tool outputs are JSON with a top-level `ok` field.

---

## Prerequisites

- **Python 3.11+** with a virtual environment
- **Docker** running and accessible (`docker ps` should work)
- *(Optional)* `GEMINI_API_KEY` in a `.env` file for LLM-powered verdicts

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows PowerShell
pip install --upgrade pip
pip install -r requirements.txt
```

> First run can be slow — Docker may need to pull `python:3.11-slim` and/or `node:20-slim`.

---

## Usage

### MCP server (standalone)

```bash
python3 hazmat_server.py
```

The server runs over **stdio** transport and is consumed by the agent or any MCP client.

### Agent (direct)

```bash
python3 agent.py
```

Override package/manager via environment variables:

```bash
HAZMAT_PACKAGE=requests HAZMAT_MANAGER=pip python3 agent.py
```

For local `.tgz` artifacts:

```bash
HAZMAT_PACKAGE_SOURCE=demo_packages/react-helper-dom/react-helper-dom-1.0.0.tgz \
  HAZMAT_MANAGER=npm python3 agent.py
```

### CLI (recommended)

```bash
# Single package scan
python3 hazmat_cli.py --package requests --manager pip

# Local tarball scan
python3 hazmat_cli.py --package-source demo_packages/react-helper-dom/react-helper-dom-1.0.0.tgz --manager npm

# Raw JSON output
python3 hazmat_cli.py --package requests --manager pip --raw-json

# Custom timeout (default: 180s)
python3 hazmat_cli.py --package requests --manager npm --timeout 120
```

Or use the shorthand wrapper:

```bash
chmod +x hazmat
./hazmat --package requests --manager pip
```

### Batch mode

Create a targets file (`target[,manager]` per line):

```text
lodash,npm
requests,pip
this-package-should-not-exist-xyz123,pip
demo_packages/react-helper-dom/react-helper-dom-1.0.0.tgz,npm
```

Run in parallel:

```bash
# Plain batch
python3 hazmat_cli.py --batch-file batch_targets.txt --parallel 4

# Live Rich dashboard
python3 hazmat_cli.py --batch-file batch_targets.txt --parallel 4 --live

# JSON batch output
python3 hazmat_cli.py --batch-file batch_targets.txt --parallel 4 --raw-json
```

### Timeout runner (bash)

For edge-case tests or demo reliability:

```bash
chmod +x run_agent_timeout.sh
./run_agent_timeout.sh requests pip 120
./run_agent_timeout.sh this-package-should-not-exist-xyz123 pip 60
```

Sets `PIP_DEFAULT_TIMEOUT=10`, `PIP_RETRIES=0`, and wraps `python3 agent.py` with a hard timeout.

---

## LLM Analysis

Analysis follows a model-first strategy with deterministic fallback:

1. **Gemini** — used when `GEMINI_API_KEY` is set (model: `HAZMAT_GEMINI_MODEL`, default `gemini-3.1-flash-lite-preview`)
2. **Rule-based** — automatic fallback if no API key is present or the model call fails

Create a `.env` file in the project root:

```
GEMINI_API_KEY=your-key-here
# HAZMAT_GEMINI_MODEL=gemini-3.1-flash-lite-preview   # optional override
```

---

## Telemetry Shape

`get_telemetry()` returns a `telemetry` object with:

| Key | Contents |
|---|---|
| `session_id` | Active sandbox session |
| `install` | Package name/source, manager, exit code, output preview, source mode |
| `network.verdict` | `clean` or `suspicious` |
| `network.tcp_added` / `tcp6_added` | New outbound TCP connections (ip hex, port, state) |
| `network.unusual_outbound` | Connections to non-80/443 ports |
| `filesystem.changed` | Boolean diff vs. baseline |
| `filesystem.added_paths_head` | Up to 40 newly created file paths |
| `filesystem.has_expected_install_markers` | True if changes match expected cache/install locations |
| `filesystem.has_credential_markers` | True if activity touches credential-like paths |
| `filesystem.suspicious_install_artifacts` | Marker/beacon files created in temp dirs |
| `processes.current_head` | Current running processes snapshot |
| `risk_level` | `low` / `medium` / `high` / `critical` |
| `alerts` | Human-readable alert strings |
| `classification.suspicious_indicators` | Evidence of suspicious behavior |
| `classification.expected_activity` | Recognized benign activity |

---

## Post-Analysis Guards

The agent applies automatic guards before emitting a final verdict:

- **Manager mismatch precheck** — detects when a known PyPI package is scanned with npm (or vice versa) and downgrades to `suspicious/medium` instead of a false-positive `malicious`.
- **Expected npm noise normalization** — recognizes that outbound HTTPS to registry + npm cache writes are normal npm install behavior and normalizes to `safe/low`.

---

## Demo Malicious Package

`demo_packages/react-helper-dom/` contains a controlled malicious npm package with a `postinstall.js` that:
- Reads `/etc/passwd`
- Scans for SSH keys, AWS credentials, kube configs
- Writes marker/beacon files to `/tmp`

Use it to validate detection:

```bash
python3 hazmat_cli.py \
  --package-source demo_packages/react-helper-dom/react-helper-dom-1.0.0.tgz \
  --manager npm
```

---

## Testing

### Smoke test (direct function calls)

```bash
python3 smoke_test.py
```

### MCP client integration test

```bash
python3 test_client.py
```

### npm `.tgz` integration test

```bash
python3 test_npm_tgz_client.py
```

### Hardening checks (Step 7)

```bash
chmod +x scripts/step7_hardening_tests.sh
./scripts/step7_hardening_tests.sh
```

Validates:
- Manager mismatch detection → `suspicious/medium`
- Nonexistent package graceful failure via timeout runner
- Malicious local `.tgz` payload detection → elevated risk + alerts

See `TEST_REPORT.md` for full test matrix and notable bugs fixed.

---

## Notes

- This is a **hackathon-grade** security tool, not a production malware sandbox.
- Rich TUI features (live dashboard, colored panels) require the `rich` package and a terminal that supports ANSI. Falls back to plain text on pipes or dumb terminals.
- Windows is supported — the CLI enables VT100 ANSI processing automatically on Windows 10+ terminals.

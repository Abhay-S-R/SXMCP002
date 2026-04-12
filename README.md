# Hazmat-MCP

Dynamic dependency auditor for suspicious `pip`/`npm` packages using MCP and Docker sandboxes.

## Overview

Hazmat-MCP is a Python-based audit framework that installs untrusted Python or Node packages inside an isolated Docker sandbox, captures runtime telemetry, and produces a security verdict.

The project combines:

- A FastMCP server (`src/hazmat_mcp/server.py`) exposing sandbox tools over stdio
- Docker sandbox management and telemetry diffing (`src/hazmat_mcp/sandbox_core.py`)
- An orchestration agent with deterministic and optional LLM-assisted verdict logic (`src/hazmat_mcp/agent.py`)
- A user-facing CLI wrapper with human-readable and raw JSON output (`src/hazmat_mcp/cli.py`)

## CLI-focused workflow

The primary interface for Hazmat-MCP is the command-line tool.

After setup, use the installed `hazmat` console script or run the CLI module directly from the repository.

### Primary commands

If the package is installed in your environment:

```bash
hazmat --package requests --manager pip
```

If you are running from the repo without installing the package:

```bash
python -m hazmat_mcp.cli --package requests --manager pip
```

Both forms execute the same CLI entrypoint.

### Command reference

- `--package <name>`: package name to install
- `--manager pip|npm`: package manager to use
- `--raw-json`: output raw JSON instead of human-readable text
- `--timeout <seconds>`: network/install timeout for the CLI runner
- `--batch-file <path>`: scan multiple package targets from a file
- `--parallel <n>`: run batch targets in parallel
- `--live`: stream live progress during batch execution

### Example CLI workflows

Install a Python package with `pip`:

```bash
hazmat --package requests --manager pip
```

Install an npm package:

```bash
hazmat --package lodash --manager npm
```

Use raw JSON output for automation:

```bash
hazmat --package requests --manager pip --raw-json
```

Run a batch scan from a file:

```bash
hazmat --batch-file examples/batch_targets.txt --parallel 4
```

## Architecture and workflow

The Hazmat-MCP CLI is the recommended entrypoint for users. It executes a sandbox-based audit workflow using Docker and MCP tooling.

Workflow details:

1. User invokes the CLI via `hazmat` or `python -m hazmat_mcp.cli`.
2. The CLI parses package name, manager, timeout, and batch options.
3. The CLI requests sandbox creation and package install through the internal MCP orchestration.
4. A Docker sandbox container is launched with either a Python or Node base image.
5. The package is installed inside the sandbox and install output is captured.
6. Telemetry is collected by comparing baseline and post-install snapshots for network, filesystem, and process changes.
7. The CLI processes the results and prints a verdict, summary, telemetry details, or raw JSON.
8. The sandbox is cleaned up after the audit completes.

The CLI front end is implemented in `src/hazmat_mcp/cli.py`. It has the following responsibilities:

- parse user arguments
- select `pip` or `npm` install mode
- run the sandbox install and telemetry flow
- display human readable or raw JSON output
- support batch scanning and timeout handling

### Windows PowerShell examples

```powershell
hazmat --package requests --manager pip
```

Run from repo without install:

```powershell
python -m hazmat_mcp.cli --package requests --manager pip
```

## How the CLI works

The CLI uses `src/hazmat_mcp/cli.py` as the main entrypoint. It drives the audit by orchestrating the sandbox tooling and printing either human-readable output or raw JSON.

Key behavior includes:

- selecting `pip` or `npm` install mode
- invoking the sandbox orchestration flow
- showing install progress and verdict data
- allowing batch input and timeout controls

## Setup

### Linux / macOS

```bash
cd /path/to/Hazmat
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
```

### Windows PowerShell

```powershell
cd C:\path\to\Hazmat
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

### Without editable install

Linux / macOS:

```bash
export PYTHONPATH="${PWD}/src"
python3 -m hazmat_mcp.cli --help
```

Windows PowerShell:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m hazmat_mcp.cli --help
```

## Requirements

- Python 3.11 or newer
- Docker Engine / Docker Desktop
- `pip` available inside the activated Python environment

## Background architecture

Hazmat-MCP is built around these components:

- `server.py`: MCP tool server exposing sandbox operations
- `sandbox_core.py`: Docker sandbox lifecycle, command execution, and telemetry diffing
- `agent.py`: optional orchestration agent that sequences install, telemetry, and verdict generation
- `cli.py`: main user-facing command-line interface

The CLI is the recommended entrypoint for most users.

## Developer reference

The project also supports direct module invocations for developer workflows:

- `python -m hazmat_mcp.cli ...` runs the CLI from the repo
- `python -m hazmat_mcp ...` is equivalent because `src/hazmat_mcp/__main__.py` forwards to the CLI

Optional internal workflows:

- `python -m hazmat_mcp.agent` runs the orchestrator directly
- `python -m hazmat_mcp.server` starts the MCP tool server

## Notes

- Docker may need to pull base images on first run (`python:3.11-slim` and `node:20-slim`), so initial execution can take longer.
- Windows users must have Docker Desktop configured to run the CLI.

## Caution

- The current implementation is a proof-of-concept baseline for auditing package installs, not a hardened production malware sandbox.

## PyPI / packaging

Build and install from `pyproject.toml` (`hazmat-mcp` distribution, `hazmat` console script). See `[project]` and `[project.scripts]` in `pyproject.toml`.

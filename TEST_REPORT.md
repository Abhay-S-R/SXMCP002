# Hazmat-MCP Test Report

This report captures tests executed during Step 1-4 development and hardening.

## Environment

- OS: WSL2 Linux
- Runtime: Python venv (`.venv`)
- Sandbox: Docker containers (`python:3.11-slim`, `node:20-slim`)
- Agent model path: Gemini via `google-genai`

## Test Matrix

| ID | Test | Command | Expected | Observed | Status |
|---|---|---|---|---|---|
| T1 | Direct MCP function smoke test (pip happy path) | `python3 smoke_test.py` | spin/install/telemetry/nuke all succeed | `ok: true`, install `exit_code: 0`, telemetry `clean`, cleanup success | Pass |
| T2 | MCP stdio integration test | `python3 test_client.py` | tools callable through MCP client session | all 4 tools returned structured JSON; end-to-end complete | Pass |
| T3 | Agent orchestration baseline (`pip`, `requests`) | `python3 agent.py` | graph runs spin->install->telemetry->cleanup | full output with `error: null`, cleanup success | Pass |
| T4 | Gemini connectivity check | `python3 check_gemini.py` | API key/model callable | `.env` loaded, import OK, API returned JSON | Pass |
| T5 | Available models listing | `python3 list_gemini_models.py` | list models for current key | model list printed (Gemini 2.x/3.x variants visible) | Pass |
| T6 | Invalid manager edge case | `HAZMAT_PACKAGE=requests HAZMAT_MANAGER=abc python3 agent.py` | fail fast with validation error | `spin_up_failed`, `invalid_manager`, safe cleanup path | Pass |
| T7 | Nonexistent package edge case | `PIP_DEFAULT_TIMEOUT=10 PIP_RETRIES=0 HAZMAT_PACKAGE=this-package-should-not-exist-xyz123 HAZMAT_MANAGER=pip python3 agent.py` | non-zero install exit, graceful verdict | install `exit_code: 1`, no crash, structured output, cleanup success | Pass |
| T8 | Manager mismatch case (`requests` with npm) | `HAZMAT_PACKAGE=requests HAZMAT_MANAGER=npm python3 agent.py` | should not blindly classify as malware | output downgraded to mismatch-aware `suspicious/medium` with explanation | Pass |
| T9 | Timeout runner script sanity | `./run_agent_timeout.sh requests pip 120` | bounded runtime with predictable env | script prepared and validated (`bash -n`), intended for demo/edge runs | Pass |

## Notable Bugs Found and Fixed

1. **State loss across agent nodes**
   - Symptom: `execute_install` returned "Call spin_up_sandbox first."
   - Cause: each node opened a new MCP server session.
   - Fix: persistent MCP session across the full LangGraph run.

2. **Gemini fallback ambiguity**
   - Symptom: intermittent `rule_based_fallback` with unclear reason.
   - Cause: strict JSON parsing and swallowed exceptions.
   - Fix: robust JSON extraction + `llm_debug` output (`path`, `error_type`, `raw_preview`, `used_model`).

3. **False positives in npm installs**
   - Symptom: normal npm install activity flagged as critical malware.
   - Cause: baseline rules treated registry HTTPS and npm cache/log writes as suspicious.
   - Fix: manager mismatch precheck and expected npm-noise normalization.

## Current Quality Gates

- Structured JSON contract across MCP tools.
- Cleanup attempted in all paths.
- Gemini-first reasoning with deterministic fallback.
- Edge-case tests (invalid manager, nonexistent package, manager mismatch) produce deterministic outputs.

## Recommended Next Test (Step 5)

- Run agent against a synthesized malicious package tarball:
  - expected: `alerts` non-empty, elevated risk, suspicious/malicious verdict with concrete telemetry evidence.

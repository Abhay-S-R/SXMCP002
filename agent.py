import json
import os
import re
import sys
import uuid
from typing import Any, Dict, Optional, TypedDict

from langgraph.graph import END, StateGraph
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from dotenv import load_dotenv

# Auto-load environment variables from .env (if present).
load_dotenv()


class AgentState(TypedDict, total=False):
    package_name: str
    manager: str
    session_id: str
    spin_response: Dict[str, Any]
    install_response: Dict[str, Any]
    telemetry_response: Dict[str, Any]
    final_verdict: Dict[str, Any]
    cleanup_response: Dict[str, Any]
    llm_debug: Dict[str, Any]
    error: str
    mcp_session: Any
    precheck: Dict[str, Any]


def _parse_json_or_wrap(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except Exception:
        return {"ok": False, "status": "error", "raw_text": text, "error": "invalid_json_response"}


def _parse_llm_json(text: str) -> Dict[str, Any]:
    """
    Parse JSON from model output robustly.
    Handles:
    - raw JSON
    - fenced ```json ... ``` blocks
    - surrounding prose with embedded JSON object
    """
    stripped = (text or "").strip()
    # 1) Direct parse
    try:
        return json.loads(stripped)
    except Exception:
        pass

    # 2) Try fenced JSON blocks
    fence_matches = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, flags=re.DOTALL | re.IGNORECASE)
    for chunk in fence_matches:
        try:
            return json.loads(chunk)
        except Exception:
            continue

    # 3) Try extracting first JSON object with raw_decode
    decoder = json.JSONDecoder()
    for idx, ch in enumerate(stripped):
        if ch == "{":
            try:
                obj, _ = decoder.raw_decode(stripped[idx:])
                if isinstance(obj, dict):
                    return obj
            except Exception:
                continue

    return {"ok": False, "status": "error", "raw_text": stripped, "error": "invalid_json_response"}


async def _call_mcp_tool(session: ClientSession, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    response = await session.call_tool(tool_name, arguments=arguments)
    text = response.content[0].text if response.content else ""
    return _parse_json_or_wrap(text)


async def node_spin_up(state: AgentState) -> AgentState:
    session_id = state.get("session_id") or f"hazmat-{uuid.uuid4()}"
    resp = await _call_mcp_tool(
        state["mcp_session"],
        "spin_up_sandbox",
        {"manager": state["manager"], "session_id": session_id},
    )
    next_state: AgentState = {"session_id": session_id, "spin_response": resp, "mcp_session": state["mcp_session"]}
    if not resp.get("ok"):
        next_state["error"] = f"spin_up_failed: {resp.get('message') or resp.get('error')}"
    return next_state


async def node_install(state: AgentState) -> AgentState:
    if state.get("error"):
        return {"mcp_session": state["mcp_session"]}
    resp = await _call_mcp_tool(
        state["mcp_session"],
        "execute_install",
        {"package_name": state["package_name"], "manager": state["manager"]},
    )
    next_state: AgentState = {"install_response": resp, "mcp_session": state["mcp_session"]}
    if not resp.get("ok"):
        next_state["error"] = f"install_failed: {resp.get('message') or resp.get('error')}"
    return next_state


async def node_get_telemetry(state: AgentState) -> AgentState:
    if state.get("error"):
        return {"mcp_session": state["mcp_session"]}
    resp = await _call_mcp_tool(state["mcp_session"], "get_telemetry", {})
    next_state: AgentState = {"telemetry_response": resp, "mcp_session": state["mcp_session"]}
    if not resp.get("ok"):
        next_state["error"] = f"telemetry_failed: {resp.get('message') or resp.get('error')}"
    return next_state


def _rule_based_verdict(telemetry: Dict[str, Any]) -> Dict[str, Any]:
    alerts = telemetry.get("alerts", [])
    risk_level = telemetry.get("risk_level", "unknown")
    install = telemetry.get("install") or {}
    exit_code = install.get("exit_code")
    if risk_level == "critical":
        verdict = "malicious"
    elif risk_level in {"high", "medium"}:
        verdict = "suspicious"
    elif risk_level == "low" and exit_code == 0:
        verdict = "safe"
    else:
        verdict = "suspicious"
    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "evidence": alerts[:5],
        "reasoning_mode": "rule_based",
    }


KNOWN_PYPI_PACKAGES = {
    "requests",
    "numpy",
    "pandas",
    "scipy",
    "scikit-learn",
    "django",
    "flask",
    "fastapi",
    "pydantic",
    "pytest",
}

KNOWN_NPM_PACKAGES = {
    "react",
    "lodash",
    "express",
    "next",
    "vue",
    "typescript",
    "axios",
    "webpack",
    "vite",
}


def _manager_mismatch_precheck(package_name: str, manager: str) -> Dict[str, Any]:
    pkg = (package_name or "").strip().lower()
    mgr = (manager or "").strip().lower()
    if not pkg or mgr not in {"pip", "npm"}:
        return {"suspected": False, "reason": None}

    # npm scope/package format should not be used with pip.
    if mgr == "pip" and pkg.startswith("@"):
        return {"suspected": True, "reason": "scoped_npm_name_used_with_pip"}

    if mgr == "npm" and pkg in KNOWN_PYPI_PACKAGES:
        return {"suspected": True, "reason": "known_pypi_package_used_with_npm"}

    if mgr == "pip" and pkg in KNOWN_NPM_PACKAGES:
        return {"suspected": True, "reason": "known_npm_package_used_with_pip"}

    return {"suspected": False, "reason": None}


def _looks_like_expected_npm_install_noise(telemetry: Dict[str, Any], manager: str) -> bool:
    if (manager or "").strip().lower() != "npm":
        return False
    alerts = telemetry.get("alerts") or []
    if not alerts:
        return False

    install = telemetry.get("install") or {}
    if install.get("exit_code") != 0:
        return False

    network = telemetry.get("network") or {}
    tcp_added = network.get("tcp_added") or []
    if not tcp_added:
        return False
    # npm registry and similar normal installs are usually outbound 443
    if not all((item or {}).get("remote_port") == 443 for item in tcp_added):
        return False

    fs = telemetry.get("filesystem") or {}
    if not fs.get("changed"):
        return False
    after_tail = "\n".join(fs.get("after_tail") or [])
    npm_markers = ["/root/.npm/", "_update-notifier-last-checked", "_logs/"]
    if not any(marker in after_tail for marker in npm_markers):
        return False

    alert_text = " | ".join(alerts).lower()
    has_only_expected_alert_types = (
        "outbound connection" in alert_text and "file access/creation detected" in alert_text
    )
    return has_only_expected_alert_types


def _apply_post_analysis_guards(
    verdict: Dict[str, Any],
    telemetry: Dict[str, Any],
    package_name: str,
    manager: str,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    precheck = _manager_mismatch_precheck(package_name, manager)
    if precheck.get("suspected"):
        # Prevent false "malicious" conclusions for obvious manager mismatch cases.
        verdict["verdict"] = "suspicious"
        verdict["risk_level"] = "medium"
        verdict["summary"] = (
            f"Possible manager/package mismatch ({precheck['reason']}). "
            f"Re-test with the likely correct manager before treating as malware."
        )
        evidence = verdict.get("evidence") or []
        evidence.insert(0, f"Manager mismatch suspected: {precheck['reason']}")
        verdict["evidence"] = evidence[:5]

    elif _looks_like_expected_npm_install_noise(telemetry, manager):
        # Normalize known npm install side effects to avoid false positives.
        verdict["verdict"] = "safe"
        verdict["risk_level"] = "low"
        verdict["summary"] = (
            "Observed network/filesystem activity matches expected npm install behavior "
            "(registry HTTPS + npm cache/log writes)."
        )
        verdict["evidence"] = [
            "Observed outbound traffic is HTTPS (port 443) consistent with package registry access.",
            "Filesystem changes are confined to expected npm cache/log locations.",
        ]

    return verdict, precheck


def _llm_verdict_with_gemini(telemetry: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    api_key = os.getenv("GEMINI_API_KEY")
    model_name = os.getenv("HAZMAT_GEMINI_MODEL", "gemini-3.1-flash-lite-preview")
    debug: Dict[str, Any] = {
        "attempted": False,
        "path": "not_attempted",
        "used_model": model_name,
        "error_type": None,
        "error_message": None,
        "raw_preview": None,
    }
    if not api_key:
        debug["path"] = "no_api_key"
        return None, debug
    try:
        from google import genai

        debug["attempted"] = True
        client = genai.Client(api_key=api_key)
        prompt = (
            "You are a supply-chain security analyst.\n"
            "Given telemetry JSON, return STRICT JSON only with keys:\n"
            "verdict (safe|suspicious|malicious),\n"
            "risk_level (low|medium|high|critical),\n"
            "evidence (array of short strings),\n"
            "summary (string).\n"
            "Use only evidence present in telemetry."
        )
        resp = client.models.generate_content(
            model=model_name,
            contents=[prompt, json.dumps(telemetry)],
        )
        text = (resp.text or "").strip()
        debug["raw_preview"] = text[:200] if text else None
        parsed = _parse_llm_json(text)
        if "verdict" in parsed and "risk_level" in parsed:
            parsed["reasoning_mode"] = "llm_gemini"
            debug["path"] = "llm_success"
            return parsed, debug
        debug["path"] = "parse_failed"
        debug["error_type"] = "ParseError"
        debug["error_message"] = "Model response missing required keys: verdict/risk_level."
        return None, debug
    except Exception as exc:
        debug["path"] = "llm_exception"
        debug["error_type"] = exc.__class__.__name__
        debug["error_message"] = str(exc)[:200]
        return None, debug


def _gemini_first_verdict(telemetry: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """
    Model-first strategy:
    1) Gemini (if GEMINI_API_KEY present)
    2) Rule-based fallback
    """
    return _llm_verdict_with_gemini(telemetry)


async def node_analyze(state: AgentState) -> AgentState:
    if state.get("error"):
        return {
            "final_verdict": {"verdict": "suspicious", "summary": state["error"], "reasoning_mode": "error_path"},
            "llm_debug": {
                "attempted": False,
                "path": "skipped_due_to_error",
                "used_model": os.getenv("HAZMAT_GEMINI_MODEL", "gemini-3.1-flash-lite-preview"),
                "error_type": None,
                "error_message": None,
                "raw_preview": None,
            },
            "mcp_session": state["mcp_session"],
        }
    telemetry = (state.get("telemetry_response") or {}).get("telemetry", {})
    llm, llm_debug = _gemini_first_verdict(telemetry)
    verdict = llm if llm else _rule_based_verdict(telemetry)
    verdict, precheck = _apply_post_analysis_guards(
        verdict=verdict,
        telemetry=telemetry,
        package_name=state.get("package_name", ""),
        manager=state.get("manager", ""),
    )
    if not llm:
        verdict["reasoning_mode"] = "rule_based_fallback"
    if "summary" not in verdict:
        verdict["summary"] = telemetry.get("summary", "No summary available.")
    return {
        "final_verdict": verdict,
        "llm_debug": llm_debug,
        "precheck": precheck,
        "mcp_session": state["mcp_session"],
    }


async def node_cleanup(state: AgentState) -> AgentState:
    # Always attempt cleanup, even if previous nodes failed.
    session_id = state.get("session_id")
    resp = await _call_mcp_tool(
        state["mcp_session"],
        "nuke_sandbox",
        {"session_id": session_id} if session_id else {},
    )
    return {"cleanup_response": resp}


def _build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("spin_up", node_spin_up)
    graph.add_node("install", node_install)
    graph.add_node("get_telemetry", node_get_telemetry)
    graph.add_node("analyze", node_analyze)
    graph.add_node("cleanup", node_cleanup)

    graph.set_entry_point("spin_up")
    graph.add_edge("spin_up", "install")
    graph.add_edge("install", "get_telemetry")
    graph.add_edge("get_telemetry", "analyze")
    graph.add_edge("analyze", "cleanup")
    graph.add_edge("cleanup", END)
    return graph.compile()


async def _run_hazmat_audit_async(package_name: str, manager: str = "pip") -> Dict[str, Any]:
    app = _build_graph()
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["hazmat_server.py"],
        env=os.environ.copy(),
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            initial: AgentState = {
                "package_name": package_name,
                "manager": manager,
                "mcp_session": session,
            }
            result = await app.ainvoke(initial)
            return {
                "package_name": package_name,
                "manager": manager,
                "session_id": result.get("session_id"),
                "spin_response": result.get("spin_response"),
                "install_response": result.get("install_response"),
                "telemetry_response": result.get("telemetry_response"),
                "final_verdict": result.get("final_verdict"),
                "llm_debug": result.get("llm_debug"),
                "precheck": result.get("precheck"),
                "cleanup_response": result.get("cleanup_response"),
                "error": result.get("error"),
            }


def run_hazmat_audit(package_name: str, manager: str = "pip") -> Dict[str, Any]:
    import asyncio

    return asyncio.run(_run_hazmat_audit_async(package_name=package_name, manager=manager))


if __name__ == "__main__":
    pkg = os.getenv("HAZMAT_PACKAGE", "requests")
    mgr = os.getenv("HAZMAT_MANAGER", "pip")
    output = run_hazmat_audit(package_name=pkg, manager=mgr)
    print(json.dumps(output, indent=2, sort_keys=True))

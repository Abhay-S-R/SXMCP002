import json
import sys
from pathlib import Path

# Allow `python tests/smoke_test.py` without `pip install -e .`
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import hazmat_mcp.server as hz

print("1) spin_up_sandbox")
resp1 = json.loads(hz.spin_up_sandbox(manager="pip", session_id="demo-001"))
print(json.dumps(resp1, indent=2)[:500])

print("\n2) execute_install")
resp2 = json.loads(hz.execute_install("six", manager="pip"))
print("ok:", resp2.get("ok"))
print("exit_code:", (resp2.get("install") or {}).get("exit_code"))

print("\n3) get_telemetry")
resp3 = json.loads(hz.get_telemetry())
telemetry = resp3.get("telemetry", {})
print("ok:", resp3.get("ok"))
print("session_id:", telemetry.get("session_id"))
print("network_verdict:", (telemetry.get("network") or {}).get("verdict"))
print("tcp_added_count:", len((telemetry.get("network") or {}).get("tcp_added", [])))
print("fs_changed:", (telemetry.get("filesystem") or {}).get("changed"))

print("\n4) nuke_sandbox")
resp4 = json.loads(hz.nuke_sandbox(session_id="demo-001"))
print(json.dumps(resp4, indent=2))
import asyncio
import json
import os
import sys
from pathlib import Path
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def run_tests() -> None:
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["hazmat_server.py"],
        env=os.environ.copy(),
    )

    tgz_path = (
        Path(__file__).resolve().parent
        / "demo_packages"
        / "react-helper-dom"
        / "react-helper-dom-1.0.0.tgz"
    )
    if not tgz_path.exists():
        raise FileNotFoundError(f"Missing demo tarball: {tgz_path}")

    print("Starting npm tgz MCP test sequence...\n")
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("1) spin_up_sandbox(manager=npm)")
            r1 = await session.call_tool("spin_up_sandbox", arguments={"manager": "npm", "session_id": "demo-npm-tgz"})
            print(r1.content[0].text)

            print("\n2) execute_install(package_source=.tgz)")
            r2 = await session.call_tool(
                "execute_install",
                arguments={
                    "manager": "npm",
                    "package_source": str(tgz_path),
                },
            )
            payload2 = json.loads(r2.content[0].text)
            print(json.dumps(payload2, indent=2))

            print("\n3) get_telemetry()")
            r3 = await session.call_tool("get_telemetry", arguments={})
            payload3 = json.loads(r3.content[0].text)
            telemetry = payload3.get("telemetry", {})
            print("risk_level:", telemetry.get("risk_level"))
            print("alerts:", telemetry.get("alerts"))
            print("tcp_added_count:", len((telemetry.get("network") or {}).get("tcp_added", [])))
            print("fs_changed:", (telemetry.get("filesystem") or {}).get("changed"))

            print("\n4) nuke_sandbox()")
            r4 = await session.call_tool("nuke_sandbox", arguments={"session_id": "demo-npm-tgz"})
            print(r4.content[0].text)

    print("\nDone. Step 5B path validated.")


if __name__ == "__main__":
    asyncio.run(run_tests())

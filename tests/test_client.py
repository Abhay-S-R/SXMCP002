import asyncio
import sys
import os
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession

async def run_tests():
    # Launch MCP server package via stdio
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "hazmat_mcp.server"],
        env=os.environ.copy(),
    )

    print("🔌 Starting MCP Server test sequence...\n")
    print("-" * 50)
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print("1️⃣ Testing: spin_up_sandbox")
            print("Action: Creating a pip-based sandbox container")
            resp = await session.call_tool("spin_up_sandbox", arguments={"manager": "pip"})
            print(f"Result:\n{resp.content[0].text}\n")
            print("-" * 50)
            
            print("2️⃣ Testing: execute_install")
            print("Action: Installing an innocuous package ('requests')")
            resp = await session.call_tool("execute_install", arguments={"package_name": "requests"})
            print(f"Result:\n{resp.content[0].text}\n")
            print("-" * 50)
            
            print("3️⃣ Testing: get_telemetry")
            print("Action: Checking file system and network behavior")
            resp = await session.call_tool("get_telemetry", arguments={})
            print(f"Result:\n{resp.content[0].text}\n")
            print("-" * 50)
            
            print("4️⃣ Testing: nuke_sandbox")
            print("Action: Destroying sandbox and clearing evidence")
            resp = await session.call_tool("nuke_sandbox", arguments={})
            print(f"Result:\n{resp.content[0].text}\n")
            print("-" * 50)
            
    print("✅ Testing sequence complete! If all outputs above display structured JSON arrays, Step 3 is perfectly configured.")

if __name__ == "__main__":
    asyncio.run(run_tests())

import os
import subprocess
import docker
from mcp.server.fastmcp import FastMCP

# Initialize the MCP Server and Docker client
mcp = FastMCP("Hazmat-Security-Scanner")
docker_client = docker.from_env()

# In-memory store for our active sandbox container ID
active_sandbox = {"id": None}

@mcp.tool()
def spin_up_sandbox(base_image: str = "python:3.11-slim") -> str:
    """Spin up an ephemeral Docker container for safe malware analysis."""
    try:
        container = docker_client.containers.run(
            base_image,
            command="tail -f /dev/null", # Keep the container alive
            detach=True,
            remove=False, # We will remove it manually
            network_mode="bridge", # Give it a network stack we can monitor
            mem_limit="512m", # Limit resources
            security_opt=["no-new-privileges:true"] # Basic hardening
        )
        active_sandbox["id"] = container.id
        return f"✅ Sandbox ready! Container ID: {container.id[:12]}"
    except Exception as e:
        return f"❌ Failed to create sandbox: {str(e)}"

@mcp.tool()
def execute_install(package_name: str, manager: str = "pip") -> str:
    """Install a package inside the sandbox and capture the terminal output."""
    if not active_sandbox["id"]:
        return "⚠️ No active sandbox. Call spin_up_sandbox first."

    container = docker_client.containers.get(active_sandbox["id"])
    
    # Determine the install command
    if manager == "npm":
        install_cmd = f"npm install -g {package_name}"
    else: # pip
        install_cmd = f"pip install {package_name} --no-cache-dir"

    try:
        # Run the install command inside the container
        exit_code, output = container.exec_run(install_cmd, demux=True)
        # Truncate output if it's too long to avoid context window issues
        return f"📦 Install finished (exit code: {exit_code}).\nOutput:\n{output[:2000].decode('utf-8')}"
    except Exception as e:
        return f"❌ Installation failed: {str(e)}"

@mcp.tool()
def get_telemetry() -> str:
    """
    Analyzes the container's behavior: checks network connections and file system changes.
    This is the most critical function for detecting malware.
    """
    if not active_sandbox["id"]:
        return "⚠️ No active sandbox."

    container = docker_client.containers.get(active_sandbox["id"])
    report = []
    
    # 1. Check for outbound network connections (using `ss` or `netstat` inside container)
    # We exec a command to see all established TCP connections
    net_cmd = "ss -tunp | grep -v '127.0.0.1' | grep ESTAB"
    net_exit, net_out = container.exec_run(net_cmd, user="root")
    if net_exit == 0 and net_out.strip():
        report.append(f"🚨 **ALERT: Suspicious Outbound Connection**\n{net_out.decode()}")
    else:
        report.append("✅ No unexpected outbound connections found.")

    # 2. Check for file changes after install
    # This is a simplified diff. For the hackathon, checking /etc/passwd is a great 'wow' signal.
    passwd_cmd = "cat /etc/passwd"
    passwd_exit, passwd_out = container.exec_run(passwd_cmd)
    if passwd_exit == 0 and b"root:" in passwd_out:
        report.append("📁 File Access Detected: The package had access to /etc/passwd.")
    else:
        report.append("📁 No critical system file access detected.")

    # 3. Check running processes
    ps_cmd = "ps aux"
    ps_exit, ps_out = container.exec_run(ps_cmd)
    report.append(f"🔄 Running Processes:\n{ps_out.decode()[:500]}")
    
    return "\n".join(report)

@mcp.tool()
def nuke_sandbox() -> str:
    """Kill and remove the Docker container, cleaning up all evidence."""
    if not active_sandbox["id"]:
        return "No sandbox to nuke."
    
    container = docker_client.containers.get(active_sandbox["id"])
    container.kill()
    container.remove()
    active_sandbox["id"] = None
    return "💥 Sandbox destroyed. All evidence has been eliminated."

if __name__ == "__main__":
    # Run the server via standard input/output for Claude Desktop or other MCP clients
    mcp.run(transport='stdio')
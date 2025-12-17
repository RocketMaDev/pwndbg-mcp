from pwndbg_mcp.gdb_controller import AsyncGdbController
import pwndbg_mcp.tools as tools
import logging
from fastmcp import FastMCP

mcp = FastMCP('pwndbg-mcp')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Register MCP tools
@mcp.tool()
async def load_executable(executable_path: str, args: list[str] | None = None) -> str:
    return await tools.load_executable(executable_path, args)


@mcp.tool()
async def execute_command(command: str) -> str:
    return await tools.execute_command(command)


@mcp.tool()
async def send_to_process(data: str) -> str:
    return await tools.send_to_process(data)


@mcp.tool()
async def read_from_process(size: int = 1024, timeout: float = 1.0) -> str:
    return await tools.read_from_process(size, timeout)

@mcp.tool()
async def pwndbg_status() -> str:
    return await tools.pwndbg_status()

# Pwndbg command wrappers
@mcp.tool()
async def list_pwndbg_commands() -> str:
    return await tools.execute_command("pwndbg --all")

@mcp.tool()
async def telescope(address: str, count: int = 10) -> str:
    return await tools.execute_command(f"telescope {address} {count}")

@mcp.tool()
async def context() -> str:
    return await tools.execute_command("context")

@mcp.tool()
async def heap() -> str:
    return await tools.execute_command("heap")

@mcp.tool()
async def bins() -> str:
    return await tools.execute_command("bins")

@mcp.tool()
async def stack(count: int = 10) -> str:
    return await tools.execute_command(f"stack {count}")

@mcp.tool()
async def backtrace() -> str:
    return await tools.execute_command("backtrace")

@mcp.tool()
async def procinfo() -> str:
    return await tools.execute_command("procinfo")

@mcp.tool()
async def tls() -> str:
    return await tools.execute_command("tls")

@mcp.tool()
async def disassemble(function_name: str) -> str:
    return await tools.execute_command(f"disassemble {function_name}")

@mcp.tool()
async def vmmap() -> str:
    return await tools.execute_command("vmmap")

@mcp.tool()
async def checksec() -> str:
    return await tools.execute_command("checksec")


def launch_mcp(mode: str, host: str | None = None, port: int | None = None):
    mcp.run(mode, host=host, port=port)

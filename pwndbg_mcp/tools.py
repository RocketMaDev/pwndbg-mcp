import logging
from pwndbg_mcp.gdb_controller import AsyncGdbController
from pwndbg_mcp.toon_formatter import ToonFormatter
from pwn import *

from fastmcp import FastMCP

mcp = FastMCP('pwndbg-mcp')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

_gdb_controller: AsyncGdbController | None = None
gdb_path: str = None


async def may_start_gdb() -> AsyncGdbController:
    global _gdb_controller
    if _gdb_controller is None:
        _gdb_controller = AsyncGdbController(gdb_path)
        await _gdb_controller.start()
    return _gdb_controller


# GDB controller part
@mcp.tool()
async def load_executable(executable_path: str, args: list[str] | None = None) -> str:
    """Load an executable file into GDB and set up PTY for process I/O.

    Args:
        executable_path: Path to the executable file
        args: Command-line arguments for the program

    Returns:
        TOON-formatted GDB responses
    """
    gdb = await may_start_gdb()
    logging.info(f'{gdb}')

    # Load executable
    responses = await gdb.execute(f'-file-exec-and-symbols "{executable_path}"')

    # Set arguments if provided
    if args:
        args_str = " ".join(args)
        await gdb.execute(f'-exec-arguments {args_str}')

    return ToonFormatter.format_response(responses, f"load {executable_path}")


async def execute_command(command: str) -> str:
    """Execute an arbitrary GDB command.

    Args:
        command: GDB command to execute, use ` ` to split args

    Returns:
        TOON-formatted GDB responses or null if GDB is waiting tracee
    """
    gdb = await may_start_gdb()
    responses = await gdb.execute(command)
    return ToonFormatter.format_response(responses, command)


# process controller part
@mcp.tool()
async def send_to_process(data: str) -> str:
    """Send data to the target process through PTY.

    Args:
        data: String to send to the process

    Returns:
        how many bytes sent if successfully sent
    """
    gdb = await may_start_gdb()
    if all(ord(ch) < 0x100 for ch in data):
        await gdb.send_to_process(data.encode('latin1'))
    else:
        await gdb.send_to_process(data.encode())
    return ToonFormatter.format_simple(f"Sent {len(data)} chars to process")

@mcp.tool()
async def eval_to_send_to_process(statement: str) -> str:
    """Given `statement`, evaluate it in Python and `bytes()` it,
    then send to process. This tool is not that safe.
    e.g. eval_to_send_to_process('flat(0x333, 0x222) + p64(1)')

    Args:
        statement: Python statement to evalute. pwntools have already imported.

    Returns:
        the evaluate result if successfully sent, or the error if not able
        to `bytes()` it
    """
    gdb = await may_start_gdb()
    try:
        result = eval(statement)
    except Exception as e:
        return ToonFormatter.format_simple({'status': 'error',
            'detail': f'Can not eval statement, raised {e}'})
    try:
        bytes_result = bytes(result)
    except Exception as e:
        return ToonFormatter.format_simple({'status': 'error',
            'detail': f"Can not convert eval'ed result to bytes, raised {e}"})

    await gdb.send_to_process(bytes_result)
    return ToonFormatter.format_simple({'status': 'success',
            'detail': str(result)})

@mcp.tool()
async def read_from_process(size: int = 1024, timeout: float = 1.0) -> str:
    """Read data from the target process through PTY.

    Args:
        size: Maximum bytes to read
        timeout: Read timeout in seconds

    Returns:
        TOON-formatted result with data read from process;
        raw str decoded from process if all bytes are printable,
        hexdump result if unprintable bytes found.
    """
    gdb = await may_start_gdb()
    data = await gdb.read_from_process(size, timeout)
    return ToonFormatter.format_simple(data)

@mcp.tool()
async def interrupt_process() -> str:
    """Interrupt target process through PTY. Equivalent to press Ctrl-C
    """
    gdb = await may_start_gdb()
    await gdb.interrupt_process()
    return ToonFormatter.format_simple('Interrupt request sent')

@mcp.tool()
async def pwndbg_status() -> str:
    """Return gdb status

    Returns:
        TOON-formatted gdb status
    """
    gdb = await may_start_gdb()
    return ToonFormatter.format_simple({"gdb": gdb.state})


###########################################################
# some aliases
###########################################################
@mcp.tool()
async def list_pwndbg_commands() -> str:
    """If you don't know all pwndbg commands, run this tool first to
    explore pwndbg commands usages. If you find any interesting command not
    in tool list, or you want to set more args, please invoke the command
    by `execute_command` directly.

    Return:
        pwndbg commands list
    """
    return await execute_command("pwndbg --all")

@mcp.tool()
async def telescope(statement: str, count: int = 10) -> str:
    """Examine given address `statement` with `count` words,
    dereference pointers if valid.

    Args:
        statement: a raw address or a statement can be eval'ed to address
        count: words to deref

    Returns:
        derefing address block results
    """
    return await execute_command(f"telescope {statement} {count}")

@mcp.tool()
async def context(subsection: str | None = None) -> str:
    """Display pwndbg section with `subsection` or leave it to null
    to display default context defined by `context-sections`.

    Args:
        subsection: null to display default context, or one of 'regs', 'disasm',
        'code', 'stack', 'backtrace', 'ghidra', 'args', 'threads', 'heap_tracker',
        'expressions', 'last_signal'
    Returns:
        program context
    """
    if subsection is None:
        return await execute_command("context")
    return await execute_command(f"context {subsection}")

@mcp.tool()
async def heap() -> str:
    """Examine heap with pwndbg

    Returns:
        overall heap status
    """
    return await execute_command("heap")

@mcp.tool()
async def bins() -> str:
    """Examine available chunks with pwndbg command bins

    Returns:
        overall bins status
    """
    return await execute_command("bins")

@mcp.tool()
async def backtrace() -> str:
    """Display program function backtrace

    Returns:
        gdb backtrace view
    """
    return await execute_command("backtrace")

@mcp.tool()
async def procinfo() -> str:
    """Display current process infomation

    Returns:
        process info including pid, opened fd, etc
    """
    return await execute_command("procinfo")

@mcp.tool()
async def vmmap() -> str:
    """Display current program memory layout

    Returns:
        maps layout
    """
    return await execute_command("vmmap")

def launch_mcp(mode: str, host: str | None = None, port: int | None = None):
    mcp.tool(execute_command)
    mcp.run(mode, host=host, port=port)

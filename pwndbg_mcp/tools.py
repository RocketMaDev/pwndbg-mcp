from pwndbg_mcp.gdb_controller import AsyncGdbController, GdbState, update_gdb_state, process_responses
from pwndbg_mcp.toon_formatter import format_response, format_simple
from pwn import *
import logging
import socket
from concurrent import futures
from dataclasses import dataclass

from fastmcp import FastMCP

mcp = FastMCP('pwndbg-mcp')

@dataclass
class D2dSetup:
    name: str
    host: str | None
    port: int | None

    def __init__(self, d2dname: str, d2dhost: str | None, d2dport: int | None) -> None:
        if not d2dname.isalnum():
            raise RuntimeError('decomp2dbg section name only accept alphanumeric names')
        self.name = d2dname
        if d2dhost:
            with futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(socket.getaddrinfo, d2dhost, None)
                try:
                    future.result(timeout=3)
                except futures.TimeoutError:
                    raise RuntimeError('Resolve d2dhost timeout, perhaps use a ip address') from None
                except socket.gaierror as e:
                    raise RuntimeError('Can not resolve d2dhost') from e
        elif not d2dhost:
            d2dhost = None
        self.host = d2dhost

        if d2dport and (d2dport < 1 or d2dport > 65535):
            raise RuntimeError(f'Invalid decomp2dbg port {d2dport}')
        self.port = d2dport

    def __str__(self) -> str:
        if self.host:
            return f'{self.name} --host {self.host} --port {self.port}'
        if self.port:
            return f'{self.name} --port {self.port}'
        return self.name

d2d_setup: D2dSetup | None = None

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
    # start if need or restart if dead
    if _gdb_controller is None:
        _gdb_controller = AsyncGdbController(gdb_path)
        await _gdb_controller.start()
    if _gdb_controller.state is GdbState.DEAD:
        await _gdb_controller.close()
        _gdb_controller = AsyncGdbController(gdb_path)
        await _gdb_controller.start()
    return _gdb_controller


# GDB controller part
@mcp.tool(output_schema=None)
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

    return format_response(responses, f"load {executable_path}")


async def execute_command(command: str) -> str:
    """Execute an arbitrary GDB command.

    Args:
        command: GDB command to execute, use ` ` to split args

    Returns:
        TOON-formatted GDB responses or null if GDB is waiting tracee
    """
    gdb = await may_start_gdb()
    responses = await gdb.execute(command)
    return format_response(responses, command)

AVAILABLE_ACTIONS = [
    'c', 'n', 'r', 's', 'kill', 'fin', 'ni', 'si', 'entry', 'start',
    'sstart', 'nextcall', 'nextjmp', 'nextret', 'nextsyscall', 'nextproginstr',
    'stepover', 'stepret', 'strpsyscall', 'stepuntilasm', 'xuntil',
]
@mcp.tool(output_schema=None)
async def debug_control(action: str) -> str:
    """Control tracee running state by step, next or finish, etc. Use this prior
    than running individual execute_command to separate state control and actual command.

    Args:
        action: Any of 'c', 'n', 'r', 's', 'kill', 'fin', 'ni', 'si', 'entry', 'start',
        'sstart', 'nextcall', 'nextjmp', 'nextret', 'nextsyscall', 'nextproginstr',
        'stepover', 'stepret', 'strpsyscall', 'stepuntilasm', 'xuntil'
    Returns:
        GDB responses or null if GDB is waiting tracee
    """
    if action in AVAILABLE_ACTIONS:
        return await execute_command(action)
    return format_simple({'error': 'Unknown state action. Take a look at documentation'})

async def connect_decomp2dbg() -> str:
    """Try to connect to decomp2dbg bridge with setup provided in cli. Requires
    decomp2dbg loaded into GDB and have a started debug.

    Returns:
        GDB responses
    """
    assert d2d_setup
    return await execute_command(f'decompiler connect {d2d_setup}')

# process controller part
@mcp.tool(output_schema=None)
async def send_to_process(data: str) -> str:
    """Send data to the target process through PTY in raw mode.

    Args:
        data: String to send to the process

    Returns:
        how many bytes sent if successfully sent
    """
    gdb = await may_start_gdb()
    if all(ord(ch) < 0x100 for ch in data):
        tosend = data.encode('latin1')
    else:
        tosend = data.encode()
    await gdb.send_to_process(tosend)
    return format_simple(f"Sent {len(data)} bytes to process")

@mcp.tool(output_schema=None)
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
        return format_simple({'status': 'error',
            'detail': f'Can not eval statement, raised {e}'})
    try:
        bytes_result = bytes(result)
    except Exception as e:
        return format_simple({'status': 'error',
            'detail': f"Can not convert eval'ed result to bytes, raised {e}"})

    await gdb.send_to_process(bytes_result)
    return format_simple({'status': 'success',
            'detail': str(result)})

@mcp.tool(output_schema=None)
async def read_from_process(size: int = 1024, timeout: int = 5) -> str:
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
    return format_simple(data)

CTRL_MAP = {
    'C-c': (b'\x03', 'SIGINT'),
    'C-d': (b'\x04', 'EOF'),
    'C-z': (b'\x1a', 'SIGTSTP'),
}
@mcp.tool(output_schema=None)
async def interrupt_process(ctrl: str | None = None) -> str:
    """Interrupt target process through PTY. Equivalent to press Ctrl-C, Ctrl-Z or Ctrl-D

    Args:
        ctrl: Default is "Ctrl-C". Any of "C-c", "C-z" or "C-d"
    """
    gdb = await may_start_gdb()
    tosend = CTRL_MAP.get(ctrl if ctrl is not None else 'C-c', None)
    if tosend:
        await gdb.interrupt_process(tosend[0])
        return format_simple(f'Interrupt request {tosend[1]} sent')

    return format_simple({'error': 'No such ctrl char'})

@mcp.tool(output_schema=None)
async def pwndbg_status() -> str:
    """Return GDB status and additional GDB messages if some new messages
    available since last execute

    Returns:
        TOON-formatted GDB status and GDB responses if available
    """
    gdb = await may_start_gdb()
    if gdb.state is not GdbState.RUNNING:
        return format_simple({"gdb": gdb.state})

    resps = await gdb.get_responses()
    if not resps:
        return format_simple({"gdb": gdb.state})
    if new_state := update_gdb_state(resps):
        gdb.state = new_state
    process_responses(resps)
    return format_response(resps, f'gdb now has state {new_state}')


@mcp.tool(output_schema=None)
async def pwndbg_hard_reset() -> str:
    """Hard reset pwndbg status by reset gdb controller. If interrupt can not stop process,
    call this to restart debug session.

    Returns:
        New gdb message
    """
    gdb = await may_start_gdb()
    await gdb.close()
    await may_start_gdb()
    return format_simple('success')

###########################################################
# some aliases
###########################################################
@mcp.tool(output_schema=None)
async def list_pwndbg_commands() -> str:
    """If you don't know all pwndbg commands, run this tool first to
    explore pwndbg commands usages. If you find any interesting command not
    in tool list, or you want to set more args, please invoke the command
    by `execute_command` directly.

    Return:
        pwndbg commands list or null if pwndbg waiting
    """
    return await execute_command("pwndbg --all")

@mcp.tool(output_schema=None)
async def telescope(statement: str, count: int = 10) -> str:
    """Examine given address `statement` with `count` words,
    dereference pointers if valid.

    Args:
        statement: a raw address or a statement can be eval'ed to address
        count: words to deref

    Returns:
        derefing address block results or null if pwndbg waiting
    """
    return await execute_command(f"telescope {statement} {count}")

@mcp.tool(output_schema=None)
async def context(subsection: str | None = None) -> str:
    """Display pwndbg section with `subsection` or leave it to null
    to display default context defined by `context-sections`.

    Args:
        subsection: null to display default context, or one of 'regs', 'disasm',
        'code', 'stack', 'backtrace', 'ghidra', 'args', 'threads', 'heap_tracker',
        'expressions', 'last_signal'
    Returns:
        program context or null if pwndbg waiting
    """
    if subsection is None:
        return await execute_command("context")
    return await execute_command(f"context {subsection}")

@mcp.tool(output_schema=None)
async def heap() -> str:
    """Examine heap with pwndbg

    Returns:
        overall heap status or null if pwndbg waiting
    """
    return await execute_command("heap")

@mcp.tool(output_schema=None)
async def bins() -> str:
    """Examine available chunks with pwndbg command bins

    Returns:
        overall bins status or null if pwndbg waiting
    """
    return await execute_command("bins")

@mcp.tool(output_schema=None)
async def backtrace() -> str:
    """Display program function backtrace

    Returns:
        gdb backtrace view or null if pwndbg waiting
    """
    return await execute_command("backtrace")

@mcp.tool(output_schema=None)
async def procinfo() -> str:
    """Display current process infomation

    Returns:
        process info including pid, opened fd, etc or null if pwndbg waiting
    """
    return await execute_command("procinfo")

@mcp.tool(output_schema=None)
async def vmmap(pattern: str | None = None) -> str:
    """Display current program memory layout or pages match pattern

    Args:
        pattern: match the name of page, e.g. libc
    Returns:
        maps layout or null if pwndbg waiting
    """
    if pattern:
        return await execute_command(f'vmmap {pattern}')
    return await execute_command("vmmap")

@mcp.tool(output_schema=None)
async def xinfo(statement: str) -> str:
    """Shows offsets of the specified address from various useful locations

    Args:
        statement: address or statement that can be eval'ed to address
    Returns:
        Related address offsets or null if pwndbg waiting
    """
    return await execute_command(f'xinfo {statement}')

def launch_mcp(mode: str, host: str | None = None, port: int | None = None):
    mcp.tool(execute_command, output_schema=None)
    if d2d_setup:
        mcp.tool(connect_decomp2dbg, output_schema=None)
    if mode == 'stdio':
        mcp.run(mode)
    else:
        mcp.run(mode, host=host, port=port)

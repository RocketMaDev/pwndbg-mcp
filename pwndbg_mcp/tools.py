"""MCP tools for pwndbg debugging."""

import logging
from pwndbg_mcp.gdb_controller import AsyncGdbController, GdbState
from pwndbg_mcp.toon_formatter import ToonFormatter

_gdb_controller: AsyncGdbController | None = None
gdb_path: str = None


async def may_start_gdb() -> AsyncGdbController:
    global _gdb_controller
    if _gdb_controller is None:
        _gdb_controller = AsyncGdbController(gdb_path)
        await _gdb_controller.start()
    return _gdb_controller


async def load_executable(executable_path: str, args: list[str] | None = None) -> str:
    """Load an executable file into GDB and set up PTY for process I/O.

    Args:
        executable_path: Path to the executable file
        args: Command-line arguments for the program

    Returns:
        TOON-formatted result
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
        command: GDB command to execute

    Returns:
        TOON-formatted result
    """
    gdb = await may_start_gdb()
    responses = await gdb.execute(command, raise_error=False)
    return ToonFormatter.format_response(responses, command)


async def send_to_process(data: str) -> str:
    """Send data to the target process through PTY.

    Args:
        data: String to send to the process

    Returns:
        TOON-formatted result
    """
    gdb = await may_start_gdb()
    await gdb.send_to_process(data)
    return ToonFormatter.format_simple(f"Sent {len(data)} bytes to process")


async def read_from_process(size: int = 1024, timeout: float = 1.0) -> str:
    """Read data from the target process through PTY.

    Args:
        size: Maximum bytes to read
        timeout: Read timeout in seconds

    Returns:
        TOON-formatted result with data read from process
    """
    gdb = await may_start_gdb()
    data = await gdb.read_from_process(size, timeout)
    return ToonFormatter.format_simple(data)

async def interrupt_process() -> str:
    """Interrupt target process through PTY.
    """
    gdb = await may_start_gdb()
    await gdb.interrupt_process()
    return ToonFormatter.format_simple('Interrupt request sent')

async def pwndbg_status() -> str:
    gdb = await may_start_gdb()
    if gdb.state is GdbState.DEAD:
        return ToonFormatter.format_simple('No file loaded')
    return ToonFormatter.format_simple('Gdb running')

from toon import encode
from pwndbg_mcp.gdb_controller import GdbResponse
from typing import Any


def format_response(responses: list[GdbResponse], command: str = "") -> str:
    """Format GDB responses as TOON.

    Args:
        responses: List of GDB responses
        command: Original command (for context)

    Returns:
        TOON-formatted string
    """
    # Extract console output

    # Format using TOON
    result = {
        "command": command,
        "output": [
            { 'type': r.mitype, 'msg': r.message }
            for r in responses
        ] if responses else responses, # pass through None
    }

    return encode(result)

def format_simple(text: Any) -> str:
    """Format simple text output as TOON.

    Args:
        text: Plain text output

    Returns:
        TOON-formatted string
    """
    return encode(text)

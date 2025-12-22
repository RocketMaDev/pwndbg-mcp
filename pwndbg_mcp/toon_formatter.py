"""TOON formatter for GDB outputs."""

from toon_format import encode
from pwndbg_mcp.gdb_controller import GdbResponse


class ToonFormatter:
    """Formatter to convert GDB outputs to TOON format."""

    @staticmethod
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
            ],
        }

        return encode(result)

    @staticmethod
    def format_simple(text: str) -> str:
        """Format simple text output as TOON.

        Args:
            text: Plain text output

        Returns:
            TOON-formatted string
        """
        return encode(text)

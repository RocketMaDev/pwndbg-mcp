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
        console_output = []
        result_data = None

        for resp in responses:
            if resp.type in ("console", "log", "target") and resp.payload:
                console_output.append(resp.payload)
            elif resp.type == "result" and resp.payload:
                result_data = resp.payload

        output_text = "".join(console_output)

        # Format using TOON
        result = {
            "command": command,
            "output": output_text
        }

        if result_data:
            result["data"] = result_data

        return encode(result)

    @staticmethod
    def format_simple(text: str) -> str:
        """Format simple text output as TOON.

        Args:
            text: Plain text output

        Returns:
            TOON-formatted string
        """
        return encode({"output": text})

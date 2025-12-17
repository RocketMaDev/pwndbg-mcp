import argparse
from typing import cast
from pwndbg_mcp import server, tools

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='pwndbg-mcp: MCP server for pwndbg debugging')
    parser.add_argument('--transport', '-t', choices=['stdio', 'http', 'sse'], default='http',
        help='Transport mode: stdio, http (streamable HTTP, default), or sse')
    parser.add_argument('--host', '-H', default='localhost',
        help='Host for HTTP/SSE modes (default: localhost)')
    parser.add_argument('--port', '-p', type=int, default=8780,
        help='Port for HTTP/SSE modes (default: 8780)')
    parser.add_argument('--pwndbg', '-b', default='gdb',
        help='pwndbg binary to launch (default: gdb)')
    args = parser.parse_args()
    tools.gdb_path = args.pwndbg
    cast(str, args.transport)

    match args.transport:
        case 'stdio':
            server.launch_mcp(args.transport)
        case 'http' | 'sse':
            server.launch_mcp(args.transport, args.host, args.port)
        case trans:
            assert not f'Unknown transport {trans}'

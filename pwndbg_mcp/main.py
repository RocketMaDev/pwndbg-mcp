import argparse
from typing import cast
from pwndbg_mcp import tools

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
    parser.add_argument('--unsafe', '-U', action='store_true',
        help='Allow mcp to run eval() to send request like pwntools, '
             'ONLY ENABLE THIS IF YOU DID ISOLATION!')
    args = parser.parse_args()
    cast(str, args.transport)
    cast(bool, args.unsafe)
    tools.gdb_path = args.pwndbg

    match args.transport:
        case 'stdio':
            tools.launch_mcp(args.transport, unsafe=args.unsafe)
        case 'http' | 'sse':
            tools.launch_mcp(args.transport, args.host, args.port, unsafe=args.unsafe)
        case trans:
            assert not f'Unknown transport {trans}'

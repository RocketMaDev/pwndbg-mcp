import argparse
from typing import cast
from pwndbg_mcp import tools
import sys

DESC = 'An MCP tool endows AI agent with the capability to debug ELF'

def main():
    parser = argparse.ArgumentParser(description=f'pwndbg-mcp: {DESC}')
    parser.add_argument('--transport', '-t', choices=['stdio', 'http', 'sse'], default='http',
        help='Transport mode: stdio, http (streamable HTTP, default), or sse')
    parser.add_argument('--host', '-H', default='localhost',
        help='Host for HTTP/SSE modes (default: localhost)')
    parser.add_argument('--port', '-p', type=int, default=8780,
        help='Port for HTTP/SSE modes (default: 8780)')
    parser.add_argument('--pwndbg', '-b', default='gdb', metavar='BIN',
        help='pwndbg binary to launch (default: gdb)')
    parser.add_argument('--d2dname', '-d', metavar='NAME',
        help='Decomp2dbg section display name. Set this to enable decomp2dbg support')
    parser.add_argument('--d2dhost', '-D', metavar='HOST',
        help='Decomp2dbg connection host')
    parser.add_argument('--d2dport', '-P', type=int, metavar='PORT',
        help='Decomp2dbg connection port')
    args = parser.parse_args()
    cast(str, args.transport)
    cast(str, args.d2dname)
    tools.gdb_path = args.pwndbg

    if args.d2dname:
        try:
            setup = tools.D2dSetup(args.d2dname, args.d2dhost, args.d2dport)
        except RuntimeError as e:
            print(e.args[0])
            sys.exit(1)
        tools.d2d_setup = setup

    match args.transport:
        case 'stdio':
            tools.launch_mcp(args.transport)
        case 'http' | 'sse':
            tools.launch_mcp(args.transport, args.host, args.port)
        case trans:
            assert not f'Unknown transport {trans}'


if __name__ == '__main__':
    main()

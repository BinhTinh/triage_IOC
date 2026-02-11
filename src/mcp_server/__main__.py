import sys

from src.mcp_server.server import run_server


def main():
    transport = "stdio"
    host = "0.0.0.0"
    port = 8000
    
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ["--transport", "-t"] and i + 1 < len(args):
            transport = args[i + 1]
            i += 2
        elif args[i] == "--host" and i + 1 < len(args):
            host = args[i + 1]
            i += 2
        elif args[i] in ["--port", "-p"] and i + 1 < len(args):
            port = int(args[i + 1])
            i += 2
        elif args[i] in ["--help", "-h"]:
            print("Usage: python -m src.mcp_server [OPTIONS]")
            print()
            print("Options:")
            print("  -t, --transport [stdio|http|sse]  Transport protocol (default: stdio)")
            print("  --host TEXT                       Host to bind (default: 0.0.0.0)")
            print("  -p, --port INTEGER                Port to bind (default: 8000)")
            print("  -h, --help                        Show this message and exit")
            sys.exit(0)
        else:
            i += 1
    
    run_server(transport, host, port)


if __name__ == "__main__":
    main()
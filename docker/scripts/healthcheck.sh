#!/bin/bash

set -e

if [ "$MCP_TRANSPORT" = "http" ] || [ "$MCP_TRANSPORT" = "sse" ]; then
    HOST="${MCP_HOST:-localhost}"
    PORT="${MCP_PORT:-8000}"
    
    response=$(curl -s -o /dev/null -w "%{http_code}" "http://${HOST}:${PORT}/mcp" 2>/dev/null || echo "000")
    
    if [ "$response" = "200" ] || [ "$response" = "405" ] || [ "$response" = "400" ]; then
        echo "Health check passed"
        exit 0
    else
        echo "Health check failed: HTTP $response"
        exit 1
    fi
else
    if pgrep -f "python.*mcp_server" > /dev/null; then
        echo "MCP server process is running"
        exit 0
    else
        echo "MCP server process not found"
        exit 1
    fi
fi
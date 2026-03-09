#!/bin/bash

set -e

echo "Starting Volatility3 IOC Extraction Server..."

mkdir -p /app/data/dumps
mkdir -p /app/data/symbols
mkdir -p /app/data/reports
mkdir -p /app/data/cache

if [ -n "$REDIS_URL" ]; then
    echo "Waiting for Redis..."
    REDIS_HOST=$(echo $REDIS_URL | sed -e 's|redis://||' -e 's|:.*||')
    REDIS_PORT=$(echo $REDIS_URL | sed -e 's|.*:||' -e 's|/.*||')
    REDIS_PORT=${REDIS_PORT:-6379}
    
    for i in {1..30}; do
        if nc -z "$REDIS_HOST" "$REDIS_PORT" 2>/dev/null; then
            echo "Redis is available"
            break
        fi
        echo "Waiting for Redis... ($i/30)"
        sleep 1
    done
fi

if [ -n "$DATABASE_URL" ]; then
    echo "Waiting for PostgreSQL..."
    DB_HOST=$(echo $DATABASE_URL | sed -e 's|.*@||' -e 's|:.*||' -e 's|/.*||')
    DB_PORT=$(echo $DATABASE_URL | sed -e 's|.*:||' -e 's|/.*||')
    DB_PORT=${DB_PORT:-5432}
    
    for i in {1..30}; do
        if nc -z "$DB_HOST" "$DB_PORT" 2>/dev/null; then
            echo "PostgreSQL is available"
            break
        fi
        echo "Waiting for PostgreSQL... ($i/30)"
        sleep 1
    done
fi

echo "Verifying Volatility3 installation..."
python3 -c "import volatility3; print(f'Volatility3 version: {volatility3.__version__}')" 2>/dev/null || echo "Volatility3 not found, some features may be unavailable"

export PYTHONUNBUFFERED=1
export PYTHONPATH=/app:$PYTHONPATH

if [ "$MCP_TRANSPORT" = "http" ]; then
    echo "Starting MCP server with HTTP transport on ${MCP_HOST:-0.0.0.0}:${MCP_PORT:-8000}..."
    exec python -m src.mcp_server --transport http --host "${MCP_HOST:-0.0.0.0}" --port "${MCP_PORT:-8000}"
elif [ "$MCP_TRANSPORT" = "sse" ]; then
    echo "Starting MCP server with SSE transport on ${MCP_HOST:-0.0.0.0}:${MCP_PORT:-8000}..."
    exec python -m src.mcp_server --transport sse --host "${MCP_HOST:-0.0.0.0}" --port "${MCP_PORT:-8000}"
else
    echo "Starting MCP server with stdio transport..."
    exec python -m src.mcp_server --transport stdio
fi

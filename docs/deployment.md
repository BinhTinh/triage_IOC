# Deployment Guide

## Prerequisites

- Docker 24.0+
- Docker Compose 2.20+
- 16GB RAM minimum
- 100GB storage
- API keys for VirusTotal and AbuseIPDB

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/yourorg/volatility3-ioc-extraction.git
cd volatility3-ioc-extraction
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_KEY=your_abuseipdb_api_key
REDIS_URL=redis://redis:6379
DATABASE_URL=postgresql://user:pass@postgres/volatility
LOG_LEVEL=INFO
```

### 3. Start Services

```bash
docker-compose up -d
```

### 4. Verify Deployment

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status": "healthy", "version": "1.0.0"}
```

## Docker Compose Configuration

```yaml
version: '3.8'

services:
  mcp-server:
    build:
      context: .
      dockerfile: docker/Dockerfile.server
    ports:
      - "8000:8000"
    volumes:
      - ./data/dumps:/app/data/dumps:ro
      - ./data/reports:/app/data/reports
      - ./data/symbols:/app/data/symbols
    environment:
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://user:pass@postgres/volatility
      - VT_API_KEY=${VT_API_KEY}
      - ABUSEIPDB_KEY=${ABUSEIPDB_KEY}
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G

  worker:
    build:
      context: .
      dockerfile: docker/Dockerfile.worker
    volumes:
      - ./data/dumps:/app/data/dumps:ro
      - ./data/symbols:/app/data/symbols
    environment:
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
      replicas: 2

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 2G

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=volatility
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user -d volatility"]
      interval: 10s
      timeout: 5s
      retries: 5
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 2G

volumes:
  redis_data:
  postgres_data:
```

## Dockerfile

### Server Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/ ./config/

RUN useradd -m -u 1000 appuser
USER appuser

EXPOSE 8000

CMD ["python", "-m", "src.mcp_server", "--host", "0.0.0.0", "--port", "8000"]
```

### Worker Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install volatility3

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/ ./config/

RUN useradd -m -u 1000 appuser
USER appuser

CMD ["python", "-m", "src.workers.plugin_worker"]
```

## MCP Client Configuration

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%/Claude/claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "volatility3": {
      "command": "docker",
      "args": [
        "exec", "-i", 
        "volatility3-ioc-extraction-mcp-server-1",
        "python", "-m", "src.mcp_server", "--transport", "stdio"
      ]
    }
  }
}
```

### Cline (VSCode)

Add to VSCode settings:

```json
{
  "cline.mcpServers": {
    "volatility3": {
      "url": "http://localhost:8000/mcp",
      "transport": "http"
    }
  }
}
```

### Standalone Python Client

```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server_params = StdioServerParameters(
        command="docker",
        args=[
            "exec", "-i",
            "volatility3-ioc-extraction-mcp-server-1",
            "python", "-m", "src.mcp_server", "--transport", "stdio"
        ]
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            result = await session.call_tool(
                "smart_triage",
                {"dump_path": "/app/data/dumps/sample.raw"}
            )
            print(result)

asyncio.run(main())
```

## Production Checklist

### Security

- [ ] Change default database passwords
- [ ] Use Docker secrets for API keys
- [ ] Enable TLS for external connections
- [ ] Restrict dump directory to read-only
- [ ] Configure firewall rules
- [ ] Enable audit logging

### Performance

- [ ] Allocate sufficient memory for workers
- [ ] Configure Redis persistence
- [ ] Set appropriate cache TTLs
- [ ] Monitor API rate limits
- [ ] Scale workers based on load

### Monitoring

- [ ] Configure log aggregation
- [ ] Set up health check alerts
- [ ] Monitor disk usage
- [ ] Track API quota consumption
- [ ] Enable performance metrics

### Backup

- [ ] Configure PostgreSQL backups
- [ ] Backup Redis RDB files
- [ ] Archive generated reports
- [ ] Document recovery procedures

## Troubleshooting

### Container Won't Start

```bash
docker-compose logs mcp-server
```

Common issues:
- Missing environment variables
- Port already in use
- Insufficient memory

### Plugin Execution Fails

```bash
docker-compose exec worker python -c "import volatility3; print(volatility3.__version__)"
```

Common issues:
- Volatility3 not installed
- Missing symbol files (Linux)
- Corrupt dump file

### API Rate Limits

Check current usage:

```bash
docker-compose exec mcp-server python -c "
from src.utils.cache import redis
print(redis.get('vt:rate_limit'))
print(redis.get('abuse:rate_limit'))
"
```

### Cache Issues

Clear cache:

```bash
docker-compose exec redis redis-cli FLUSHALL
```

## Scaling

### Horizontal Scaling

Increase worker replicas:

```yaml
services:
  worker:
    deploy:
      replicas: 4
```

### Vertical Scaling

Increase resource limits:

```yaml
services:
  worker:
    deploy:
      resources:
        limits:
          cpus: '8'
          memory: 16G
```

## Updating

```bash
git pull origin main
docker-compose build
docker-compose up -d
```

## Uninstalling

```bash
docker-compose down -v
rm -rf data/cache data/reports
```
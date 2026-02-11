# Volatility3 IOC Extraction with MCP Server

Automated memory forensics platform that extracts Indicators of Compromise (IOCs) from malware-infected memory dumps using Volatility3, powered by Model Context Protocol (MCP) for AI-assisted analysis.

## What This Does

- **Automated Triage**: Intelligently selects optimal Volatility3 plugins based on analysis goals
- **IOC Extraction**: Extracts IPs, domains, hashes, processes, registry keys from memory dumps
- **Threat Validation**: Validates IOCs against VirusTotal, AbuseIPDB with confidence scoring
- **MITRE Mapping**: Maps findings to ATT&CK techniques automatically
- **AI Integration**: MCP interface allows Claude/GPT to perform forensic analysis interactively

## Quick Start

```bash
# Clone repository
git clone https://github.com/yourorg/volatility3-ioc-extraction.git
cd volatility3-ioc-extraction

# Copy environment file
cp .env.example .env
# Edit .env with your API keys (VT_API_KEY, ABUSEIPDB_KEY)

# Start services
docker-compose up -d

# Verify server is running
curl http://localhost:8000/health
```

## Usage

### With Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "volatility3": {
      "command": "docker",
      "args": ["exec", "-i", "volatility3-mcp-server", "python", "-m", "src.mcp_server"]
    }
  }
}
```

Then ask Claude:
> "Analyze /data/dumps/infected.raw for malware indicators"

### With Cline (VSCode)

Add to settings:

```json
{
  "cline.mcpServers": {
    "volatility3": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

### Programmatic API

```python
from mcp import ClientSession
from mcp.client.stdio import stdio_client

async with stdio_client(server_params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        
        # Run intelligent triage
        result = await session.call_tool(
            "smart_triage",
            {"dump_path": "/data/dumps/sample.raw", "goal": "malware_detection"}
        )
        
        # Get validated IOCs
        iocs = await session.call_tool(
            "extract_iocs",
            {"plugin_results": result}
        )
```

## Available Tools

| Tool | Description |
|------|-------------|
| `detect_os` | Auto-detect OS from memory dump |
| `smart_triage` | Get recommended plugins for analysis goal |
| `run_plugin` | Execute single Volatility3 plugin |
| `batch_plugins` | Execute multiple plugins in parallel |
| `extract_iocs` | Extract IOCs from plugin results |
| `validate_iocs` | Validate IOCs against threat intel |
| `map_mitre` | Map findings to MITRE ATT&CK |
| `generate_report` | Generate JSON/PDF report |
| `win_processes` | Windows process analysis |
| `win_injection` | Detect Windows code injection |
| `linux_processes` | Linux process analysis |
| `linux_rootkit` | Linux rootkit detection |

## Analysis Goals

| Goal | Description | Est. Time |
|------|-------------|-----------|
| `malware_detection` | Find malware indicators | 8-12 min |
| `incident_response` | IR artifacts | 15-20 min |
| `quick_triage` | Fast initial scan | 3-5 min |
| `rootkit_hunt` | Kernel-level threats | 10-15 min |
| `full_audit` | Complete analysis | 30-45 min |

## Output Example

```json
{
  "case_id": "CASE-2026-0128-001",
  "os": "Windows 10 x64",
  "threat_level": "HIGH",
  "iocs": [
    {
      "type": "ip",
      "value": "192.0.2.100",
      "confidence": 0.85,
      "context": "C2 connection from malware.exe (PID 1234)",
      "mitre": ["T1071.001"]
    }
  ],
  "mitre_techniques": [
    {"id": "T1055", "name": "Process Injection", "count": 3},
    {"id": "T1071", "name": "Application Layer Protocol", "count": 2}
  ],
  "recommendations": [
    "Block IP 192.0.2.100 at firewall",
    "Isolate affected host",
    "Collect additional artifacts"
  ]
}
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VT_API_KEY` | Yes | VirusTotal API key |
| `ABUSEIPDB_KEY` | Yes | AbuseIPDB API key |
| `REDIS_URL` | No | Redis connection (default: localhost:6379) |
| `DATABASE_URL` | No | PostgreSQL connection |
| `LOG_LEVEL` | No | Logging level (default: INFO) |

### Plugin Profiles

Edit `config/plugin_profiles.yaml` to customize plugin selection per goal.

### Whitelist

Edit `config/whitelist.yaml` to add known-good indicators.

## System Requirements

- Docker 24.0+
- 16GB RAM minimum (32GB recommended)
- 100GB storage for dumps and cache
- Internet access for threat intel APIs

## Supported Platforms

**Memory Dumps:**
- Windows 7, 8, 8.1, 10, 11 (x64)
- Linux kernel 4.x - 6.x (requires symbols)

**MCP Clients:**
- Claude Desktop
- Cline (VSCode)
- Custom MCP clients

## Known Limitations

1. Windows network plugins (netscan/netstat) unavailable in Vol3 2.5+ - uses handles-based approach
2. Linux analysis requires matching kernel symbols
3. Free API tiers have rate limits affecting batch validation
4. Memory dumps >16GB may require additional RAM

## Documentation

- [System Architecture](./system_architecture.md)
- [Phase 1: Intake & Profiling](./docs/phase1_intake.md)
- [Phase 2: Plugin Execution](./docs/phase2_execution.md)
- [Phase 3: IOC Extraction](./docs/phase3_extraction.md)
- [Phase 4: Validation](./docs/phase4_validation.md)
- [Phase 5: Presentation](./docs/phase5_presentation.md)

## License

MIT License - See LICENSE file

## Contributing

See CONTRIBUTING.md for guidelines.
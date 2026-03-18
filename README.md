# Automatic Volatility3 Pipeline IOC Extraction with AI Agent

Automated memory forensics pipeline that runs Volatility3 against Windows memory dumps, extracts Indicators of Compromise (IOCs), and exposes the entire workflow through a **Model Context Protocol (MCP) server** — so an AI agent (Claude Desktop, Cline, etc.) can drive the full analysis interactively.

---

## What This Does

| Stage | What happens |
|-------|-------------|
| **OS Detection** | Auto-detects Windows version from dump header |
| **Plugin Execution** | Runs 18 Volatility3 plugins in parallel (network + host) |
| **IOC Extraction** | Context-aware + regex extraction pipeline |
| **Threat Validation** | VirusTotal · AbuseIPDB · DeepSeek LLM · Whitelist |
| **Report Generation** | JSON reports with confidence scores and MITRE tags |

### Detected IOC Types

| IOC Type | Source Plugin | MITRE Technique |
|----------|--------------|-----------------|
| Process Injection | `malfind` | T1055 |
| Process Hollowing | `hollowprocesses` | T1055.012 |
| Service Persistence | `svcscan` | T1543.003 |
| DKOM-Hidden Processes | `psscan` vs `pslist` | T1564.001 |
| C2 Network Traffic | `netscan`, `handles` | T1071 |
| Suspicious Commands | `cmdline` | T1059 |
| Registry Persistence | `printkey`, `hivelist` | T1547 |
| File Hashes (MD5/SHA1/SHA256) | `filescan`, `amcache`, `ldrmodules` | T1204 |
| Suspicious File Paths | `filescan`, `dlllist` | T1036 |

---

## Quick Start

```bash
# 1. Copy and configure environment
cp .env.example .env
# Edit .env — add API keys (VT_API_KEY, ABUSEIPDB_KEY, DEEPSEEK_API_KEY)

# 2. Place memory dumps
mkdir -p data/dumps
cp /path/to/infected.raw data/dumps/

# 3. Start services
docker compose up -d

# 4. Verify
curl http://localhost:8000/health
```

### Connect an AI Agent

**Claude Desktop** — add to `claude_desktop_config.json`:

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

**Cline (VSCode)** — add to settings:

```json
{
  "cline.mcpServers": {
    "volatility3": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

Then ask the agent:
> *"Analyze /data/dumps/infected.raw for malware indicators and give me a full report"*

---

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `detect_os` | Auto-detect OS type from memory dump |
| `run_plugins` | Execute a preset of Volatility3 plugins in parallel |
| `run_plugin` | Execute a single Volatility3 plugin |
| `ioc_extract_from_store` | Extract IOCs from stored plugin results |
| `ioc_validate` | Validate IOCs against VT · AbuseIPDB · DeepSeek |
| `generate_report` | Generate a JSON analysis report |

---

## Windows Plugin Preset (18 plugins)

### Network (3)
- `windows.netscan.NetScan`
- `windows.netstat.NetStat`
- `windows.handles.Handles` ← fallback for Vol3 2.5+ where netscan is unavailable

### Host (15)
- `windows.pslist.PsList` + `windows.psscan.PsScan` ← hidden process detection
- `windows.cmdline.CmdLine`
- `windows.malware.malfind.Malfind`
- `windows.malware.hollowprocesses.HollowProcesses`
- `windows.malware.ldrmodules.LdrModules`
- `windows.dlllist.DllList`
- `windows.filescan.FileScan`
- `windows.svcscan.SvcScan`
- `windows.registry.hivelist.HiveList`
- `windows.registry.printkey.PrintKey` (Run, RunOnce, Services keys)
- `windows.registry.userassist.UserAssist`
- `windows.registry.amcache.Amcache`

---

## IOC Extraction Pipeline

```
Memory Dump
    │
    ▼
VolatilityExecutor ──── runs 18 plugins in parallel
    │
    ▼
ExtractionPipeline
    ├── IOCExtractor          (regex: IPs, hashes, domains, paths)
    ├── ContextAwareExtractor (structured: injection, services, hidden procs, network)
    └── RegistryAnalyzer      (persistence, credential access, defense evasion)
    │
    ▼
ValidationPipeline
    ├── WhitelistValidator    (private IPs, known-good domains, system processes)
    ├── VirusTotalValidator   (hashes, IPs, domains — cached in Redis)
    ├── AbuseIPDBValidator    (IP reputation — cached in Redis)
    ├── DeepSeekValidator     (LLM reasoning for behavioral IOCs)
    └── CorrelationGuard      (downgrade isolated behavior-only findings)
    │
    ▼
JSON Report  →  data/reports/
```

---

## Configuration

### Environment Variables (`.env`)

| Variable | Required | Description |
|----------|----------|-------------|
| `VT_API_KEY` | Optional | VirusTotal API key — enables hash/IP/domain lookup |
| `ABUSEIPDB_KEY` | Optional | AbuseIPDB key — enables IP reputation scoring |
| `DEEPSEEK_API_KEY` | Optional | DeepSeek key — enables LLM validation of behavioral IOCs |
| `DEEPSEEK_MODEL` | No | Model to use (default: `deepseek-chat`) |
| `USE_DEEPSEEK` | No | Enable DeepSeek validation (default: `true`) |
| `ENABLE_THREAT_INTEL` | No | Enable VT + AbuseIPDB (default: `false`) |
| `REDIS_URL` | No | Redis connection string (default: `redis://redis:6379`) |
| `DUMPS_DIR` | No | Directory for memory dumps (default: `/app/data/dumps`) |
| `STRICT_DOCKER_PATHS` | No | Enforce Docker-only paths (default: `false`) |
| `LOG_LEVEL` | No | Logging level (default: `INFO`) |

All API keys are optional — the pipeline runs without them using local heuristics only.

### Whitelist

Edit `config/whitelist.yaml` to add known-good IPs, domains, processes, and hashes. The default whitelist already excludes:
- Private IP ranges (10.x, 172.16–31.x, 192.168.x, 127.x, all IPv6 loopback/link-local)
- Common Microsoft/Google/CDN domains
- Standard Windows system processes

---

## Developer Workflow

```bash
# Live interactive shell (mounts ./src live — no rebuild needed):
docker compose run --rm dev

# Rebuild after code changes to mcp-server:
docker compose build mcp-server && docker compose up -d mcp-server

# Run the end-to-end pipeline test against all dumps:
docker exec volatility3-mcp-server python3 /app/data/e2e_test.py

# Run against a specific dump:
docker exec volatility3-mcp-server python3 /app/data/e2e_test.py /app/data/dumps/infected.raw
```

---

## Real Test Results

Tested against two Windows memory dumps:

| Dump | OS | IOCs | Network | Host | Key Findings |
|------|----|------|---------|------|-------------|
| `MemoryDump_Lab1.raw` | Windows | 86 | 1 | 85 | 11 injections (T1055), 71 services checked |
| `mem_phase1.raw` | Windows | 190 | 0 | 190 | 2 hidden processes (T1564.001), 59 SHA1 hashes |

---

## System Requirements

- **Docker** 24.0+
- **RAM**: 16 GB minimum (32 GB recommended for large dumps)
- **Storage**: 50 GB+ for dumps, symbol cache, and plugin output
- **Internet**: Optional — only needed for VT/AbuseIPDB/DeepSeek validation

## Supported Platforms

**Memory Dumps (Windows only focus):**
- Windows 7, 8, 8.1, 10, 11 (x64)
- Volatility3 2.x (including 2.5+ where netscan/netstat are unavailable)

**MCP Clients:**
- Claude Desktop
- Cline (VSCode)
- Any MCP-compatible client

## Known Limitations

1. **Vol3 2.5+ network**: `netscan`/`netstat` unavailable on newer builds — the pipeline falls back to `handles`-based network extraction automatically
2. **Symbol requirement**: Volatility3 needs matching symbol packs for the target OS build; symbols are cached after first run
3. **Large dumps**: Dumps > 16 GB may require additional RAM and longer timeouts
4. **Free API tiers**: VirusTotal free tier is rate-limited (4 req/min) — Redis caching minimises repeat lookups

---

## License

MIT License — see [LICENSE](./LICENSE)
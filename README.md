# Automatic Volatility3 Pipeline IOC Extraction with AI Agent

Automated memory forensics pipeline that runs Volatility3 against Windows memory dumps, extracts Indicators of Compromise (IOCs), and exposes the entire workflow through a **Model Context Protocol (MCP) server** — so an AI agent (Claude Desktop, Cline, etc.) can drive the full analysis interactively.

> **What's New (v2):** Procdump hash extraction, enriched injection tables (PPID / Region Size / Header Hex), false-positive hash elimination, structured Amcache + LdrModules parsers, lab network support, and threat intel enabled by default.

---

## What This Does

| Stage | What happens |
|-------|-------------|
| **OS Detection** | Auto-detects Windows version from dump header |
| **Plugin Execution** | Runs 18 Volatility3 plugins in parallel (network + host) |
| **Procdump Hashing** | Dumps suspicious process EXEs from memory and computes SHA256/MD5 |
| **IOC Extraction** | Context-aware + regex extraction pipeline |
| **Threat Validation** | VirusTotal · AbuseIPDB · Whitelist (enabled by default) |
| **Report Generation** | Forensic Markdown report with evidence tables and MITRE tags |

### Detected IOC Types

| IOC Type | Source | MITRE Technique |
|----------|--------------|-----------------|
| Process Injection (+ PPID, Region Size, Header Hex) | `malfind` + `pslist` cross-ref | T1055 |
| Process Hollowing | `hollowprocesses` | T1055.012 |
| Hidden DLL Injection | `ldrmodules` (structured) | T1055.001 |
| Service Persistence | `svcscan` | T1543.003 |
| DKOM-Hidden Processes | `psscan` vs `pslist` | T1564.001 |
| C2 Network Traffic | `netscan`, `handles` | T1071 |
| Suspicious Commands | `cmdline` | T1059 |
| Registry Persistence | `printkey`, `hivelist` | T1547 |
| **File Hashes (SHA256/MD5)** | **`procdump`** (dumped from memory) | T1204 |
| File Hashes (SHA1) | `amcache` (when available) | T1204 |
| Suspicious File Paths | `filescan`, `dlllist` | T1036 |

---

## Quick Start

```bash
# 1. Copy and configure environment
cp .env.example .env
# Edit .env — add API keys (VT_API_KEY, ABUSEIPDB_KEY)

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
| `list_dumps` | Discover memory dump files in the data directory |
| `detect_os` | Auto-detect OS type from memory dump |
| `run_plugins` | Execute preset plugins + procdump hashing in parallel |
| `run_plugin` | Execute a single Volatility3 plugin for follow-up |
| `ioc_extract_from_store` | Extract IOCs from stored plugin results |
| `ioc_validate_from_report` | Validate IOCs via whitelist + VT + AbuseIPDB |
| `forensic_report_from_validation` | Generate Markdown forensic incident report |

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
Procdump Post-Step ──── dumps suspicious process EXEs → SHA256 + MD5
    │
    ▼
ExtractionPipeline
    ├── IOCExtractor            (regex: IPs, domains, paths — with false-hash filter)
    ├── ContextAwareExtractor
    │     ├── analyze_processes        (parent-child anomalies)
    │     ├── analyze_malfind          (injection + PPID + region size + header hex)
    │     ├── analyze_procdump_hashes  (real SHA256/MD5 from dumped EXEs)
    │     ├── analyze_amcache          (SHA1 hashes of executed programs)
    │     ├── analyze_ldrmodules       (hidden DLLs — noise-filtered)
    │     ├── analyze_netscan          (C2 connections + lab network awareness)
    │     ├── analyze_hollowprocesses  (T1055.012)
    │     ├── analyze_hidden_processes (DKOM rootkit detection)
    │     └── analyze_svcscan          (service persistence)
    └── RegistryAnalyzer      (persistence, credential access, defense evasion)
    │
    ▼
ValidationPipeline
    ├── WhitelistValidator    (private IPs, known-good domains, system processes)
    ├── VirusTotalValidator   (hashes, IPs, domains — L1 in-memory + L2 Redis cache)
    ├── AbuseIPDBValidator    (IP reputation — cached in Redis)
    └── CorrelationGuard      (downgrade isolated behavior-only findings)
    │
    ▼
Forensic Markdown Report  →  data/reports/forensic_incident_report_*.md
```

---

## Configuration

### Environment Variables (`.env`)

| Variable | Required | Description |
|----------|----------|-------------|
| `VT_API_KEY` | Recommended | VirusTotal API key — enables hash/IP/domain lookup |
| `ABUSEIPDB_KEY` | Optional | AbuseIPDB key — enables IP reputation scoring |
| `ENABLE_THREAT_INTEL` | No | Enable VT + AbuseIPDB (default: **`true`**) |
| `LAB_NETWORK` | No | CIDR range(s) for lab subnets that bypass private-IP filter (e.g. `192.168.56.0/24`) |
| `REDIS_URL` | No | Redis connection string (default: `redis://redis:6379`) |
| `DUMPS_DIR` | No | Directory for memory dumps (default: `/app/data/dumps`) |
| `STRICT_DOCKER_PATHS` | No | Enforce Docker-only paths (default: `false`) |
| `LOG_LEVEL` | No | Logging level (default: `INFO`) |

Threat intelligence is **enabled by default**. The pipeline runs without API keys using local heuristics only, but adding a `VT_API_KEY` enables automated VirusTotal lookups for all extracted hashes.

### Lab Network Support

If you're analyzing dumps from a lab environment (e.g. victim `192.168.56.100` + INetSim `192.168.56.150`), set:

```env
LAB_NETWORK=192.168.56.0/24
```

IPs matching `LAB_NETWORK` bypass the private-IP filter and are treated as external C2 candidates, so INetSim traffic is correctly captured in the report.

### Redis Caching

VirusTotal and AbuseIPDB responses are cached in Redis with a **6-hour TTL** using a two-tier strategy:
- **L1 — in-memory dict**: instant hits within the same container run
- **L2 — Redis**: persistent across restarts, shared across pipeline runs

This minimizes API calls — re-analyzing the same dump costs zero VT quota.

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

## Forensic Report Output

The pipeline generates a **Markdown forensic incident report** with the following sections:

| Section | Content |
|---------|--------|
| **3.1 Process Injection** | Target Process, PID, PPID, Start VPN, Region Size, Memory Protection, Header Hex (first 16 bytes), MZ flag |
| **3.2 Persistence & Suspicious Actions** | Registry Run keys, services, scheduled tasks, suspicious binaries |
| **3.3 Network IOCs** | C2 IPs/domains, connection state, owning process, lab network tagging |
| **4. File Hashes** | SHA256/MD5 from procdump of suspicious processes — ready for VT lookup |
| **5. MITRE ATT&CK Mapping** | All IOCs tagged with technique IDs |

### Process Injection Table (Section 3.1)

The injection evidence table now includes analyst-friendly context:

```
| # | Target Process | PID | PPID | Start VPN | Region Size | Memory Protection | Header / Hex (first 16 B) | MZ? | Source Plugin |
|---|---------------|-----|------|-----------|-------------|-------------------|-----------------------------|-----|---------------|
| 1 | MsMpEng.exe   | 3868| 812  | 0x298...  | 1076.0 KB   | PAGE_EXECUTE_RW   | `56 57 53 55 41 54 41 55...` | —   | malfind       |
```

- **PPID**: Parent PID cross-referenced from `pslist` (e.g. 812 = services.exe)
- **Region Size**: Calculated from Start/End VPN, formatted as KB/MB
- **Header Hex**: First 16 bytes at the injection address — identifies MZ headers or shellcode patterns

---

## Procdump Hash Extraction

After the standard plugin preset completes, the pipeline automatically:

1. Identifies **suspicious PIDs** from malfind injection hits
2. Runs `pslist --pid <PID> --dump` to extract the process executable from memory
3. Computes **SHA256 + MD5** of each dumped file
4. Checks for **MZ header** to confirm valid PE
5. Stores results in `host_data["_procdump_hashes"]` for IOC extraction

These real file hashes are then automatically validated against VirusTotal during phase 5.

> **Note:** This adds ~30-60 seconds per suspicious PID to the `run_plugins` phase. Results are cached by Redis.

---

## False-Positive Hash Elimination

Previously, the regex scanner produced false-positive MD5 matches from:
- Memory addresses in `ldrmodules` Base fields
- NativeImage cache paths in `filescan` containing 32-char hex substrings

These have been eliminated by:
- Removing `ldrmodules` and `filescan` from the hash regex `source_gate`
- Adding an `_is_likely_false_hash()` filter for address-like hex patterns
- Using **structured parsers** (`analyze_amcache`, `analyze_ldrmodules`) instead of regex

---

## Real Test Results

Tested against Windows 11 memory dump (`win_Smoke.raw`):

| Category | Count | Details |
|----------|-------|---------|
| Process Injection | 17 | MsMpEng.exe (13×), powershell.exe (3×), Wireshark.exe (1×) |
| Procdump Hashes | 6 | 3 SHA256 + 3 MD5 from dumped suspicious process EXEs |
| Hidden DLLs | 3 | Genuinely anomalous modules (post-noise-filter, was 569) |
| C2 Network | 1 | Lab network traffic correctly identified |
| False-Positive Hashes | 0 | Down from 29 |

---

## System Requirements

- **Docker** 24.0+
- **RAM**: 16 GB minimum (32 GB recommended for large dumps)
- **Storage**: 50 GB+ for dumps, symbol cache, and plugin output
- **Internet**: Optional — only needed for VT/AbuseIPDB validation

## Supported Platforms

**Memory Dumps (Windows only focus):**
- Windows 7, 8, 8.1, 10, 11 (x64)
- Volatility3 2.x (including 2.5+ where netscan/netstat are unavailable)

**MCP Clients:**
- Claude Desktop
- Cline (VSCode)
- Antigravity
- Any MCP-compatible client

## Known Limitations

1. **Vol3 2.5+ network**: `netscan`/`netstat` unavailable on newer builds — the pipeline falls back to `handles`-based network extraction automatically
2. **Symbol requirement**: Volatility3 needs matching symbol packs for the target OS build; symbols are cached after first run
3. **Large dumps**: Dumps > 16 GB may require additional RAM and longer timeouts
4. **Free API tiers**: VirusTotal free tier is rate-limited (4 req/min) — Redis caching minimises repeat lookups
5. **Amcache availability**: Some memory dumps have empty Amcache hives — the pipeline falls back to procdump hashing in these cases
6. **Procdump timing**: The procdump post-step adds ~30-60s per suspicious PID to `run_plugins`

---

## License

MIT License — see [LICENSE](./LICENSE)
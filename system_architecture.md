# System Architecture: Volatility3 IOC Extraction với MCP Server

## 1. TỔNG QUAN HỆ THỐNG

### 1.1 Mục tiêu
Xây dựng hệ thống tự động hóa trích xuất Indicators of Compromise (IOC) từ memory dump bị nhiễm malware sử dụng Volatility3, tích hợp Model Context Protocol (MCP) để AI agent tương tác thông minh với forensics tools.

### 1.2 Vấn đề giải quyết

| Vấn đề | Mô tả | Giải pháp |
|--------|-------|-----------|
| Plugin Selection | 150+ plugins, analyst không biết chọn plugin nào | Decision Engine với goal-based selection |
| False Positive | Raw output không phân biệt IOC thật vs noise | Multi-source threat intel validation |
| Thiếu Context | Kết quả rời rạc, không có MITRE mapping | Automated IOC extraction + ATT&CK mapping |
| Linux Symbols | Vol3 Linux cần kernel symbols để hoạt động | Symbol resolver với auto-detection |

### 1.3 Scope

**Trong scope:**
- Windows memory analysis (Windows 7 - Windows 11)
- Linux memory analysis (kernel 4.x - 6.x với symbol support)
- IOC types: IP, Domain, Hash, Process, Registry, File Path
- Threat intel: VirusTotal, AbuseIPDB (với local cache)

**Ngoài scope:**
- macOS memory analysis
- Live memory acquisition
- Real-time monitoring
- Zero-day detection

## 2. KIẾN TRÚC TỔNG QUAN

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            MCP CLIENTS                                   │
│         (Claude Desktop / Cline / Custom AI Agent)                       │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │ MCP Protocol (stdio/HTTP)
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         MCP SERVER LAYER                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                      │
│  │   Tools     │  │  Resources  │  │   Prompts   │                      │
│  │  (15 core)  │  │  (8 URIs)   │  │(5 templates)│                      │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                      │
└─────────┼────────────────┼────────────────┼─────────────────────────────┘
          │                │                │
          ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          CORE LAYER                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Decision   │  │  Volatility  │  │     IOC      │  │   Threat     │ │
│  │    Engine    │  │   Executor   │  │  Extractor   │  │  Validator   │ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘ │
│  ┌──────────────┐  ┌──────────────┐                                     │
│  │    MITRE     │  │    Symbol    │                                     │
│  │    Mapper    │  │   Resolver   │                                     │
│  └──────────────┘  └──────────────┘                                     │
└─────────────────────────────────────────────────────────────────────────┘
          │                │                │
          ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       INFRASTRUCTURE LAYER                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │    Redis     │  │  PostgreSQL  │  │ File Storage │                   │
│  │   (Cache)    │  │   (Cases)    │  │   (Dumps)    │                   │
│  └──────────────┘  └──────────────┘  └──────────────┘                   │
└─────────────────────────────────────────────────────────────────────────┘
          │                │                │
          ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       EXTERNAL SERVICES                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │  VirusTotal  │  │  AbuseIPDB   │  │ MITRE ATT&CK │                   │
│  │     API      │  │     API      │  │     API      │                   │
│  └──────────────┘  └──────────────┘  └──────────────┘                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Pipeline 5 Phases

```
Phase 1          Phase 2              Phase 3           Phase 4            Phase 5
INTAKE     →    EXECUTION      →    EXTRACTION   →   VALIDATION    →   PRESENTATION
                                                                    
[Dump]          [Vol3 Plugins]       [Pattern]        [Threat Intel]     [Report]
   │                 │                  │                  │                │
   ▼                 ▼                  ▼                  ▼                ▼
OS Detect       Parallel Run        Regex+Context     VT/AbuseIPDB      JSON/PDF
Profile         Cache Check         IOC Struct        Confidence        MITRE Map
Triage          Error Handle        Dedup             Whitelist         Actions
```

## 3. COMPONENT SPECIFICATIONS

### 3.1 MCP Server Layer

#### 3.1.1 Tools (15 Core Functions)

| Tool | Input | Output | Description |
|------|-------|--------|-------------|
| `detect_os` | dump_path | {os, version, arch} | Auto-detect OS từ memory dump |
| `smart_triage` | dump_path, goal | plugin_list, est_time | Suggest plugins dựa trên goal |
| `run_plugin` | dump_path, plugin, args | structured_result | Execute single Vol3 plugin |
| `batch_plugins` | dump_path, plugins[] | results[] | Parallel plugin execution |
| `extract_iocs` | plugin_results | ioc_list | Extract IOCs từ results |
| `validate_iocs` | ioc_list | validated_iocs | Threat intel validation |
| `map_mitre` | iocs, findings | attack_matrix | Map to ATT&CK |
| `generate_report` | case_id, format | report_path | Generate JSON/PDF report |
| `win_processes` | dump_path | process_tree | Windows process analysis |
| `win_network` | dump_path | connections | Windows network (handles-based) |
| `win_injection` | dump_path | injections | Detect code injection |
| `linux_processes` | dump_path | process_tree | Linux process analysis |
| `linux_network` | dump_path | connections | Linux network analysis |
| `linux_rootkit` | dump_path | findings | Rootkit detection |
| `get_symbols` | dump_path | symbol_status | Linux symbol management |

#### 3.1.2 Resources (8 URIs)

| URI Pattern | Description |
|-------------|-------------|
| `plugins://catalog` | Available plugins với metadata |
| `plugins://{name}/info` | Chi tiết plugin cụ thể |
| `profiles://{goal}/{os}` | Analysis profile |
| `cases://list` | Tất cả cases |
| `cases://{id}/summary` | Case summary |
| `cases://{id}/iocs` | Case IOCs |
| `threats://{indicator}` | Cached threat intel |
| `symbols://{kernel}` | Linux symbol status |

#### 3.1.3 Prompts (5 Templates)

| Prompt | Parameters | Use Case |
|--------|------------|----------|
| `malware_triage` | dump_path, os_type | Initial malware investigation |
| `incident_response` | dump_path, incident_type | IR playbook |
| `rootkit_hunt` | dump_path | Linux rootkit detection |
| `network_forensics` | dump_path, suspicious_ips | C2 investigation |
| `full_analysis` | dump_path | Comprehensive forensics |

### 3.2 Core Layer

#### 3.2.1 Decision Engine

**Input:** OS type, dump size, analysis goal
**Output:** Ordered plugin list với rationale

**Goals & Plugin Mapping:**

```yaml
malware_detection:
  windows:
    phase1: [windows.info, windows.pslist, windows.pstree]
    phase2: [windows.malware.malfind, windows.malware.hollowprocesses]
    phase3: [windows.cmdline, windows.dlllist]
    phase4: [windows.handles, windows.filescan]
    estimated_time: 8-12 minutes
  linux:
    phase1: [linux.pslist, linux.pstree, linux.psscan]
    phase2: [linux.malware.malfind, linux.malware.check_syscall]
    phase3: [linux.bash, linux.lsof]
    phase4: [linux.sockstat]
    estimated_time: 10-15 minutes

incident_response:
  windows:
    phase1: [windows.info, windows.pslist, windows.pstree]
    phase2: [windows.handles, windows.filescan]
    phase3: [windows.registry.hivelist, windows.registry.userassist]
    phase4: [windows.svcscan, windows.scheduled_tasks]
    estimated_time: 15-20 minutes

quick_triage:
  windows:
    phase1: [windows.info, windows.pslist]
    phase2: [windows.malware.malfind, windows.cmdline]
    estimated_time: 3-5 minutes
  linux:
    phase1: [linux.pslist, linux.bash]
    phase2: [linux.malware.malfind]
    estimated_time: 3-5 minutes
```

#### 3.2.2 Volatility Executor

**Responsibilities:**
- Subprocess management cho Vol3 CLI
- Output parsing (JSON renderer)
- Error handling với retry logic
- Cache integration

**Plugin Validation (CRITICAL):**

```yaml
validated_plugins:
  windows:
    process:
      - windows.pslist
      - windows.pstree
      - windows.psscan
      - windows.cmdline
      - windows.envars
    malware:
      - windows.malware.malfind
      - windows.malware.hollowprocesses
      - windows.malware.ldrmodules
      - windows.malware.drivermodule
    network:
      # NOTE: windows.netscan/netstat KHÔNG hoạt động trong Vol3 2.5+
      # Sử dụng windows.handles với filter TCP/UDP thay thế
      - windows.handles  # filter: Type=File, Name contains \Device\Tcp
    filesystem:
      - windows.filescan
      - windows.dumpfiles
    registry:
      - windows.registry.hivelist
      - windows.registry.printkey
      - windows.registry.userassist
    
  linux:
    process:
      - linux.pslist
      - linux.pstree
      - linux.psscan
      - linux.psaux
      - linux.bash
    malware:
      - linux.malware.malfind
      - linux.malware.check_syscall
      - linux.malware.check_modules
      - linux.malware.hidden_modules
    network:
      - linux.sockstat
      - linux.sockscan
    filesystem:
      - linux.lsof
      - linux.pagecache.Files

deprecated_plugins:
  # KHÔNG sử dụng - đã deprecated
  - windows.malfind          # → windows.malware.malfind
  - windows.hollowprocesses  # → windows.malware.hollowprocesses
  - windows.netscan          # → KHÔNG CÓ THAY THẾ TRỰC TIẾP
  - windows.netstat          # → KHÔNG CÓ THAY THẾ TRỰC TIẾP
  - linux.malfind            # → linux.malware.malfind
  - linux.check_syscall      # → linux.malware.check_syscall
  - linux.check_modules      # → linux.malware.check_modules
```

#### 3.2.3 IOC Extractor

**Extraction Patterns:**

| IOC Type | Pattern | Context Required |
|----------|---------|------------------|
| IPv4 | `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b` | Exclude private ranges optionally |
| IPv6 | `\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b` | Full format only |
| Domain | `\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b` | Exclude common (google.com, etc.) |
| MD5 | `\b[a-fA-F0-9]{32}\b` | From malfind, dumpfiles |
| SHA256 | `\b[a-fA-F0-9]{64}\b` | From malfind, dumpfiles |
| File Path | `[A-Za-z]:\\[\\\S\|*\S]+` (Win) | From cmdline, filescan |
| Registry | `HKEY_[A-Z_]+\\[\\\S]+` | From registry plugins |

**Context-Aware Rules:**

```yaml
suspicious_process_patterns:
  windows:
    - parent: "winword.exe", child: "cmd.exe"      # T1059
    - parent: "excel.exe", child: "powershell.exe" # T1059.001
    - process: "svchost.exe", path_not: "System32" # T1036
    - cmdline_contains: ["-enc", "-encoded", "bypass", "hidden"]
    
  linux:
    - parent: "nginx", child: "bash"               # Webshell
    - parent: "apache2", child: "sh"               # Webshell
    - cmdline_contains: ["/dev/tcp", "nc -e", "bash -i"]

suspicious_network:
  windows:
    - process: "notepad.exe", has_connection: true
    - process: "calc.exe", has_connection: true
    - connection_port: [4444, 5555, 6666, 1337]    # Common C2
    
  linux:
    - process: "bash", state: "ESTABLISHED"
    - process: "sh", remote_port: [443, 8443]
```

#### 3.2.4 Threat Validator

**Validation Sources:**

| Source | Rate Limit | Cache TTL | Weight |
|--------|------------|-----------|--------|
| VirusTotal | 4/min (free) | 6 hours | 40% |
| AbuseIPDB | 1000/day | 6 hours | 30% |
| Local Whitelist | N/A | Permanent | 30% |

**Confidence Scoring:**

```
confidence = (vt_score * 0.4) + (abuse_score * 0.3) + (whitelist_score * 0.3)

Thresholds:
- HIGH (malicious): confidence > 0.7
- MEDIUM (suspicious): 0.4 < confidence <= 0.7
- LOW (likely benign): confidence <= 0.4
```

**Local Whitelist:**

```yaml
whitelist:
  ips:
    - 8.8.8.8        # Google DNS
    - 8.8.4.4        # Google DNS
    - 1.1.1.1        # Cloudflare
    - 0.0.0.0        # Localhost binding
    - 127.0.0.1      # Loopback
    
  domains:
    - microsoft.com
    - google.com
    - windowsupdate.com
    
  processes:
    windows:
      - path: "C:\\Windows\\System32\\svchost.exe"
      - path: "C:\\Windows\\System32\\csrss.exe"
      - path: "C:\\Windows\\System32\\smss.exe"
    linux:
      - path: "/usr/sbin/sshd"
      - path: "/usr/bin/bash"
```

#### 3.2.5 Symbol Resolver (Linux-specific)

**Problem:** Volatility3 Linux plugins yêu cầu symbol file (ISF JSON) khớp với kernel version.

**Solution:**

```
1. Detect kernel version từ dump (banners.Banners)
2. Check local cache: data/symbols/{kernel_version}.json
3. If miss:
   a. Search online ISF repository
   b. If found → download và cache
   c. If not found → prompt user để generate với dwarf2json
4. Return symbol path cho Vol3 --symbol-dirs
```

**Symbol Sources:**
- Volatility3 ISF Server: https://isf-server.techanarchy.net/
- Local generation: dwarf2json + kernel debug symbols

#### 3.2.6 MITRE Mapper

**Mapping Rules:**

| Finding | MITRE Technique | Tactic |
|---------|-----------------|--------|
| Hidden process (psscan vs pslist) | T1055 | Defense Evasion |
| Code injection (malfind RWX) | T1055.001 | Defense Evasion |
| Suspicious parent-child | T1059 | Execution |
| PowerShell encoded | T1059.001 | Execution |
| Registry Run key | T1547.001 | Persistence |
| Scheduled task | T1053.005 | Persistence |
| Service creation | T1543.003 | Persistence |
| DLL side-loading | T1574.002 | Persistence |
| Network connection | T1071 | Command & Control |

## 4. DATA FLOW

### 4.1 Complete Analysis Flow

```
[1] User Request
    │
    │  "Analyze dump.raw for malware"
    ▼
[2] MCP Server receives request
    │
    │  Parse parameters, validate dump_path
    ▼
[3] OS Detection
    │
    │  vol3 windows.info / banners.Banners
    │  Result: Windows 10 x64 / Linux 5.15
    ▼
[4] Decision Engine
    │
    │  Input: os=windows, goal=malware_detection
    │  Output: [pslist, pstree, malfind, cmdline, handles]
    ▼
[5] Symbol Resolution (Linux only)
    │
    │  Check/download kernel symbols
    ▼
[6] Plugin Execution
    │
    │  ┌─────────────────────────────────────┐
    │  │  For each plugin:                   │
    │  │  1. Check Redis cache               │
    │  │  2. If miss → run vol3 subprocess   │
    │  │  3. Parse JSON output               │
    │  │  4. Store in cache                  │
    │  └─────────────────────────────────────┘
    ▼
[7] IOC Extraction
    │
    │  Regex patterns + Context rules
    │  Output: 50 potential IOCs
    ▼
[8] Validation Pipeline
    │
    │  ┌─────────────────────────────────────┐
    │  │  1. Check local whitelist           │
    │  │  2. Query VirusTotal (batch)        │
    │  │  3. Query AbuseIPDB                 │
    │  │  4. Calculate confidence score      │
    │  └─────────────────────────────────────┘
    │  Output: 15 validated IOCs (HIGH/MEDIUM)
    ▼
[9] MITRE Mapping
    │
    │  Map findings → ATT&CK techniques
    ▼
[10] Report Generation
    │
    │  JSON for AI agent + PDF for analyst
    ▼
[11] Response to Client
```

### 4.2 Caching Strategy

```
┌─────────────────────────────────────────────────────────────────┐
│                      CACHE HIERARCHY                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  L1: Plugin Result Cache (Redis)                                │
│  ├─ Key: vol3:{dump_sha256}:{plugin}:{args_hash}                │
│  ├─ TTL: 24 hours                                               │
│  └─ Hit rate target: >80%                                       │
│                                                                  │
│  L2: Threat Intel Cache (Redis)                                 │
│  ├─ Key: threat:{source}:{indicator_hash}                       │
│  ├─ TTL: 6 hours                                                │
│  └─ Prevents API rate limit exhaustion                          │
│                                                                  │
│  L3: Symbol Cache (Filesystem)                                  │
│  ├─ Path: data/symbols/{kernel_version}.json                    │
│  ├─ TTL: Permanent                                              │
│  └─ ~50-200MB per kernel version                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 5. FOLDER STRUCTURE

```
volatility3-ioc-extraction/
├── README.md
├── system_architecture.md
├── docker-compose.yml
├── .env.example
├── pyproject.toml
│
├── docs/
│   ├── phase1_intake.md
│   ├── phase2_execution.md
│   ├── phase3_extraction.md
│   ├── phase4_validation.md
│   ├── phase5_presentation.md
│   └── api_reference.md
│
├── docker/
│   ├── Dockerfile.server
│   ├── Dockerfile.worker
│   └── scripts/
│       ├── entrypoint.sh
│       └── healthcheck.sh
│
├── src/
│   ├── __init__.py
│   ├── mcp_server/
│   │   ├── __init__.py
│   │   ├── server.py
│   │   ├── tools/
│   │   │   ├── __init__.py
│   │   │   ├── triage.py
│   │   │   ├── windows.py
│   │   │   ├── linux.py
│   │   │   └── validation.py
│   │   ├── resources/
│   │   │   ├── __init__.py
│   │   │   ├── plugins.py
│   │   │   └── cases.py
│   │   └── prompts/
│   │       ├── __init__.py
│   │       └── templates.py
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── decision_engine.py
│   │   ├── volatility_executor.py
│   │   ├── ioc_extractor.py
│   │   ├── validator.py
│   │   ├── mitre_mapper.py
│   │   └── symbol_resolver.py
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── ioc.py
│   │   ├── case.py
│   │   └── plugin.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── cache.py
│       ├── logging.py
│       └── security.py
│
├── config/
│   ├── settings.py
│   ├── plugin_profiles.yaml
│   ├── whitelist.yaml
│   └── mitre_mappings.yaml
│
├── data/
│   ├── dumps/           # Input memory dumps (gitignored)
│   ├── symbols/         # Linux kernel symbols
│   ├── cache/           # Local file cache
│   └── reports/         # Generated reports
│
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── test_decision_engine.py
│   │   ├── test_ioc_extractor.py
│   │   └── test_validator.py
│   ├── integration/
│   │   ├── test_mcp_server.py
│   │   └── test_pipeline.py
│   └── fixtures/
│       └── sample_outputs/
│
└── scripts/
    ├── setup.sh
    ├── benchmark.py
    └── validate_plugins.py
```

## 6. DEPLOYMENT

### 6.1 Docker Compose

```yaml
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
    depends_on:
      - redis
      - postgres
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

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
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
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 2G

volumes:
  redis_data:
  postgres_data:
```

### 6.2 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 16 GB | 32 GB |
| Storage | 100 GB SSD | 500 GB SSD |
| Docker | 24.0+ | Latest |
| Python | 3.10+ | 3.11+ |

### 6.3 Security Considerations

```yaml
security_measures:
  input_validation:
    - dump_path must be within allowed directories
    - plugin_name must be in whitelist
    - file extension validation (.raw, .dmp, .mem)
    
  network_isolation:
    - Only MCP server exposed externally
    - Redis/PostgreSQL internal network only
    
  secrets_management:
    - API keys via environment variables
    - Docker secrets in production
    
  rate_limiting:
    - 10 requests/minute per client
    - Threat intel API budget management
```

## 7. PERFORMANCE TARGETS

| Metric | Target | Measurement |
|--------|--------|-------------|
| Analysis time (4GB dump) | < 10 minutes | End-to-end with caching |
| Cache hit rate | > 80% | Redis metrics |
| IOC Recall | > 85% | vs. manual analysis |
| False Positive Rate | < 20% | After validation |
| API utilization | < 80% quota | Daily budget |

## 8. LIMITATIONS

1. **Network Analysis Gap**: Windows netscan/netstat không hoạt động trong Vol3 2.5+, sử dụng handles-based approach thay thế (less comprehensive)

2. **Linux Symbol Dependency**: Linux analysis yêu cầu kernel symbols, có thể không available cho custom kernels

3. **Zero-day Blindness**: System dựa trên known patterns và threat intel, không detect được unknown malware

4. **API Rate Limits**: Free tier APIs giới hạn throughput, batch analysis bị throttle

5. **Memory Constraints**: Dump files > 16GB có thể gây memory pressure

## 9. REFERENCES

- Volatility3 Documentation: https://volatility3.readthedocs.io/
- FastMCP Documentation: https://gofastmcp.com/
- MITRE ATT&CK: https://attack.mitre.org/
- VirusTotal API: https://developers.virustotal.com/
- AbuseIPDB API: https://docs.abuseipdb.com/
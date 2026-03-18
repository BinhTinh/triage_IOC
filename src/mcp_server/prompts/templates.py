from fastmcp import FastMCP


def register_prompts(mcp: FastMCP):

    @mcp.prompt()
    async def ioc_extraction_workflow(dump_path: str = "", os_hint: str = "auto") -> str:
        return """\
# Automatic Volatility3 IOC Extraction — Full Pipeline Guide

You are an AI forensic analyst. Follow these phases **in strict order**.
Never ask the user for paths or API keys — everything is discoverable via tools.

---
## PATH RULES (non-negotiable)
- All memory dumps are under `/app/data/dumps/`
- All reports are under `/app/data/reports/`
- All Volatility3 symbol caches are under `/app/data/symbols/`
- Never use Windows-style paths (e.g. `C:\\...`). Always use POSIX Docker paths.

---
## PHASE 1 — Discover Dumps
```
list_dumps()
```
- Returns all dump files in `/app/data/dumps/`
- If multiple dumps exist, pick the most recently modified one unless the user specified one
- Store: `dump_path`

---
## PHASE 2 — OS Detection
```
detect_os(dump_path=<dump_path>)
```
- Returns `os_type` ("windows" or "linux"), OS build, architecture
- This server is **Windows-only** — if `os_type` is not "windows", inform the user
- Store: `os_type`
- **Never skip this step.** Passing the wrong os_type generates completely wrong IOCs.

---
## PHASE 3 — Run Volatility3 Plugins
```
run_plugins(dump_path=<dump_path>, os_type=<os_type>, store_only=true)
```
- Executes the full Windows plugin preset **in parallel** (18 plugins):
  - Network: netscan, netstat, handles
  - Host: pslist, psscan, cmdline, malfind, hollowprocesses, ldrmodules,
          dlllist, filescan, svcscan, hivelist, printkey×3, userassist, amcache
- `store_only=true` — results stored server-side so they don't flood the MCP response
- Returns: `result_id` (a UUID string), `report_path` (raw plugin output JSON)
- Store: `result_id`, `plugin_report_path`
- Plugin failures are normal (e.g. svcscan not found) — continue anyway

---
## PHASE 4 — IOC Extraction
```
ioc_extract_from_store(result_id=<result_id>, os_type=<os_type>)
```
- Reads stored plugin results, runs the full extraction pipeline:
  - IOCExtractor (regex: IPs, hashes, file paths, domains, registry keys)
  - ContextAwareExtractor (structured: injection, services, hidden procs, network)
  - RegistryAnalyzer (persistence, defense evasion, credential access, execution)
- Returns compact response containing:
  - `summary`: total, network_count, host_count, high/medium/low, **process_groups**, unattributed
  - `by_process`: top-10 processes ranked by threat score (0.0–1.0), each with:
    - `process`, `pid`, `threat_level` (HIGH/MEDIUM/LOW), `threat_score`
    - `techniques` (MITRE ATT&CK list), `ioc_count`, `iocs` list
  - `report_path`: full extraction JSON (all IOC types, all groups)
- Store: `ioc_extract_report_path` = returned `report_path`

**Reading by_process output:**
- Process groups are sorted by `threat_score` descending — most dangerous process is FIRST
- `threat_level: "HIGH"` means threat_score ≥ 0.75 — flag immediately
- `unattributed_count` = hashes/paths with no process attribution (from filescan, amcache)
- Read the `report_path` JSON for the full set of all groups and unattributed IOCs

---
## PHASE 5 — IOC Validation
```
ioc_validate_from_report(report_path=<ioc_extract_report_path>, os_type=<os_type>)
```
- Runs the ValidationPipeline against all extracted IOCs:
  - WhitelistValidator: filters private IPs, known-good domains, system processes
  - VirusTotalValidator: hash/IP/domain lookup (only if VT_API_KEY configured)
  - AbuseIPDBValidator: IP reputation (only if ABUSEIPDB_KEY configured)
  - CorrelationGuard: context-only IOCs (injection, process, command) downgraded if isolated
- Returns compact response containing:
  - `summary`: malicious, suspicious, benign counts, **process_groups**, **unattributed**
  - `by_process`: top-10 processes with post-validation IOCs
  - `malware_assessment`: threat_level (CRITICAL/HIGH/MEDIUM/LOW), threat_score/100, narrative
  - `report_path`: full validation JSON
- Store: `ioc_validate_report_path` = returned `report_path`

**Interpreting verdicts:**
- `malicious` (confidence ≥ 0.70): confirmed — recommend blocking/isolation
- `suspicious` (0.40–0.69): investigate — provide context to the user
- `benign` (< 0.40): filtered by whitelist or low signal
- Without API keys, all verdicts are local-heuristic only — inform the user

---
## PHASE 6 — Forensic Report
```
forensic_report_from_validation(report_path=<ioc_validate_report_path>)
```
- Generates a structured forensic markdown report saved to `/app/data/reports/`
- Returns the `report_path` of the markdown file
- This is the final deliverable for the user

---
## COMPLETE EXAMPLE CONVERSATION

```
1. list_dumps()
   → ["/app/data/dumps/infected.raw"]

2. detect_os(dump_path="/app/data/dumps/infected.raw")
   → {"os_type": "windows", "build": "Windows 10 x64 19041"}

3. run_plugins(dump_path="/app/data/dumps/infected.raw", os_type="windows", store_only=true)
   → {"result_id": "abc123", "report_path": "/app/data/reports/run_abc123.json"}

4. ioc_extract_from_store(result_id="abc123", os_type="windows")
   → {
       "summary": {"total": 190, "high": 12, "process_groups": 8, "unattributed": 72},
       "by_process": [
         {"process": "powershell.exe", "pid": 3892, "threat_level": "HIGH",
          "threat_score": 0.92, "techniques": ["T1055", "T1059.001"], "ioc_count": 5}
       ],
       "report_path": "/app/data/reports/ioc_extract_abc123.json"
     }

5. ioc_validate_from_report(report_path="/app/data/reports/ioc_extract_abc123.json", os_type="windows")
   → {
       "summary": {"malicious": 8, "suspicious": 14, "benign": 168},
       "malware_assessment": {"threat_level": "HIGH", "threat_score": 74},
       "by_process": [...],
       "report_path": "/app/data/reports/ioc_validate_abc123.json"
     }

6. forensic_report_from_validation(report_path="/app/data/reports/ioc_validate_abc123.json")
   → {"report_path": "/app/data/reports/CASE_WINDOWS_.../SUMMARY.md"}
```

---
## WHAT TO TELL THE USER AFTER EACH PHASE

| Phase | Report to user |
|-------|----------------|
| detect_os | OS version, architecture |
| run_plugins | How many plugins succeeded vs failed |
| ioc_extract | Total IOCs, top 3 dangerous processes with their techniques |
| ioc_validate | Malicious/suspicious counts, threat level, top findings |
| forensic_report | Report path, 3-5 key actionable findings |

---
## IOC TYPES AND MITRE MAPPING

| IOC Type | Source Plugin | MITRE Technique | Meaning |
|----------|--------------|-----------------|---------|
| injection | malfind | T1055 | Code injected into another process |
| process (hollowing) | hollowprocesses | T1055.012 | Process image replaced in memory |
| process (service) | svcscan | T1543.003 | Malicious Windows service |
| process (hidden) | psscan vs pslist | T1564.001 | DKOM rootkit-hidden process |
| ipv4 | netscan, handles | T1071 | C2 network connection |
| command | cmdline | T1059 | Suspicious command line |
| md5/sha1/sha256 | filescan, amcache | T1204 | Suspicious file hash |
| filepath | filescan, dlllist | T1036 | Suspicious file location |
| registry_persistence | printkey | T1547 | Autorun registry key |
| registry_defense_evasion | printkey | T1112 | Registry-based evasion |

---
## CONFIDENCE SCORING

| Score | Verdict | Meaning |
|-------|---------|---------|
| ≥ 0.85 | malicious (confirmed) | Rare C2 port, known bad hash, process hollowing |
| 0.70–0.84 | malicious | Strong indicators, multiple signals |
| 0.40–0.69 | suspicious | Single indicator, no threat-intel confirmation |
| < 0.40 | benign | Whitelisted or insufficient signal |

---
## ERROR HANDLING

- Plugin failure (e.g. "Volatility error"): note it, continue to next phase
- `result_id` not found: re-run `run_plugins` with same dump
- `os_type` mismatch: re-run `detect_os`, use returned value
- Zero IOCs after extraction: check if `store_only=true` was used in `run_plugins`
- No threat-intel results: API keys not configured — local heuristics only, inform user
"""

    @mcp.prompt()
    async def ioc_reference() -> str:
        return """\
# IOC Tool Quick Reference

## Tool Chain (always in this order)
```
list_dumps
  → detect_os(dump_path)
    → run_plugins(dump_path, os_type, store_only=true)          → result_id
      → ioc_extract_from_store(result_id, os_type)              → ioc report_path
        → ioc_validate_from_report(report_path, os_type)        → validate report_path
          → forensic_report_from_validation(report_path)        → final report
```

## Tools

### Discovery
| Tool | Key params | Returns |
|------|-----------|---------|
| `list_dumps` | — | list of dump file paths |
| `detect_os` | `dump_path` | `os_type`, build, arch |

### Execution
| Tool | Key params | Returns |
|------|-----------|---------|
| `run_plugins` | `dump_path`, `os_type`, `store_only=true` | `result_id`, `report_path` |
| `run_plugin` | `dump_path`, `plugin_name`, `os_type` | single plugin output |

### Extraction
| Tool | Key params | Returns |
|------|-----------|---------|
| `ioc_extract_from_store` | `result_id`, `os_type` | summary, **by_process**, report_path |
| `ioc_extract` | `plugin_results` dict, `os_type` | same as above (direct input) |

### Validation
| Tool | Key params | Returns |
|------|-----------|---------|
| `ioc_validate_from_report` | `report_path` (extraction), `os_type` | malicious/suspicious/benign, **by_process**, report_path |
| `ioc_validate` | `network_iocs[]`, `host_iocs[]`, `os_type` | same (direct input) |

### Reporting
| Tool | Key params | Returns |
|------|-----------|---------|
| `forensic_report_from_validation` | `report_path` (validation) | forensic markdown report path |

## by_process Structure
```json
{
  "process": "powershell.exe",
  "pid": 3892,
  "threat_level": "HIGH",
  "threat_score": 0.92,
  "techniques": ["T1055", "T1059.001"],
  "ioc_count": 5,
  "iocs": [
    {"type": "injection", "value": "PID 3892 @ 0x1400000",
     "confidence": 0.92, "technique": "T1055", "source": "malfind"}
  ]
}
```
Groups sorted by threat_score descending. HIGH = score ≥ 0.75.

## Path Rules
- Dumps:   `/app/data/dumps/<name>.raw`
- Reports: `/app/data/reports/<prefix>_<id>.json`
- Symbols: `/app/data/symbols/volatility3/`
- Never use Windows paths or relative paths.

## Validation Policy
- Whitelist always runs (private IPs, Microsoft/Google domains, system processes)
- VT + AbuseIPDB only when `ENABLE_THREAT_INTEL=true` and API keys are set
- Without API keys: local heuristic scoring only — verdicts may have false positives
"""

# API Reference

## MCP Tools

### Phase 1: Intake & Profiling

#### detect_os

Detect operating system from memory dump.

```python
await detect_os(dump_path: str) -> dict
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| dump_path | string | Yes | Path to memory dump file |

**Returns:**
```json
{
  "os_type": "windows",
  "version": "10",
  "arch": "x64",
  "build": "19041"
}
```

---

#### smart_triage

Analyze dump and recommend analysis plan.

```python
await smart_triage(dump_path: str, goal: str = "malware_detection") -> dict
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| dump_path | string | Yes | Path to memory dump file |
| goal | string | No | Analysis goal (malware_detection, incident_response, quick_triage, rootkit_hunt, full_audit) |

**Returns:**
```json
{
  "case_id": "CASE-20260128-143052",
  "os": {"type": "windows", "version": "10", "arch": "x64"},
  "plan": {
    "goal": "malware_detection",
    "plugins": ["windows.pslist", "windows.malware.malfind"],
    "estimated_minutes": 10
  },
  "next_action": "Call batch_plugins to execute analysis"
}
```

---

### Phase 2: Execution

#### run_plugin

Execute single Volatility3 plugin.

```python
await run_plugin(dump_path: str, plugin: str, args: dict = None) -> dict
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| dump_path | string | Yes | Path to memory dump |
| plugin | string | Yes | Plugin name |
| args | object | No | Plugin arguments |

**Returns:**
```json
{
  "plugin": "windows.pslist",
  "success": true,
  "rows": 45,
  "data": [...]
}
```

---

#### batch_plugins

Execute multiple plugins in parallel.

```python
await batch_plugins(dump_path: str, plugins: List[str], max_concurrent: int = 3) -> dict
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| dump_path | string | Yes | Path to memory dump |
| plugins | array | Yes | List of plugin names |
| max_concurrent | integer | No | Max parallel executions |

**Returns:**
```json
{
  "total": 5,
  "successful": 4,
  "failed": 1,
  "results": {...},
  "data": {...}
}
```

---

### Phase 3: Extraction

#### extract_iocs

Extract IOCs from plugin results.

```python
await extract_iocs(plugin_results: dict, os_type: str = "windows") -> dict
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| plugin_results | object | Yes | Results from batch_plugins |
| os_type | string | No | Operating system type |

**Returns:**
```json
{
  "total": 45,
  "by_confidence": {"high": 8, "medium": 22, "low": 15},
  "by_type": {"ip": 12, "domain": 5, "process": 8},
  "iocs": [...],
  "next_action": "Call validate_iocs"
}
```

---

### Phase 4: Validation

#### validate_iocs

Validate IOCs against threat intelligence.

```python
await validate_iocs(iocs: List[dict], os_type: str = "windows") -> dict
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| iocs | array | Yes | IOCs from extract_iocs |
| os_type | string | No | Operating system type |

**Returns:**
```json
{
  "total": 45,
  "summary": {"malicious": 5, "suspicious": 12, "benign": 28},
  "malicious": [...],
  "suspicious": [...],
  "benign": [...],
  "next_action": "Call map_mitre"
}
```

---

### Phase 5: Presentation

#### map_mitre

Map IOCs to MITRE ATT&CK.

```python
await map_mitre(validated_iocs: dict) -> dict
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| validated_iocs | object | Yes | Results from validate_iocs |

**Returns:**
```json
{
  "total_techniques": 5,
  "tactics_involved": ["Execution", "Defense Evasion"],
  "matrix": {...},
  "techniques": [...],
  "next_action": "Call generate_report"
}
```

---

#### generate_report

Generate forensic analysis report.

```python
await generate_report(case_id: str, validated_iocs: dict, mitre_mapping: dict, format: str = "both") -> dict
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| case_id | string | Yes | Case identifier |
| validated_iocs | object | Yes | Results from validate_iocs |
| mitre_mapping | object | Yes | Results from map_mitre |
| format | string | No | Output format (json, markdown, both) |

**Returns:**
```json
{
  "case_id": "CASE-20260128-143052",
  "status": "completed",
  "threat_level": "HIGH",
  "summary": {...},
  "report_paths": {"json": "...", "markdown": "..."},
  "top_recommendations": [...],
  "techniques_detected": [...]
}
```

---

## MCP Resources

### Plugin Catalog

#### plugins://catalog

List all available plugins.

```
GET plugins://catalog
```

**Response:**
```json
{
  "total": 150,
  "windows": [...],
  "linux": [...],
  "mac": [...]
}
```

---

#### plugins://{name}/info

Get plugin details.

```
GET plugins://windows.malware.malfind/info
```

**Response:**
```json
{
  "name": "windows.malware.malfind",
  "description": "Lists process memory ranges with injected code",
  "os": "windows",
  "category": "malware",
  "estimated_time": "2-5 minutes"
}
```

---

### Analysis Profiles

#### profiles://{goal}/{os}

Get analysis profile.

```
GET profiles://malware_detection/windows
```

**Response:**
```json
{
  "goal": "malware_detection",
  "os": "windows",
  "plugins": [...],
  "estimated_minutes": 10
}
```

---

### Cases

#### cases://list

List all cases.

```
GET cases://list
```

**Response:**
```json
{
  "total": 25,
  "cases": [...]
}
```

---

#### cases://{id}/summary

Get case summary.

```
GET cases://CASE-20260128-143052/summary
```

**Response:**
```json
{
  "id": "CASE-20260128-143052",
  "status": "completed",
  "threat_level": "HIGH",
  "ioc_count": 45,
  "created_at": "2026-01-28T14:30:52Z"
}
```

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 400 | ValidationError | Invalid input parameters |
| 401 | AuthenticationError | Missing or invalid API key |
| 403 | SecurityError | Path outside allowed directories |
| 404 | NotFoundError | Resource not found |
| 408 | TimeoutError | Plugin execution timeout |
| 429 | RateLimitError | API rate limit exceeded |
| 500 | InternalError | Server error |

---

## Rate Limits

| Service | Limit | Period |
|---------|-------|--------|
| MCP Server | 60 requests | per minute |
| VirusTotal | 4 requests | per minute |
| AbuseIPDB | 1000 requests | per day |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| VT_API_KEY | Yes | - | VirusTotal API key |
| ABUSEIPDB_KEY | Yes | - | AbuseIPDB API key |
| REDIS_URL | No | localhost:6379 | Redis connection |
| DATABASE_URL | No | sqlite:///data/cases.db | Database connection |
| LOG_LEVEL | No | INFO | Logging level |
| MAX_DUMP_SIZE | No | 64GB | Maximum dump size |
| PLUGIN_TIMEOUT | No | 600 | Plugin timeout seconds |
| CACHE_TTL | No | 86400 | Cache TTL seconds |
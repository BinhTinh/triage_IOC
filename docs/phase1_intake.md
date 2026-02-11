# Phase 1: Intake & Profiling

## Overview

Phase 1 handles initial memory dump intake, OS detection, and triage decision making.

## Components

### 1.1 Dump Intake

**Input Validation:**

```python
ALLOWED_EXTENSIONS = ['.raw', '.dmp', '.mem', '.vmem', '.lime']
ALLOWED_DIRECTORIES = ['/app/data/dumps', '/data/dumps']
MAX_DUMP_SIZE = 64 * 1024 * 1024 * 1024  # 64GB

def validate_dump_path(dump_path: str) -> bool:
    path = Path(dump_path).resolve()
    
    if not any(str(path).startswith(d) for d in ALLOWED_DIRECTORIES):
        raise SecurityError("Path outside allowed directories")
    
    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValidationError(f"Invalid extension: {path.suffix}")
    
    if not path.exists():
        raise FileNotFoundError(f"Dump not found: {path}")
    
    if path.stat().st_size > MAX_DUMP_SIZE:
        raise ValidationError("Dump exceeds maximum size")
    
    return True
```

**Metadata Extraction:**

```python
@dataclass
class DumpMetadata:
    path: str
    size_bytes: int
    sha256: str
    created_at: datetime
    
def extract_metadata(dump_path: str) -> DumpMetadata:
    path = Path(dump_path)
    
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    
    return DumpMetadata(
        path=str(path),
        size_bytes=path.stat().st_size,
        sha256=sha256.hexdigest(),
        created_at=datetime.fromtimestamp(path.stat().st_ctime)
    )
```

### 1.2 OS Detection

**Detection Strategy:**

```
1. Try windows.info plugin
   - Success → Windows detected
   - Parse version, architecture
   
2. Try banners.Banners plugin
   - Look for Linux kernel strings
   - Extract kernel version
   
3. Fallback
   - Default to Windows (most common)
   - Log warning for manual verification
```

**Implementation:**

```python
async def detect_os(dump_path: str) -> OSInfo:
    try:
        result = await run_volatility(
            dump_path, 
            'windows.info',
            renderer='json'
        )
        if result.success:
            return OSInfo(
                os_type='windows',
                version=result.data.get('NtMajorVersion'),
                build=result.data.get('NtBuildNumber'),
                arch='x64' if result.data.get('Is64Bit') else 'x86'
            )
    except PluginError:
        pass
    
    try:
        result = await run_volatility(
            dump_path,
            'banners.Banners',
            renderer='json'
        )
        if result.success and result.data:
            banner = result.data[0].get('Banner', '')
            kernel_match = re.search(r'Linux version (\d+\.\d+\.\d+)', banner)
            if kernel_match:
                return OSInfo(
                    os_type='linux',
                    version=kernel_match.group(1),
                    arch='x64'
                )
    except PluginError:
        pass
    
    logger.warning(f"Could not detect OS for {dump_path}, defaulting to Windows")
    return OSInfo(os_type='windows', version='unknown', arch='x64')
```

### 1.3 Triage Decision

**Goal Definitions:**

| Goal | Description | Use Case |
|------|-------------|----------|
| `malware_detection` | Find malicious code, injection, C2 | Suspected malware infection |
| `incident_response` | Artifacts for IR timeline | Active incident |
| `quick_triage` | Fast scan, critical indicators only | Initial assessment |
| `rootkit_hunt` | Kernel-level threats, hidden modules | Advanced persistent threat |
| `full_audit` | All plugins, comprehensive | Legal/compliance |

**Decision Engine:**

```python
PLUGIN_PROFILES = {
    'malware_detection': {
        'windows': {
            'plugins': [
                ('windows.pslist', {}),
                ('windows.pstree', {}),
                ('windows.psscan', {}),
                ('windows.malware.malfind', {}),
                ('windows.malware.hollowprocesses', {}),
                ('windows.cmdline', {}),
                ('windows.dlllist', {}),
                ('windows.handles', {'type': 'File'}),
            ],
            'estimated_minutes': 10
        },
        'linux': {
            'plugins': [
                ('linux.pslist', {}),
                ('linux.pstree', {}),
                ('linux.psscan', {}),
                ('linux.malware.malfind', {}),
                ('linux.malware.check_syscall', {}),
                ('linux.bash', {}),
                ('linux.sockstat', {}),
            ],
            'estimated_minutes': 12
        }
    },
    'quick_triage': {
        'windows': {
            'plugins': [
                ('windows.pslist', {}),
                ('windows.malware.malfind', {}),
                ('windows.cmdline', {}),
            ],
            'estimated_minutes': 4
        },
        'linux': {
            'plugins': [
                ('linux.pslist', {}),
                ('linux.malware.malfind', {}),
                ('linux.bash', {}),
            ],
            'estimated_minutes': 4
        }
    }
}

def get_triage_plan(os_type: str, goal: str) -> TriagePlan:
    profile = PLUGIN_PROFILES.get(goal, {}).get(os_type)
    if not profile:
        raise ValueError(f"No profile for {goal}/{os_type}")
    
    return TriagePlan(
        plugins=profile['plugins'],
        estimated_minutes=profile['estimated_minutes'],
        goal=goal,
        os_type=os_type
    )
```

### 1.4 Case Initialization

**Case Model:**

```python
@dataclass
class Case:
    id: str
    dump_path: str
    dump_hash: str
    os_info: OSInfo
    goal: str
    status: str  # pending, running, completed, failed
    created_at: datetime
    updated_at: datetime
    findings: List[Finding] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)

def create_case(dump_path: str, goal: str) -> Case:
    metadata = extract_metadata(dump_path)
    os_info = detect_os(dump_path)
    
    case = Case(
        id=f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        dump_path=dump_path,
        dump_hash=metadata.sha256,
        os_info=os_info,
        goal=goal,
        status='pending',
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    
    save_case(case)
    return case
```

## MCP Tool: smart_triage

```python
@mcp.tool()
async def smart_triage(
    dump_path: str,
    goal: str = "malware_detection"
) -> dict:
    """
    Analyze memory dump and return recommended analysis plan.
    
    Args:
        dump_path: Path to memory dump file
        goal: Analysis goal (malware_detection, incident_response, quick_triage, rootkit_hunt, full_audit)
    
    Returns:
        Analysis plan with plugins, estimated time, and case ID
    """
    validate_dump_path(dump_path)
    
    os_info = await detect_os(dump_path)
    await ctx.info(f"Detected OS: {os_info.os_type} {os_info.version}")
    
    plan = get_triage_plan(os_info.os_type, goal)
    case = create_case(dump_path, goal)
    
    return {
        "case_id": case.id,
        "os": {
            "type": os_info.os_type,
            "version": os_info.version,
            "arch": os_info.arch
        },
        "plan": {
            "goal": goal,
            "plugins": [p[0] for p in plan.plugins],
            "estimated_minutes": plan.estimated_minutes
        },
        "next_action": "Call batch_plugins to execute analysis"
    }
```

## Output Schema

```json
{
  "case_id": "CASE-20260128-143052",
  "os": {
    "type": "windows",
    "version": "10",
    "arch": "x64"
  },
  "plan": {
    "goal": "malware_detection",
    "plugins": [
      "windows.pslist",
      "windows.pstree",
      "windows.malware.malfind",
      "windows.cmdline"
    ],
    "estimated_minutes": 10
  },
  "next_action": "Call batch_plugins to execute analysis"
}
```

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `SecurityError` | Path outside allowed dirs | Use valid dump directory |
| `ValidationError` | Invalid extension/size | Check file format |
| `FileNotFoundError` | Dump not found | Verify path |
| `OSDetectionError` | Cannot detect OS | Manual OS specification |
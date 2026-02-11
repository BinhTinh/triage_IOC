from fastmcp import FastMCP


def register_prompts(mcp: FastMCP):
    
    @mcp.prompt()
    async def malware_triage() -> str:
        return """# Malware Triage Workflow

## Step 1: List Available Dumps
First, check what memory dumps are available for analysis:
```
Call tool: list_available_dumps
```

## Step 2: Select and Analyze
Once you have the filename, start the triage:
```
Call tool: select_dump_and_triage
Parameters:
  - filename: "<filename from step 1>"
  - goal: "malware_detection"
```

## Step 3: Execute Plugins
Based on the triage plan, execute the recommended plugins:

**For Windows:**
```
Call tool: win_batch_plugins
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
  - plugins: ["windows.pslist.PsList", "windows.pstree.PsTree", "windows.malware.malfind.Malfind", "windows.cmdline.CmdLine"]
```

**For Linux:**
```
Call tool: linux_batch_plugins
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
  - plugins: ["linux.pslist.PsList", "linux.pstree.PsTree", "linux.malware.malfind.Malfind", "linux.bash.Bash"]
```

## Step 4: Extract IOCs
Extract indicators from plugin results:
```
Call tool: ioc_extract
Parameters:
  - plugin_results: <results from step 3>
  - os_type: "windows" or "linux"
```

## Step 5: Validate IOCs
Validate extracted IOCs against threat intelligence:
```
Call tool: ioc_validate
Parameters:
  - iocs: <iocs from step 4>
  - os_type: "windows" or "linux"
```

## Step 6: Map to MITRE ATT&CK
Map findings to ATT&CK framework:
```
Call tool: ioc_map_mitre
Parameters:
  - validated_iocs: <results from step 5>
```

## Step 7: Generate Report
Create the final report:
```
Call tool: ioc_generate_report
Parameters:
  - case_id: <case_id from step 2>
  - validated_iocs: <results from step 5>
  - mitre_mapping: <results from step 6>
  - format: "both"
```

## Key Focus Areas:
- Process injection (RWX memory regions)
- Suspicious parent-child process relationships
- Encoded/obfuscated command lines
- Network connections to unknown IPs
- Persistence mechanisms
"""

    @mcp.prompt()
    async def quick_analysis() -> str:
        return """# Quick Analysis Workflow (5 minutes)

## Step 1: List Available Dumps
```
Call tool: list_available_dumps
```

## Step 2: Run Quick Analysis
Use the automated full analysis pipeline:
```
Call tool: quick_analyze
Parameters:
  - filename: "<filename from step 1>"
```

This will automatically:
1. Detect OS
2. Run essential plugins (pslist, malfind, cmdline)
3. Extract IOCs
4. Validate against threat intelligence
5. Map to MITRE ATT&CK
6. Generate reports

## Output Location:
Reports saved to: `/app/data/reports/CASE_<OS>_<TIMESTAMP>/`
- `SUMMARY.txt` - Human readable summary
- `iocs.json` - Machine readable IOC data
- `plugins/` - Raw plugin outputs
"""

    @mcp.prompt()
    async def incident_response() -> str:
        return """# Incident Response Workflow

## Step 1: List Available Dumps
```
Call tool: list_available_dumps
```

## Step 2: Start IR Triage
```
Call tool: select_dump_and_triage
Parameters:
  - filename: "<filename>"
  - goal: "incident_response"
```

## Step 3: Process Investigation

**3a. List all processes:**
```
Call tool: win_pslist (Windows) or linux_pslist (Linux)
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**3b. Process tree view:**
```
Call tool: win_pstree (Windows) or linux_pstree (Linux)
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**3c. Compare processes (find hidden):**
```
Call tool: win_compare_processes (Windows) or linux_compare_processes (Linux)
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**3d. Command lines:**
```
Call tool: win_cmdline (Windows) or linux_bash (Linux)
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

## Step 4: Artifact Collection (Windows)

**4a. Registry hives:**
```
Call tool: win_registry_hivelist
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**4b. User activity:**
```
Call tool: win_userassist
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**4c. Services:**
```
Call tool: win_svcscan
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**4d. Scheduled tasks:**
```
Call tool: win_scheduled_tasks
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

## Step 5: Malware Detection
```
Call tool: win_malware_scan (Windows) or linux_malware_scan (Linux)
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

## Step 6: Extract and Validate IOCs
```
Call tool: ioc_extract
Parameters:
  - plugin_results: <combined results from above>
  - os_type: "windows" or "linux"
```

```
Call tool: ioc_validate
Parameters:
  - iocs: <extracted iocs>
  - os_type: "windows" or "linux"
```

## Step 7: MITRE Mapping and Report
```
Call tool: ioc_map_mitre
Parameters:
  - validated_iocs: <validated results>
```

```
Call tool: ioc_generate_report
Parameters:
  - case_id: <case_id>
  - validated_iocs: <validated results>
  - mitre_mapping: <mitre results>
  - format: "both"
```

## Deliverables:
- Complete IOC list with confidence scores
- MITRE ATT&CK mapping
- Timeline of events
- Remediation recommendations
"""

    @mcp.prompt()
    async def rootkit_hunt() -> str:
        return """# Rootkit Detection Workflow

## Step 1: List Available Dumps
```
Call tool: list_available_dumps
```

## Step 2: Start Rootkit Hunt
```
Call tool: select_dump_and_triage
Parameters:
  - filename: "<filename>"
  - goal: "rootkit_hunt"
```

## Step 3: Process Comparison (Critical)
Compare pslist vs psscan to find hidden processes:

**Windows:**
```
Call tool: win_compare_processes
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**Linux:**
```
Call tool: linux_compare_processes
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

> Hidden processes = Strong rootkit indicator!

## Step 4: Module Analysis

**Linux - Check for hidden modules:**
```
Call tool: linux_compare_modules
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

```
Call tool: linux_check_syscall
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**Windows - Driver analysis:**
```
Call tool: win_driverscan
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

```
Call tool: win_modules
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

## Step 5: Kernel Integrity

**Windows:**
```
Call tool: win_ssdt
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

```
Call tool: win_callbacks
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**Linux:**
```
Call tool: linux_check_modules
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

```
Call tool: linux_hidden_modules
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

## Step 6: Extract IOCs and Report
```
Call tool: ioc_extract
Call tool: ioc_validate
Call tool: ioc_map_mitre
Call tool: ioc_generate_report
```

## Rootkit Indicators:
- Hidden processes (psscan vs pslist mismatch)
- Hidden kernel modules (Linux)
- SSDT hooks (Windows)
- Modified syscall table (Linux)
- Suspicious kernel callbacks (Windows)
"""

    @mcp.prompt()
    async def network_forensics() -> str:
        return """# Network Forensics Workflow

## Step 1: List Available Dumps
```
Call tool: list_available_dumps
```

## Step 2: Identify OS
```
Call tool: select_dump_and_triage
Parameters:
  - filename: "<filename>"
  - goal: "quick_triage"
```

## Step 3: Network Connection Analysis

**Linux:**
```
Call tool: linux_network_analysis
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

Or individually:
```
Call tool: linux_sockstat
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**Windows:**
```
Call tool: win_handles
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

## Step 4: Process Correlation
Get process list to correlate with network connections:
```
Call tool: win_pslist or linux_pslist
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

## Step 5: Validate Network IOCs
Extract and validate IP addresses:
```
Call tool: ioc_extract
Parameters:
  - plugin_results: <network results>
  - os_type: "windows" or "linux"
```

```
Call tool: validate_ip
Parameters:
  - ip: "<suspicious IP address>"
```

Or for domains:
```
Call tool: validate_domain
Parameters:
  - domain: "<suspicious domain>"
```

## Step 6: Generate Report
```
Call tool: ioc_validate
Call tool: ioc_map_mitre
Call tool: ioc_generate_report
```

## C2 Indicators to Look For:
- Unusual ports (4444, 5555, 6666, 1337, 8080)
- Connections from non-browser processes
- Beaconing patterns
- Connections to known bad IPs
"""

    @mcp.prompt()
    async def persistence_analysis() -> str:
        return """# Persistence Mechanism Analysis

## Step 1: List Available Dumps
```
Call tool: list_available_dumps
```

## Step 2: Start Analysis
```
Call tool: select_dump_and_triage
Parameters:
  - filename: "<filename>"
  - goal: "malware_detection"
```

## Step 3: Windows Persistence Checks

**3a. Registry Run Keys:**
```
Call tool: win_userassist
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

```
Call tool: win_registry_printkey
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
  - key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
```

**3b. Services:**
```
Call tool: win_svcscan
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**3c. Scheduled Tasks:**
```
Call tool: win_scheduled_tasks
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**3d. Check for persistence scan:**
```
Call tool: win_persistence_check
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

## Step 4: Linux Persistence Checks

**4a. Bash History (cron commands):**
```
Call tool: linux_bash
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**4b. Kernel Modules:**
```
Call tool: linux_lsmod
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

**4c. Environment Variables:**
```
Call tool: linux_envars
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

## Step 5: Extract and Map IOCs
```
Call tool: ioc_extract
Call tool: ioc_validate
Call tool: ioc_map_mitre
```

Look for these MITRE techniques:
- T1547 (Boot/Logon Autostart)
- T1053 (Scheduled Task)
- T1543 (Create/Modify System Process)
- T1546 (Event Triggered Execution)

## Step 6: Generate Report
```
Call tool: ioc_generate_report
Parameters:
  - case_id: <case_id>
  - validated_iocs: <results>
  - mitre_mapping: <mitre results>
  - format: "both"
```
"""

    @mcp.prompt()
    async def full_forensic_analysis() -> str:
        return """# Complete Forensic Analysis Pipeline

## Overview
This is a comprehensive analysis that covers all aspects of memory forensics.
Expected duration: 30-45 minutes

## Step 1: Setup
```
Call tool: list_available_dumps
```

## Step 2: Automated Full Analysis (Recommended)
For a complete automated analysis:
```
Call tool: quick_analyze
Parameters:
  - filename: "<filename>"
```

This runs the entire pipeline automatically and generates all reports.

---

## OR: Manual Step-by-Step Analysis

### Phase 1: Preparation
```
Call tool: select_dump_and_triage
Parameters:
  - filename: "<filename>"
  - goal: "malware_detection"
```

### Phase 2: Process Analysis
```
Call tool: win_process_analysis (Windows) or linux_process_analysis (Linux)
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

### Phase 3: Memory/Malware Analysis
```
Call tool: win_malware_scan (Windows) or linux_malware_scan (Linux)
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

### Phase 4: Rootkit Detection
```
Call tool: win_compare_processes (Windows) or linux_compare_processes (Linux)
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

### Phase 5: Persistence Analysis
```
Call tool: win_persistence_check (Windows)
Parameters:
  - dump_path: "/app/data/dumps/<filename>"
```

### Phase 6: IOC Processing
```
Call tool: ioc_extract
Parameters:
  - plugin_results: <all results combined>
  - os_type: "windows" or "linux"
```

```
Call tool: ioc_validate
Parameters:
  - iocs: <extracted iocs>
  - os_type: "windows" or "linux"
```

```
Call tool: ioc_map_mitre
Parameters:
  - validated_iocs: <validated results>
```

### Phase 7: Reporting
```
Call tool: ioc_generate_report
Parameters:
  - case_id: <case_id from phase 1>
  - validated_iocs: <from phase 6>
  - mitre_mapping: <from phase 6>
  - format: "both"
```

## Output Location
All reports saved to: `/app/data/reports/CASE_<OS>_<TIMESTAMP>/`

Contents:
- `SUMMARY.txt` - Human readable executive summary with threat scoring
- `iocs.json` - Machine readable IOC data for SIEM/SOAR integration  
- `plugins/*.txt` - Raw plugin outputs for evidence preservation
"""

    @mcp.prompt()
    async def validate_single_ioc() -> str:
        return """# Single IOC Validation Workflow

## Validate an IP Address
```
Call tool: validate_ip
Parameters:
  - ip: "<IP address to check>"
```

## Validate a Domain
```
Call tool: validate_domain
Parameters:
  - domain: "<domain to check>"
```

## Validate a File Hash
```
Call tool: validate_hash
Parameters:
  - hash_value: "<MD5, SHA1, or SHA256 hash>"
```

## Get MITRE Technique Info
```
Call tool: get_mitre_technique
Parameters:
  - technique_id: "<technique ID, e.g., T1055>"
```

## Response includes:
- Verdict: malicious / suspicious / benign
- Confidence score
- Reason for classification
- Threat intelligence sources checked
"""

    @mcp.prompt()
    async def list_tools() -> str:
        return """# Available MCP Tools

## Discovery Tools
- `list_available_dumps` - List all memory dumps in /app/data/dumps/
- `health_check` - Check server health

## Triage Tools
- `select_dump_and_triage` - Select a dump file and start triage
- `quick_analyze` - Run automated full analysis pipeline
- `smart_triage` - Smart triage with custom goal
- `full_analysis` - Complete analysis pipeline

## Windows Analysis Tools
- `win_pslist` - List processes
- `win_pstree` - Process tree view
- `win_psscan` - Scan for hidden processes
- `win_cmdline` - Process command lines
- `win_dlllist` - Loaded DLLs
- `win_handles` - Open handles
- `win_filescan` - File objects in memory
- `win_malfind` - Find injected code
- `win_hollowprocesses` - Hollowed processes
- `win_ldrmodules` - Loaded modules check
- `win_registry_hivelist` - Registry hives
- `win_registry_printkey` - Registry key values
- `win_userassist` - User activity
- `win_svcscan` - Windows services
- `win_scheduled_tasks` - Scheduled tasks
- `win_modules` - Kernel modules
- `win_driverscan` - Drivers
- `win_ssdt` - System call table
- `win_callbacks` - Kernel callbacks
- `win_batch_plugins` - Run multiple plugins
- `win_process_analysis` - Comprehensive process analysis
- `win_malware_scan` - Malware detection scan
- `win_persistence_check` - Persistence mechanisms
- `win_compare_processes` - Find hidden processes

## Linux Analysis Tools
- `linux_pslist` - List processes
- `linux_pstree` - Process tree view
- `linux_psscan` - Scan for processes
- `linux_bash` - Bash history
- `linux_lsof` - Open files
- `linux_sockstat` - Network connections
- `linux_lsmod` - Kernel modules
- `linux_malfind` - Find injected code
- `linux_check_syscall` - Syscall hooks
- `linux_check_modules` - Module integrity
- `linux_hidden_modules` - Hidden modules
- `linux_envars` - Environment variables
- `linux_batch_plugins` - Run multiple plugins
- `linux_process_analysis` - Comprehensive process analysis
- `linux_malware_scan` - Malware detection scan
- `linux_rootkit_hunt` - Rootkit detection
- `linux_network_analysis` - Network analysis
- `linux_compare_processes` - Find hidden processes
- `linux_compare_modules` - Find hidden modules

## IOC Tools
- `ioc_extract` - Extract IOCs from plugin results
- `ioc_validate` - Validate IOCs against threat intel
- `ioc_map_mitre` - Map to MITRE ATT&CK
- `ioc_generate_report` - Generate analysis report
- `validate_ip` - Validate single IP
- `validate_domain` - Validate single domain
- `validate_hash` - Validate file hash
- `get_mitre_technique` - Get technique details

## Analysis Goals
- `malware_detection` - Focus on malware indicators
- `incident_response` - IR artifact collection
- `quick_triage` - Fast initial assessment
- `rootkit_hunt` - Kernel-level threats
"""
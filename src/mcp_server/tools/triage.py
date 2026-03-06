# triage.py
import asyncio
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import redis.asyncio as aioredis
from fastmcp import FastMCP, Context

from src.config.settings import settings
from src.core.decision_engine import DecisionEngine, get_triage_plan
from src.core.volatility_executor import VolatilityExecutor
from src.core.symbol_resolver import SymbolResolver
from src.models.case import Case
from src.utils.security import validate_dump_path

executor = VolatilityExecutor()
decision_engine = DecisionEngine()
symbol_resolver = SymbolResolver()

_CASE_TTL = 86400
_REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
_VALID_GOALS = frozenset({"malware_detection", "incident_response", "rootkit_hunt", "network_forensics"})

_redis_client: Optional[aioredis.Redis] = None


async def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = await aioredis.from_url(_REDIS_URL, decode_responses=True)
    return _redis_client


async def _redis_get(key: str):
    client = await _get_redis()
    data = await client.get(key)
    return json.loads(data) if data else None


async def _redis_set(key: str, value: dict, ttl: int = _CASE_TTL):
    client = await _get_redis()
    await client.set(key, json.dumps(value), ex=ttl)


async def get_case(case_id: str) -> Optional[Case]:
    data = await _redis_get(f"case:{case_id}")
    return Case(**data) if data else None


async def save_case(case: Case) -> None:
    await _redis_set(f"case:{case.id}", case.to_dict())
    index = await _redis_get("cases:index") or []
    if case.id not in index:
        index.append(case.id)
    await _redis_set("cases:index", index)


async def update_case_status(case_id: str, status: str) -> None:
    data = await _redis_get(f"case:{case_id}")
    if data:
        data["status"] = status
        data["updated_at"] = datetime.now().isoformat()
        await _redis_set(f"case:{case_id}", data)


async def _detect_os_helper(dump_path: str) -> dict:
    try:
        result = await executor.run_plugin(dump_path, "windows.info.Info", renderer="json")
        if result.success and result.data:
            row = result.data[0]
            return {
                "os_type": "windows",
                "version": str(row.get("NtMajorVersion", "unknown")),
                "build": str(row.get("NtBuildNumber", "unknown")),
                "arch": "x64" if row.get("Is64Bit", True) else "x86",
            }
    except Exception:
        pass
    try:
        result = await executor.run_plugin(dump_path, "banners.Banners", renderer="json")
        if result.success and result.data:
            for banner in result.data:
                match = re.search(r"Linux version (\d+\.\d+\.\d+)", banner.get("Banner", ""))
                if match:
                    return {"os_type": "linux", "version": match.group(1), "build": None, "arch": "x64"}
    except Exception:
        pass
    return {"os_type": "windows", "version": "unknown", "build": "unknown", "arch": "x64"}


def register_triage_tools(mcp: FastMCP):

    @mcp.tool(
        name="list_available_dumps",
        description="""
List all memory dump files available for analysis in the configured dumps directory.

## WHEN TO USE
- At the START of every analysis session before calling any other tool
- To discover which dump files are available without knowing paths in advance
- To check file sizes before estimating analysis duration

## DIRECTORY
Default: /app/data/dumps/ (configurable via DUMPS_DIR environment variable)
Scanned recursively — subdirectories are included.

## SUPPORTED FORMATS
.raw  → most common, from WinPmem / LiME / FTK Imager
.dmp  → Windows crash dump / full memory dump
.mem  → generic raw memory
.vmem → VMware suspended VM memory
.lime → Linux Memory Extractor (LKM-based acquisition)
.img  → raw disk/memory image

## OUTPUT SCHEMA
{
  "dumps_directory": "/app/data/dumps",
  "available": true,
  "total_files": 3,
  "files": [
    {
      "filename": "infected_win10.raw",
      "path": "/app/data/dumps/infected_win10.raw",
      "size_bytes": 4294967296,
      "size_human": "4.00 GB",
      "modified": "2026-02-24T10:00:00"
    }
  ]
}

## NEXT STEP
→ Pick a file from files[] and call: detect_os(file["path"])
""",
    )
    async def list_available_dumps(ctx: Context) -> dict:
        dumps_dir = Path(settings.dumps_dir)
        if not dumps_dir.exists():
            return {"dumps_directory": str(dumps_dir), "available": False, "total_files": 0, "files": []}

        valid_extensions = {".raw", ".dmp", ".mem", ".vmem", ".lime", ".img"}
        dump_files: set = set()
        for ext in valid_extensions:
            dump_files.update(dumps_dir.glob(f"*{ext}"))
            dump_files.update(dumps_dir.glob(f"**/*{ext}"))

        files_info = []
        for f in sorted(dump_files):
            stat = f.stat()
            size = stat.st_size
            files_info.append({
                "filename": f.name,
                "path": str(f),
                "size_bytes": size,
                "size_human": (
                    f"{size / (1024**3):.2f} GB" if size > 1024**3
                    else f"{size / (1024**2):.2f} MB"
                ),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })

        return {
            "dumps_directory": str(dumps_dir),
            "available": True,
            "total_files": len(files_info),
            "files": files_info,
        }

    @mcp.tool(
        name="detect_os",
        description="""
Identify the operating system, version, and architecture from a memory dump using Volatility3.

## WHY THIS IS MANDATORY
Volatility3 plugins are OS-specific. Calling a windows.* plugin on a Linux dump (or vice versa)
will fail immediately. All downstream tools — smart_triage, batch_plugins, compare_processes,
ioc_extract — require os_type from this tool's output.

## DETECTION STRATEGY
1. Attempt windows.info.Info → success = Windows dump
   Extracts: NtMajorVersion, NtBuildNumber, Is64Bit
2. Fall back to banners.Banners → parse "Linux version X.Y.Z" from kernel banner
3. Final fallback: assume Windows (most common forensics scenario)

## RESULT IS CACHED
Redis key: vol3:{dump_sha256}:windows.info.Info:{}
TTL: 24 hours — re-running detect_os on the same dump is free (cache hit)

## OUTPUT SCHEMA
{
  "os_type": "windows",     // "windows" | "linux"
  "version":  "10",         // Windows: NtMajorVersion | Linux: kernel X.Y.Z
  "build":    "19041",      // Windows: NtBuildNumber  | Linux: null
  "arch":     "x64"         // "x64" | "x86"
}

## NEXT STEP
→ smart_triage(dump_path, os_type=result["os_type"], goal="malware_detection")
""",
    )
    async def detect_os(ctx: Context, dump_path: str) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to memory dump file from list_available_dumps["files"][n]["path"].
        """
        validate_dump_path(dump_path)
        await ctx.info(f"Detecting OS: {dump_path}")
        return await _detect_os_helper(dump_path)

    @mcp.tool(
        name="smart_triage",
        description="""
Generate a forensic analysis plan: select and order the optimal Volatility3 plugins for a given goal.


## WHAT THIS TOOL DOES
- Creates a tracked Case object (stored in Redis, retrievable via get_analysis_status)
- Maps the analysis goal to a validated, ordered plugin list with per-plugin args
- Returns estimated duration based on dump size and goal complexity
- For Linux dumps: checks kernel symbol availability and warns if missing (does NOT abort)


## ANALYSIS GOALS
┌──────────────────────┬────────────────────────────────────────────────┬──────────────┐
│ goal                 │ focus                                          │ est. duration│
├──────────────────────┼────────────────────────────────────────────────┼──────────────┤
│ malware_detection    │ process injection, code hiding, C2 connections │ 10-15 min    │
│ incident_response    │ full artifact collection, registry, services   │ 20-25 min    │
│ rootkit_hunt         │ DKOM, SSDT hooks, hidden modules, callbacks    │ 15-20 min    │
│ network_forensics    │ network connections, handles, C2 investigation │ 8-12 min     │
└──────────────────────┴────────────────────────────────────────────────┴──────────────┘


## LINUX SYMBOL HANDLING
If kernel symbols are missing for a Linux dump, this tool will:
- Log a WARNING with exact instructions to generate symbols via dwarf2json
- Still return a valid case_id and plugin plan
- NOT raise an error or abort the pipeline
If result contains "warning" key → symbols are missing → read "symbol_instructions" for fix steps.
Linux plugins will fail during batch_plugins until symbols are placed in /app/data/symbols/


## PLUGIN LIST FORMAT
plan["plugins"] is a list of objects ready for batch_plugins:
[
  {"name": "windows.pslist.PsList",              "args": {}},
  {"name": "windows.registry.printkey.PrintKey", "args": {"key": "Software\\\\...\\\\Run"}}
]
Pass this list DIRECTLY to batch_plugins — do not extract just the names.


## OUTPUT SCHEMA
{
  "case_id": "CASE-20260224-113907-a1b2c3",
  "os": {"os_type": "windows", "version": "10", "build": "19041", "arch": "x64"},
  "plan": {
    "goal": "malware_detection",
    "plugins": [ {"name": str, "args": dict}, ... ],
    "estimated_minutes": 15
  },
  "warning": "(Linux only) symbol unavailability message — omitted if symbols are OK",
  "symbol_instructions": "(Linux only) step-by-step dwarf2json commands — omitted if symbols are OK"
}


## ⚠️ CRITICAL — NEXT STEP
→ batch_plugins(dump_path=dump_path, plugins=plan["plugins"])
   MUST pass plan["plugins"] EXACTLY as-is — do NOT build your own plugin list.
   The plan already includes registry plugins for persistence analysis.
   Omitting plan["plugins"] will miss registry, SSDT, and callbacks data.
""",
    )
    async def smart_triage(
        ctx: Context,
        dump_path: str,
        os_type: str,
        goal: str = "malware_detection",
    ) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to memory dump file.
            Supported extensions: .raw .dmp .mem .vmem .lime .img
            Example: "/app/data/dumps/infected.raw"

        os_type : str
            "windows" or "linux" — MUST come from detect_os["os_type"].
            Do not hardcode or guess.

        goal : str
            Analysis objective. One of:
            "malware_detection" | "incident_response" | "rootkit_hunt" | "network_forensics"
            Default: "malware_detection"
        """
        validate_dump_path(dump_path)
        if goal not in _VALID_GOALS:
            raise ValueError(f"Invalid goal '{goal}'. Valid options: {sorted(_VALID_GOALS)}")
        if os_type not in ("windows", "linux"):
            raise ValueError(f"Invalid os_type '{os_type}'. Must be 'windows' or 'linux'.")

        await ctx.info(f"Triage: {os_type} / {goal}")
        os_info = await _detect_os_helper(dump_path)

        # ── Tạo Case TRƯỚC symbol check để case_id luôn tồn tại ──────
        plan = get_triage_plan(os_type, goal)
        case = Case(
            dump_path=dump_path,
            dump_hash=await executor.get_dump_hash(dump_path),
            os_type=os_type,
            os_version=os_info.get("version", "unknown"),
            os_arch=os_info.get("arch", "x64"),
            goal=goal,
        )
        await save_case(case)
        await ctx.info(f"Case created: {case.id}")

        # ── Linux only: symbol check — warn, không crash ──────────────
        symbol_warning = None
        if os_type == "linux":
            await ctx.info("Linux detected — checking kernel symbols...")
            try:
                symbol_status = await symbol_resolver.ensure_symbols(
                    dump_path=dump_path,
                    kernel_version=os_info.get("version"),
                    ctx=ctx,
                )
                if not symbol_status["available"]:
                    symbol_warning = (
                        f"Kernel symbols unavailable for "
                        f"{symbol_status.get('kernel_version', os_info.get('version'))}. "
                        f"Reason: {symbol_status.get('message')}. "
                        f"Action: {symbol_status.get('action_required')}"
                    )
                    await ctx.warning(f"⚠️  {symbol_warning}")
                    await ctx.warning(
                        "Linux plugins will fail without symbols — "
                        "proceeding with plan. Run get_symbols_status for fix instructions."
                    )
                else:
                    await ctx.info(f"✓ Symbols ready: {symbol_status['symbol_path']}")
            except Exception as e:
                symbol_warning = f"Symbol check failed: {e}"
                await ctx.warning(f"⚠️  {symbol_warning}")

        result = {
            "case_id": case.id,
            "os": os_info,
            "plan": {
                "goal": goal,
                "plugins": plan.plugins,
                "estimated_minutes": plan.estimated_minutes,
            },
        }

        if symbol_warning:
            kernel_ver = os_info.get("version", "KERNEL_VERSION")
            result["warning"] = symbol_warning
            result["symbol_instructions"] = (
                f"To generate symbols for {kernel_ver}:\n"
                f"  1. apt download linux-image-{kernel_ver}-dbgsym\n"
                f"  2. dpkg -x *.ddeb /tmp/dbgsym\n"
                f"  3. dwarf2json linux --elf "
                f"/tmp/dbgsym/usr/lib/debug/boot/vmlinux-{kernel_ver} "
                f"> /app/data/symbols/{kernel_ver}.json\n"
                f"  4. Re-run analysis"
            )

        return result


    @mcp.tool(
        name="automated_pipeline",
        description="""
Run the complete end-to-end IOC extraction pipeline in a single call.


## PIPELINE STAGES
Stage 1  OS Detection      → Identify Windows/Linux, version, architecture
Stage 2  Triage Planning   → Select plugins for goal, create tracked case
Stage 3  Symbol Check      → Linux only: verify kernel ISF symbols, warn if missing
Stage 4  Plugin Execution  → Run all plugins in parallel (cached in Redis)
Stage 5  IOC Extraction    → Regex broad-scan + context-aware rules (recall-first strategy)
Stage 6  Threat Validation → Whitelist → VirusTotal → AbuseIPDB → confidence scoring
Stage 7  MITRE Mapping     → Map validated IOCs to ATT&CK techniques and tactics
Stage 8  Report Generation → Structured JSON report + human-readable summary


## WHEN TO USE vs MANUAL FLOW
Use automated_pipeline when:
  - You want full IOC coverage with minimal tool calls
  - You are doing a first-pass analysis of an unknown dump
  - You trust the default plugin selection for the given goal

Use manual flow (detect_os → smart_triage → batch_plugins → ...) when:
  - You need to inspect intermediate results before proceeding
  - You want to add custom plugins not in the default profile
  - You are debugging a specific malware family


## LINUX SYMBOL HANDLING
- If kernel symbols are missing: pipeline logs a WARNING and continues
- Linux plugins will fail at Stage 4 (plugin execution) → 0 IOCs extracted
- Report will still be generated with empty results + symbol fix instructions
- To fix: call get_symbols_status(dump_path) for step-by-step instructions


## THREAT SCORING
threat_score (0-100):  malicious_iocs × 10 + suspicious_iocs × 3  (capped at 100)
threat_level mapping:
  CRITICAL  → score ≥ 70   (active compromise, multiple confirmed malicious IOCs)
  HIGH      → score ≥ 40   (strong indicators, investigation required)
  MEDIUM    → score ≥ 15   (suspicious activity, possible false positives)
  LOW       → score < 15   (minimal indicators or clean dump)


## OUTPUT SCHEMA
{
  "case_id":        "CASE-20260224-113907-a1b2c3",
  "threat_level":   "HIGH",
  "threat_score":   55,
  "total_iocs":     23,
  "malicious_iocs": 5,
  "suspicious_iocs": 8,
  "report_paths": {
    "summary": "/app/data/reports/CASE_.../SUMMARY.txt",
    "json":    "/app/data/reports/CASE_.../report.json"
  }
}


## NEXT STEP
→ Read report_paths["json"] for full IOC list with MITRE mapping
→ Use get_analysis_status(case_id) to retrieve case metadata
→ If Linux + 0 IOCs: call get_symbols_status(dump_path) for symbol fix instructions
""",
    )
    async def automated_pipeline(
        ctx: Context,
        dump_path: str,
        goal: str = "malware_detection",
    ) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to memory dump file.
            Supported extensions: .raw .dmp .mem .vmem .lime .img
            Example: "/app/data/dumps/infected.raw"

        goal : str
            "malware_detection" | "incident_response" | "rootkit_hunt" | "network_forensics"
            Default: "malware_detection"
        """
        validate_dump_path(dump_path)
        if goal not in _VALID_GOALS:
            raise ValueError(f"Invalid goal '{goal}'. Valid options: {sorted(_VALID_GOALS)}")

        from src.core.ioc_extractor import ExtractionPipeline
        from src.core.validator import ValidationPipeline
        from src.core.mitre_mapper import MITREMapper
        from src.core.report_generator import ReportGenerator
        from src.mcp_server.tools.execution import _batch_plugins

        # Stage 1 — OS Detection
        await ctx.report_progress(0, 7, "Stage 1/7: Detecting OS...")
        os_info = await _detect_os_helper(dump_path)
        os_type = os_info["os_type"]

        # Stage 2 — Case + Plan (case tạo trước mọi thứ)
        await ctx.report_progress(1, 7, "Stage 2/7: Creating triage plan...")
        plan = get_triage_plan(os_type, goal)
        case = Case(
            dump_path=dump_path,
            dump_hash=await executor.get_dump_hash(dump_path),
            os_type=os_type,
            os_version=os_info.get("version", "unknown"),
            os_arch=os_info.get("arch", "x64"),
            goal=goal,
        )
        await save_case(case)
        await ctx.info(f"Case: {case.id} | OS: {os_type} | Goal: {goal}")

        # Stage 3 — Linux symbol check (warn only, không crash)
        await ctx.report_progress(2, 7, "Stage 3/7: Checking symbols (Linux only)...")
        if os_type == "linux":
            try:
                symbol_status = await symbol_resolver.ensure_symbols(
                    dump_path=dump_path,
                    kernel_version=os_info.get("version"),
                    ctx=ctx,
                )
                if not symbol_status["available"]:
                    await ctx.warning(
                        f"⚠️  Symbols unavailable for "
                        f"{symbol_status.get('kernel_version', os_info.get('version'))}. "
                        f"Linux plugins will fail — run get_symbols_status for fix instructions."
                    )
                else:
                    await ctx.info(f"✓ Symbols: {symbol_status['symbol_path']}")
            except Exception as e:
                await ctx.warning(f"⚠️  Symbol check error: {e} — continuing anyway")

        # Stage 4 — Plugin Execution
        await ctx.report_progress(3, 7, f"Stage 4/7: Running {len(plan.plugins)} plugins...")
        batch_result = await _batch_plugins(ctx, dump_path, plan.plugins)
        await ctx.info(
            f"Plugins: {batch_result['successful']}/{batch_result['total']} succeeded"
        )

        # Stage 5 — IOC Extraction
        await ctx.report_progress(4, 7, "Stage 5/7: Extracting IOCs...")
        extractor = ExtractionPipeline(os_type=os_type)
        raw_iocs = await extractor.extract(batch_result.get("data", {}))
        await ctx.info(f"Extracted {len(raw_iocs)} IOC candidates")

        # Stage 6 — Validation
        await ctx.report_progress(5, 7, "Stage 6/7: Validating IOCs (VT + AbuseIPDB)...")
        validator = ValidationPipeline(config={
            "vt_api_key": settings.vt_api_key,
            "abuse_api_key": settings.abuseipdb_key,
        })
        try:
            validated_iocs = await validator.validate_batch(raw_iocs, os_type=os_type)
        finally:
            await validator.close()
        await ctx.info(f"Validated: {len(validated_iocs)} IOCs")

        # Stage 7 — MITRE + Report
        await ctx.report_progress(6, 7, "Stage 7/7: MITRE mapping + report generation...")
        mitre_report = MITREMapper().map_iocs(validated_iocs)
        report_paths = await ReportGenerator().generate(case, validated_iocs, mitre_report)

        malicious  = [i for i in validated_iocs if i.verdict == "malicious"]
        suspicious = [i for i in validated_iocs if i.verdict == "suspicious"]
        threat_score = min(100, len(malicious) * 10 + len(suspicious) * 3)
        threat_level = (
            "CRITICAL" if threat_score >= 70 else
            "HIGH"     if threat_score >= 40 else
            "MEDIUM"   if threat_score >= 15 else
            "LOW"
        )

        await update_case_status(case.id, "completed")
        await ctx.report_progress(7, 7, f"Complete — {threat_level} ({threat_score}/100)")

        return {
            "case_id":        case.id,
            "threat_level":   threat_level,
            "threat_score":   threat_score,
            "total_iocs":     len(validated_iocs),
            "malicious_iocs": len(malicious),
            "suspicious_iocs": len(suspicious),
            "report_paths":   report_paths,
        }

    @mcp.tool(
        name="get_analysis_status",
        description="""
Retrieve the current status and metadata of an existing analysis case by case_id.

## WHEN TO USE
- After calling smart_triage or automated_pipeline to track progress
- To retrieve IOC counts, OS info, and timestamps for a completed case
- To check if a case is still "running" before calling batch_plugins again

## CASE LIFECYCLE
created → running → completed | failed

## OUTPUT SCHEMA
{
  "id":             "CASE_WIN_20260224_a1b2c3",
  "status":         "completed",      // created | running | completed | failed
  "os_type":        "windows",
  "os_version":     "10",
  "goal":           "malware_detection",
  "dump_path":      "/app/data/dumps/infected.raw",
  "findings_count": 12,
  "iocs_count":     5,
  "created_at":     "2026-02-24T10:00:00",
  "updated_at":     "2026-02-24T10:15:00"
}
""",
    )
    async def get_analysis_status(ctx: Context, case_id: str) -> dict:
        """
        Parameters
        ----------
        case_id : str
            Case ID from smart_triage["case_id"] or automated_pipeline["case_id"].
        """
        case = await get_case(case_id)
        if not case:
            raise ValueError(f"Case not found: {case_id}")
        return case.to_dict()

    @mcp.tool(
        name="list_cases",
        description="""
List all analysis cases stored in Redis with their status, OS type, goal, and IOC counts.

## WHEN TO USE
- At the start of a session to see previously analyzed dumps
- To find a case_id when you know the dump filename but not the ID
- To audit all analyses performed in the current Redis instance

## OUTPUT SCHEMA
{
  "total": 3,
  "cases": [
    {
      "id": "CASE_WIN_20260224_a1b2c3",
      "status": "completed",
      "os_type": "windows",
      "goal": "malware_detection",
      "iocs_count": 5,
      "created_at": "2026-02-24T10:00:00"
    }
  ]
}
""",
    )
    async def list_cases(ctx: Context) -> dict:
        index = await _redis_get("cases:index") or []
        cases = []
        for case_id in index:
            data = await _redis_get(f"case:{case_id}")
            if data:
                cases.append(data)
        return {"total": len(cases), "cases": cases}

    @mcp.tool(
        name="get_symbols_status",
        description="""
[LINUX ONLY] Check whether kernel ISF symbol files are available for Linux memory analysis.

## WHY SYMBOLS ARE REQUIRED
Volatility3 Linux plugins require an ISF (Intermediate Symbol File) that matches the exact
kernel version of the dump. Without matching symbols, ALL linux.* plugins will fail with:
"No suitable address space mapping found"

## SYMBOL RESOLUTION ORDER
1. Check local cache: /app/data/symbols/{kernel_version}.json
2. Check compressed: /app/data/symbols/{kernel_version}.json.xz
3. If not found → return instructions to generate with dwarf2json

## GENERATING MISSING SYMBOLS
If available=false, follow action_required instructions:
  1. Obtain kernel debug package for the detected kernel_version
  2. Install dwarf2json: go install github.com/volatilityfoundation/dwarf2json@latest
  3. Run: dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-{version} > symbols/{version}.json
  4. Place .json file in /app/data/symbols/ (mounted as Docker volume)

## OUTPUT SCHEMA
{
  "available":      true,
  "kernel_version": "5.15.0-91-generic",
  "symbol_path":    "/app/data/symbols/5.15.0-91-generic.json",
  "message":        "Symbols found locally",
  "action_required": null
}

## WINDOWS DUMPS
Pass os_type="windows" — this tool returns immediately with available=true
(Windows analysis does not require symbol files)
""",
    )
    async def get_symbols_status(
        ctx: Context,
        dump_path: str,
        os_type: str = "linux",
    ) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to memory dump.

        os_type : str
            "linux" or "windows".
            Windows skips symbol check and returns available=true immediately.
            Default: "linux"
        """
        validate_dump_path(dump_path)
        return await symbol_resolver.check_symbols(dump_path, os_type)

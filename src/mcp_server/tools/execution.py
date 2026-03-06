# execution.py
import asyncio
from typing import List, Optional

from fastmcp import FastMCP, Context

from src.core.volatility_executor import VolatilityExecutor
from src.utils.security import validate_dump_path, validate_plugin_name, canonicalize_plugin_name

executor = VolatilityExecutor()


async def _run_plugin(ctx: Context, dump_path: str, plugin: str, args: Optional[dict] = None) -> dict:
    validate_dump_path(dump_path)
    plugin = canonicalize_plugin_name(plugin)
    validate_plugin_name(plugin)
    await ctx.info(f"Running {plugin}...")
    result = await executor.run_plugin(dump_path, plugin, args)
    if result.success:
        await ctx.info(f"✓ {plugin}: {len(result.data or [])} rows")
    else:
        await ctx.warning(f"✗ {plugin}: {result.error}")
    return result.to_dict()


async def _batch_plugins(
    ctx: Context,
    dump_path: str,
    plugins: List[dict],
    max_concurrent: int = 3,
) -> dict:
    validate_dump_path(dump_path)
    total = len(plugins)
    semaphore = asyncio.Semaphore(max_concurrent)
    lock = asyncio.Lock()
    completed_count = 0
    successful = 0
    failed = 0
    results = {}
    data = {}

    async def _run_one(plugin_config: dict):
        nonlocal completed_count
        name = plugin_config["name"]
        args = plugin_config.get("args") or {}

        if args:
            import hashlib, json as _json
            args_hash = hashlib.md5(_json.dumps(args, sort_keys=True).encode()).hexdigest()[:6]
            storage_key = f"{name}#{args_hash}"
        else:
            storage_key = name
        async with semaphore:
            async with lock:
                await ctx.report_progress(completed_count, total, f"Running {name}")
            try:
                result = await _run_plugin(ctx, dump_path, name, args)
            finally:
                async with lock:
                    completed_count += 1
        return storage_key, result
    items = await asyncio.gather(*[_run_one(p) for p in plugins], return_exceptions=True)

    for i, item in enumerate(items):
        if isinstance(item, Exception):
            failed += 1
            plugin_name = plugins[i]["name"] if i < len(plugins) else f"plugin_{i}"
            # Tạo lại storage_key cho error case
            args = plugins[i].get("args") or {}
            if args:
                import hashlib, json as _json
                args_hash = hashlib.md5(_json.dumps(args, sort_keys=True).encode()).hexdigest()[:6]
                storage_key = f"{plugin_name}#{args_hash}"
            else:
                storage_key = plugin_name
            results[storage_key] = {"success": False, "rows": 0, "error": str(item)}
            continue

        storage_key, result = item
        ok = result.get("success", False)
        results[storage_key] = {
            "success": ok,
            "rows": len(result.get("data") or []),
            "error": result.get("error"),
        }
        if ok:
            successful += 1
            data[storage_key] = result.get("data", [])
        else:
            failed += 1


    await ctx.report_progress(total, total, "Complete")
    return {"total": total, "successful": successful, "failed": failed, "results": results, "data": data}


def register_execution_tools(mcp: FastMCP):

    @mcp.tool(
        name="run_plugin",
        description="""
Execute a single Volatility3 plugin against a memory dump file.

## WHEN TO USE
- You need output from one specific plugin only
- You are investigating a specific PID, registry key, or artifact
- You want to test whether a plugin works on this dump before batching

## PREREQUISITES
- `detect_os` must be called first — plugin namespace depends on OS type
- Windows dumps → use `windows.*` plugins only
- Linux dumps → use `linux.*` plugins only

## VALIDATED WINDOWS PLUGINS
Process:     windows.pslist.PsList, windows.pstree.PsTree, windows.psscan.PsScan
             windows.cmdline.CmdLine, windows.dlllist.DllList, windows.envars.Envars
Malware:     windows.malware.malfind.Malfind, windows.malware.hollowprocesses.HollowProcesses
             windows.malware.ldrmodules.LdrModules, windows.malware.drivermodule.DriverModule
Network:     windows.handles.Handles  (use with filter — netscan is DEPRECATED in Vol3 2.5+)
Persistence: windows.registry.hivelist.HiveList, windows.registry.printkey.PrintKey
             windows.registry.userassist.UserAssist, windows.svcscan.SvcScan
Rootkit:     windows.ssdt.SSDT, windows.callbacks.Callbacks, windows.modules.Modules
             windows.driverscan.DriverScan
Filesystem:  windows.filescan.FileScan, windows.dumpfiles.DumpFiles

## VALIDATED LINUX PLUGINS
Process:     linux.pslist.PsList, linux.pstree.PsTree, linux.psscan.PsScan
             linux.bash.Bash, linux.psaux.PsAux
Malware:     linux.malware.malfind.Malfind, linux.malware.check_syscall.Check_syscall
             linux.malware.check_modules.Check_modules, linux.malware.hidden_modules.Hidden_modules
Network:     linux.sockstat.Sockstat, linux.sockscan.Sockscan
Filesystem:  linux.lsof.Lsof, linux.pagecache.Files
Rootkit:     linux.lsmod.Lsmod

## DEPRECATED — DO NOT USE
windows.netscan.NetScan, windows.netstat.NetStat  → use windows.handles.Handles instead
windows.malfind                                    → use windows.malware.malfind.Malfind
linux.malfind                                      → use linux.malware.malfind.Malfind
linux.check_syscall                                → use linux.malware.check_syscall.Check_syscall

## OUTPUT SCHEMA
{
  "success": bool,
  "plugin": str,
  "data": [ {...row...} ],   // list of dicts, one per result row
  "error": str | null        // populated only when success=false
}

## NEXT STEP
→ Pass result["data"] to ioc_extract tool for IOC extraction
→ Or call batch_plugins with a full plugin list from smart_triage
""",
    )
    async def run_plugin(
        ctx: Context,
        dump_path: str,
        plugin: str,
        args: Optional[dict] = None,
    ) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to memory dump file.
            Supported extensions: .raw .dmp .mem .vmem .lime .img
            Example: "/app/data/dumps/infected.raw"

        plugin : str
            Full Volatility3 plugin name including module path.
            Example: "windows.malware.malfind.Malfind"

        args : dict | None
            Optional plugin-specific arguments as key-value pairs.
            Examples:
              {"pid": 1234}                          — filter by PID
              {"key": "Software\\Microsoft\\..."}    — registry PrintKey path
              {"dump": True}                         — enable memory dumping
        """
        return await _run_plugin(ctx, dump_path, plugin, args)

    @mcp.tool(
        name="batch_plugins",
        description="""
Execute multiple Volatility3 plugins in parallel with semaphore-controlled concurrency.
Results are cached in Redis (24h TTL keyed by dump SHA256 + plugin + args).

## WHEN TO USE
- After smart_triage returns a plugin list — pass plan["plugins"] directly
- When collecting full IOC evidence across process, network, registry, and malware vectors
- Always prefer batch_plugins over multiple run_plugin calls for efficiency

## INPUT FORMAT
plugins is a list of objects from smart_triage["plan"]["plugins"]:
[
  {"name": "windows.pslist.PsList",          "args": {}},
  {"name": "windows.malware.malfind.Malfind","args": {}},
  {"name": "windows.registry.printkey.PrintKey", "args": {"key": "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"}}
]
Do NOT pass plain strings — each item must be {"name": str, "args": dict}.

## CONCURRENCY GUIDANCE
max_concurrent=3  → safe default, avoids memory pressure on 16GB RAM systems
max_concurrent=5  → use for quick_triage (lightweight plugins only)
max_concurrent=1  → use only when debugging plugin failures sequentially

## OUTPUT SCHEMA
{
  "total": int,        // total plugins attempted
  "successful": int,
  "failed": int,
  "results": {
    "windows.pslist.PsList": {"success": true,  "rows": 87,  "error": null},
    "windows.malware.malfind.Malfind": {"success": false, "rows": 0, "error": "timeout"}
  },
  "data": {
    "windows.pslist.PsList": [ {...}, {...} ],  // raw plugin rows
    "windows.cmdline.CmdLine": [ {...} ]
  }
}

## NEXT STEP
→ Pass entire result to ioc_extract tool: ioc_extract(result["data"], os_type)
→ If failed > 0: retry failed plugins individually with run_plugin for debugging
""",
    )
    async def batch_plugins(
        ctx: Context,
        dump_path: str,
        plugins: List[dict],
        max_concurrent: int = 3,
    ) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to memory dump file.

        plugins : list[dict]
            List of plugin configs from smart_triage["plan"]["plugins"].
            Each item: {"name": "windows.pslist.PsList", "args": {}}

        max_concurrent : int
            Maximum parallel plugin executions. Default 3. Max recommended 5.
        """
        return await _batch_plugins(ctx, dump_path, plugins, max_concurrent)

    @mcp.tool(
        name="compare_processes",
        description="""
Detect hidden processes by cross-referencing pslist (active process list) vs psscan (pool tag scan).

## THREAT DETECTION LOGIC
- pslist  → walks the ActiveProcessLinks doubly-linked list (can be manipulated by DKOM rootkits)
- psscan  → scans raw memory for EPROCESS pool tags (bypasses linked list manipulation)
- A process in psscan but NOT in pslist = actively hidden = DKOM rootkit indicator (T1014)

## WHEN TO USE
- Immediately after batch_plugins when rootkit_hunt or malware_detection goal is active
- Whenever malfind reports suspicious injections and you want to verify process visibility
- As a quick standalone check: compare_processes is fast (2 plugins, cached after first run)

## OS FIELD MAPPING
Windows: PID field is uppercase "PID" — from EPROCESS.UniqueProcessId
Linux:   PID field is lowercase "pid" — from task_struct.pid

## OUTPUT SCHEMA
{
  "pslist_count":    int,   // processes visible via linked list
  "psscan_count":    int,   // processes found via pool scan
  "hidden_count":    int,   // processes in psscan but absent from pslist
  "hidden_processes": [     // full EPROCESS/task_struct rows for hidden PIDs
    {"PID": 1234, "ImageFileName": "evil.exe", ...}
  ],
  "suspicious": bool        // true if hidden_count > 0
}

## NEXT STEP
→ If suspicious=true: run run_plugin("windows.malware.malfind.Malfind", args={"pid": hidden_pid})
→ If suspicious=true on Linux: run compare_modules to check for hidden LKM rootkit
""",
    )
    async def compare_processes(ctx: Context, dump_path: str, os_type: str) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to memory dump.

        os_type : str
            "windows" or "linux" — must come from detect_os output.
            Determines plugin namespace and PID field name.
        """
        validate_dump_path(dump_path)
        if os_type == "windows":
            pslist = await _run_plugin(ctx, dump_path, "windows.pslist.PsList")
            psscan = await _run_plugin(ctx, dump_path, "windows.psscan.PsScan")
            pid_key = "PID"
        elif os_type == "linux":
            pslist = await _run_plugin(ctx, dump_path, "linux.pslist.PsList")
            psscan = await _run_plugin(ctx, dump_path, "linux.psscan.PsScan")
            pid_key = "pid"
        else:
            raise ValueError(f"Unsupported os_type: '{os_type}'. Must be 'windows' or 'linux'.")

        pslist_pids = set()
        if pslist.get("success") and pslist.get("data"):
            pslist_pids = {p.get(pid_key) for p in pslist["data"] if p.get(pid_key) is not None}

        hidden = []
        psscan_pids = set()
        if psscan.get("success") and psscan.get("data"):
            for p in psscan["data"]:
                pid = p.get(pid_key)
                if pid is not None:
                    psscan_pids.add(pid)
                    if pid not in pslist_pids:
                        hidden.append(p)

        return {
            "pslist_count": len(pslist_pids),
            "psscan_count": len(psscan_pids),
            "hidden_count": len(hidden),
            "hidden_processes": hidden,
            "suspicious": len(hidden) > 0,
        }

    @mcp.tool(
        name="compare_modules",
        description="""
[LINUX ONLY] Detect hidden kernel modules by comparing lsmod output vs hidden_modules deep scan.

## THREAT DETECTION LOGIC
- lsmod                   → reads kernel's THIS_MODULE linked list (manipulatable by LKM rootkits)
- hidden_modules scan     → scans kernel memory for module structures bypassing the linked list
- A module found by scan but absent from lsmod = actively hidden LKM rootkit (T1014, T1547)

## WHEN TO USE
- After compare_processes reveals hidden processes on a Linux dump
- When rootkit_hunt goal is active on Linux
- When linux.malware.check_modules reports anomalies

## IMPORTANT
- Linux only — calling on a Windows dump will fail
- Requires kernel symbols to be available (check get_symbols_status first)
- Hidden LKM rootkits often hide both themselves AND their spawned processes simultaneously

## OUTPUT SCHEMA
{
  "lsmod_count":    int,    // modules visible via linked list
  "hidden_count":   int,    // modules found only via deep scan
  "hidden_modules": [       // full module structs for hidden entries
    {"name": "evil_mod", "base": "0xffff...", "size": 4096}
  ],
  "suspicious": bool        // true if hidden_count > 0
}

## NEXT STEP
→ If suspicious=true: document module names as IOCs with technique T1014
→ Run linux.malware.check_syscall to check if syscall table was hooked by the rootkit
""",
    )
    async def compare_modules(ctx: Context, dump_path: str) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to Linux memory dump.
            Do not call on Windows dumps.
        """
        validate_dump_path(dump_path)
        lsmod = await _run_plugin(ctx, dump_path, "linux.lsmod.Lsmod")
        hidden = await _run_plugin(ctx, dump_path, "linux.malware.hidden_modules.Hidden_modules")

        lsmod_count = len(lsmod.get("data") or []) if lsmod.get("success") else 0
        hidden_modules = hidden.get("data", []) if hidden.get("success") else []

        return {
            "lsmod_count": lsmod_count,
            "hidden_count": len(hidden_modules),
            "hidden_modules": hidden_modules,
            "suspicious": len(hidden_modules) > 0,
        }

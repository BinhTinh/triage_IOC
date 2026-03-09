import asyncio
from typing import Optional

from fastmcp import FastMCP, Context

from src.core.volatility_executor import VolatilityExecutor
from src.utils.security import validate_dump_path, validate_plugin_name, canonicalize_plugin_name
from src.mcp_server.resources.plugins import WINDOWS_PLUGINS, LINUX_PLUGINS

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


async def _run_preset(ctx: Context, dump_path: str, os_type: str, max_concurrent: int = 3) -> dict:
    if os_type == "windows":
        preset = WINDOWS_PLUGINS
    elif os_type == "linux":
        preset = LINUX_PLUGINS
    else:
        raise ValueError(f"Unsupported os_type: '{os_type}'. Must be 'windows' or 'linux'.")

    plugins = preset["network"] + preset["host"]
    total = len(plugins)
    semaphore = asyncio.Semaphore(max_concurrent)
    lock = asyncio.Lock()
    completed_count = 0
    successful = 0
    failed = 0
    network_data = {}
    host_data = {}
    results = {}

    network_names = {p["name"] for p in preset["network"]}

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
        return storage_key, name, result

    items = await asyncio.gather(*[_run_one(p) for p in plugins], return_exceptions=True)

    for i, item in enumerate(items):
        if isinstance(item, Exception):
            failed += 1
            plugin_name = plugins[i]["name"] if i < len(plugins) else f"plugin_{i}"
            args = plugins[i].get("args") or {}
            if args:
                import hashlib, json as _json
                args_hash = hashlib.md5(_json.dumps(args, sort_keys=True).encode()).hexdigest()[:6]
                storage_key = f"{plugin_name}#{args_hash}"
            else:
                storage_key = plugin_name
            results[storage_key] = {"success": False, "rows": 0, "error": str(item)}
            continue

        storage_key, name, result = item
        ok = result.get("success", False)
        results[storage_key] = {
            "success": ok,
            "rows": len(result.get("data") or []),
            "error": result.get("error"),
        }
        if ok:
            successful += 1
            if name in network_names:
                network_data[storage_key] = result.get("data", [])
            else:
                host_data[storage_key] = result.get("data", [])
        else:
            failed += 1

    await ctx.report_progress(total, total, "Complete")
    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "results": results,
        "network_data": network_data,
        "host_data": host_data,
    }


def register_execution_tools(mcp: FastMCP):

    @mcp.tool(
        name="run_plugins",
        description="""
Run the full plugin preset for a given OS type and return raw data split by IOC category.

## WHEN TO USE
- After detect_os — this is the ONLY plugin execution tool needed
- Runs all network plugins + host plugins in parallel automatically
- Do NOT call run_plugin manually for each plugin — use this instead

## PLUGIN PRESETS
Windows network : netscan, netstat, handles
Windows host    : pslist, psscan, cmdline, malfind, hollowprocesses, ldrmodules,
                  dlllist, filescan, registry.printkey (Run/RunOnce/Services),
                  registry.userassist, amcache
Linux network   : sockstat, lsof
Linux host      : pslist, pstree, bash, malfind, check_syscall, check_modules

## OUTPUT SCHEMA
{
  "total": 15,
  "successful": 14,
  "failed": 1,
  "results": {
    "windows.netscan.NetScan": {"success": true, "rows": 12, "error": null}
  },
  "network_data": {
    "windows.netscan.NetScan": [ {...row...} ]
  },
  "host_data": {
    "windows.malware.malfind.Malfind": [ {...row...} ],
    "windows.cmdline.CmdLine": [ {...row...} ]
  }
}

## NEXT STEP
→ Pass full output to ioc_extract(plugin_results=<output>, os_type=<os_type>)
""",
    )
    async def run_plugins(
        ctx: Context,
        dump_path: str,
        os_type: str,
        max_concurrent: int = 3,
    ) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to memory dump file.
            Supported: .raw .dmp .mem .vmem .lime .img

        os_type : str
            "windows" or "linux" — must come from detect_os output.

        max_concurrent : int
            Max parallel plugin executions. Default 3.
        """
        validate_dump_path(dump_path)
        await ctx.info(f"Running {os_type} preset plugins on {dump_path}")
        return await _run_preset(ctx, dump_path, os_type, max_concurrent)

    @mcp.tool(
        name="run_plugin",
        description="""
Execute a single Volatility3 plugin. Use for targeted follow-up investigation only.

## WHEN TO USE
- Investigating a specific PID found suspicious by ioc_extract
- Re-running a single failed plugin after run_plugins
- Ad-hoc deep-dive on a specific registry key or process

## DO NOT USE for initial data collection — use run_plugins instead.

## OUTPUT SCHEMA
{
  "success": bool,
  "plugin":  str,
  "data":    [ {...row...} ],
  "error":   str | null
}
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

        plugin : str
            Full plugin name. Example: "windows.malware.malfind.Malfind"

        args : dict | None
            Optional plugin args. Example: {"pid": 1234}
        """
        return await _run_plugin(ctx, dump_path, plugin, args)

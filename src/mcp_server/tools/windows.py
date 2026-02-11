import asyncio
from typing import List, Optional, Dict, Any
from fastmcp import FastMCP, Context

from src.core.volatility_executor import VolatilityExecutor
from src.utils.security import validate_dump_path, validate_plugin_name, canonicalize_plugin_name
from src.utils.cache import CacheManager

executor = VolatilityExecutor()
cache = CacheManager()


async def run_plugin(ctx: Context, dump_path: str, plugin: str, args: Optional[dict] = None) -> dict:
    validate_dump_path(dump_path)
    plugin = canonicalize_plugin_name(plugin)
    validate_plugin_name(plugin)
    
    cache_key = cache.generate_key(dump_path, plugin, args)
    cached_result = await cache.get(cache_key)
    if cached_result:
        await ctx.info(f"Cache hit for {plugin}")
        return cached_result
    
    await ctx.info(f"Running {plugin}...")
    result = await executor.run_plugin(dump_path, plugin, args)
    
    if result.success:
        await cache.set(cache_key, result.to_dict())
        await ctx.info(f"✓ {plugin}: {len(result.data or [])} rows")
    else:
        await ctx.warning(f"✗ {plugin}: {result.error}")
    
    return result.to_dict()


async def batch_plugins(ctx: Context, dump_path: str, plugins: List[str], max_concurrent: int = 3) -> dict:
    validate_dump_path(dump_path)
    plugins = [canonicalize_plugin_name(p) for p in plugins]
    for plugin in plugins:
        validate_plugin_name(plugin)
    
    total = len(plugins)
    results = {}
    successful = 0
    failed = 0
    
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def run_with_semaphore(plugin: str) -> tuple:
        async with semaphore:
            await ctx.report_progress(progress=len(results), total=total, message=f"Running {plugin}...")
            result = await run_plugin(ctx, dump_path, plugin)
            return plugin, result
    
    tasks = [run_with_semaphore(p) for p in plugins]
    completed = await asyncio.gather(*tasks, return_exceptions=True)
    
    data = {}
    for item in completed:
        if isinstance(item, Exception):
            failed += 1
            continue
        plugin, result = item
        results[plugin] = {
            "success": result.get("success", False),
            "rows": len(result.get("data", [])) if result.get("data") else 0,
            "error": result.get("error")
        }
        if result.get("success"):
            successful += 1
            data[plugin] = result.get("data", [])
        else:
            failed += 1
    
    await ctx.report_progress(progress=total, total=total, message="Complete")
    
    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "results": results,
        "data": data
    }


def register_windows_tools(mcp: FastMCP):
    
    @mcp.tool()
    async def win_run_plugin(ctx: Context, dump_path: str, plugin: str, args: Optional[dict] = None) -> dict:
        return await run_plugin(ctx, dump_path, plugin, args)
    
    @mcp.tool()
    async def win_batch_plugins(ctx: Context, dump_path: str, plugins: List[str], max_concurrent: int = 3) -> dict:
        return await batch_plugins(ctx, dump_path, plugins, max_concurrent)
    
    @mcp.tool()
    async def win_pslist(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.pslist")
    
    @mcp.tool()
    async def win_pstree(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.pstree")
    
    @mcp.tool()
    async def win_psscan(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.psscan")
    
    @mcp.tool()
    async def win_cmdline(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.cmdline")
    
    @mcp.tool()
    async def win_dlllist(ctx: Context, dump_path: str, pid: Optional[int] = None) -> dict:
        args = {"pid": pid} if pid else None
        return await run_plugin(ctx, dump_path, "windows.dlllist", args)
    
    @mcp.tool()
    async def win_handles(ctx: Context, dump_path: str, pid: Optional[int] = None) -> dict:
        args = {"pid": pid} if pid else None
        return await run_plugin(ctx, dump_path, "windows.handles", args)
    
    @mcp.tool()
    async def win_filescan(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.filescan")
    
    @mcp.tool()
    async def win_malfind(ctx: Context, dump_path: str, pid: Optional[int] = None) -> dict:
        args = {"pid": pid} if pid else None
        return await run_plugin(ctx, dump_path, "windows.malware.malfind", args)
    
    @mcp.tool()
    async def win_hollowprocesses(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.malware.hollowprocesses")
    
    @mcp.tool()
    async def win_ldrmodules(ctx: Context, dump_path: str, pid: Optional[int] = None) -> dict:
        args = {"pid": pid} if pid else None
        return await run_plugin(ctx, dump_path, "windows.malware.ldrmodules", args)
    
    @mcp.tool()
    async def win_registry_hivelist(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.registry.hivelist")
    
    @mcp.tool()
    async def win_registry_printkey(ctx: Context, dump_path: str, key: Optional[str] = None) -> dict:
        args = {"key": key} if key else None
        return await run_plugin(ctx, dump_path, "windows.registry.printkey", args)
    
    @mcp.tool()
    async def win_userassist(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.registry.userassist")
    
    @mcp.tool()
    async def win_svcscan(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.svcscan")
    
    @mcp.tool()
    async def win_scheduled_tasks(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.registry.scheduled_tasks")
    
    @mcp.tool()
    async def win_modules(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.modules")
    
    @mcp.tool()
    async def win_driverscan(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.driverscan")
    
    @mcp.tool()
    async def win_ssdt(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.ssdt")
    
    @mcp.tool()
    async def win_callbacks(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.callbacks")
    
    @mcp.tool()
    async def win_envars(ctx: Context, dump_path: str, pid: Optional[int] = None) -> dict:
        args = {"pid": pid} if pid else None
        return await run_plugin(ctx, dump_path, "windows.envars", args)
    
    @mcp.tool()
    async def win_getsids(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.getsids")
    
    @mcp.tool()
    async def win_privs(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "windows.privileges")
    
    @mcp.tool()
    async def win_process_analysis(ctx: Context, dump_path: str) -> dict:
        await ctx.info("Running comprehensive Windows process analysis...")
        
        plugins = [
            "windows.pslist",
            "windows.pstree",
            "windows.psscan",
            "windows.cmdline"
        ]
        
        return await batch_plugins(ctx, dump_path, plugins)
    
    @mcp.tool()
    async def win_malware_scan(ctx: Context, dump_path: str) -> dict:
        await ctx.info("Running Windows malware scan...")
        
        plugins = [
            "windows.malware.malfind",
            "windows.malware.hollowprocesses",
            "windows.malware.ldrmodules"
        ]
        
        return await batch_plugins(ctx, dump_path, plugins)
    
    @mcp.tool()
    async def win_persistence_check(ctx: Context, dump_path: str) -> dict:
        await ctx.info("Checking Windows persistence mechanisms...")
        
        plugins = [
            "windows.registry.userassist",
            "windows.registry.scheduled_tasks",
            "windows.svcscan"
        ]
        
        return await batch_plugins(ctx, dump_path, plugins)
    
    @mcp.tool()
    async def win_compare_processes(ctx: Context, dump_path: str) -> dict:
        await ctx.info("Comparing process lists to find hidden processes...")
        
        pslist_result = await run_plugin(ctx, dump_path, "windows.pslist")
        psscan_result = await run_plugin(ctx, dump_path, "windows.psscan")
        
        pslist_pids = set()
        if pslist_result.get("success") and pslist_result.get("data"):
            pslist_pids = {p.get("PID") for p in pslist_result["data"] if p.get("PID")}
        
        psscan_pids = set()
        hidden_processes = []
        if psscan_result.get("success") and psscan_result.get("data"):
            for p in psscan_result["data"]:
                pid = p.get("PID")
                if pid:
                    psscan_pids.add(pid)
                    if pid not in pslist_pids:
                        hidden_processes.append(p)
        
        return {
            "pslist_count": len(pslist_pids),
            "psscan_count": len(psscan_pids),
            "hidden_count": len(hidden_processes),
            "hidden_processes": hidden_processes,
            "suspicious": len(hidden_processes) > 0
        }
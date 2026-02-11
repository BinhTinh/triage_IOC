import asyncio
from typing import List, Optional
from fastmcp import FastMCP, Context

from src.core.volatility_executor import VolatilityExecutor
from src.core.symbol_resolver import SymbolResolver
from src.utils.security import validate_dump_path, validate_plugin_name, canonicalize_plugin_name
from src.utils.cache import CacheManager

executor = VolatilityExecutor()
symbol_resolver = SymbolResolver()
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


def register_linux_tools(mcp: FastMCP):
    
    @mcp.tool()
    async def linux_run_plugin(ctx: Context, dump_path: str, plugin: str, args: Optional[dict] = None) -> dict:
        return await run_plugin(ctx, dump_path, plugin, args)
    
    @mcp.tool()
    async def linux_batch_plugins(ctx: Context, dump_path: str, plugins: List[str], max_concurrent: int = 3) -> dict:
        return await batch_plugins(ctx, dump_path, plugins, max_concurrent)
    
    @mcp.tool()
    async def linux_check_symbols(ctx: Context, dump_path: str) -> dict:
        validate_dump_path(dump_path)
        return await symbol_resolver.check_symbols(dump_path)
    
    @mcp.tool()
    async def linux_pslist(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.pslist")
    
    @mcp.tool()
    async def linux_pstree(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.pstree")
    
    @mcp.tool()
    async def linux_psscan(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.psscan")
    
    @mcp.tool()
    async def linux_psaux(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.psaux")
    
    @mcp.tool()
    async def linux_bash(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.bash")
    
    @mcp.tool()
    async def linux_lsof(ctx: Context, dump_path: str, pid: Optional[int] = None) -> dict:
        args = {"pid": pid} if pid else None
        return await run_plugin(ctx, dump_path, "linux.lsof", args)
    
    @mcp.tool()
    async def linux_sockstat(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.sockstat")
    
    @mcp.tool()
    async def linux_sockscan(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.sockscan")
    
    @mcp.tool()
    async def linux_lsmod(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.lsmod")
    
    @mcp.tool()
    async def linux_malfind(ctx: Context, dump_path: str, pid: Optional[int] = None) -> dict:
        args = {"pid": pid} if pid else None
        return await run_plugin(ctx, dump_path, "linux.malware.malfind", args)
    
    @mcp.tool()
    async def linux_check_syscall(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.malware.check_syscall")
    
    @mcp.tool()
    async def linux_check_modules(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.malware.check_modules")
    
    @mcp.tool()
    async def linux_hidden_modules(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.malware.hidden_modules")
    
    @mcp.tool()
    async def linux_envars(ctx: Context, dump_path: str, pid: Optional[int] = None) -> dict:
        args = {"pid": pid} if pid else None
        return await run_plugin(ctx, dump_path, "linux.envars", args)
    
    @mcp.tool()
    async def linux_mountinfo(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.mountinfo")
    
    @mcp.tool()
    async def linux_kmsg(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.kmsg")
    
    @mcp.tool()
    async def linux_kthreads(ctx: Context, dump_path: str) -> dict:
        return await run_plugin(ctx, dump_path, "linux.kthreads")
    
    @mcp.tool()
    async def linux_process_analysis(ctx: Context, dump_path: str) -> dict:
        await ctx.info("Running comprehensive Linux process analysis...")
        
        plugins = [
            "linux.pslist",
            "linux.pstree",
            "linux.psscan",
            "linux.psaux",
            "linux.bash"
        ]
        
        return await batch_plugins(ctx, dump_path, plugins)
    
    @mcp.tool()
    async def linux_malware_scan(ctx: Context, dump_path: str) -> dict:
        await ctx.info("Running Linux malware scan...")
        
        plugins = [
            "linux.malware.malfind",
            "linux.malware.check_syscall",
            "linux.malware.check_modules",
            "linux.malware.hidden_modules"
        ]
        
        return await batch_plugins(ctx, dump_path, plugins)
    
    @mcp.tool()
    async def linux_rootkit_hunt(ctx: Context, dump_path: str) -> dict:
        await ctx.info("Hunting for Linux rootkits...")
        
        plugins = [
            "linux.lsmod",
            "linux.malware.check_modules",
            "linux.malware.hidden_modules",
            "linux.malware.check_syscall",
            "linux.kthreads"
        ]
        
        return await batch_plugins(ctx, dump_path, plugins)
    
    @mcp.tool()
    async def linux_network_analysis(ctx: Context, dump_path: str) -> dict:
        await ctx.info("Analyzing Linux network connections...")
        
        plugins = [
            "linux.sockstat",
            "linux.sockscan"
        ]
        
        return await batch_plugins(ctx, dump_path, plugins)
    
    @mcp.tool()
    async def linux_compare_processes(ctx: Context, dump_path: str) -> dict:
        await ctx.info("Comparing process lists to find hidden processes...")
        
        pslist_result = await run_plugin(ctx, dump_path, "linux.pslist")
        psscan_result = await run_plugin(ctx, dump_path, "linux.psscan")
        
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
    
    @mcp.tool()
    async def linux_compare_modules(ctx: Context, dump_path: str) -> dict:
        await ctx.info("Comparing module lists to find hidden modules...")
        
        lsmod_result = await run_plugin(ctx, dump_path, "linux.lsmod")
        hidden_result = await run_plugin(ctx, dump_path, "linux.malware.hidden_modules")
        
        lsmod_count = 0
        if lsmod_result.get("success") and lsmod_result.get("data"):
            lsmod_count = len(lsmod_result["data"])
        
        hidden_modules = []
        if hidden_result.get("success") and hidden_result.get("data"):
            hidden_modules = hidden_result["data"]
        
        return {
            "lsmod_count": lsmod_count,
            "hidden_count": len(hidden_modules),
            "hidden_modules": hidden_modules,
            "suspicious": len(hidden_modules) > 0
        }
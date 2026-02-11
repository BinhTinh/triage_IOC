# Phase 2: Intelligent Execution

## Overview

Phase 2 executes Volatility3 plugins with caching, parallelization, and error handling.

## Components

### 2.1 Volatility Executor

**Core Execution:**

```python
async def run_volatility(
    dump_path: str,
    plugin: str,
    args: dict = None,
    timeout: int = 600
) -> PluginResult:
    """Execute single Volatility3 plugin."""
    
    cmd = [
        'python3', '-m', 'volatility3.cli',
        '-f', dump_path,
        '-r', 'json',
        plugin
    ]
    
    if args:
        for key, value in args.items():
            cmd.extend([f'--{key}', str(value)])
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout
        )
        
        if process.returncode != 0:
            return PluginResult(
                plugin=plugin,
                success=False,
                error=stderr.decode(),
                data=None
            )
        
        data = json.loads(stdout.decode())
        return PluginResult(
            plugin=plugin,
            success=True,
            error=None,
            data=data
        )
        
    except asyncio.TimeoutError:
        process.kill()
        return PluginResult(
            plugin=plugin,
            success=False,
            error=f"Plugin timed out after {timeout}s",
            data=None
        )
```

### 2.2 Caching Layer

**Cache Key Generation:**

```python
def generate_cache_key(dump_path: str, plugin: str, args: dict = None) -> str:
    dump_hash = get_dump_hash(dump_path)
    args_str = json.dumps(args or {}, sort_keys=True)
    args_hash = hashlib.md5(args_str.encode()).hexdigest()[:8]
    return f"vol3:{dump_hash[:16]}:{plugin}:{args_hash}"
```

**Cached Execution:**

```python
async def run_volatility_cached(
    dump_path: str,
    plugin: str,
    args: dict = None,
    cache_ttl: int = 86400
) -> PluginResult:
    """Execute plugin with caching."""
    
    cache_key = generate_cache_key(dump_path, plugin, args)
    
    cached = await redis.get(cache_key)
    if cached:
        logger.debug(f"Cache HIT: {plugin}")
        return PluginResult.from_json(cached)
    
    logger.debug(f"Cache MISS: {plugin}")
    result = await run_volatility(dump_path, plugin, args)
    
    if result.success:
        await redis.setex(cache_key, cache_ttl, result.to_json())
    
    return result
```

### 2.3 Parallel Execution

**Batch Executor:**

```python
async def batch_execute(
    dump_path: str,
    plugins: List[Tuple[str, dict]],
    max_concurrent: int = 3
) -> List[PluginResult]:
    """Execute multiple plugins with controlled parallelism."""
    
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def run_with_semaphore(plugin: str, args: dict) -> PluginResult:
        async with semaphore:
            return await run_volatility_cached(dump_path, plugin, args)
    
    tasks = [
        run_with_semaphore(plugin, args)
        for plugin, args in plugins
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    return [
        r if isinstance(r, PluginResult) 
        else PluginResult(plugin=plugins[i][0], success=False, error=str(r), data=None)
        for i, r in enumerate(results)
    ]
```

### 2.4 Progress Tracking

```python
async def execute_with_progress(
    ctx: Context,
    dump_path: str,
    plugins: List[Tuple[str, dict]]
) -> List[PluginResult]:
    """Execute plugins with MCP progress reporting."""
    
    total = len(plugins)
    results = []
    
    for i, (plugin, args) in enumerate(plugins):
        await ctx.report_progress(
            current=i,
            total=total,
            message=f"Running {plugin}..."
        )
        
        result = await run_volatility_cached(dump_path, plugin, args)
        results.append(result)
        
        if result.success:
            await ctx.info(f"✓ {plugin}: {len(result.data)} rows")
        else:
            await ctx.warning(f"✗ {plugin}: {result.error}")
    
    await ctx.report_progress(current=total, total=total, message="Complete")
    return results
```

### 2.5 Error Recovery

```python
async def run_with_retry(
    dump_path: str,
    plugin: str,
    args: dict = None,
    max_retries: int = 3,
    backoff_base: float = 2.0
) -> PluginResult:
    """Execute plugin with exponential backoff retry."""
    
    for attempt in range(max_retries):
        result = await run_volatility(dump_path, plugin, args)
        
        if result.success:
            return result
        
        if "out of memory" in result.error.lower():
            return result
        
        if attempt < max_retries - 1:
            wait_time = backoff_base ** attempt
            logger.warning(f"Retry {attempt + 1}/{max_retries} for {plugin} in {wait_time}s")
            await asyncio.sleep(wait_time)
    
    return result
```

## MCP Tool: batch_plugins

```python
@mcp.tool()
async def batch_plugins(
    dump_path: str,
    plugins: List[str],
    max_concurrent: int = 3
) -> dict:
    """
    Execute multiple Volatility3 plugins in parallel.
    
    Args:
        dump_path: Path to memory dump
        plugins: List of plugin names to execute
        max_concurrent: Maximum concurrent executions
    
    Returns:
        Results from all plugins with success/failure status
    """
    validate_dump_path(dump_path)
    
    plugin_tuples = [(p, {}) for p in plugins]
    results = await execute_with_progress(ctx, dump_path, plugin_tuples)
    
    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    
    return {
        "total": len(results),
        "successful": len(successful),
        "failed": len(failed),
        "results": {
            r.plugin: {
                "success": r.success,
                "rows": len(r.data) if r.data else 0,
                "error": r.error
            }
            for r in results
        },
        "data": {
            r.plugin: r.data
            for r in successful
        }
    }
```

## Plugin Compatibility Matrix

### Windows Plugins (Validated)

| Plugin | Status | Notes |
|--------|--------|-------|
| windows.pslist | ✅ Working | |
| windows.pstree | ✅ Working | |
| windows.psscan | ✅ Working | |
| windows.cmdline | ✅ Working | |
| windows.dlllist | ✅ Working | |
| windows.handles | ✅ Working | Use for network (filter Type=File) |
| windows.filescan | ✅ Working | |
| windows.malware.malfind | ✅ Working | Replaces windows.malfind |
| windows.malware.hollowprocesses | ✅ Working | Replaces windows.hollowprocesses |
| windows.malware.ldrmodules | ✅ Working | |
| windows.registry.hivelist | ✅ Working | |
| windows.registry.printkey | ✅ Working | |
| windows.registry.userassist | ✅ Working | |
| windows.svcscan | ✅ Working | |
| windows.netscan | ❌ Not Loading | No direct replacement |
| windows.netstat | ❌ Not Loading | No direct replacement |

### Linux Plugins (Validated)

| Plugin | Status | Notes |
|--------|--------|-------|
| linux.pslist | ✅ Working | Requires symbols |
| linux.pstree | ✅ Working | Requires symbols |
| linux.psscan | ✅ Working | Requires symbols |
| linux.bash | ✅ Working | Critical for IOCs |
| linux.lsof | ✅ Working | |
| linux.sockstat | ✅ Working | Network connections |
| linux.malware.malfind | ✅ Working | Replaces linux.malfind |
| linux.malware.check_syscall | ✅ Working | Rootkit detection |
| linux.malware.check_modules | ✅ Working | Hidden modules |
| linux.malware.hidden_modules | ✅ Working | |
| linux.lsmod | ✅ Working | |

## Output Schema

```json
{
  "total": 5,
  "successful": 4,
  "failed": 1,
  "results": {
    "windows.pslist": {"success": true, "rows": 45, "error": null},
    "windows.pstree": {"success": true, "rows": 45, "error": null},
    "windows.malware.malfind": {"success": true, "rows": 3, "error": null},
    "windows.cmdline": {"success": true, "rows": 42, "error": null},
    "windows.handles": {"success": false, "rows": 0, "error": "timeout"}
  },
  "data": {
    "windows.pslist": [...],
    "windows.pstree": [...],
    "windows.malware.malfind": [...],
    "windows.cmdline": [...]
  }
}
```

## Performance Metrics

| Metric | Target | Measurement Point |
|--------|--------|-------------------|
| Plugin execution | < 5 min each | Per-plugin timer |
| Cache hit rate | > 80% | Redis stats |
| Parallel efficiency | > 70% | CPU utilization |
| Memory usage | < 8GB | Peak during execution |
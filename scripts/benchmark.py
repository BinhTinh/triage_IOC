#!/usr/bin/env python3

import asyncio
import argparse
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.volatility_executor import VolatilityExecutor
from src.core.decision_engine import get_triage_plan


async def benchmark_plugins(dump_path: str, os_type: str = "windows"):
    print(f"Benchmarking plugins for {dump_path}")
    print(f"OS Type: {os_type}")
    print("-" * 60)
    
    executor = VolatilityExecutor()
    
    plan = get_triage_plan(os_type, "quick_triage")
    plugins = [p["name"] for p in plan.plugins]
    
    results = []
    
    for plugin in plugins:
        print(f"Running {plugin}...", end=" ", flush=True)
        
        start = time.time()
        result = await executor.run_plugin(dump_path, plugin)
        duration = time.time() - start
        
        status = "OK" if result.success else "FAIL"
        rows = len(result.data) if result.data else 0
        
        print(f"{status} ({duration:.2f}s, {rows} rows)")
        
        results.append({
            "plugin": plugin,
            "success": result.success,
            "duration": duration,
            "rows": rows,
            "error": result.error
        })
    
    print("-" * 60)
    
    total_time = sum(r["duration"] for r in results)
    successful = sum(1 for r in results if r["success"])
    
    print(f"Total time: {total_time:.2f}s")
    print(f"Successful: {successful}/{len(results)}")
    print(f"Average time per plugin: {total_time/len(results):.2f}s")


def main():
    parser = argparse.ArgumentParser(description="Benchmark Volatility3 plugins")
    parser.add_argument("dump", help="Path to memory dump")
    parser.add_argument("--os", choices=["windows", "linux"], default="windows")
    
    args = parser.parse_args()
    
    if not Path(args.dump).exists():
        print(f"Error: File not found: {args.dump}")
        sys.exit(1)
    
    asyncio.run(benchmark_plugins(args.dump, args.os))


if __name__ == "__main__":
    main()
#!/usr/bin/env python3

import asyncio
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.volatility_executor import VolatilityExecutor
from src.mcp_server.resources.plugins import WINDOWS_PLUGINS, LINUX_PLUGINS, UNAVAILABLE_PLUGINS


async def validate_plugins(dump_path: str, os_type: str = "windows"):
    print(f"Validating plugins for {os_type}...")
    print(f"Dump: {dump_path}")
    print("-" * 60)
    
    executor = VolatilityExecutor()
    
    if os_type == "windows":
        plugins_dict = WINDOWS_PLUGINS
    else:
        plugins_dict = LINUX_PLUGINS
    
    all_plugins = []
    for category, plugins in plugins_dict.items():
        for plugin in plugins:
            all_plugins.append((category, plugin))
    
    results = {
        "available": [],
        "unavailable": [],
        "error": []
    }
    
    for category, plugin in all_plugins:
        short_name = plugin.split(".")[-1]
        print(f"Testing {plugin}...", end=" ", flush=True)
        
        if any(unavail in plugin for unavail in UNAVAILABLE_PLUGINS):
            print("SKIP (known unavailable)")
            results["unavailable"].append(plugin)
            continue
        
        try:
            result = await executor.run_plugin(dump_path, plugin)
            
            if result.success:
                print(f"OK ({len(result.data or [])} rows)")
                results["available"].append(plugin)
            else:
                if "unsatisfied" in str(result.error).lower() or "symbol" in str(result.error).lower():
                    print("SKIP (symbols required)")
                    results["unavailable"].append(plugin)
                else:
                    print(f"FAIL: {result.error[:50]}...")
                    results["error"].append(plugin)
        except Exception as e:
            print(f"ERROR: {str(e)[:50]}...")
            results["error"].append(plugin)
    
    print("-" * 60)
    print(f"\nSummary:")
    print(f"  Available: {len(results['available'])}")
    print(f"  Unavailable: {len(results['unavailable'])}")
    print(f"  Errors: {len(results['error'])}")
    
    if results["error"]:
        print(f"\nPlugins with errors:")
        for plugin in results["error"]:
            print(f"  - {plugin}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Validate Volatility3 plugins")
    parser.add_argument("dump", help="Path to memory dump")
    parser.add_argument("--os", choices=["windows", "linux"], default="windows")
    
    args = parser.parse_args()
    
    if not Path(args.dump).exists():
        print(f"Error: File not found: {args.dump}")
        sys.exit(1)
    
    asyncio.run(validate_plugins(args.dump, args.os))


if __name__ == "__main__":
    main()
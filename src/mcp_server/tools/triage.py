import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP, Context

from src.config.settings import settings
from src.core.volatility_executor import VolatilityExecutor
from src.utils.security import validate_dump_path

executor = VolatilityExecutor()


async def _detect_os_helper(dump_path: str) -> dict:
    try:
        result = await executor.run_plugin(dump_path, "windows.info.Info", renderer="json")
        if result.success and result.data:
            row = result.data[0]
            return {
                "os_type": "windows",
                "version": str(row.get("NtMajorVersion", "unknown")),
                "build":   str(row.get("NtBuildNumber", "unknown")),
                "arch":    "x64" if row.get("Is64Bit", True) else "x86",
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
        name="list_dumps",
        description="""
List all memory dump files available for analysis.

## WHEN TO USE
First tool to call in every session — discovers dump files automatically.
Never ask the user for a file path.

## DIRECTORY
Default: /app/data/dumps/ (override via DUMPS_DIR env var)
Scanned recursively.

## SUPPORTED FORMATS
.raw .dmp .mem .vmem .lime .img

## OUTPUT SCHEMA
{
  "dumps_directory": "/app/data/dumps",
  "available": true,
  "total_files": 2,
  "files": [
    {
      "filename": "infected.raw",
      "path":     "/app/data/dumps/infected.raw",
      "size_bytes": 4294967296,
      "size_human": "4.00 GB",
      "modified":   "2026-03-07T10:00:00"
    }
  ]
}

## SELECTION RULE
- total_files == 1 → use it directly
- total_files  > 1 → pick most recently modified
- total_files == 0 → stop, report no dumps found

## NEXT STEP
→ detect_os(dump_path=files[0]["path"])
""",
    )
    async def list_dumps(ctx: Context) -> dict:
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
                "filename":   f.name,
                "path":       str(f),
                "size_bytes": size,
                "size_human": (
                    f"{size / (1024**3):.2f} GB" if size > 1024**3
                    else f"{size / (1024**2):.2f} MB"
                ),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })

        files_info.sort(key=lambda x: x["modified"], reverse=True)

        return {
            "dumps_directory": str(dumps_dir),
            "available":       True,
            "total_files":     len(files_info),
            "files":           files_info,
        }

    @mcp.tool(
        name="detect_os",
        description="""
Identify OS type, version, and architecture from a memory dump.

## WHY MANDATORY
All plugins are OS-specific. Wrong os_type = immediate plugin failure.
Must be called before run_plugins or ioc_extract.

## DETECTION STRATEGY
1. windows.info.Info   → success = Windows (extracts version + build + arch)
2. banners.Banners     → parse "Linux version X.Y.Z"
3. Fallback            → assume Windows

## OUTPUT SCHEMA
{
  "os_type": "windows",  // "windows" | "linux"
  "version": "10",       // NtMajorVersion | kernel X.Y.Z
  "build":   "19041",    // NtBuildNumber  | null for Linux
  "arch":    "x64"       // "x64" | "x86"
}

## NEXT STEP
→ run_plugins(dump_path=<dump_path>, os_type=result["os_type"])
""",
    )
    async def detect_os(ctx: Context, dump_path: str) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to memory dump from list_dumps["files"][n]["path"].
        """
        validate_dump_path(dump_path)
        await ctx.info(f"Detecting OS: {dump_path}")
        return await _detect_os_helper(dump_path)

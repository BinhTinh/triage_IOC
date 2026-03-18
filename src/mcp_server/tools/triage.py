import re
from datetime import datetime
import json
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP, Context

from src.config.settings import settings
from src.core.volatility_executor import VolatilityExecutor
from src.utils.security import validate_dump_path

executor = VolatilityExecutor()

_OS_PROFILE_CACHE_PATH = Path(settings.reports_dir) / "os_profile_cache.json"


def _load_os_profile_cache() -> dict:
    if not _OS_PROFILE_CACHE_PATH.exists():
        return {}
    try:
        with _OS_PROFILE_CACHE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_os_profile_cache(cache: dict) -> None:
    _OS_PROFILE_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _OS_PROFILE_CACHE_PATH.open("w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=True, indent=2)


def cache_os_profile(dump_path: str, profile: dict) -> None:
    cache = _load_os_profile_cache()
    cache[dump_path] = {
        **profile,
        "cached_at": datetime.now().isoformat(),
    }
    _save_os_profile_cache(cache)


def get_cached_os_profile(dump_path: str) -> Optional[dict]:
    cache = _load_os_profile_cache()
    value = cache.get(dump_path)
    if isinstance(value, dict):
        return value
    return None


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
                description="List dump files under /app/data/dumps and return metadata for phase 1 discovery.",
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
                description="Detect dump OS profile (os_type/version/build/arch) for phase 2 and plugin routing.",
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
        result = await _detect_os_helper(dump_path)
        cache_os_profile(dump_path, result)
        return result

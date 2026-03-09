import asyncio
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any, List

from src.config.settings import settings


@dataclass
class PluginResult:
    plugin: str
    success: bool
    data: Optional[List[Dict[str, Any]]]
    error: Optional[str]

    def to_dict(self) -> dict:
        return {
            "plugin": self.plugin,
            "success": self.success,
            "data": self.data,
            "error": self.error,
        }


class VolatilityExecutor:
    def __init__(self, redis_client=None):
        self.vol_command = self._detect_vol_command()
        self.timeout = settings.plugin_timeout
        self.symbol_dirs = settings.symbols_dir
        self._dump_hashes: Dict[str, str] = {}
        self._redis = redis_client

    def _detect_vol_command(self) -> list:
        import subprocess

        for vol_path in ["/opt/volatility3/vol.py", "/app/volatility3/vol.py", "./volatility3/vol.py"]:
            if Path(vol_path).exists():
                print(f"✅ Using Volatility3 standalone: {vol_path}", file=sys.stderr)
                return ["python3", vol_path]

        try:
            result = subprocess.run(
                ["python3", "-m", "volatility3.cli", "-h"],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                print("✅ Using Volatility3 module: python3 -m volatility3.cli", file=sys.stderr)
                return ["python3", "-m", "volatility3.cli"]
        except Exception:
            pass

        try:
            result = subprocess.run(["vol", "-h"], capture_output=True, timeout=5)
            if result.returncode == 0:
                print("✅ Using Volatility3 command: vol", file=sys.stderr)
                return ["vol"]
        except Exception:
            pass

        print("⚠️ Using default: python3 -m volatility3.cli", file=sys.stderr)
        return ["python3", "-m", "volatility3.cli"]

    async def get_dump_hash(self, dump_path: str) -> str:
        if dump_path in self._dump_hashes:
            return self._dump_hashes[dump_path]

        sha256 = hashlib.sha256()
        path = Path(dump_path)
        chunk_size = 1024 * 1024
        bytes_read = 0
        max_bytes = 100 * 1024 * 1024

        with open(path, "rb") as f:
            while bytes_read < max_bytes:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)
                bytes_read += len(chunk)

        sha256.update(str(path.stat().st_size).encode())
        hash_value = sha256.hexdigest()
        self._dump_hashes[dump_path] = hash_value
        return hash_value

    async def run_plugin(
        self,
        dump_path: str,
        plugin: str,
        args: Optional[Dict[str, Any]] = None,
        renderer: str = "json",
    ) -> PluginResult:
        cache_key = None
        if self._redis:
            dump_hash = await self.get_dump_hash(dump_path)
            args_hash = hashlib.md5(
                json.dumps(args or {}, sort_keys=True).encode()
            ).hexdigest()[:8]
            cache_key = f"vol3:{dump_hash}:{plugin}:{args_hash}"
            try:
                cached = await self._redis.get(cache_key)
                if cached:
                    return PluginResult(plugin=plugin, success=True, data=json.loads(cached), error=None)
            except Exception:
                pass

        cmd = self.vol_command.copy()
        cmd.extend(["-f", dump_path, "-r", renderer])

        if self.symbol_dirs and Path(self.symbol_dirs).exists():
            cmd.extend(["-s", self.symbol_dirs])

        cmd.append(plugin)

        if args:
            for key, value in args.items():
                if value is True:
                    cmd.append(f"--{key}")
                elif value is not False and value is not None:
                    cmd.extend([f"--{key}", str(value)])

        print(f"🔧 Running: {' '.join(cmd)}", file=sys.stderr)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _HEAVY_PLUGINS = {"malfind", "linux.malware.malfind.malfind"}
            plugin_timeout = 1800 if any(p in plugin.lower() for p in _HEAVY_PLUGINS) else self.timeout
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=plugin_timeout)

            if process.returncode != 0:
                error_msg = stderr.decode().strip() if stderr else "Unknown error"
                return PluginResult(plugin=plugin, success=False, data=None, error=error_msg[:500])

            output = stdout.decode().strip()
            if not output:
                return PluginResult(plugin=plugin, success=True, data=[], error=None)

            try:
                data = json.loads(output)
                result_data = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                result_data = [{"raw_output": output}]

            result = PluginResult(plugin=plugin, success=True, data=result_data, error=None)

            if self._redis and cache_key:
                try:
                    await self._redis.setex(cache_key, 86400, json.dumps(result_data))
                except Exception:
                    pass

            return result

        except asyncio.TimeoutError:
            return PluginResult(plugin=plugin, success=False, data=None, error=f"Plugin timed out after {self.timeout}s")
        except Exception as e:
            return PluginResult(plugin=plugin, success=False, data=None, error=str(e))

    async def run_plugins_parallel(
        self,
        dump_path: str,
        plugins: List[Dict[str, Any]],
        max_concurrent: int = 3,
    ) -> Dict[str, PluginResult]:
        semaphore = asyncio.Semaphore(max_concurrent)
        results = {}

        async def run_with_semaphore(plugin_config: Dict[str, Any]) -> tuple:
            async with semaphore:
                name = plugin_config["name"]
                args = plugin_config.get("args") or {}
                result = await self.run_plugin(dump_path, name, args)
                return name, result

        completed = await asyncio.gather(
            *[run_with_semaphore(p) for p in plugins],
            return_exceptions=True,
        )

        for item in completed:
            if isinstance(item, Exception):
                continue
            plugin_name, result = item
            results[plugin_name] = result

        return results

    async def detect_os(self, dump_path: str) -> dict:
        win_result = await self.run_plugin(dump_path, "windows.info.Info")
        if win_result.success and win_result.data:
            return {"os": "windows", "info": win_result.data[0] if win_result.data else {}}

        linux_result = await self.run_plugin(dump_path, "banners.Banners")
        if linux_result.success and linux_result.data:
            return {"os": "linux", "info": linux_result.data[0] if linux_result.data else {}}

        return {"os": "unknown", "info": {}}

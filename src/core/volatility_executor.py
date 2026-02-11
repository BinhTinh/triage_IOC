import asyncio
import hashlib
import json
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
            "error": self.error
        }

class VolatilityExecutor:
    def __init__(self):
        # DETECT VOLATILITY3 INSTALLATION METHOD
        self.vol_command = self._detect_vol_command()
        self.timeout = settings.plugin_timeout
        self.symbol_dirs = settings.symbols_dir
        self._dump_hashes: Dict[str, str] = {}
    
    def _detect_vol_command(self) -> list:
        """Auto-detect how to run Volatility3"""
        import subprocess
        
        # Try method 1: vol.py (standalone)
        vol_paths = [
            "/opt/volatility3/vol.py",
            "/app/volatility3/vol.py",
            "./volatility3/vol.py"
        ]
        
        for vol_path in vol_paths:
            if Path(vol_path).exists():
                print(f"✅ Using Volatility3 standalone: {vol_path}")
                return ["python3", vol_path]
        
        # Try method 2: Python module
        try:
            result = subprocess.run(
                ["python3", "-m", "volatility3.cli", "-h"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                print("✅ Using Volatility3 module: python3 -m volatility3.cli")
                return ["python3", "-m", "volatility3.cli"]
        except Exception:
            pass
        
        # Try method 3: Installed as command
        try:
            result = subprocess.run(
                ["vol", "-h"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                print("✅ Using Volatility3 command: vol")
                return ["vol"]
        except Exception:
            pass
        
        # Fallback to module method
        print("⚠️ Using default: python3 -m volatility3.cli")
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
        
        file_size = path.stat().st_size
        sha256.update(str(file_size).encode())
        
        hash_value = sha256.hexdigest()
        self._dump_hashes[dump_path] = hash_value
        return hash_value
    
    async def run_plugin(
        self,
        dump_path: str,
        plugin: str,
        args: Optional[Dict[str, Any]] = None,
        renderer: str = "json"
    ) -> PluginResult:
        # BUILD COMMAND
        cmd = self.vol_command.copy()  # DÙNG DETECTED COMMAND
        cmd.extend([
            "-f", dump_path,
            "-r", renderer
        ])
        
        # Add symbols directory if exists
        if self.symbol_dirs and Path(self.symbol_dirs).exists():
            cmd.extend(["-s", self.symbol_dirs])
        
        # Add plugin name
        cmd.append(plugin)
        
        # Add plugin arguments
        if args:
            for key, value in args.items():
                if value is True:
                    cmd.append(f"--{key}")
                elif value is not False and value is not None:
                    cmd.extend([f"--{key}", str(value)])
        
        # DEBUG: Print command
        print(f"🔧 Running: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode().strip() if stderr else "Unknown error"
                return PluginResult(
                    plugin=plugin,
                    success=False,
                    data=None,
                    error=error_msg[:500]
                )
            
            output = stdout.decode().strip()
            if not output:
                return PluginResult(
                    plugin=plugin,
                    success=True,
                    data=[],
                    error=None
                )
            
            try:
                data = json.loads(output)
                return PluginResult(
                    plugin=plugin,
                    success=True,
                    data=data if isinstance(data, list) else [data],
                    error=None
                )
            except json.JSONDecodeError:
                return PluginResult(
                    plugin=plugin,
                    success=True,
                    data=[{"raw_output": output}],
                    error=None
                )
        
        except asyncio.TimeoutError:
            return PluginResult(
                plugin=plugin,
                success=False,
                data=None,
                error=f"Plugin timed out after {self.timeout}s"
            )
        
        except Exception as e:
            return PluginResult(
                plugin=plugin,
                success=False,
                data=None,
                error=str(e)
            )
    
    async def run_plugins_parallel(
        self,
        dump_path: str,
        plugins: List[str],
        max_concurrent: int = 3
    ) -> Dict[str, PluginResult]:
        semaphore = asyncio.Semaphore(max_concurrent)
        results = {}
        
        async def run_with_semaphore(plugin: str) -> tuple:
            async with semaphore:
                result = await self.run_plugin(dump_path, plugin)
                return plugin, result
        
        tasks = [run_with_semaphore(p) for p in plugins]
        completed = await asyncio.gather(*tasks, return_exceptions=True)
        
        for item in completed:
            if isinstance(item, Exception):
                continue
            plugin, result = item
            results[plugin] = result
        
        return results

import asyncio
import re
from pathlib import Path
from typing import Optional, Dict, Any

from src.config.settings import settings


class SymbolResolver:
    def __init__(self):
        self.symbols_dir = Path(settings.symbols_dir)
        self.symbols_dir.mkdir(parents=True, exist_ok=True)
        self.isf_server_url = "https://isf-server.techanarchy.net"
    
    async def check_symbols(self, dump_path: str) -> dict:
        kernel_version = await self._detect_kernel_version(dump_path)
        
        if not kernel_version:
            return {
                "available": False,
                "kernel_version": None,
                "message": "Could not detect kernel version. This may be a Windows dump.",
                "action_required": None
            }
        
        symbol_path = self._find_local_symbol(kernel_version)
        if symbol_path:
            return {
                "available": True,
                "kernel_version": kernel_version,
                "symbol_path": str(symbol_path),
                "message": "Symbols found locally"
            }
        
        return {
            "available": False,
            "kernel_version": kernel_version,
            "message": f"Symbols not found for kernel {kernel_version}",
            "action_required": f"Generate symbols using dwarf2json for kernel {kernel_version}"
        }
    
    async def _detect_kernel_version(self, dump_path: str) -> Optional[str]:
        try:
            cmd = [
                "python3", "-m", "volatility3.cli",
                "-f", dump_path,
                "-r", "json",
                "banners.Banners"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=60
            )
            
            output = stdout.decode()
            match = re.search(r"Linux version (\d+\.\d+\.\d+[-\w]*)", output)
            if match:
                return match.group(1)
            
        except Exception:
            pass
        
        return None
    
    def _find_local_symbol(self, kernel_version: str) -> Optional[Path]:
        patterns = [
            f"*{kernel_version}*.json",
            f"*{kernel_version}*.json.xz",
            f"*{kernel_version}*.isf",
        ]
        
        for pattern in patterns:
            matches = list(self.symbols_dir.glob(pattern))
            if matches:
                return matches[0]
        
        return None
    
    async def download_symbols(self, kernel_version: str) -> dict:
        return {
            "success": False,
            "message": "Auto-download not implemented. Please generate symbols manually using dwarf2json.",
            "instructions": [
                f"1. Obtain debug symbols for kernel {kernel_version}",
                "2. Install dwarf2json: go install github.com/volatilityfoundation/dwarf2json@latest",
                f"3. Run: dwarf2json linux --elf /path/to/vmlinux > {self.symbols_dir}/{kernel_version}.json",
                f"4. Place the generated JSON in {self.symbols_dir}/"
            ]
        }
    
    def get_symbol_dirs(self) -> str:
        return str(self.symbols_dir)
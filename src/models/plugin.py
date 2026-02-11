from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class PluginCategory(Enum):
    PROCESS = "process"
    MEMORY = "memory"
    MALWARE = "malware"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    REGISTRY = "registry"
    KERNEL = "kernel"
    ARTIFACTS = "artifacts"
    MODULES = "modules"
    SERVICES = "services"
    GUI = "gui"
    YARA = "yara"
    MISC = "misc"


class PluginStatus(Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEPRECATED = "deprecated"


class OSType(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MAC = "mac"
    GENERIC = "generic"


@dataclass
class PluginInfo:
    name: str
    os_type: OSType
    category: PluginCategory
    description: str = ""
    status: PluginStatus = PluginStatus.AVAILABLE
    replacement: Optional[str] = None
    estimated_time_seconds: int = 60
    requires_symbols: bool = False
    args: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "os_type": self.os_type.value,
            "category": self.category.value,
            "description": self.description,
            "status": self.status.value,
            "replacement": self.replacement,
            "estimated_time_seconds": self.estimated_time_seconds,
            "requires_symbols": self.requires_symbols,
            "args": self.args
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "PluginInfo":
        return cls(
            name=data["name"],
            os_type=OSType(data.get("os_type", "generic")),
            category=PluginCategory(data.get("category", "misc")),
            description=data.get("description", ""),
            status=PluginStatus(data.get("status", "available")),
            replacement=data.get("replacement"),
            estimated_time_seconds=data.get("estimated_time_seconds", 60),
            requires_symbols=data.get("requires_symbols", False),
            args=data.get("args", {})
        )


@dataclass
class PluginResult:
    plugin_name: str
    success: bool
    data: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None
    execution_time_seconds: float = 0.0
    row_count: int = 0
    cached: bool = False
    
    def to_dict(self) -> dict:
        return {
            "plugin_name": self.plugin_name,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "execution_time_seconds": self.execution_time_seconds,
            "row_count": self.row_count,
            "cached": self.cached
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "PluginResult":
        return cls(
            plugin_name=data["plugin_name"],
            success=data["success"],
            data=data.get("data"),
            error=data.get("error"),
            execution_time_seconds=data.get("execution_time_seconds", 0.0),
            row_count=data.get("row_count", 0),
            cached=data.get("cached", False)
        )


@dataclass
class PluginProfile:
    name: str
    description: str
    os_type: OSType
    plugins: List[PluginInfo]
    estimated_total_minutes: int = 10
    priority_order: List[str] = field(default_factory=list)
    
    def get_plugin_names(self) -> List[str]:
        if self.priority_order:
            return self.priority_order
        return [p.name for p in self.plugins]
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "os_type": self.os_type.value,
            "plugins": [p.to_dict() for p in self.plugins],
            "estimated_total_minutes": self.estimated_total_minutes,
            "priority_order": self.priority_order
        }


class PluginRegistry:
    def __init__(self):
        self._plugins: Dict[str, PluginInfo] = {}
        self._profiles: Dict[str, PluginProfile] = {}
        self._load_default_plugins()
    
    def _load_default_plugins(self):
        windows_process_plugins = [
            PluginInfo(
                name="windows.pslist.PsList",
                os_type=OSType.WINDOWS,
                category=PluginCategory.PROCESS,
                description="Lists the processes present in a particular windows memory image",
                estimated_time_seconds=30
            ),
            PluginInfo(
                name="windows.pstree.PsTree",
                os_type=OSType.WINDOWS,
                category=PluginCategory.PROCESS,
                description="Plugin for listing processes in a tree based on their parent process ID",
                estimated_time_seconds=30
            ),
            PluginInfo(
                name="windows.psscan.PsScan",
                os_type=OSType.WINDOWS,
                category=PluginCategory.PROCESS,
                description="Scans for processes present in a particular windows memory image",
                estimated_time_seconds=120
            ),
            PluginInfo(
                name="windows.cmdline.CmdLine",
                os_type=OSType.WINDOWS,
                category=PluginCategory.PROCESS,
                description="Lists process command line arguments",
                estimated_time_seconds=30
            ),
        ]
        
        windows_malware_plugins = [
            PluginInfo(
                name="windows.malware.malfind.Malfind",
                os_type=OSType.WINDOWS,
                category=PluginCategory.MALWARE,
                description="Lists process memory ranges that potentially contain injected code",
                estimated_time_seconds=180
            ),
            PluginInfo(
                name="windows.malware.hollowprocesses.HollowProcesses",
                os_type=OSType.WINDOWS,
                category=PluginCategory.MALWARE,
                description="Lists hollowed processes",
                estimated_time_seconds=120
            ),
            PluginInfo(
                name="windows.malware.ldrmodules.LdrModules",
                os_type=OSType.WINDOWS,
                category=PluginCategory.MALWARE,
                description="Lists the loaded modules in a particular windows memory image",
                estimated_time_seconds=90
            ),
        ]
        
        linux_process_plugins = [
            PluginInfo(
                name="linux.pslist.PsList",
                os_type=OSType.LINUX,
                category=PluginCategory.PROCESS,
                description="Lists the processes present in a particular linux memory image",
                estimated_time_seconds=30,
                requires_symbols=True
            ),
            PluginInfo(
                name="linux.pstree.PsTree",
                os_type=OSType.LINUX,
                category=PluginCategory.PROCESS,
                description="Plugin for listing processes in a tree based on their parent process ID",
                estimated_time_seconds=30,
                requires_symbols=True
            ),
            PluginInfo(
                name="linux.bash.Bash",
                os_type=OSType.LINUX,
                category=PluginCategory.ARTIFACTS,
                description="Recovers bash command history from memory",
                estimated_time_seconds=60,
                requires_symbols=True
            ),
        ]
        
        linux_malware_plugins = [
            PluginInfo(
                name="linux.malware.malfind.Malfind",
                os_type=OSType.LINUX,
                category=PluginCategory.MALWARE,
                description="Lists process memory ranges that potentially contain injected code",
                estimated_time_seconds=180,
                requires_symbols=True
            ),
            PluginInfo(
                name="linux.malware.check_syscall.Check_syscall",
                os_type=OSType.LINUX,
                category=PluginCategory.MALWARE,
                description="Check system call table for hooks",
                estimated_time_seconds=60,
                requires_symbols=True
            ),
            PluginInfo(
                name="linux.malware.hidden_modules.Hidden_modules",
                os_type=OSType.LINUX,
                category=PluginCategory.MALWARE,
                description="Carves memory to find hidden kernel modules",
                estimated_time_seconds=120,
                requires_symbols=True
            ),
        ]
        
        for plugin in (windows_process_plugins + windows_malware_plugins + 
                       linux_process_plugins + linux_malware_plugins):
            self._plugins[plugin.name] = plugin
    
    def register_plugin(self, plugin: PluginInfo):
        self._plugins[plugin.name] = plugin
    
    def get_plugin(self, name: str) -> Optional[PluginInfo]:
        return self._plugins.get(name)
    
    def get_plugins_by_os(self, os_type: OSType) -> List[PluginInfo]:
        return [p for p in self._plugins.values() if p.os_type == os_type]
    
    def get_plugins_by_category(self, category: PluginCategory) -> List[PluginInfo]:
        return [p for p in self._plugins.values() if p.category == category]
    
    def get_available_plugins(self) -> List[PluginInfo]:
        return [p for p in self._plugins.values() if p.status == PluginStatus.AVAILABLE]
    
    def register_profile(self, profile: PluginProfile):
        self._profiles[profile.name] = profile
    
    def get_profile(self, name: str) -> Optional[PluginProfile]:
        return self._profiles.get(name)
    
    def list_profiles(self) -> List[str]:
        return list(self._profiles.keys())
    
    def to_dict(self) -> dict:
        return {
            "plugins": {name: p.to_dict() for name, p in self._plugins.items()},
            "profiles": {name: p.to_dict() for name, p in self._profiles.items()},
            "total_plugins": len(self._plugins),
            "total_profiles": len(self._profiles)
        }


plugin_registry = PluginRegistry()
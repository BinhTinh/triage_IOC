from dataclasses import dataclass, field
from typing import List, Dict, Any
from pathlib import Path
import yaml

from src.config.settings import settings


@dataclass
class TriagePlan:
    goal: str
    os_type: str
    plugins: List[Dict[str, Any]]
    estimated_minutes: int
    description: str = ""


class DecisionEngine:
    def __init__(self):
        self.profiles = self._load_profiles()
    
    def _load_profiles(self) -> dict:
        profile_path = Path(settings.config_dir) / "plugin_profiles.yaml"
        if profile_path.exists():
            with open(profile_path) as f:
                return yaml.safe_load(f)
        return self._get_default_profiles()
    
    def _get_default_profiles(self) -> dict:
        return {
            "malware_detection": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.pstree", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.psscan", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.registry.hivelist", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.registry.printkey", "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, "priority": 2, "required": False},
                        {"name": "windows.registry.printkey", "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}, "priority": 2, "required": False},
                        {"name": "windows.registry.printkey", "args": {"key": "System\\CurrentControlSet\\Services"}, "priority": 3, "required": False},
                        {"name": "windows.registry.printkey", "args": {"key": "Software\\Microsoft\\Windows Defender\\Exclusions"}, "priority": 3, "required": False},
                        {"name": "windows.registry.userassist", "args": {}, "priority": 3, "required": False},
                        
                        {"name": "windows.malware.malfind", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.cmdline", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.dlllist", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.handles", "args": {}, "priority": 2, "required": False},
                    ],
                    "estimated_minutes": 15,
                    "description": "Detect malware indicators with registry analysis"
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.pstree", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.malfind", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.bash", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.sockstat", "args": {}, "priority": 2, "required": False},
                    ],
                    "estimated_minutes": 12,
                    "description": "Detect Linux malware"
                }
            },
            "quick_triage": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.malware.malfind", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.cmdline", "args": {}, "priority": 1, "required": True},
                    ],
                    "estimated_minutes": 4,
                    "description": "Fast initial assessment"
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.malfind", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.bash", "args": {}, "priority": 1, "required": True},
                    ],
                    "estimated_minutes": 4,
                    "description": "Fast Linux assessment"
                }
            },
            "incident_response": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.pstree", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.cmdline", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.handles", "args": {}, "priority": 2, "required": True},
                        {"name": "windows.filescan", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.registry.hivelist", "args": {}, "priority": 2, "required": True},
                        {"name": "windows.registry.printkey", "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, "priority": 2, "required": True},
                        {"name": "windows.registry.printkey", "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}, "priority": 2, "required": True},
                        {"name": "windows.registry.printkey", "args": {"key": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"}, "priority": 2, "required": False},
                        {"name": "windows.registry.printkey", "args": {"key": "System\\CurrentControlSet\\Services"}, "priority": 2, "required": True},
                        {"name": "windows.registry.userassist", "args": {}, "priority": 3, "required": False},
                        
                        {"name": "windows.svcscan", "args": {}, "priority": 2, "required": False},
                    ],
                    "estimated_minutes": 25,
                    "description": "IR artifact collection with comprehensive registry analysis"
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.pstree", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.bash", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.lsof", "args": {}, "priority": 2, "required": True},
                        {"name": "linux.sockstat", "args": {}, "priority": 2, "required": True},
                    ],
                    "estimated_minutes": 15,
                    "description": "Linux IR artifacts"
                }
            },
            "rootkit_hunt": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.psscan", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.malware.drivermodule", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.modules", "args": {}, "priority": 2, "required": True},
                        {"name": "windows.ssdt", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.callbacks", "args": {}, "priority": 2, "required": False},
                    ],
                    "estimated_minutes": 15,
                    "description": "Detect kernel rootkits"
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.psscan", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.lsmod", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.check_modules", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.hidden_modules", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.check_syscall", "args": {}, "priority": 1, "required": True},
                    ],
                    "estimated_minutes": 12,
                    "description": "Detect Linux rootkits"
                }
            }
        }
    
    def get_triage_plan(self, os_type: str, goal: str) -> TriagePlan:
        if goal not in self.profiles:
            raise ValueError(f"Unknown goal: {goal}. Available: {list(self.profiles.keys())}")
        
        if os_type not in self.profiles[goal]:
            raise ValueError(f"Unknown OS type: {os_type}. Available: windows, linux")
        
        profile = self.profiles[goal][os_type]
        
        return TriagePlan(
            goal=goal,
            os_type=os_type,
            plugins=profile["plugins"],
            estimated_minutes=profile.get("estimated_minutes", 10),
            description=profile.get("description", "")
        )
    
    def get_plugin_catalog(self) -> dict:
        windows_plugins = [
            "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline",
            "windows.dlllist", "windows.handles", "windows.filescan",
            "windows.malware.malfind", "windows.malware.hollowprocesses",
            "windows.registry.hivelist", 
            "windows.registry.printkey",
            "windows.registry.userassist",
            "windows.registry.certificates",
            
            "windows.svcscan", "windows.modules", "windows.driverscan"
        ]
        
        linux_plugins = [
            "linux.pslist", "linux.pstree", "linux.psscan", "linux.bash",
            "linux.lsof", "linux.sockstat", "linux.lsmod",
            "linux.malware.malfind", "linux.malware.check_syscall",
            "linux.malware.check_modules", "linux.malware.hidden_modules"
        ]
        
        return {
            "windows": windows_plugins,
            "linux": linux_plugins,
            "total": len(windows_plugins) + len(linux_plugins)
        }
    
    def get_plugin_info(self, plugin_name: str) -> dict:
        plugin_info = {
            "windows.pslist": {"description": "Lists processes", "category": "process"},
            "windows.pstree": {"description": "Process tree view", "category": "process"},
            "windows.malware.malfind": {"description": "Find injected code", "category": "malware"},
            "windows.cmdline": {"description": "Process command lines", "category": "process"},
            "windows.registry.hivelist": {"description": "List registry hives", "category": "registry"},
            "windows.registry.printkey": {"description": "Print registry key values", "category": "registry"},
            "windows.registry.userassist": {"description": "UserAssist execution history", "category": "registry"},
            "windows.registry.certificates": {"description": "List certificates", "category": "registry"},
            
            "linux.pslist": {"description": "Lists Linux processes", "category": "process"},
            "linux.bash": {"description": "Bash history", "category": "artifacts"},
            "linux.malware.malfind": {"description": "Find injected code", "category": "malware"},
        }
        
        if plugin_name in plugin_info:
            return {"name": plugin_name, **plugin_info[plugin_name]}
        
        return {"name": plugin_name, "description": "No description available", "category": "unknown"}


def get_triage_plan(os_type: str, goal: str) -> TriagePlan:
    engine = DecisionEngine()
    return engine.get_triage_plan(os_type, goal)
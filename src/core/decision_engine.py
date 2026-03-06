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
                        {"name": "windows.pslist.PsList", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.pstree.PsTree", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.psscan.PsScan", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.registry.hivelist.HiveList", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.registry.printkey.PrintKey", "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, "priority": 2, "required": False},
                        {"name": "windows.registry.printkey.PrintKey", "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}, "priority": 2, "required": False},
                        {"name": "windows.registry.printkey.PrintKey", "args": {"key": "System\\CurrentControlSet\\Services"}, "priority": 3, "required": False},
                        {"name": "windows.registry.printkey.PrintKey", "args": {"key": "Software\\Microsoft\\Windows Defender\\Exclusions"}, "priority": 3, "required": False},
                        {"name": "windows.registry.userassist.UserAssist", "args": {}, "priority": 3, "required": False},
                        {"name": "windows.malware.malfind.Malfind", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.cmdline.CmdLine", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.dlllist.DllList", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.handles.Handles", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.hollowprocesses.HollowProcesses", "args": {}, "priority": 2, "required": False}, 
                    ],
                    "estimated_minutes": 15,
                    "description": "Detect malware indicators with registry analysis"
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist.PsList", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.pstree.PsTree", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.malfind.Malfind", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.bash.Bash", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.sockstat.Sockstat", "args": {}, "priority": 2, "required": False},
                    ],
                    "estimated_minutes": 12,
                    "description": "Detect Linux malware"
                }
            },
            "quick_triage": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist.PsList", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.malware.malfind.Malfind", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.cmdline.CmdLine", "args": {}, "priority": 1, "required": True},
                    ],
                    "estimated_minutes": 4,
                    "description": "Fast initial assessment"
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist.PsList", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.malfind.Malfind", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.bash.Bash", "args": {}, "priority": 1, "required": True},
                    ],
                    "estimated_minutes": 4,
                    "description": "Fast Linux assessment"
                }
            },
            "incident_response": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist.PsList", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.pstree.PsTree", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.cmdline.CmdLine", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.handles.Handles", "args": {}, "priority": 2, "required": True},
                        {"name": "windows.filescan.FileScan", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.registry.hivelist.HiveList", "args": {}, "priority": 2, "required": True},
                        {"name": "windows.registry.printkey.PrintKey", "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, "priority": 2, "required": True},
                        {"name": "windows.registry.printkey.PrintKey", "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}, "priority": 2, "required": True},
                        {"name": "windows.registry.printkey.PrintKey", "args": {"key": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"}, "priority": 2, "required": False},
                        {"name": "windows.registry.printkey.PrintKey", "args": {"key": "System\\CurrentControlSet\\Services"}, "priority": 2, "required": True},
                        {"name": "windows.registry.userassist.UserAssist", "args": {}, "priority": 3, "required": False},
                        {"name": "windows.svcscan.SvcScan", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.malfind.Malfind", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.registry.printkey.PrintKey", "args": {"key": "System\\CurrentControlSet\\Control\\Lsa"}, "priority": 2, "required": False},
                        {"name": "windows.malware.hollowprocesses.HollowProcesses", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.registry.printkey.PrintKey", "args": {"key": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"}, "priority": 2, "required": False}, 
                    ],
                    "estimated_minutes": 25,
                    "description": "IR artifact collection with comprehensive registry analysis"
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist.PsList", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.pstree.PsTree", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.bash.Bash", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.lsof.Lsof", "args": {}, "priority": 2, "required": True},
                        {"name": "linux.sockstat.Sockstat", "args": {}, "priority": 2, "required": True},
                    ],
                    "estimated_minutes": 15,
                    "description": "Linux IR artifacts"
                }
            },
            "rootkit_hunt": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist.PsList", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.psscan.PsScan", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.malware.drivermodule.DriverModule", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.modules.Modules", "args": {}, "priority": 2, "required": True},
                        {"name": "windows.ssdt.SSDT", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.callbacks.Callbacks", "args": {}, "priority": 2, "required": False},
                    ],
                    "estimated_minutes": 15,
                    "description": "Detect kernel rootkits"
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist.PsList", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.psscan.PsScan", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.lsmod.Lsmod", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.check_modules.Check_modules", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.hidden_modules.Hidden_modules", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.check_syscall.Check_syscall", "args": {}, "priority": 1, "required": True},
                    ],
                    "estimated_minutes": 12,
                    "description": "Detect Linux rootkits"
                }
            },
            "network_forensics": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist.PsList", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.handles.Handles", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.cmdline.CmdLine", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.malware.malfind.Malfind", "args": {}, "priority": 2, "required": False},
                    ],
                    "estimated_minutes": 10,
                    "description": "C2 and network connection investigation",
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist.PsList", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.sockstat.Sockstat", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.bash.Bash", "args": {}, "priority": 1, "required": True},
                    ],
                    "estimated_minutes": 8,
                    "description": "Linux network forensics",
                },
            },

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
        "windows.pslist.PsList", "windows.pstree.PsTree", "windows.psscan.PsScan",
        "windows.cmdline.CmdLine", "windows.handles.Handles",
        "windows.dlllist.DllList", "windows.filescan.FileScan",
        "windows.malware.malfind.Malfind", "windows.malware.hollowprocesses.HollowProcesses",
        "windows.registry.hivelist.HiveList",
        "windows.registry.printkey.PrintKey",
        "windows.registry.userassist.UserAssist",
        "windows.registry.certificates.Certificates",
        "windows.svcscan.SvcScan", "windows.modules.Modules", "windows.driverscan.DriverScan"
    ]
        
        linux_plugins = [
            "linux.pslist.PsList", "linux.pstree.PsTree", "linux.psscan.PsScan", "linux.bash.Bash",
            "linux.lsof.Lsof", "linux.sockstat.Sockstat", "linux.lsmod.Lsmod",
            "linux.malware.malfind.Malfind", "linux.malware.check_syscall.Check_syscall",
            "linux.malware.check_modules.Check_modules", "linux.malware.hidden_modules.Hidden_modules"
        ]
        
        return {
            "windows": windows_plugins,
            "linux": linux_plugins,
            "total": len(windows_plugins) + len(linux_plugins)
        }
    
    def get_plugin_info(self, plugin_name: str) -> dict:
        plugin_info = {
            "windows.pslist.PsList": {"description": "Lists processes", "category": "process"},
            "windows.pstree.PsTree": {"description": "Process tree view", "category": "process"},
            "windows.malware.malfind.Malfind": {"description": "Find injected code", "category": "malware"},
            "windows.cmdline.CmdLine": {"description": "Process command lines", "category": "process"},
            "windows.registry.hivelist.HiveList": {"description": "List registry hives", "category": "registry"},
            "windows.registry.printkey.PrintKey": {"description": "Print registry key values", "category": "registry"},
            "windows.registry.userassist.UserAssist": {"description": "UserAssist execution history", "category": "registry"},
            "windows.registry.certificates.Certificates": {"description": "List certificates", "category": "registry"},
            "linux.pslist.PsList": {"description": "Lists Linux processes", "category": "process"},
            "linux.bash.Bash": {"description": "Bash history", "category": "artifacts"},
            "linux.malware.malfind.Malfind": {"description": "Find injected code", "category": "malware"},
        }
        
        if plugin_name in plugin_info:
            return {"name": plugin_name, **plugin_info[plugin_name]}
        
        return {"name": plugin_name, "description": "No description available", "category": "unknown"}

_engine = DecisionEngine()

def get_triage_plan(os_type: str, goal: str) -> TriagePlan:
    return _engine.get_triage_plan(os_type, goal)
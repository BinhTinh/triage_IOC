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
                        {"name": "windows.pslist.PsList",                    "args": {}, "priority": 1, "required": True},
                        {"name": "windows.pstree.PsTree",                    "args": {}, "priority": 1, "required": True},
                        {"name": "windows.malware.malfind.Malfind",          "args": {}, "priority": 1, "required": True},
                        {"name": "windows.cmdline.CmdLine",                  "args": {}, "priority": 1, "required": True},
                        {"name": "windows.netscan.NetScan",  "args": {}, "priority": 1, "required": True},
                        {"name": "windows.netstat.NetStat",  "args": {}, "priority": 2, "required": False},
                        {"name": "windows.psscan.PsScan",                    "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.hollowprocesses.HollowProcesses", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.ldrmodules.LdrModules",    "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.psxview.PsXView",          "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.pebmasquerade.PebMasquerade", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.dlllist.DllList",                  "args": {}, "priority": 2, "required": False},
                        {"name": "windows.getsids.GetSIDs",                  "args": {}, "priority": 2, "required": False},
                        {"name": "windows.privileges.Privs",                 "args": {}, "priority": 2, "required": False},
                        {"name": "windows.handles.Handles",                  "args": {}, "priority": 2, "required": False},
                        {"name": "windows.netstat.NetStat",                  "args": {}, "priority": 3, "required": False},
                        {"name": "windows.registry.hivelist.HiveList",       "args": {}, "priority": 3, "required": False},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},     "priority": 3, "required": False},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}, "priority": 3, "required": False},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "System\\CurrentControlSet\\Services"},                  "priority": 3, "required": False},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "Software\\Microsoft\\Windows Defender\\Exclusions"},    "priority": 3, "required": False},
                        {"name": "windows.registry.userassist.UserAssist",   "args": {}, "priority": 3, "required": False},
                        {"name": "windows.registry.amcache.Amcache",         "args": {}, "priority": 3, "required": False},
                    ],
                    "estimated_minutes": 18,
                    "description": "Full malware indicator extraction — process injection, C2 connections, host-based and network-based IOCs",
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist.PsList",              "args": {}, "priority": 1, "required": True},
                        {"name": "linux.pstree.PsTree",              "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.malfind.Malfind",    "args": {}, "priority": 1, "required": True},
                        {"name": "linux.bash.Bash",                  "args": {}, "priority": 1, "required": True},
                        {"name": "linux.sockstat.Sockstat",          "args": {}, "priority": 2, "required": False},
                    ],
                    "estimated_minutes": 12,
                    "description": "Detect Linux malware",
                },
            },
            "quick_triage": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist.PsList",           "args": {}, "priority": 1, "required": True},
                        {"name": "windows.malware.malfind.Malfind", "args": {}, "priority": 1, "required": True},
                        {"name": "windows.cmdline.CmdLine",         "args": {}, "priority": 1, "required": True},
                        {"name": "windows.netscan.NetScan",         "args": {}, "priority": 1, "required": True},
                    ],
                    "estimated_minutes": 5,
                    "description": "Fast initial assessment",
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist.PsList",              "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.malfind.Malfind",    "args": {}, "priority": 1, "required": True},
                        {"name": "linux.bash.Bash",                  "args": {}, "priority": 1, "required": True},
                    ],
                    "estimated_minutes": 4,
                    "description": "Fast Linux assessment",
                },
            },
            "incident_response": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist.PsList",                    "args": {}, "priority": 1, "required": True},
                        {"name": "windows.pstree.PsTree",                    "args": {}, "priority": 1, "required": True},
                        {"name": "windows.cmdline.CmdLine",                  "args": {}, "priority": 1, "required": True},
                        {"name": "windows.malware.malfind.Malfind",          "args": {}, "priority": 1, "required": True},
                        {"name": "windows.netscan.NetScan",                  "args": {}, "priority": 1, "required": True},
                        {"name": "windows.psscan.PsScan",                    "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.hollowprocesses.HollowProcesses", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.ldrmodules.LdrModules",    "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.psxview.PsXView",          "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.processghosting.ProcessGhosting", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.handles.Handles",                  "args": {}, "priority": 2, "required": True},
                        {"name": "windows.filescan.FileScan",                "args": {}, "priority": 2, "required": False},
                        {"name": "windows.getsids.GetSIDs",                  "args": {}, "priority": 2, "required": False},
                        {"name": "windows.privileges.Privs",                 "args": {}, "priority": 2, "required": False},
                        {"name": "windows.sessions.Sessions",                "args": {}, "priority": 2, "required": False},
                        {"name": "windows.svcscan.SvcScan",                  "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.svcdiff.SvcDiff",          "args": {}, "priority": 2, "required": False},
                        {"name": "windows.registry.hivelist.HiveList",       "args": {}, "priority": 2, "required": True},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},                "priority": 2, "required": True},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},            "priority": 2, "required": True},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"},       "priority": 2, "required": False},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "System\\CurrentControlSet\\Services"},                            "priority": 2, "required": True},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "System\\CurrentControlSet\\Control\\Lsa"},                        "priority": 2, "required": False},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"},       "priority": 2, "required": False},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "Software\\Microsoft\\Windows Defender\\Exclusions"},              "priority": 3, "required": False},
                        {"name": "windows.registry.printkey.PrintKey",       "args": {"key": "System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"}, "priority": 3, "required": False},
                        {"name": "windows.registry.userassist.UserAssist",   "args": {}, "priority": 3, "required": False},
                        {"name": "windows.registry.amcache.Amcache",         "args": {}, "priority": 3, "required": False},
                        {"name": "windows.registry.scheduled_tasks.ScheduledTasks", "args": {}, "priority": 3, "required": False},
                        {"name": "windows.registry.hashdump.Hashdump",       "args": {}, "priority": 3, "required": False},
                        {"name": "windows.registry.lsadump.Lsadump",         "args": {}, "priority": 3, "required": False},
                        {"name": "windows.netstat.NetStat",                  "args": {}, "priority": 3, "required": False},
                        {"name": "windows.mftscan.MFTScan",                  "args": {}, "priority": 3, "required": False},
                    ],
                    "estimated_minutes": 28,
                    "description": "Complete IR artifact collection — persistence, registry, services, filesystem, credentials, network",
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist.PsList",     "args": {}, "priority": 1, "required": True},
                        {"name": "linux.pstree.PsTree",     "args": {}, "priority": 1, "required": True},
                        {"name": "linux.bash.Bash",         "args": {}, "priority": 1, "required": True},
                        {"name": "linux.lsof.Lsof",         "args": {}, "priority": 2, "required": True},
                        {"name": "linux.sockstat.Sockstat", "args": {}, "priority": 2, "required": True},
                    ],
                    "estimated_minutes": 15,
                    "description": "Linux IR artifacts",
                },
            },
            "rootkit_hunt": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist.PsList",                                "args": {}, "priority": 1, "required": True},
                        {"name": "windows.psscan.PsScan",                                "args": {}, "priority": 1, "required": True},
                        {"name": "windows.malware.psxview.PsXView",                     "args": {}, "priority": 1, "required": True},
                        {"name": "windows.malware.drivermodule.DriverModule",            "args": {}, "priority": 1, "required": True},
                        {"name": "windows.modules.Modules",                              "args": {}, "priority": 2, "required": True},
                        {"name": "windows.driverscan.DriverScan",                        "args": {}, "priority": 2, "required": False},
                        {"name": "windows.ssdt.SSDT",                                    "args": {}, "priority": 2, "required": False},
                        {"name": "windows.callbacks.Callbacks",                          "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.svcdiff.SvcDiff",                     "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.unhooked_system_calls.UnhookedSystemCalls", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.suspicious_threads.SuspiciousThreads","args": {}, "priority": 3, "required": False},
                        {"name": "windows.malware.direct_system_calls.DirectSystemCalls","args": {}, "priority": 3, "required": False},
                        {"name": "windows.malware.indirect_system_calls.IndirectSystemCalls", "args": {}, "priority": 3, "required": False},
                        {"name": "windows.malware.skeleton_key_check.Skeleton_Key_Check","args": {}, "priority": 3, "required": False},
                    ],
                    "estimated_minutes": 20,
                    "description": "Kernel-level threat detection — SSDT hooks, hidden modules, driver anomalies, syscall tampering",
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist.PsList",                             "args": {}, "priority": 1, "required": True},
                        {"name": "linux.psscan.PsScan",                             "args": {}, "priority": 1, "required": True},
                        {"name": "linux.lsmod.Lsmod",                               "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.check_modules.Check_modules",       "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.hidden_modules.Hidden_modules",     "args": {}, "priority": 1, "required": True},
                        {"name": "linux.malware.check_syscall.Check_syscall",       "args": {}, "priority": 1, "required": True},
                    ],
                    "estimated_minutes": 12,
                    "description": "Detect Linux rootkits",
                },
            },
            "network_forensics": {
                "windows": {
                    "plugins": [
                        {"name": "windows.pslist.PsList",                    "args": {}, "priority": 1, "required": True},
                        {"name": "windows.netscan.NetScan",                  "args": {}, "priority": 1, "required": True},
                        {"name": "windows.cmdline.CmdLine",                  "args": {}, "priority": 1, "required": True},
                        {"name": "windows.psscan.PsScan",                    "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.malfind.Malfind",          "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.hollowprocesses.HollowProcesses", "args": {}, "priority": 2, "required": False},
                        {"name": "windows.malware.psxview.PsXView",          "args": {}, "priority": 2, "required": False},
                        {"name": "windows.getsids.GetSIDs",                  "args": {}, "priority": 2, "required": False},
                        {"name": "windows.privileges.Privs",                 "args": {}, "priority": 2, "required": False},
                        {"name": "windows.handles.Handles",                  "args": {}, "priority": 2, "required": False},
                        {"name": "windows.netstat.NetStat",                  "args": {}, "priority": 3, "required": False},
                    ],
                    "estimated_minutes": 12,
                    "description": "Network connection and C2 investigation — netscan primary, process-to-socket correlation, privilege context",
                },
                "linux": {
                    "plugins": [
                        {"name": "linux.pslist.PsList",     "args": {}, "priority": 1, "required": True},
                        {"name": "linux.sockstat.Sockstat", "args": {}, "priority": 1, "required": True},
                        {"name": "linux.bash.Bash",         "args": {}, "priority": 1, "required": True},
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
            description=profile.get("description", ""),
        )

    def get_plugin_catalog(self) -> dict:
        windows_plugins = [
            "windows.pslist.PsList", "windows.pstree.PsTree", "windows.psscan.PsScan",
            "windows.cmdline.CmdLine", "windows.handles.Handles",
            "windows.dlllist.DllList", "windows.filescan.FileScan",
            "windows.netscan.NetScan", "windows.netstat.NetStat",
            "windows.getsids.GetSIDs", "windows.privileges.Privs", "windows.sessions.Sessions",
            "windows.malware.malfind.Malfind", "windows.malware.hollowprocesses.HollowProcesses",
            "windows.malware.ldrmodules.LdrModules", "windows.malware.psxview.PsXView",
            "windows.malware.pebmasquerade.PebMasquerade", "windows.malware.processghosting.ProcessGhosting",
            "windows.malware.svcdiff.SvcDiff", "windows.malware.suspicious_threads.SuspiciousThreads",
            "windows.malware.skeleton_key_check.Skeleton_Key_Check",
            "windows.malware.unhooked_system_calls.UnhookedSystemCalls",
            "windows.malware.direct_system_calls.DirectSystemCalls",
            "windows.malware.indirect_system_calls.IndirectSystemCalls",
            "windows.malware.drivermodule.DriverModule",
            "windows.registry.hivelist.HiveList", "windows.registry.printkey.PrintKey",
            "windows.registry.userassist.UserAssist", "windows.registry.amcache.Amcache",
            "windows.registry.certificates.Certificates", "windows.registry.scheduled_tasks.ScheduledTasks",
            "windows.registry.hashdump.Hashdump", "windows.registry.lsadump.Lsadump",
            "windows.registry.cachedump.Cachedump",
            "windows.svcscan.SvcScan", "windows.svclist.SvcList",
            "windows.modules.Modules", "windows.driverscan.DriverScan",
            "windows.ssdt.SSDT", "windows.callbacks.Callbacks",
            "windows.mftscan.MFTScan",
        ]
        linux_plugins = [
            "linux.pslist.PsList", "linux.pstree.PsTree", "linux.psscan.PsScan", "linux.bash.Bash",
            "linux.lsof.Lsof", "linux.sockstat.Sockstat", "linux.lsmod.Lsmod",
            "linux.malware.malfind.Malfind", "linux.malware.check_syscall.Check_syscall",
            "linux.malware.check_modules.Check_modules", "linux.malware.hidden_modules.Hidden_modules",
        ]
        return {
            "windows": windows_plugins,
            "linux": linux_plugins,
            "total": len(windows_plugins) + len(linux_plugins),
        }

    def get_plugin_info(self, plugin_name: str) -> dict:
        plugin_info = {
            "windows.pslist.PsList":                   {"description": "Lists processes via EPROCESS linked list",               "category": "process"},
            "windows.pstree.PsTree":                   {"description": "Process tree view",                                      "category": "process"},
            "windows.psscan.PsScan":                   {"description": "Pool scan for hidden/terminated processes",              "category": "process"},
            "windows.cmdline.CmdLine":                 {"description": "Process command line arguments",                        "category": "process"},
            "windows.getsids.GetSIDs":                 {"description": "SIDs per process — detects privilege escalation",       "category": "process"},
            "windows.privileges.Privs":                {"description": "Token privileges per process",                          "category": "process"},
            "windows.sessions.Sessions":               {"description": "Process session and logon context",                     "category": "process"},
            "windows.netscan.NetScan":                 {"description": "Pool scan for TCP/UDP connections — works on Win10/11",  "category": "network"},
            "windows.netstat.NetStat":                 {"description": "Linked-list walk for connections — may fail on Win10+", "category": "network"},
            "windows.handles.Handles":                 {"description": "All open handles per process",                          "category": "handles"},
            "windows.dlllist.DllList":                 {"description": "Loaded DLLs per process",                               "category": "dlls_modules"},
            "windows.filescan.FileScan":               {"description": "Pool scan for FILE_OBJECT — finds hidden files",        "category": "filesystem"},
            "windows.malware.malfind.Malfind":         {"description": "RWX memory regions — process injection detector",       "category": "malware"},
            "windows.malware.hollowprocesses.HollowProcesses": {"description": "Process hollowing detector",                   "category": "malware"},
            "windows.malware.ldrmodules.LdrModules":   {"description": "Hidden DLL detector via PEB list cross-reference",      "category": "malware"},
            "windows.malware.psxview.PsXView":         {"description": "Hidden process detector via four-method cross-view",    "category": "malware"},
            "windows.malware.pebmasquerade.PebMasquerade": {"description": "Process name spoofing detector",                   "category": "malware"},
            "windows.malware.processghosting.ProcessGhosting": {"description": "Process ghosting detector",                    "category": "malware"},
            "windows.malware.svcdiff.SvcDiff":         {"description": "Hidden service detector via SCM vs registry diff",      "category": "malware"},
            "windows.malware.suspicious_threads.SuspiciousThreads": {"description": "Threads starting in non-image memory",    "category": "malware"},
            "windows.malware.skeleton_key_check.Skeleton_Key_Check": {"description": "Skeleton Key malware detector",          "category": "malware"},
            "windows.malware.unhooked_system_calls.UnhookedSystemCalls": {"description": "Hooked ntdll stub detector",         "category": "malware"},
            "windows.malware.direct_system_calls.DirectSystemCalls": {"description": "Direct syscall bypass detector",         "category": "malware"},
            "windows.malware.indirect_system_calls.IndirectSystemCalls": {"description": "Indirect syscall bypass detector",   "category": "malware"},
            "windows.malware.drivermodule.DriverModule": {"description": "Hidden kernel driver detector",                      "category": "malware"},
            "windows.registry.hivelist.HiveList":      {"description": "List loaded registry hives",                            "category": "registry"},
            "windows.registry.printkey.PrintKey":      {"description": "Dump registry key values",                             "category": "registry"},
            "windows.registry.userassist.UserAssist":  {"description": "UserAssist execution history",                         "category": "registry"},
            "windows.registry.amcache.Amcache":        {"description": "Amcache.hve — executed programs with file hashes",     "category": "registry"},
            "windows.registry.certificates.Certificates": {"description": "Installed certificates — detect rogue root CAs",   "category": "registry"},
            "windows.registry.scheduled_tasks.ScheduledTasks": {"description": "Scheduled tasks from registry",               "category": "registry"},
            "windows.registry.hashdump.Hashdump":      {"description": "NTLM hashes from SAM hive",                           "category": "registry"},
            "windows.registry.lsadump.Lsadump":        {"description": "LSA secrets — service account passwords",              "category": "registry"},
            "windows.registry.cachedump.Cachedump":    {"description": "Cached domain credentials (DCC2)",                    "category": "registry"},
            "windows.svcscan.SvcScan":                 {"description": "Pool scan for hidden services",                        "category": "services"},
            "windows.modules.Modules":                 {"description": "Loaded kernel modules via PsLoadedModuleList",         "category": "kernel"},
            "windows.driverscan.DriverScan":           {"description": "Pool scan for DRIVER_OBJECT — hidden drivers",         "category": "kernel"},
            "windows.ssdt.SSDT":                       {"description": "SSDT dump — detect hooked syscalls",                   "category": "kernel"},
            "windows.callbacks.Callbacks":             {"description": "Kernel notification callbacks",                        "category": "kernel"},
            "windows.mftscan.MFTScan":                 {"description": "MFT scan for file system artifacts",                   "category": "filesystem"},
            "linux.pslist.PsList":                     {"description": "Lists Linux processes",                                 "category": "process"},
            "linux.bash.Bash":                         {"description": "Bash command history",                                 "category": "artifacts"},
            "linux.malware.malfind.Malfind":           {"description": "RWX anonymous memory — injection indicator",           "category": "malware"},
        }
        if plugin_name in plugin_info:
            return {"name": plugin_name, **plugin_info[plugin_name]}
        return {"name": plugin_name, "description": "No description available", "category": "unknown"}


_engine = DecisionEngine()


def get_triage_plan(os_type: str, goal: str) -> TriagePlan:
    return _engine.get_triage_plan(os_type, goal)

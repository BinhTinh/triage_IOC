from fastmcp import FastMCP

from src.core.decision_engine import DecisionEngine, get_triage_plan

WINDOWS_PLUGINS = {
    "process": [
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.psscan.PsScan",
        "windows.cmdline.CmdLine",
        "windows.envars.Envars",
        "windows.getsids.GetSIDs",
        "windows.privileges.Privs",
        "windows.sessions.Sessions",
        "windows.joblinks.JobLinks",
    ],
    "memory": [
        "windows.memmap.Memmap",
        "windows.vadinfo.VadInfo",
        "windows.vadwalk.VadWalk",
        "windows.virtmap.VirtMap",
    ],
    "malware": [
        "windows.malware.malfind.Malfind",
        "windows.malware.hollowprocesses.HollowProcesses",
        "windows.malware.ldrmodules.LdrModules",
        "windows.malware.drivermodule.DriverModule",
        "windows.malware.direct_system_calls.DirectSystemCalls",
        "windows.malware.indirect_system_calls.IndirectSystemCalls",
        "windows.malware.pebmasquerade.PebMasquerade",
        "windows.malware.processghosting.ProcessGhosting",
        "windows.malware.svcdiff.SvcDiff",
    ],
    "dlls_modules": [
        "windows.dlllist.DllList",
        "windows.ldrmodules.LdrModules",
        "windows.modules.Modules",
        "windows.modscan.ModScan",
        "windows.unloadedmodules.UnloadedModules",
    ],
    "handles": [
        "windows.handles.Handles",
        "windows.mutantscan.MutantScan",
        "windows.symlinkscan.SymlinkScan",
    ],
    "filesystem": [
        "windows.filescan.FileScan",
        "windows.dumpfiles.DumpFiles",
        "windows.mftscan.MFTScan",
        "windows.mftscan.ADS",
        "windows.mftscan.ResidentData",
    ],
    "registry": [
        "windows.registry.hivelist.HiveList",
        "windows.registry.hivescan.HiveScan",
        "windows.registry.printkey.PrintKey",
        "windows.registry.userassist.UserAssist",
        "windows.registry.amcache.Amcache",
        "windows.registry.certificates.Certificates",
        "windows.registry.getcellroutine.GetCellRoutine",
        "windows.registry.scheduled_tasks.ScheduledTasks",
    ],
    "services": [
        "windows.svcscan.SvcScan",
        "windows.svclist.SvcList",
        "windows.getservicesids.GetServiceSIDs",
    ],
    "kernel": [
        "windows.ssdt.SSDT",
        "windows.callbacks.Callbacks",
        "windows.driverscan.DriverScan",
        "windows.driverirp.DriverIrp",
        "windows.devicetree.DeviceTree",
        "windows.timers.Timers",
        "windows.kpcrs.KPCRs",
        "windows.bigpools.BigPools",
        "windows.poolscanner.PoolScanner",
    ],
    "gui": [
        "windows.windows.Windows",
        "windows.windowstations.WindowStations",
        "windows.desktops.Desktops",
        "windows.deskscan.DeskScan",
    ],
    "misc": [
        "windows.info.Info",
        "windows.crashinfo.Crashinfo",
        "windows.statistics.Statistics",
        "windows.strings.Strings",
        "windows.pedump.PEDump",
        "windows.mbrscan.MBRScan",
        "windows.shimcachemem.ShimcacheMem",
        "windows.truecrypt.Passphrase",
    ],
    "yara": [
        "windows.vadyarascan.VadYaraScan",
        "windows.vadregexscan.VadRegExScan",
    ],
}

LINUX_PLUGINS = {
    "process": [
        "linux.pslist.PsList",
        "linux.pstree.PsTree",
        "linux.psscan.PsScan",
        "linux.psaux.PsAux",
        "linux.pscallstack.PsCallStack",
        "linux.pidhashtable.PIDHashTable",
        "linux.envars.Envars",
        "linux.capabilities.Capabilities",
        "linux.ptrace.Ptrace",
    ],
    "memory": [
        "linux.proc.Maps",
        "linux.elfs.Elfs",
        "linux.library_list.LibraryList",
    ],
    "malware": [
        "linux.malware.malfind.Malfind",
        "linux.malware.check_syscall.Check_syscall",
        "linux.malware.check_modules.Check_modules",
        "linux.malware.hidden_modules.Hidden_modules",
        "linux.malware.check_afinfo.Check_afinfo",
        "linux.malware.check_creds.Check_creds",
        "linux.malware.check_idt.Check_idt",
        "linux.malware.keyboard_notifiers.Keyboard_notifiers",
        "linux.malware.modxview.Modxview",
        "linux.malware.netfilter.Netfilter",
        "linux.malware.process_spoofing.ProcessSpoofing",
        "linux.malware.tty_check.Tty_Check",
    ],
    "modules": [
        "linux.lsmod.Lsmod",
        "linux.module_extract.ModuleExtract",
    ],
    "network": [
        "linux.sockstat.Sockstat",
        "linux.sockscan.Sockscan",
        "linux.ip.Addr",
        "linux.ip.Link",
    ],
    "filesystem": [
        "linux.lsof.Lsof",
        "linux.mountinfo.MountInfo",
        "linux.pagecache.Files",
        "linux.pagecache.InodePages",
        "linux.pagecache.RecoverFs",
    ],
    "kernel": [
        "linux.kthreads.Kthreads",
        "linux.kallsyms.Kallsyms",
        "linux.kmsg.Kmsg",
        "linux.boottime.Boottime",
        "linux.iomem.IOMem",
        "linux.vmcoreinfo.VMCoreInfo",
        "linux.ebpf.EBPF",
    ],
    "tracing": [
        "linux.tracing.ftrace.CheckFtrace",
        "linux.tracing.perf_events.PerfEvents",
        "linux.tracing.tracepoints.CheckTracepoints",
    ],
    "artifacts": [
        "linux.bash.Bash",
    ],
    "graphics": [
        "linux.graphics.fbdev.Fbdev",
    ],
    "yara": [
        "linux.vmayarascan.VmaYaraScan",
        "linux.vmaregexscan.VmaRegExScan",
    ],
}

MAC_PLUGINS = {
    "process": [
        "mac.pslist.PsList",
        "mac.pstree.PsTree",
        "mac.psaux.Psaux",
    ],
    "malware": [
        "mac.malfind.Malfind",
        "mac.check_syscall.Check_syscall",
        "mac.check_sysctl.Check_sysctl",
        "mac.check_trap_table.Check_trap_table",
        "mac.trustedbsd.Trustedbsd",
        "mac.timers.Timers",
    ],
    "modules": [
        "mac.lsmod.Lsmod",
    ],
    "network": [
        "mac.netstat.Netstat",
        "mac.ifconfig.Ifconfig",
        "mac.socket_filters.Socket_filters",
    ],
    "filesystem": [
        "mac.lsof.Lsof",
        "mac.list_files.List_Files",
        "mac.mount.Mount",
        "mac.vfsevents.VFSevents",
    ],
    "kernel": [
        "mac.dmesg.Dmesg",
        "mac.kauth_listeners.Kauth_listeners",
        "mac.kauth_scopes.Kauth_scopes",
        "mac.kevents.Kevents",
    ],
    "artifacts": [
        "mac.bash.Bash",
    ],
    "memory": [
        "mac.proc_maps.Maps",
    ],
}

GENERIC_PLUGINS = {
    "banners": ["banners.Banners"],
    "timeliner": ["timeliner.Timeliner"],
    "yara": ["yarascan.YaraScan", "regexscan.RegExScan"],
    "framework": [
        "frameworkinfo.FrameworkInfo",
        "isfinfo.IsfInfo",
        "configwriter.ConfigWriter",
        "layerwriter.LayerWriter",
    ],
    "vm": ["vmscan.Vmscan"],
}

UNAVAILABLE_PLUGINS = [
    "windows.netscan",
    "windows.netstat",
    "windows.cachedump",
    "windows.cmdscan",
    "windows.consoles",
    "windows.debugregisters",
    "windows.etwpatch",
    "windows.hashdump",
    "windows.iat",
    "windows.lsadump",
    "windows.malware.psxview",
    "windows.malware.skeleton_key_check",
    "windows.malware.suspicious_threads",
    "windows.malware.unhooked_system_calls",
    "windows.orphan_kernel_threads",
    "windows.pe_symbols",
    "windows.psxview",
    "windows.registry.cachedump",
    "windows.registry.hashdump",
    "windows.registry.lsadump",
    "windows.skeleton_key_check",
    "windows.suspended_threads",
    "windows.suspicious_threads",
    "windows.thrdscan",
    "windows.threads",
    "windows.unhooked_system_calls",
    "windows.verinfo",
]

DEPRECATED_PLUGINS = {
    "windows.malfind.Malfind": "windows.malware.malfind.Malfind",
    "windows.hollowprocesses.HollowProcesses": "windows.malware.hollowprocesses.HollowProcesses",
    "windows.ldrmodules.LdrModules": "windows.malware.ldrmodules.LdrModules",
    "windows.drivermodule.DriverModule": "windows.malware.drivermodule.DriverModule",
    "windows.direct_system_calls.DirectSystemCalls": "windows.malware.direct_system_calls.DirectSystemCalls",
    "windows.indirect_system_calls.IndirectSystemCalls": "windows.malware.indirect_system_calls.IndirectSystemCalls",
    "windows.processghosting.ProcessGhosting": "windows.malware.processghosting.ProcessGhosting",
    "windows.svcdiff.SvcDiff": "windows.malware.svcdiff.SvcDiff",
    "windows.amcache.Amcache": "windows.registry.amcache.Amcache",
    "windows.scheduled_tasks.ScheduledTasks": "windows.registry.scheduled_tasks.ScheduledTasks",
    "linux.malfind.Malfind": "linux.malware.malfind.Malfind",
    "linux.check_syscall.Check_syscall": "linux.malware.check_syscall.Check_syscall",
    "linux.check_modules.Check_modules": "linux.malware.check_modules.Check_modules",
    "linux.hidden_modules.Hidden_modules": "linux.malware.hidden_modules.Hidden_modules",
    "linux.check_afinfo.Check_afinfo": "linux.malware.check_afinfo.Check_afinfo",
    "linux.check_creds.Check_creds": "linux.malware.check_creds.Check_creds",
    "linux.check_idt.Check_idt": "linux.malware.check_idt.Check_idt",
    "linux.keyboard_notifiers.Keyboard_notifiers": "linux.malware.keyboard_notifiers.Keyboard_notifiers",
    "linux.modxview.Modxview": "linux.malware.modxview.Modxview",
    "linux.netfilter.Netfilter": "linux.malware.netfilter.Netfilter",
    "linux.tty_check.tty_check": "linux.malware.tty_check.Tty_Check",
}

PLUGIN_DESCRIPTIONS = {
    "windows.pslist.PsList": "Lists the processes present in a particular windows memory image",
    "windows.pstree.PsTree": "Plugin for listing processes in a tree based on their parent process ID",
    "windows.psscan.PsScan": "Scans for processes present in a particular windows memory image",
    "windows.cmdline.CmdLine": "Lists process command line arguments",
    "windows.dlllist.DllList": "Lists the loaded DLLs in a particular windows memory image",
    "windows.handles.Handles": "Lists process open handles",
    "windows.filescan.FileScan": "Scans for file objects present in a particular windows memory image",
    "windows.malware.malfind.Malfind": "Lists process memory ranges that potentially contain injected code",
    "windows.malware.hollowprocesses.HollowProcesses": "Lists hollowed processes",
    "windows.malware.ldrmodules.LdrModules": "Lists the loaded modules in a particular windows memory image",
    "windows.registry.hivelist.HiveList": "Lists the registry hives present in a particular memory image",
    "windows.registry.userassist.UserAssist": "Print userassist registry keys and information",
    "windows.svcscan.SvcScan": "Scans for windows services",
    "windows.ssdt.SSDT": "Lists the system call table",
    "windows.callbacks.Callbacks": "Lists kernel callbacks and notification routines",
    "windows.info.Info": "Show OS & kernel details of the memory sample being analyzed",
    "linux.pslist.PsList": "Lists the processes present in a particular linux memory image",
    "linux.pstree.PsTree": "Plugin for listing processes in a tree based on their parent process ID",
    "linux.psscan.PsScan": "Scans for processes present in a particular linux image",
    "linux.bash.Bash": "Recovers bash command history from memory",
    "linux.lsof.Lsof": "Lists open files for each processes",
    "linux.sockstat.Sockstat": "Lists all network connections for all processes",
    "linux.lsmod.Lsmod": "Lists loaded kernel modules",
    "linux.malware.malfind.Malfind": "Lists process memory ranges that potentially contain injected code",
    "linux.malware.check_syscall.Check_syscall": "Check system call table for hooks",
    "linux.malware.check_modules.Check_modules": "Compares module list to sysfs info, if available",
    "linux.malware.hidden_modules.Hidden_modules": "Carves memory to find hidden kernel modules",
    "banners.Banners": "Attempts to identify potential linux banners in an image",
    "timeliner.Timeliner": "Runs all relevant plugins that provide time related information",
}


def get_all_plugins_flat() -> list:
    all_plugins = []
    for category_plugins in WINDOWS_PLUGINS.values():
        all_plugins.extend(category_plugins)
    for category_plugins in LINUX_PLUGINS.values():
        all_plugins.extend(category_plugins)
    for category_plugins in MAC_PLUGINS.values():
        all_plugins.extend(category_plugins)
    for category_plugins in GENERIC_PLUGINS.values():
        all_plugins.extend(category_plugins)
    return all_plugins


def register_plugin_resources(mcp: FastMCP):
    
    @mcp.resource("plugins://catalog")
    async def get_plugin_catalog() -> dict:
        return {
            "windows": WINDOWS_PLUGINS,
            "linux": LINUX_PLUGINS,
            "mac": MAC_PLUGINS,
            "generic": GENERIC_PLUGINS,
            "total_count": len(get_all_plugins_flat()),
            "unavailable": UNAVAILABLE_PLUGINS,
            "deprecated": DEPRECATED_PLUGINS,
        }
    
    @mcp.resource("plugins://windows")
    async def get_windows_plugins() -> dict:
        all_windows = []
        for plugins in WINDOWS_PLUGINS.values():
            all_windows.extend(plugins)
        return {
            "os": "windows",
            "categories": WINDOWS_PLUGINS,
            "all_plugins": all_windows,
            "total": len(all_windows),
            "unavailable": [p for p in UNAVAILABLE_PLUGINS if p.startswith("windows.")],
        }
    
    @mcp.resource("plugins://windows/process")
    async def get_windows_process_plugins() -> dict:
        return {
            "category": "process",
            "plugins": WINDOWS_PLUGINS["process"],
            "descriptions": {p: PLUGIN_DESCRIPTIONS.get(p, "") for p in WINDOWS_PLUGINS["process"]}
        }
    
    @mcp.resource("plugins://windows/malware")
    async def get_windows_malware_plugins() -> dict:
        return {
            "category": "malware",
            "plugins": WINDOWS_PLUGINS["malware"],
            "descriptions": {p: PLUGIN_DESCRIPTIONS.get(p, "") for p in WINDOWS_PLUGINS["malware"]}
        }
    
    @mcp.resource("plugins://windows/registry")
    async def get_windows_registry_plugins() -> dict:
        return {
            "category": "registry",
            "plugins": WINDOWS_PLUGINS["registry"],
            "descriptions": {p: PLUGIN_DESCRIPTIONS.get(p, "") for p in WINDOWS_PLUGINS["registry"]}
        }
    
    @mcp.resource("plugins://windows/kernel")
    async def get_windows_kernel_plugins() -> dict:
        return {
            "category": "kernel",
            "plugins": WINDOWS_PLUGINS["kernel"],
            "descriptions": {p: PLUGIN_DESCRIPTIONS.get(p, "") for p in WINDOWS_PLUGINS["kernel"]}
        }
    
    @mcp.resource("plugins://linux")
    async def get_linux_plugins() -> dict:
        all_linux = []
        for plugins in LINUX_PLUGINS.values():
            all_linux.extend(plugins)
        return {
            "os": "linux",
            "categories": LINUX_PLUGINS,
            "all_plugins": all_linux,
            "total": len(all_linux),
        }
    
    @mcp.resource("plugins://linux/process")
    async def get_linux_process_plugins() -> dict:
        return {
            "category": "process",
            "plugins": LINUX_PLUGINS["process"],
            "descriptions": {p: PLUGIN_DESCRIPTIONS.get(p, "") for p in LINUX_PLUGINS["process"]}
        }
    
    @mcp.resource("plugins://linux/malware")
    async def get_linux_malware_plugins() -> dict:
        return {
            "category": "malware",
            "plugins": LINUX_PLUGINS["malware"],
            "descriptions": {p: PLUGIN_DESCRIPTIONS.get(p, "") for p in LINUX_PLUGINS["malware"]}
        }
    
    @mcp.resource("plugins://linux/network")
    async def get_linux_network_plugins() -> dict:
        return {
            "category": "network",
            "plugins": LINUX_PLUGINS["network"],
            "descriptions": {p: PLUGIN_DESCRIPTIONS.get(p, "") for p in LINUX_PLUGINS["network"]}
        }
    
    @mcp.resource("plugins://mac")
    async def get_mac_plugins() -> dict:
        all_mac = []
        for plugins in MAC_PLUGINS.values():
            all_mac.extend(plugins)
        return {
            "os": "mac",
            "categories": MAC_PLUGINS,
            "all_plugins": all_mac,
            "total": len(all_mac),
        }
    
    @mcp.resource("plugins://generic")
    async def get_generic_plugins() -> dict:
        all_generic = []
        for plugins in GENERIC_PLUGINS.values():
            all_generic.extend(plugins)
        return {
            "categories": GENERIC_PLUGINS,
            "all_plugins": all_generic,
            "total": len(all_generic),
        }
    
    @mcp.resource("plugins://unavailable")
    async def get_unavailable_plugins() -> dict:
        return {
            "plugins": UNAVAILABLE_PLUGINS,
            "total": len(UNAVAILABLE_PLUGINS),
            "note": "These plugins could not be loaded in current Volatility3 installation"
        }
    
    @mcp.resource("plugins://deprecated")
    async def get_deprecated_plugins() -> dict:
        return {
            "mappings": DEPRECATED_PLUGINS,
            "total": len(DEPRECATED_PLUGINS),
            "note": "Use the new plugin names instead of deprecated ones"
        }
    
    @mcp.resource("plugins://{plugin_name}/info")
    async def get_plugin_info(plugin_name: str) -> dict:
        normalized = plugin_name.replace("-", ".").replace("_", ".")
        
        if normalized in DEPRECATED_PLUGINS:
            return {
                "name": plugin_name,
                "status": "deprecated",
                "replacement": DEPRECATED_PLUGINS[normalized],
                "description": PLUGIN_DESCRIPTIONS.get(normalized, "Deprecated plugin")
            }
        
        if any(normalized in p for p in UNAVAILABLE_PLUGINS):
            return {
                "name": plugin_name,
                "status": "unavailable",
                "description": "This plugin could not be loaded"
            }
        
        all_plugins = get_all_plugins_flat()
        matched = None
        for p in all_plugins:
            if normalized in p.lower() or p.lower().endswith(normalized.lower()):
                matched = p
                break
        
        if matched:
            return {
                "name": matched,
                "status": "available",
                "description": PLUGIN_DESCRIPTIONS.get(matched, "No description available")
            }
        
        return {
            "name": plugin_name,
            "status": "unknown",
            "description": "Plugin not found in catalog"
        }
    
    @mcp.resource("profiles://list")
    async def list_profiles() -> dict:
        return {
            "profiles": [
                {"name": "malware_detection", "description": "Detect malware indicators"},
                {"name": "incident_response", "description": "IR artifact collection"},
                {"name": "quick_triage", "description": "Fast initial assessment"},
                {"name": "rootkit_hunt", "description": "Detect kernel rootkits"},
            ],
            "os_types": ["windows", "linux"]
        }
    
    @mcp.resource("profiles://{goal}/{os_type}")
    async def get_analysis_profile(goal: str, os_type: str) -> dict:
        try:
            plan = get_triage_plan(os_type, goal)
            return {
                "goal": goal,
                "os_type": os_type,
                "plugins": [p["name"] for p in plan.plugins],
                "estimated_minutes": plan.estimated_minutes,
                "description": plan.description
            }
        except ValueError as e:
            return {"error": str(e)}
    
    @mcp.resource("profiles://malware_detection/windows")
    async def get_malware_windows_profile() -> dict:
        return {
            "goal": "malware_detection",
            "os_type": "windows",
            "plugins": [
                "windows.pslist.PsList",
                "windows.pstree.PsTree",
                "windows.psscan.PsScan",
                "windows.malware.malfind.Malfind",
                "windows.malware.hollowprocesses.HollowProcesses",
                "windows.cmdline.CmdLine",
                "windows.dlllist.DllList",
                "windows.handles.Handles",
            ],
            "estimated_minutes": 10,
            "description": "Detect malware indicators including injection, suspicious processes"
        }
    
    @mcp.resource("profiles://malware_detection/linux")
    async def get_malware_linux_profile() -> dict:
        return {
            "goal": "malware_detection",
            "os_type": "linux",
            "plugins": [
                "linux.pslist.PsList",
                "linux.pstree.PsTree",
                "linux.psscan.PsScan",
                "linux.malware.malfind.Malfind",
                "linux.malware.check_syscall.Check_syscall",
                "linux.bash.Bash",
                "linux.sockstat.Sockstat",
            ],
            "estimated_minutes": 12,
            "description": "Detect Linux malware including rootkits and webshells"
        }
    
    @mcp.resource("profiles://quick_triage/windows")
    async def get_quick_windows_profile() -> dict:
        return {
            "goal": "quick_triage",
            "os_type": "windows",
            "plugins": [
                "windows.pslist.PsList",
                "windows.malware.malfind.Malfind",
                "windows.cmdline.CmdLine",
            ],
            "estimated_minutes": 4,
            "description": "Fast initial assessment"
        }
    
    @mcp.resource("profiles://quick_triage/linux")
    async def get_quick_linux_profile() -> dict:
        return {
            "goal": "quick_triage",
            "os_type": "linux",
            "plugins": [
                "linux.pslist.PsList",
                "linux.malware.malfind.Malfind",
                "linux.bash.Bash",
            ],
            "estimated_minutes": 4,
            "description": "Fast Linux assessment"
        }
    
    @mcp.resource("profiles://incident_response/windows")
    async def get_ir_windows_profile() -> dict:
        return {
            "goal": "incident_response",
            "os_type": "windows",
            "plugins": [
                "windows.pslist.PsList",
                "windows.pstree.PsTree",
                "windows.cmdline.CmdLine",
                "windows.handles.Handles",
                "windows.filescan.FileScan",
                "windows.registry.hivelist.HiveList",
                "windows.registry.userassist.UserAssist",
                "windows.svcscan.SvcScan",
                "windows.registry.scheduled_tasks.ScheduledTasks",
            ],
            "estimated_minutes": 18,
            "description": "IR artifact collection"
        }
    
    @mcp.resource("profiles://incident_response/linux")
    async def get_ir_linux_profile() -> dict:
        return {
            "goal": "incident_response",
            "os_type": "linux",
            "plugins": [
                "linux.pslist.PsList",
                "linux.pstree.PsTree",
                "linux.bash.Bash",
                "linux.lsof.Lsof",
                "linux.sockstat.Sockstat",
                "linux.lsmod.Lsmod",
                "linux.envars.Envars",
            ],
            "estimated_minutes": 15,
            "description": "Linux IR artifacts"
        }
    
    @mcp.resource("profiles://rootkit_hunt/windows")
    async def get_rootkit_windows_profile() -> dict:
        return {
            "goal": "rootkit_hunt",
            "os_type": "windows",
            "plugins": [
                "windows.pslist.PsList",
                "windows.psscan.PsScan",
                "windows.malware.drivermodule.DriverModule",
                "windows.modules.Modules",
                "windows.driverscan.DriverScan",
                "windows.ssdt.SSDT",
                "windows.callbacks.Callbacks",
            ],
            "estimated_minutes": 15,
            "description": "Detect kernel-level rootkits"
        }
    
    @mcp.resource("profiles://rootkit_hunt/linux")
    async def get_rootkit_linux_profile() -> dict:
        return {
            "goal": "rootkit_hunt",
            "os_type": "linux",
            "plugins": [
                "linux.pslist.PsList",
                "linux.psscan.PsScan",
                "linux.lsmod.Lsmod",
                "linux.malware.check_modules.Check_modules",
                "linux.malware.hidden_modules.Hidden_modules",
                "linux.malware.check_syscall.Check_syscall",
                "linux.kthreads.Kthreads",
            ],
            "estimated_minutes": 12,
            "description": "Detect Linux kernel rootkits"
        }
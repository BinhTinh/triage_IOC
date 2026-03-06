# plugins.py
from fastmcp import FastMCP
from src.core.decision_engine import get_triage_plan

WINDOWS_PLUGINS = {
    "process": [
        "windows.pslist.PsList", "windows.pstree.PsTree", "windows.psscan.PsScan",
        "windows.cmdline.CmdLine", "windows.envars.Envars", "windows.getsids.GetSIDs",
        "windows.privileges.Privs", "windows.sessions.Sessions", "windows.joblinks.JobLinks",
    ],
    "memory": [
        "windows.memmap.Memmap", "windows.vadinfo.VadInfo",
        "windows.vadwalk.VadWalk", "windows.virtmap.VirtMap",
    ],
    "malware": [
        "windows.malware.malfind.Malfind", "windows.malware.hollowprocesses.HollowProcesses",
        "windows.malware.ldrmodules.LdrModules", "windows.malware.drivermodule.DriverModule",
        "windows.malware.direct_system_calls.DirectSystemCalls",
        "windows.malware.indirect_system_calls.IndirectSystemCalls",
        "windows.malware.pebmasquerade.PebMasquerade",
        "windows.malware.processghosting.ProcessGhosting",
        "windows.malware.svcdiff.SvcDiff",
    ],
    "dlls_modules": [
        "windows.dlllist.DllList", "windows.ldrmodules.LdrModules",
        "windows.modules.Modules", "windows.modscan.ModScan",
        "windows.unloadedmodules.UnloadedModules",
    ],
    "handles": [
        "windows.handles.Handles", "windows.mutantscan.MutantScan",
        "windows.symlinkscan.SymlinkScan",
    ],
    "filesystem": [
        "windows.filescan.FileScan", "windows.dumpfiles.DumpFiles",
        "windows.mftscan.MFTScan", "windows.mftscan.ADS", "windows.mftscan.ResidentData",
    ],
    "registry": [
        "windows.registry.hivelist.HiveList", "windows.registry.hivescan.HiveScan",
        "windows.registry.printkey.PrintKey", "windows.registry.userassist.UserAssist",
        "windows.registry.amcache.Amcache", "windows.registry.certificates.Certificates",
        "windows.registry.getcellroutine.GetCellRoutine",
        "windows.registry.scheduled_tasks.ScheduledTasks",
    ],
    "services": [
        "windows.svcscan.SvcScan", "windows.svclist.SvcList",
        "windows.getservicesids.GetServiceSIDs",
    ],
    "kernel": [
        "windows.ssdt.SSDT", "windows.callbacks.Callbacks", "windows.driverscan.DriverScan",
        "windows.driverirp.DriverIrp", "windows.devicetree.DeviceTree", "windows.timers.Timers",
        "windows.kpcrs.KPCRs", "windows.bigpools.BigPools", "windows.poolscanner.PoolScanner",
    ],
    "gui": [
        "windows.windows.Windows", "windows.windowstations.WindowStations",
        "windows.desktops.Desktops", "windows.deskscan.DeskScan",
    ],
    "misc": [
        "windows.info.Info", "windows.crashinfo.Crashinfo", "windows.statistics.Statistics",
        "windows.strings.Strings", "windows.pedump.PEDump", "windows.mbrscan.MBRScan",
        "windows.shimcachemem.ShimcacheMem", "windows.truecrypt.Passphrase",
    ],
    "yara": ["windows.vadyarascan.VadYaraScan", "windows.vadregexscan.VadRegExScan"],
}

LINUX_PLUGINS = {
    "process": [
        "linux.pslist.PsList", "linux.pstree.PsTree", "linux.psscan.PsScan",
        "linux.psaux.PsAux", "linux.pscallstack.PsCallStack", "linux.pidhashtable.PIDHashTable",
        "linux.envars.Envars", "linux.capabilities.Capabilities", "linux.ptrace.Ptrace",
    ],
    "memory": ["linux.proc.Maps", "linux.elfs.Elfs", "linux.library_list.LibraryList"],
    "malware": [
        "linux.malware.malfind.Malfind", "linux.malware.check_syscall.Check_syscall",
        "linux.malware.check_modules.Check_modules", "linux.malware.hidden_modules.Hidden_modules",
        "linux.malware.check_afinfo.Check_afinfo", "linux.malware.check_creds.Check_creds",
        "linux.malware.check_idt.Check_idt", "linux.malware.keyboard_notifiers.Keyboard_notifiers",
        "linux.malware.modxview.Modxview", "linux.malware.netfilter.Netfilter",
        "linux.malware.process_spoofing.ProcessSpoofing", "linux.malware.tty_check.Tty_Check",
    ],
    "modules": ["linux.lsmod.Lsmod", "linux.module_extract.ModuleExtract"],
    "network": [
        "linux.sockstat.Sockstat", "linux.sockscan.Sockscan",
        "linux.ip.Addr", "linux.ip.Link",
    ],
    "filesystem": [
        "linux.lsof.Lsof", "linux.mountinfo.MountInfo",
        "linux.pagecache.Files", "linux.pagecache.InodePages", "linux.pagecache.RecoverFs",
    ],
    "kernel": [
        "linux.kthreads.Kthreads", "linux.kallsyms.Kallsyms", "linux.kmsg.Kmsg",
        "linux.boottime.Boottime", "linux.iomem.IOMem",
        "linux.vmcoreinfo.VMCoreInfo", "linux.ebpf.EBPF",
    ],
    "tracing": [
        "linux.tracing.ftrace.CheckFtrace",
        "linux.tracing.perf_events.PerfEvents",
        "linux.tracing.tracepoints.CheckTracepoints",
    ],
    "artifacts": ["linux.bash.Bash"],
    "graphics": ["linux.graphics.fbdev.Fbdev"],
    "yara": ["linux.vmayarascan.VmaYaraScan", "linux.vmaregexscan.VmaRegExScan"],
}

MAC_PLUGINS = {
    "process": ["mac.pslist.PsList", "mac.pstree.PsTree", "mac.psaux.Psaux"],
    "malware": [
        "mac.malfind.Malfind", "mac.check_syscall.Check_syscall",
        "mac.check_sysctl.Check_sysctl", "mac.check_trap_table.Check_trap_table",
        "mac.trustedbsd.Trustedbsd", "mac.timers.Timers",
    ],
    "modules": ["mac.lsmod.Lsmod"],
    "network": ["mac.netstat.Netstat", "mac.ifconfig.Ifconfig", "mac.socket_filters.Socket_filters"],
    "filesystem": [
        "mac.lsof.Lsof", "mac.list_files.List_Files",
        "mac.mount.Mount", "mac.vfsevents.VFSevents",
    ],
    "kernel": [
        "mac.dmesg.Dmesg", "mac.kauth_listeners.Kauth_listeners",
        "mac.kauth_scopes.Kauth_scopes", "mac.kevents.Kevents",
    ],
    "artifacts": ["mac.bash.Bash"],
    "memory": ["mac.proc_maps.Maps"],
}

GENERIC_PLUGINS = {
    "banners":    ["banners.Banners"],
    "timeliner":  ["timeliner.Timeliner"],
    "yara":       ["yarascan.YaraScan", "regexscan.RegExScan"],
    "framework":  [
        "frameworkinfo.FrameworkInfo", "isfinfo.IsfInfo",
        "configwriter.ConfigWriter", "layerwriter.LayerWriter",
    ],
    "vm": ["vmscan.Vmscan"],
}

UNAVAILABLE_PLUGINS = [
    "windows.netscan", "windows.netstat", "windows.cachedump", "windows.cmdscan",
    "windows.consoles", "windows.debugregisters", "windows.etwpatch", "windows.hashdump",
    "windows.iat", "windows.lsadump", "windows.malware.psxview",
    "windows.malware.skeleton_key_check", "windows.malware.suspicious_threads",
    "windows.malware.unhooked_system_calls", "windows.orphan_kernel_threads",
    "windows.pe_symbols", "windows.psxview", "windows.registry.cachedump",
    "windows.registry.hashdump", "windows.registry.lsadump", "windows.skeleton_key_check",
    "windows.suspended_threads", "windows.suspicious_threads", "windows.thrdscan",
    "windows.threads", "windows.unhooked_system_calls", "windows.verinfo",
]

DEPRECATED_PLUGINS = {
    "windows.malfind.Malfind":                              "windows.malware.malfind.Malfind",
    "windows.hollowprocesses.HollowProcesses":              "windows.malware.hollowprocesses.HollowProcesses",
    "windows.ldrmodules.LdrModules":                        "windows.malware.ldrmodules.LdrModules",
    "windows.drivermodule.DriverModule":                    "windows.malware.drivermodule.DriverModule",
    "windows.direct_system_calls.DirectSystemCalls":        "windows.malware.direct_system_calls.DirectSystemCalls",
    "windows.indirect_system_calls.IndirectSystemCalls":    "windows.malware.indirect_system_calls.IndirectSystemCalls",
    "windows.processghosting.ProcessGhosting":              "windows.malware.processghosting.ProcessGhosting",
    "windows.svcdiff.SvcDiff":                              "windows.malware.svcdiff.SvcDiff",
    "windows.amcache.Amcache":                              "windows.registry.amcache.Amcache",
    "windows.scheduled_tasks.ScheduledTasks":               "windows.registry.scheduled_tasks.ScheduledTasks",
    "linux.malfind.Malfind":                                "linux.malware.malfind.Malfind",
    "linux.check_syscall.Check_syscall":                    "linux.malware.check_syscall.Check_syscall",
    "linux.check_modules.Check_modules":                    "linux.malware.check_modules.Check_modules",
    "linux.hidden_modules.Hidden_modules":                  "linux.malware.hidden_modules.Hidden_modules",
    "linux.check_afinfo.Check_afinfo":                      "linux.malware.check_afinfo.Check_afinfo",
    "linux.check_creds.Check_creds":                        "linux.malware.check_creds.Check_creds",
    "linux.check_idt.Check_idt":                            "linux.malware.check_idt.Check_idt",
    "linux.keyboard_notifiers.Keyboard_notifiers":          "linux.malware.keyboard_notifiers.Keyboard_notifiers",
    "linux.modxview.Modxview":                              "linux.malware.modxview.Modxview",
    "linux.netfilter.Netfilter":                            "linux.malware.netfilter.Netfilter",
    "linux.tty_check.tty_check":                            "linux.malware.tty_check.Tty_Check",
}

PLUGIN_DESCRIPTIONS = {
    "windows.pslist.PsList":                        "Lists active processes via EPROCESS ActiveProcessLinks doubly-linked list",
    "windows.pstree.PsTree":                        "Displays process hierarchy as parent→child tree using PPID relationships",
    "windows.psscan.PsScan":                        "Scans raw memory for EPROCESS pool tags — finds hidden/terminated processes missed by pslist",
    "windows.cmdline.CmdLine":                      "Extracts full command line arguments for each process from PEB.ProcessParameters",
    "windows.dlllist.DllList":                      "Lists loaded DLLs per process via InMemoryOrderModuleList — detects DLL injection",
    "windows.handles.Handles":                      "Lists all open handles (files, registry, network, mutants) per process",
    "windows.filescan.FileScan":                    "Scans memory for FILE_OBJECT pool tags — finds open/deleted/hidden files",
    "windows.malware.malfind.Malfind":              "Finds RWX memory regions with executable code — primary process injection detector (T1055)",
    "windows.malware.hollowprocesses.HollowProcesses": "Detects process hollowing by comparing on-disk PE vs in-memory VAD mappings (T1055.012)",
    "windows.malware.ldrmodules.LdrModules":        "Compares three PEB module lists to find unlisted/hidden DLLs (T1055.001)",
    "windows.malware.drivermodule.DriverModule":    "Detects kernel drivers not linked to any loaded module — rootkit driver indicator",
    "windows.malware.svcdiff.SvcDiff":              "Compares service registry vs SCM database — finds ghost/hidden services (T1543.003)",
    "windows.malware.processghosting.ProcessGhosting": "Detects process ghosting — process running from a deleted file (T1055.015)",
    "windows.malware.pebmasquerade.PebMasquerade":  "Detects masqueraded process names in PEB vs actual image path (T1036.005)",
    "windows.malware.direct_system_calls.DirectSystemCalls": "Detects direct syscall stubs bypassing ntdll hooks (T1055)",
    "windows.malware.indirect_system_calls.IndirectSystemCalls": "Detects indirect syscall patterns used by advanced injectors",
    "windows.registry.hivelist.HiveList":           "Lists all loaded registry hives with virtual/physical offsets",
    "windows.registry.printkey.PrintKey":           "Dumps registry key values — use with Run/RunOnce keys for persistence (T1547.001)",
    "windows.registry.userassist.UserAssist":       "Decodes UserAssist keys — shows recently executed programs per user",
    "windows.registry.amcache.Amcache":             "Parses Amcache.hve — records of recently executed programs with file hashes",
    "windows.registry.scheduled_tasks.ScheduledTasks": "Extracts scheduled tasks from registry — persistence mechanism (T1053.005)",
    "windows.registry.certificates.Certificates":  "Extracts installed certificates — detects rogue root CAs",
    "windows.svcscan.SvcScan":                      "Scans memory for SERVICE_RECORD structures — finds hidden/ghost services",
    "windows.ssdt.SSDT":                            "Dumps System Service Descriptor Table — detects hooked syscalls (T1014)",
    "windows.callbacks.Callbacks":                  "Lists kernel notification callbacks — rootkit persistence and hooking indicator",
    "windows.driverscan.DriverScan":                "Scans for DRIVER_OBJECT pool tags — finds hidden kernel drivers",
    "windows.modules.Modules":                      "Lists loaded kernel modules via PsLoadedModuleList",
    "windows.info.Info":                            "Extracts OS version, build number, architecture from KDBG — use for detect_os",
    "linux.pslist.PsList":                          "Lists processes via task_struct linked list",
    "linux.pstree.PsTree":                          "Displays Linux process tree via parent task_struct relationships",
    "linux.psscan.PsScan":                          "Scans memory for task_struct signatures — finds hidden processes (T1014)",
    "linux.bash.Bash":                              "Recovers bash command history from memory — shows attacker commands (T1059.004)",
    "linux.lsof.Lsof":                              "Lists all open file descriptors per process",
    "linux.sockstat.Sockstat":                      "Lists active network connections and listening sockets per process",
    "linux.lsmod.Lsmod":                            "Lists loaded kernel modules via THIS_MODULE linked list",
    "linux.malware.malfind.Malfind":                "Finds RWX anonymous memory regions — process injection indicator (T1055)",
    "linux.malware.check_syscall.Check_syscall":    "Verifies syscall table entries point to legitimate kernel text — detects hooks (T1014)",
    "linux.malware.check_modules.Check_modules":    "Cross-references module list vs sysfs — finds hidden modules",
    "linux.malware.hidden_modules.Hidden_modules":  "Deep scan for module structures outside linked list — LKM rootkit detector (T1014)",
    "linux.malware.check_afinfo.Check_afinfo":      "Checks AF_INET/AF_INET6 protocol operation tables for hooks",
    "linux.malware.check_idt.Check_idt":            "Verifies Interrupt Descriptor Table for hooks — detects kernel-level backdoors",
    "linux.malware.netfilter.Netfilter":            "Checks netfilter hooks for unexpected entries — detects network-level rootkits",
    "linux.malware.modxview.Modxview":              "Cross-references three module sources to find hidden LKMs",
    "linux.malware.tty_check.Tty_Check":            "Checks TTY line discipline structs for hooks — detects keylogger rootkits",
    "banners.Banners":                              "Scans memory for Linux kernel version strings — primary OS detection method for Linux",
    "timeliner.Timeliner":                          "Runs all time-aware plugins and merges output into a single chronological timeline",
}

_VALID_GOALS = frozenset({"malware_detection", "incident_response", "rootkit_hunt", "network_forensics"})


def get_all_plugins_flat() -> list:
    result = []
    for collection in (WINDOWS_PLUGINS, LINUX_PLUGINS, MAC_PLUGINS, GENERIC_PLUGINS):
        for plugins in collection.values():
            result.extend(plugins)
    return result


def register_plugin_resources(mcp: FastMCP):

    @mcp.resource(
        "plugins://catalog",
        name="Full Plugin Catalog",
        description="""
Complete reference catalog of all Volatility3 plugins organized by OS and category.

## PURPOSE
Single authoritative source for plugin names before calling run_plugin or batch_plugins.
Always verify plugin names against this catalog — using an incorrect name causes immediate failure.

## STRUCTURE
{
  "windows":     { "process": [...], "malware": [...], "registry": [...], ... },
  "linux":       { "process": [...], "malware": [...], "network":  [...], ... },
  "mac":         { "process": [...], "malware": [...], "network":  [...], ... },
  "generic":     { "banners": [...], "timeliner": [...], "yara": [...], ... },
  "total_count": int,
  "unavailable": [...],  // plugins that exist in docs but are NOT loadable — DO NOT USE
  "deprecated":  {...}   // old_name → new_name mapping — always use new names
}

## CRITICAL RULES
1. NEVER use plugins from "unavailable" list — they will fail with ImportError
2. NEVER use keys from "deprecated" — always use the replacement name
3. windows.netscan and windows.netstat are UNAVAILABLE — use windows.handles.Handles instead
4. All malware detection plugins moved to windows.malware.* and linux.malware.* namespaces

## RECOMMENDED READING ORDER
For Windows analysis: read plugins://windows/malware, plugins://windows/process, plugins://windows/registry
For Linux analysis:   read plugins://linux/malware, plugins://linux/process, plugins://linux/network
For quick start:      read profiles://{goal}/{os_type} — returns pre-selected plugin list

## NEXT STEP
→ plugins://windows or plugins://linux for OS-specific flat list
→ plugins://{plugin_name}/info for description of a specific plugin
→ profiles://malware_detection/windows for a ready-to-use plugin list
""",
    )
    async def get_plugin_catalog() -> dict:
        return {
            "windows":     WINDOWS_PLUGINS,
            "linux":       LINUX_PLUGINS,
            "mac":         MAC_PLUGINS,
            "generic":     GENERIC_PLUGINS,
            "total_count": len(get_all_plugins_flat()),
            "unavailable": UNAVAILABLE_PLUGINS,
            "deprecated":  DEPRECATED_PLUGINS,
        }

    @mcp.resource(
        "plugins://windows",
        name="Windows Plugins",
        description="""
All available Volatility3 plugins for Windows memory dumps, organized by category.

## CATEGORIES
process      → pslist, pstree, psscan, cmdline, envars, getsids, privileges
memory       → memmap, vadinfo, vadwalk, virtmap
malware      → malfind, hollowprocesses, ldrmodules, drivermodule, processghosting,
               pebmasquerade, direct_system_calls, indirect_system_calls, svcdiff
dlls_modules → dlllist, modules, modscan, unloadedmodules
handles      → handles, mutantscan, symlinkscan
filesystem   → filescan, dumpfiles, mftscan, mftscan.ADS
registry     → hivelist, printkey, userassist, amcache, scheduled_tasks, certificates
services     → svcscan, svclist, getservicesids
kernel       → ssdt, callbacks, driverscan, driverirp, devicetree, timers, kpcrs
gui          → windows, windowstations, desktops
misc         → info, statistics, strings, pedump, mbrscan
yara         → vadyarascan, vadregexscan

## UNAVAILABLE (do not call these)
windows.netscan, windows.netstat, windows.hashdump, windows.lsadump, windows.cachedump
→ full list in "unavailable" key

## RESPONSE SCHEMA
{
  "os": "windows",
  "categories": { "malware": [...], "process": [...], ... },
  "all_plugins": ["windows.pslist.PsList", ...],  // flat list, 60+ plugins
  "total": 63,
  "unavailable": ["windows.netscan", ...]
}

## NEXT STEP
→ plugins://windows/{category} for plugins in a specific category with descriptions
→ profiles://malware_detection/windows for a curated subset for malware hunting
""",
    )
    async def get_windows_plugins() -> dict:
        all_windows = [p for cat in WINDOWS_PLUGINS.values() for p in cat]
        return {
            "os":          "windows",
            "categories":  WINDOWS_PLUGINS,
            "all_plugins": all_windows,
            "total":       len(all_windows),
            "unavailable": [p for p in UNAVAILABLE_PLUGINS if p.startswith("windows.")],
        }

    @mcp.resource(
        "plugins://windows/{category}",
        name="Windows Plugins by Category",
        description="""
List of Windows plugins for a specific category with descriptions.

## PARAMETER
category : str
  One of: process | memory | malware | dlls_modules | handles |
          filesystem | registry | services | kernel | gui | misc | yara

## RESPONSE SCHEMA
{
  "os": "windows",
  "category": "malware",
  "plugins": ["windows.malware.malfind.Malfind", ...],
  "descriptions": {
    "windows.malware.malfind.Malfind": "Finds RWX memory regions with executable code..."
  }
}

## ERROR RESPONSE
{"error": "Unknown category 'xyz'", "available": ["process", "malware", ...]}

## RECOMMENDED CATEGORIES FOR MALWARE ANALYSIS
malware   → primary injection/evasion detection (malfind, hollowprocesses, ldrmodules)
process   → behavioral indicators (cmdline, psscan for hidden processes)
registry  → persistence mechanisms (Run keys, scheduled tasks)
kernel    → rootkit detection (ssdt, callbacks, driverscan)
""",
    )
    async def get_windows_category_plugins(category: str) -> dict:
        if category not in WINDOWS_PLUGINS:
            return {"error": f"Unknown category '{category}'", "available": list(WINDOWS_PLUGINS.keys())}
        plugins = WINDOWS_PLUGINS[category]
        return {
            "os":           "windows",
            "category":     category,
            "plugins":      plugins,
            "descriptions": {p: PLUGIN_DESCRIPTIONS.get(p, "") for p in plugins},
        }

    @mcp.resource(
        "plugins://linux",
        name="Linux Plugins",
        description="""
All available Volatility3 plugins for Linux memory dumps, organized by category.

## IMPORTANT — SYMBOLS REQUIRED
All linux.* plugins require kernel ISF symbol files matching the exact kernel version.
Run get_symbols_status before batch_plugins to verify symbols are present.

## CATEGORIES
process   → pslist, pstree, psscan, psaux, envars, capabilities, ptrace
memory    → proc.Maps, elfs, library_list
malware   → malfind, check_syscall, check_modules, hidden_modules, check_afinfo,
            check_creds, check_idt, keyboard_notifiers, modxview, netfilter,
            process_spoofing, tty_check
modules   → lsmod, module_extract
network   → sockstat, sockscan, ip.Addr, ip.Link
filesystem→ lsof, mountinfo, pagecache.Files
kernel    → kthreads, kallsyms, kmsg, ebpf
tracing   → ftrace.CheckFtrace, perf_events.PerfEvents, tracepoints.CheckTracepoints
artifacts → bash
yara      → vmayarascan, vmaregexscan

## RESPONSE SCHEMA
{
  "os": "linux",
  "categories": { "malware": [...], "process": [...], ... },
  "all_plugins": ["linux.pslist.PsList", ...],
  "total": 45
}
""",
    )
    async def get_linux_plugins() -> dict:
        all_linux = [p for cat in LINUX_PLUGINS.values() for p in cat]
        return {
            "os":          "linux",
            "categories":  LINUX_PLUGINS,
            "all_plugins": all_linux,
            "total":       len(all_linux),
        }

    @mcp.resource(
        "plugins://linux/{category}",
        name="Linux Plugins by Category",
        description="""
List of Linux plugins for a specific category with descriptions.

## PARAMETER
category : str
  One of: process | memory | malware | modules | network |
          filesystem | kernel | tracing | artifacts | graphics | yara

## RESPONSE SCHEMA
{
  "os": "linux",
  "category": "malware",
  "plugins": ["linux.malware.malfind.Malfind", ...],
  "descriptions": { "linux.malware.malfind.Malfind": "..." }
}

## RECOMMENDED CATEGORIES FOR LINUX MALWARE ANALYSIS
malware  → rootkit + injection detection (hidden_modules, check_syscall, malfind)
process  → behavioral indicators (psscan vs pslist for DKOM detection)
network  → C2 connections (sockstat, sockscan)
modules  → LKM rootkit (lsmod — cross-check with hidden_modules)
""",
    )
    async def get_linux_category_plugins(category: str) -> dict:
        if category not in LINUX_PLUGINS:
            return {"error": f"Unknown category '{category}'", "available": list(LINUX_PLUGINS.keys())}
        plugins = LINUX_PLUGINS[category]
        return {
            "os":           "linux",
            "category":     category,
            "plugins":      plugins,
            "descriptions": {p: PLUGIN_DESCRIPTIONS.get(p, "") for p in plugins},
        }

    @mcp.resource(
        "plugins://mac",
        name="Mac Plugins",
        description="""
All available Volatility3 plugins for macOS memory dumps.

## NOTE
macOS analysis support is limited — symbol availability varies significantly
by macOS version. Verify symbols before running mac.* plugins.

## CATEGORIES
process    → pslist, pstree, psaux
malware    → malfind, check_syscall, check_sysctl, check_trap_table, trustedbsd, timers
modules    → lsmod
network    → netstat, ifconfig, socket_filters
filesystem → lsof, list_files, mount, vfsevents
kernel     → dmesg, kauth_listeners, kauth_scopes, kevents
artifacts  → bash
memory     → proc_maps.Maps
""",
    )
    async def get_mac_plugins() -> dict:
        all_mac = [p for cat in MAC_PLUGINS.values() for p in cat]
        return {"os": "mac", "categories": MAC_PLUGINS, "all_plugins": all_mac, "total": len(all_mac)}

    @mcp.resource(
        "plugins://generic",
        name="Generic Plugins",
        description="""
OS-independent Volatility3 plugins that work on any memory dump.

## PLUGINS
banners.Banners          → Scans for Linux kernel version strings — used by detect_os for Linux identification
timeliner.Timeliner      → Merges output of all time-aware plugins into a single timeline
yarascan.YaraScan        → Scans all process memory with a YARA rule
regexscan.RegExScan      → Scans all process memory with a regex pattern
frameworkinfo.FrameworkInfo → Shows Volatility3 framework version and loaded plugins
isfinfo.IsfInfo          → Lists available ISF symbol files
vmscan.Vmscan            → Detects VMware/VirtualBox artifacts in memory

## MOST USEFUL FOR THIS PIPELINE
banners.Banners    → Used internally by detect_os for Linux OS detection
timeliner.Timeliner → Add to incident_response plugin list for full timeline
""",
    )
    async def get_generic_plugins() -> dict:
        all_generic = [p for cat in GENERIC_PLUGINS.values() for p in cat]
        return {"categories": GENERIC_PLUGINS, "all_plugins": all_generic, "total": len(all_generic)}

    @mcp.resource(
        "plugins://unavailable",
        name="Unavailable Plugins",
        description="""
Plugins documented in Volatility3 source but NOT loadable in this installation.

## CRITICAL
Do NOT call these plugins — they will return ImportError or PluginRequirementsError immediately.
The run_plugin and batch_plugins tools will reject these names via validate_plugin_name.

## MOST IMPORTANT UNAVAILABLE PLUGINS
windows.netscan   → REMOVED in Vol3 2.5+ — use windows.handles.Handles for network artifacts
windows.netstat   → REMOVED in Vol3 2.5+ — same replacement
windows.hashdump  → Not loadable — use windows.registry.hivelist + offline extraction
windows.lsadump   → Not loadable
windows.cachedump → Not loadable

## RESPONSE SCHEMA
{
  "plugins": ["windows.netscan", "windows.netstat", ...],
  "total": 26,
  "note": "..."
}
""",
    )
    async def get_unavailable_plugins() -> dict:
        return {
            "plugins": UNAVAILABLE_PLUGINS,
            "total":   len(UNAVAILABLE_PLUGINS),
            "note":    "These plugins cannot be loaded. Do not pass them to run_plugin or batch_plugins.",
        }

    @mcp.resource(
        "plugins://deprecated",
        name="Deprecated Plugin Names",
        description="""
Mapping of deprecated plugin names to their current replacements.

## PURPOSE
Volatility3 reorganized malware and registry plugins in v2.4+.
Old names like "windows.malfind.Malfind" will be REJECTED by validate_plugin_name.
This resource shows the canonical replacement name for any deprecated name.

## KEY RENAMES (most commonly confused)
windows.malfind.Malfind          → windows.malware.malfind.Malfind
windows.ldrmodules.LdrModules    → windows.malware.ldrmodules.LdrModules
windows.amcache.Amcache          → windows.registry.amcache.Amcache
linux.malfind.Malfind            → linux.malware.malfind.Malfind
linux.check_syscall.Check_syscall→ linux.malware.check_syscall.Check_syscall
linux.hidden_modules.Hidden_modules → linux.malware.hidden_modules.Hidden_modules

## RESPONSE SCHEMA
{
  "mappings": {
    "windows.malfind.Malfind": "windows.malware.malfind.Malfind",
    ...
  },
  "total": 21,
  "note": "Use replacement plugin names — deprecated names will be rejected"
}
""",
    )
    async def get_deprecated_plugins() -> dict:
        return {
            "mappings": DEPRECATED_PLUGINS,
            "total":    len(DEPRECATED_PLUGINS),
            "note":     "Use replacement plugin names — deprecated names will be rejected by validate_plugin_name",
        }

    @mcp.resource(
        "plugins://{plugin_name}/info",
        name="Plugin Info",
        description="""
Lookup status and description for a specific plugin by name.

## PARAMETER
plugin_name : str
  Full or partial plugin name. Examples:
  "windows.malware.malfind.Malfind"
  "malfind"  (partial — matches first result)
  "windows.netscan"  (returns unavailable status)

## RESPONSE SCHEMA — available
{
  "name":        "windows.malware.malfind.Malfind",
  "status":      "available",
  "description": "Finds RWX memory regions with executable code..."
}

## RESPONSE SCHEMA — deprecated
{
  "name":        "windows.malfind.Malfind",
  "status":      "deprecated",
  "replacement": "windows.malware.malfind.Malfind",
  "description": "Deprecated plugin"
}

## RESPONSE SCHEMA — unavailable
{
  "name":   "windows.netscan",
  "status": "unavailable",
  "description": "Plugin not loadable"
}

## RESPONSE SCHEMA — unknown
{
  "name":   "windows.xyz",
  "status": "unknown",
  "description": "Plugin not found in catalog"
}
""",
    )
    async def get_plugin_info(plugin_name: str) -> dict:
        normalized = plugin_name.replace("-", ".").replace("_", ".", 1)
        if normalized in DEPRECATED_PLUGINS:
            return {
                "name":        plugin_name,
                "status":      "deprecated",
                "replacement": DEPRECATED_PLUGINS[normalized],
                "description": PLUGIN_DESCRIPTIONS.get(normalized, "Deprecated plugin"),
            }
        if any(normalized in p for p in UNAVAILABLE_PLUGINS):
            return {"name": plugin_name, "status": "unavailable", "description": "Plugin not loadable"}
        all_plugins = get_all_plugins_flat()
        matched = next(
            (p for p in all_plugins if normalized.lower() in p.lower() or p.lower().endswith(normalized.lower())),
            None,
        )
        if matched:
            return {
                "name":        matched,
                "status":      "available",
                "description": PLUGIN_DESCRIPTIONS.get(matched, "No description available"),
            }
        return {"name": plugin_name, "status": "unknown", "description": "Plugin not found in catalog"}

    @mcp.resource(
        "profiles://list",
        name="Analysis Profiles",
        description="""
Lists all available analysis goals (profiles) and supported OS types.

## PURPOSE
Quick reference for valid goal names before calling smart_triage or automated_pipeline.
Each goal maps to a pre-configured, ordered plugin list in the decision engine.

## GOALS
┌──────────────────────┬──────────────────────────────────────────────────┬────────────┐
│ goal                 │ focus                                            │ est. time  │
├──────────────────────┼──────────────────────────────────────────────────┼────────────┤
│ malware_detection    │ process injection, code hiding, C2 connections   │ 10-15 min  │
│ incident_response    │ full IR — persistence, registry, services, files │ 20-25 min  │
│ rootkit_hunt         │ DKOM, SSDT hooks, hidden modules, callbacks      │ 15-20 min  │
│ network_forensics    │ network handles, C2 investigation                │ 8-12 min   │
└──────────────────────┴──────────────────────────────────────────────────┴────────────┘

## RESPONSE SCHEMA
{
  "goals": [
    {"name": "malware_detection", "description": "..."},
    ...
  ],
  "os_types": ["windows", "linux"],
  "note": "Use profiles://{goal}/{os_type} to get plugin list for a specific combination"
}

## NEXT STEP
→ profiles://malware_detection/windows to get the exact plugin list
→ smart_triage(dump_path, os_type, goal) to create a case with the chosen profile
""",
    )
    async def list_profiles() -> dict:
        return {
            "goals": [
                {
                    "name": "malware_detection",
                    "description": "Full malware indicator extraction — process injection, code hiding, C2 artifacts",
                },
                {
                    "name": "incident_response",
                    "description": "Complete IR artifact collection — persistence, registry, services, filesystem",
                },
                {
                    "name": "rootkit_hunt",
                    "description": "Kernel-level threat detection — SSDT hooks, hidden modules, driver anomalies",
                },
                {
                    "name": "network_forensics",
                    "description": "Network connection and C2 investigation — handles, process-to-socket mapping",
                },
            ],
            "os_types": ["windows", "linux"],
            "note": "Use profiles://{goal}/{os_type} to get plugin list for a specific combination",
        }

    @mcp.resource(
        "profiles://{goal}/{os_type}",
        name="Analysis Profile Detail",
        description="""
Get the exact ordered plugin list for a specific goal + OS combination.

## PARAMETERS
goal    : malware_detection | incident_response | rootkit_hunt | network_forensics
os_type : windows | linux

## PURPOSE
Returns the same plugin list that smart_triage would select internally.
Use this to preview or customize the plugin list before calling batch_plugins directly.

## RESPONSE SCHEMA
{
  "goal":               "malware_detection",
  "os_type":            "windows",
  "plugins":            ["windows.pslist.PsList", "windows.malware.malfind.Malfind", ...],
  "estimated_minutes":  15,
  "description":        "Full malware indicator extraction..."
}

## ERROR RESPONSE
{"error": "Invalid goal 'xyz'", "valid_goals": [...]}
{"error": "Invalid os_type 'mac'", "valid_os_types": ["windows", "linux"]}

## NEXT STEP
→ batch_plugins(dump_path, [{"name": p, "args": {}} for p in result["plugins"]])
→ Or smart_triage(dump_path, os_type, goal) to create a tracked case automatically
""",
    )
    async def get_analysis_profile(goal: str, os_type: str) -> dict:
        if goal not in _VALID_GOALS:
            return {"error": f"Invalid goal '{goal}'", "valid_goals": sorted(_VALID_GOALS)}
        if os_type not in ("windows", "linux"):
            return {"error": f"Invalid os_type '{os_type}'", "valid_os_types": ["windows", "linux"]}
        try:
            plan = get_triage_plan(os_type, goal)
            return {
                "goal":               goal,
                "os_type":            os_type,
                "plugins":            [p["name"] for p in plan.plugins],
                "estimated_minutes":  plan.estimated_minutes,
                "description":        plan.description,
            }
        except ValueError as e:
            return {"error": str(e)}

from fastmcp import FastMCP


# Mapping of deprecated plugin names to current names
DEPRECATED_PLUGINS = {
    # Add deprecated plugin mappings here as needed
    # Format: "old_name": "new_name"
}

# Mac plugins (reserved for future use)
MAC_PLUGINS = {
    "network": [],
    "host": [],
}

# Generic plugins (reserved for future use)
GENERIC_PLUGINS = {
    "network": [],
    "host": [],
}


WINDOWS_PLUGINS = {
    "network": [
        {"name": "windows.netscan.NetScan",  "priority": 1, "ioc_types": ["ipv4", "domain", "c2_socket"]},
        {"name": "windows.netstat.NetStat",  "priority": 2, "ioc_types": ["ipv4", "c2_socket"]},
        {"name": "windows.handles.Handles",  "priority": 2, "ioc_types": ["ipv4", "domain"]},
    ],
    "host": [
        {"name": "windows.pslist.PsList",                          "priority": 1, "ioc_types": ["process"]},
        {"name": "windows.psscan.PsScan",                          "priority": 1, "ioc_types": ["process"]},
        {"name": "windows.cmdline.CmdLine",                        "priority": 1, "ioc_types": ["command", "domain", "ipv4"]},
        {"name": "windows.malware.malfind.Malfind",                "priority": 1, "ioc_types": ["injection"]},
        {"name": "windows.malware.hollowprocesses.HollowProcesses","priority": 2, "ioc_types": ["injection"]},
        {"name": "windows.malware.ldrmodules.LdrModules",          "priority": 2, "ioc_types": ["injection", "filepath"]},
        {"name": "windows.dlllist.DllList",                        "priority": 2, "ioc_types": ["filepath", "md5"]},
        {"name": "windows.filescan.FileScan",                      "priority": 2, "ioc_types": ["filepath", "md5"]},
        {"name": "windows.registry.hivelist.HiveList",             "priority": 3, "ioc_types": ["registry_config"]},
        {"name": "windows.registry.printkey.PrintKey",             "priority": 3, "ioc_types": ["registry_persistence"],
         "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"}},
        {"name": "windows.registry.printkey.PrintKey",             "priority": 3, "ioc_types": ["registry_persistence"],
         "args": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}},
        {"name": "windows.registry.printkey.PrintKey",             "priority": 3, "ioc_types": ["registry_persistence"],
         "args": {"key": "System\\CurrentControlSet\\Services"}},
        {"name": "windows.registry.userassist.UserAssist",         "priority": 3, "ioc_types": ["filepath", "command"]},
        {"name": "windows.registry.amcache.Amcache",               "priority": 3, "ioc_types": ["md5", "sha1", "filepath"]},
        {"name": "windows.svcscan.SvcScan",                         "priority": 2, "ioc_types": ["process", "filepath"]},
    ],
}

LINUX_PLUGINS = {
    "network": [
        {"name": "linux.sockstat.Sockstat", "priority": 1, "ioc_types": ["ipv4", "c2_socket"]},
        {"name": "linux.lsof.Lsof",         "priority": 2, "ioc_types": ["ipv4", "filepath"]},
    ],
    "host": [
        {"name": "linux.pslist.PsList",                            "priority": 1, "ioc_types": ["process"]},
        {"name": "linux.pstree.PsTree",                            "priority": 1, "ioc_types": ["process"]},
        {"name": "linux.bash.Bash",                                "priority": 1, "ioc_types": ["command", "domain"]},
        {"name": "linux.malware.malfind.Malfind",                  "priority": 1, "ioc_types": ["injection"]},
        {"name": "linux.malware.check_syscall.Check_syscall",      "priority": 2, "ioc_types": ["injection"]},
        {"name": "linux.malware.check_modules.Check_modules",      "priority": 2, "ioc_types": ["injection"]},
    ],
}


def register_plugin_resources(mcp: FastMCP):

    @mcp.resource(
        "plugins://windows",
        name="Windows Plugin Preset",
        description=(
            "Fixed plugin list used by run_plugins for Windows memory dumps. "
            "Network plugins extract IP/domain/C2 IOCs. "
            "Host plugins extract injection/hash/filepath/registry IOCs. "
            "Do NOT call these plugins manually — use run_plugins(os_type='windows') instead."
        ),
    )
    async def windows_plugins() -> dict:
        return {
            "os_type": "windows",
            "total_plugins": len(WINDOWS_PLUGINS["network"]) + len(WINDOWS_PLUGINS["host"]),
            "network": WINDOWS_PLUGINS["network"],
            "host": WINDOWS_PLUGINS["host"],
        }

    @mcp.resource(
        "plugins://linux",
        name="Linux Plugin Preset",
        description=(
            "Fixed plugin list used by run_plugins for Linux memory dumps. "
            "Network plugins extract IP/socket IOCs. "
            "Host plugins extract injection/command/process IOCs. "
            "Do NOT call these plugins manually — use run_plugins(os_type='linux') instead."
        ),
    )
    async def linux_plugins() -> dict:
        return {
            "os_type": "linux",
            "total_plugins": len(LINUX_PLUGINS["network"]) + len(LINUX_PLUGINS["host"]),
            "network": LINUX_PLUGINS["network"],
            "host": LINUX_PLUGINS["host"],
        }

    @mcp.resource(
        "plugins://ioc_types",
        name="IOC Type Reference",
        description=(
            "Maps each IOC type to its source plugin and MITRE technique. "
            "Use this to understand what ioc_extract will return."
        ),
    )
    async def ioc_types() -> dict:
        return {
            "network_ioc_types": {
                "ipv4":       {"source": ["netscan", "netstat", "handles", "sockstat"], "technique": "T1071"},
                "domain":     {"source": ["cmdline", "handles", "bash"],                "technique": "T1071.001"},
                "c2_socket":  {"source": ["netscan", "sockstat"],                       "technique": "T1571"},
            },
            "host_ioc_types": {
                "injection":            {"source": ["malfind"],                              "technique": "T1055"},
                "hollow_process":       {"source": ["hollowprocesses"],                     "technique": "T1055.012"},
                "hidden_dll":           {"source": ["ldrmodules"],                          "technique": "T1055.001"},
                "md5":                  {"source": ["amcache", "filescan", "dlllist"],       "technique": "T1204"},
                "filepath":             {"source": ["filescan", "handles", "ldrmodules"],    "technique": "T1036"},
                "command":              {"source": ["cmdline", "bash"],                      "technique": "T1059"},
                "registry_persistence": {"source": ["registry.printkey"],                   "technique": "T1547.001"},
                "registry_config":      {"source": ["registry.hivelist"],                   "technique": "T1112"},
            },
        }

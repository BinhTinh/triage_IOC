import re
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from src.models.ioc import IOC, IOCType
from src.core.registry_analyzer import RegistryAnalyzer

IOC_PATTERNS: Dict[str, Dict[str, Any]] = {
    IOCType.IPV4: {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "source_gate": {"netscan", "netstat", "sockstat", "sockscan", "lsof", "cmdline", "bash"},
        "exclude": [
            r"^0\.0\.0\.0$",
            r"^127\.",
            r"^10\.",
            r"^172\.(1[6-9]|2[0-9]|3[01])\.",
            r"^192\.168\.",
            r"^255\.",
        ],
    },
    IOCType.DOMAIN: {
        "pattern": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
        "source_gate": {"netscan", "netstat", "sockstat", "sockscan", "lsof", "cmdline", "bash"},
        "exclude": [
            r"\.microsoft\.com$",
            r"\.windows\.com$",
            r"\.google\.com$",
            r"\.googleapis\.com$",
            r"\.exe$", r"\.dll$", r"\.sys$", r"\.scr$",
            r"\.vbs$", r"\.bat$", r"\.cmd$",
            r"^[A-Za-z]:\\",
            r"\\Device\\",
            r"\\SystemRoot\\",
        ],
    },
    IOCType.MD5: {
        "pattern": r"\b[a-fA-F0-9]{32}\b",
        "exclude": [],
        "source_gate": {"amcache", "filescan", "dumpfiles", "ldrmodules", "shimcachemem"},
    },
    IOCType.SHA1: {
        "pattern": r"\b[a-fA-F0-9]{40}\b",
        "exclude": [],
        "source_gate": {"amcache", "filescan", "dumpfiles", "ldrmodules", "shimcachemem"},
    },
    IOCType.SHA256: {
        "pattern": r"\b[a-fA-F0-9]{64}\b",
        "exclude": [],
        "source_gate": {"amcache", "filescan", "dumpfiles", "ldrmodules", "shimcachemem"},
    },

    IOCType.FILEPATH: {
        "pattern": r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*",
        "exclude": [
            r"^[A-Za-z]:\\$",
            r"^C:\\Windows\\System32\\",
            r"^C:\\Windows\\SysWOW64\\",
            r"^C:\\Program Files\\",
            r"^C:\\Program Files \(x86\)\\",
        ],
    },
    IOCType.REGISTRY_CONFIG: {
        "pattern": r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s]+",
        "exclude": [],
    },
}

SUSPICIOUS_PATTERNS: Dict[str, Dict[str, Any]] = {
    "windows": {
        "process_relationships": [
            {"parent": "winword.exe",   "child": "cmd.exe",        "technique": "T1059"},
            {"parent": "winword.exe",   "child": "powershell.exe", "technique": "T1059.001"},
            {"parent": "excel.exe",     "child": "cmd.exe",        "technique": "T1059"},
            {"parent": "excel.exe",     "child": "powershell.exe", "technique": "T1059.001"},
            {"parent": "outlook.exe",   "child": "cmd.exe",        "technique": "T1059"},
            {"parent": "services.exe",  "child": "cmd.exe",        "technique": "T1543.003"},
            {"parent": "wmiprvse.exe",  "child": "powershell.exe", "technique": "T1047"},
            {"parent": "mshta.exe",     "child": "powershell.exe", "technique": "T1059.001"},
            {"parent": "wscript.exe",   "child": "cmd.exe",        "technique": "T1059"},
            {"parent": "cscript.exe",   "child": "powershell.exe", "technique": "T1059.001"},
        ],
        "suspicious_commands": [
            {"pattern": r"-enc\s+[A-Za-z0-9+/=]{20,}",               "technique": "T1059.001", "name": "encoded_powershell"},
            {"pattern": r"-nop\s+-w\s+hidden",                         "technique": "T1059.001", "name": "hidden_powershell"},
            {"pattern": r"(?i)IEX\s*\(",                               "technique": "T1059.001", "name": "iex_invoke"},
            {"pattern": r"(?i)Invoke-Expression",                      "technique": "T1059.001", "name": "invoke_expression"},
            {"pattern": r"certutil.*-urlcache",                        "technique": "T1105",     "name": "certutil_download"},
            {"pattern": r"bitsadmin.*\/transfer",                      "technique": "T1105",     "name": "bitsadmin_download"},
            {"pattern": r"regsvr32.*\/s.*\/n.*\/u.*\/i:",              "technique": "T1218.010", "name": "regsvr32_bypass"},
            {"pattern": r"(?i)schtasks.*\/create",                     "technique": "T1053.005", "name": "schtasks_create"},
            {"pattern": r"(?i)wmic.*process.*call.*create",            "technique": "T1047",     "name": "wmic_process_create"},
            {"pattern": r"(?i)net\s+(user|localgroup).*\/add",         "technique": "T1136.001", "name": "net_user_add"},
            {"pattern": r"(?i)reg\s+(add|delete)\s+HKLM",             "technique": "T1112",     "name": "reg_modify_hklm"},
            {"pattern": r"(?i)mshta\s+https?://",                      "technique": "T1218.005", "name": "mshta_remote"},
        ],
    },
    "linux": {
        "process_relationships": [
            {"parent": "nginx",    "child": "bash",  "technique": "T1505.003"},
            {"parent": "nginx",    "child": "sh",    "technique": "T1505.003"},
            {"parent": "apache2",  "child": "bash",  "technique": "T1505.003"},
            {"parent": "httpd",    "child": "bash",  "technique": "T1505.003"},
            {"parent": "php-fpm",  "child": "bash",  "technique": "T1505.003"},
            {"parent": "mysqld",   "child": "bash",  "technique": "T1505.003"},
        ],
        "suspicious_commands": [
            {"pattern": r"\/dev\/tcp\/\d+\.\d+\.\d+\.\d+\/\d+",  "technique": "T1059.004", "name": "bash_reverse_shell"},
            {"pattern": r"nc\s+-e\s+\/bin\/(ba)?sh",              "technique": "T1059.004", "name": "netcat_shell"},
            {"pattern": r"curl.*\|\s*(ba)?sh",                    "technique": "T1059.004", "name": "curl_pipe_shell"},
            {"pattern": r"wget.*-O\s*-.*\|\s*(ba)?sh",            "technique": "T1059.004", "name": "wget_pipe_shell"},
            {"pattern": r"python[23]?\s+-c\s+['\"]import socket", "technique": "T1059.006", "name": "python_socket"},
            {"pattern": r"chmod\s+[+\d]*x\s+\/tmp\/",            "technique": "T1222.002", "name": "chmod_tmp"},
            {"pattern": r"crontab\s+-[el]",                       "technique": "T1053.003", "name": "crontab_modify"},
        ],
    },
}

WINDOWS_NETWORK_WHITELIST: frozenset = frozenset({
    "svchost.exe", "lsass.exe", "services.exe", "system",
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "outlook.exe", "teams.exe", "onedrive.exe",
    "wuauclt.exe", "wusa.exe", "msiexec.exe",
})

LINUX_NETWORK_WHITELIST: frozenset = frozenset({
    "sshd", "systemd", "networkmanager", "dhclient", "dhcpcd",
    "chronyd", "ntpd", "resolved", "avahi-daemon", "cups",
    "nginx", "apache2", "httpd", "lighttpd",
    "python3", "python", "node", "ruby", "java",
    "curl", "wget", "apt", "apt-get", "dpkg",
    "chrome", "firefox", "chromium",
})

COMMON_LEGITIMATE_PORTS: frozenset = frozenset({
    80, 443, 53, 22, 21, 25, 587, 993, 995, 8080, 8443,
})

RARE_PORTS: frozenset = frozenset({
    4444, 5555, 6666, 1337, 31337,
    9001, 9030,
    6667, 6697,
})

SYSTEM_DOMAIN_WHITELIST: frozenset = frozenset({
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com",
    "office.com", "office365.com", "microsoftonline.com", "azure.com",
    "google.com", "googleapis.com", "gstatic.com", "gvt1.com",
    "digicert.com", "verisign.com", "symantec.com", "thawte.com",
    "comodo.com", "sectigo.com", "letsencrypt.org",
    "cloudfront.net", "amazonaws.com", "awsstatic.com",
    "akamaied.net", "akamaihd.net", "edgesuite.net",
    "windowsazure.com", "visualstudio.com", "github.com",
    "apple.com", "icloud.com", "adobe.com",
    "nvidia.com", "intel.com", "amd.com",
    "vmware.com", "virtualbox.org",
})

VALID_TLDS: frozenset = frozenset({
    "com", "net", "org", "io", "gov", "edu",
    "ru", "cn", "tk", "top", "xyz", "info",
    "biz", "cc", "pw", "su", "to", "onion",
    "co", "uk", "de", "fr", "jp", "br",
})

REGEX_SCAN_PLUGINS: frozenset = frozenset({
    "cmdline", "bash", "malfind", "hollowprocesses",
    "dlllist", "handles", "filescan", "amcache",
    "svcscan", "sockscan", "sockstat", "lsof",
    "userassist", "printkey", "ldrmodules",
    "netscan", "netstat",
    # Additional plugins that produce text-scannable output
    "check_syscall", "check_modules", "hidden_modules",
})

_KNOWN_PROCESS_NAMES: frozenset = frozenset({
    "smss.exe", "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "explorer.exe", "dwm.exe", "spoolsv.exe", "msmpeng.exe",
    "nissrv.exe", "ctfmon.exe", "taskhostw.exe", "sihost.exe", "searchhost.exe",
    "wudfhost.exe", "dllhost.exe", "msdtc.exe", "wmiprvse.exe", "fontdrvhost.exe",
    "userinit.exe", "wininit.exe", "vm3dservice.exe", "vmtoolsd.exe", "onedrive.exe",
    "widgets.exe",
})

_SUSPICIOUS_FILE_PATHS = re.compile(
    r"(?i)(\\Temp\\|\\AppData\\Local\\Temp\\|\\AppData\\Roaming\\|"
    r"\\Users\\Public\\|\\ProgramData\\|\\Windows\\Temp\\)",
)

_CATEGORY_TO_IOC_TYPE: Dict[str, str] = {
    "persistence":       IOCType.REGISTRY_PERSISTENCE,
    "defense_evasion":   IOCType.REGISTRY_DEFENSE_EVASION,
    "credential_access": IOCType.REGISTRY_CREDENTIAL_ACCESS,
    "execution":         IOCType.REGISTRY_EXECUTION,
}


def _get(entry: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    for k in keys:
        v = entry.get(k)
        if v is not None:
            return v
    return default


def _is_private_ip(ip: str) -> bool:
    """Return True for IPs that should never be flagged as external C2."""
    # IPv4 private / reserved ranges
    if ip.startswith(("0.", "127.", "10.", "169.254.",
                      "192.168.",
                      "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.",
                      "172.24.", "172.25.", "172.26.", "172.27.",
                      "172.28.", "172.29.", "172.30.", "172.31.",
                      "255.")):
        return True
    # IPv6 loopback, link-local, and IPv4-mapped IPv6
    ip_lower = ip.lower()
    if ip_lower in ("::", "::1"):
        return True
    if ip_lower.startswith(("fe80:", "fc", "fd",   # link-local / ULA
                             "::ffff:",              # IPv4-mapped
                             "2001:db8:",            # documentation
                             "ff")):
        return True
    return False


class IOCExtractor:
    def __init__(self) -> None:
        self.seen: Set[str] = set()

    def _is_valid_domain(self, value: str) -> bool:
        value_lower = value.lower()
        if len(value) < 6:
            return False
        parts = value_lower.split(".")
        if len(parts) < 2 or parts[-1] not in VALID_TLDS:
            return False
        for wl in SYSTEM_DOMAIN_WHITELIST:
            if value_lower == wl or value_lower.endswith("." + wl):
                return False
        if any(len(p) > 50 for p in parts):
            return False
        return True

    def _should_exclude(self, value: str, exclude_patterns: List[str]) -> bool:
        return any(re.match(p, value, re.IGNORECASE) for p in exclude_patterns)

    def _confidence_for_type(self, ioc_type: str, source: str) -> float:
        source_lower = source.lower()
        if ioc_type == IOCType.DOMAIN:
            if any(k in source_lower for k in ("cmdline", "malfind", "handles", "sockstat", "sockscan")):
                return 0.75
            return 0.30
        if ioc_type in (IOCType.MD5, IOCType.SHA256):
            return 0.80
        if ioc_type == IOCType.FILEPATH:
            return 0.70 if _SUSPICIOUS_FILE_PATHS.search(source_lower) else 0.40
        if ioc_type == IOCType.IPV4:
            if any(k in source_lower for k in ("netscan", "netstat", "sockstat", "sockscan")):
                return 0.75
            return 0.60
        return 0.50

    def extract_from_text(self, text: str, source: str) -> List[IOC]:
        iocs: List[IOC] = []
        source_lower = source.lower()

        # Default MITRE technique assigned by IOC type when context-aware
        # analyzers haven't tagged one (prevents 'unknown' in reports).
        _DEFAULT_TECHNIQUE: Dict[str, str] = {
            IOCType.MD5:      "T1204",
            IOCType.SHA1:     "T1204",
            IOCType.SHA256:   "T1204",
            IOCType.FILEPATH: "T1036",
            IOCType.DOMAIN:   "T1071.001",
            IOCType.IPV4:     "T1071",
            IOCType.COMMAND:  "T1059",
        }

        for ioc_type, config in IOC_PATTERNS.items():
            source_gate: Optional[Set[str]] = config.get("source_gate")
            if source_gate and not any(g in source_lower for g in source_gate):
                continue

            for match in re.findall(config["pattern"], text):
                if self._should_exclude(match, config.get("exclude", [])):
                    continue
                if ioc_type == IOCType.DOMAIN:
                    if not self._is_valid_domain(match):
                        continue
                    if match.lower() in _KNOWN_PROCESS_NAMES:
                        continue
                if match in self.seen:
                    continue
                self.seen.add(match)

                iocs.append(IOC(
                    ioc_type=ioc_type,
                    value=match,
                    confidence=self._confidence_for_type(ioc_type, source),
                    source_plugin=source,
                    context={
                        "raw_match": True,
                        "from_plugin": source,
                        "technique": _DEFAULT_TECHNIQUE.get(ioc_type, ""),
                    },
                    extracted_at=datetime.now(),
                ))

        return iocs

    def reset(self) -> None:
        self.seen.clear()


class ContextAwareExtractor:
    def __init__(self, os_type: str) -> None:
        self.os_type = os_type
        self.patterns = SUSPICIOUS_PATTERNS.get(os_type, {})
        self._network_whitelist = (
            WINDOWS_NETWORK_WHITELIST if os_type == "windows" else LINUX_NETWORK_WHITELIST
        )

    def analyze_processes(
        self,
        pslist_data: List[Dict[str, Any]],
        pstree_data: List[Dict[str, Any]],
    ) -> List[IOC]:
        iocs: List[IOC] = []
        process_map: Dict[Any, Dict[str, Any]] = {}

        for proc in pslist_data:
            pid = _get(proc, "PID", "pid", "Pid")
            if pid is not None:
                process_map[pid] = proc

        for proc in pslist_data:
            ppid = _get(proc, "PPID", "ppid", "PPid")
            if ppid is None or ppid not in process_map:
                continue
            parent = process_map[ppid]
            parent_name = str(_get(parent, "ImageFileName", "name", "Name")).lower()
            child_name  = str(_get(proc,   "ImageFileName", "name", "Name")).lower()

            for rel in self.patterns.get("process_relationships", []):
                if rel["parent"] in parent_name and rel["child"] in child_name:
                    iocs.append(IOC(
                        ioc_type=IOCType.PROCESS,
                        value=f"{parent_name} -> {child_name}",
                        confidence=0.80,
                        source_plugin="windows.pslist.PsList",
                        context={
                            "parent_pid":   ppid,
                            "child_pid":    _get(proc, "PID", "pid", "Pid"),
                            "technique":    rel["technique"],
                            "relationship": "suspicious_parent_child",
                            "category":     "host",
                        },
                        extracted_at=datetime.now(),
                    ))

        return iocs

    def analyze_cmdlines(self, cmdline_data: List[Dict[str, Any]]) -> List[IOC]:
        iocs: List[IOC] = []
        for entry in cmdline_data:
            cmdline      = str(_get(entry, "Args", "cmdline", "CommandLine"))
            process_name = str(_get(entry, "ImageFileName", "name", "Name"))
            pid          = _get(entry, "PID", "pid", "Pid")

            for cmd_pattern in self.patterns.get("suspicious_commands", []):
                if re.search(cmd_pattern["pattern"], cmdline, re.IGNORECASE):
                    iocs.append(IOC(
                        ioc_type=IOCType.COMMAND,
                        value=cmdline[:500],
                        confidence=0.85,
                        source_plugin="windows.cmdline.CmdLine",
                        context={
                            "process":      process_name,
                            "pid":          pid,
                            "technique":    cmd_pattern["technique"],
                            "pattern_name": cmd_pattern["name"],
                            "category":     "host",
                        },
                        extracted_at=datetime.now(),
                    ))

        return iocs

    def analyze_malfind(self, malfind_data: List[Dict[str, Any]]) -> List[IOC]:
        iocs: List[IOC] = []
        _rwx = re.compile(r"PAGE_EXECUTE_READ(WRITE)?|rwx", re.IGNORECASE)

        for entry in malfind_data:
            protection = str(_get(entry, "Protection", "protection", "Protect"))
            if not _rwx.search(protection):
                continue

            hexdump   = str(_get(entry, "Hexdump", "hexdump", "HexDump", "Disasm", "disasm"))
            has_mz    = bool(re.search(r"^(MZ|4D\s*5A)", hexdump[:40], re.IGNORECASE))
            pid       = _get(entry, "PID", "pid", "Pid")
            process   = str(_get(entry, "Process", "name", "Name"))
            start_vpn = str(_get(entry, "Start VPN", "StartVPN", "start", "VadStart"))

            confidence = 0.90 if has_mz else 0.70

            iocs.append(IOC(
                ioc_type=IOCType.INJECTION,
                value=f"PID {pid} @ {start_vpn}",
                confidence=confidence,
                source_plugin="windows.malware.malfind.Malfind",
                context={
                    "pid":           pid,
                    "process":       process,
                    "start_vpn":     start_vpn,
                    "protection":    protection,
                    "has_pe_header": has_mz,
                    "technique":     "T1055",
                    "category":      "host",
                },
                extracted_at=datetime.now(),
            ))

        return iocs

    def analyze_handles_network(self, handles_data: List[Dict[str, Any]]) -> List[IOC]:
        iocs: List[IOC] = []
        _socket_types = re.compile(r"File", re.IGNORECASE)
        _socket_name  = re.compile(
            r"\\Device\\(?:Tcp|Udp|RawIp|Afd|NetBT_Tcpip)",
            re.IGNORECASE,
        )
        _ip_port = re.compile(
            r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d+)",
        )
        # Collect suspicious PIDs for cross-referencing Afd handles with empty names
        _suspicious_procs = frozenset({
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe", "schtasks.exe",
        })

        for entry in handles_data:
            handle_type = str(_get(entry, "Type", "type"))
            name        = str(_get(entry, "Name", "name"))
            process     = str(_get(entry, "Process", "process")).lower()
            pid         = _get(entry, "PID", "pid")

            if not _socket_types.search(handle_type):  # search() not match() — handle_type may be "FileObject" etc.
                continue

            if process in self._network_whitelist:
                continue

            if _socket_name.search(name):
                # Handle has a resolved device path — try to extract IP:port
                m = _ip_port.search(name)
                if m:
                    remote_ip   = m.group(3)
                    remote_port = int(m.group(4))
                    if _is_private_ip(remote_ip):
                        continue

                    reasons: List[str] = []
                    confidence = 0.55

                    if remote_port in RARE_PORTS:
                        reasons.append("rare_port")
                        confidence = 0.85
                    elif remote_port not in COMMON_LEGITIMATE_PORTS:
                        reasons.append("uncommon_port")
                        confidence = 0.65

                    iocs.append(IOC(
                        ioc_type=IOCType.IPV4,
                        value=remote_ip,
                        confidence=confidence,
                        source_plugin="windows.handles.Handles",
                        context={
                            "process":       process,
                            "pid":           pid,
                            "remote_port":   remote_port,
                            "handle_name":   name,
                            "reasons":       reasons,
                            "technique":     "T1071",
                            "category":      "network",
                        },
                        extracted_at=datetime.now(),
                    ))

            elif not name or name in ("", "None"):
                # Unresolved Afd/socket handle with empty name.
                # Flag the *process* as a suspicious network actor if it's
                # a well-known LOLBin — the network connection itself is
                # confirmed but we can't extract a remote IP.
                if process in _suspicious_procs:
                    iocs.append(IOC(
                        ioc_type=IOCType.PROCESS,
                        value=f"{process} (PID {pid}) — unresolved socket handle",
                        confidence=0.65,
                        source_plugin="windows.handles.Handles",
                        context={
                            "process":   process,
                            "pid":       pid,
                            "reason":    "lolbin_with_socket_handle",
                            "technique": "T1071",
                            "category":  "network",
                        },
                        extracted_at=datetime.now(),
                    ))

        return iocs
    
    def analyze_netscan(
        self,
        netscan_data: List[Dict[str, Any]],
        suspicious_pids: Optional[Set[Any]] = None,
    ) -> List[IOC]:
        iocs: List[IOC] = []
        suspicious_pids = suspicious_pids or set()
        foreign_ip_counts: Dict[str, int] = {}

        for conn in netscan_data:
            foreign_ip = str(_get(conn, "ForeignAddr", "ForeignAddress", "foreign_addr"))
            foreign_port_raw = _get(conn, "ForeignPort", "foreign_port", "FPort")
            local_port_raw = _get(conn, "LocalPort", "local_port", "LPort")
            owner = str(_get(conn, "Owner", "owner", "Process", "process")).lower()
            pid = _get(conn, "PID", "pid", "Pid")
            state = str(_get(conn, "State", "state", "Status")).upper()
            proto = str(_get(conn, "Proto", "proto", "Protocol", "Type", "type"))

            if not foreign_ip or foreign_ip in ("", "None", "*", "0.0.0.0", "::"):
                continue

            try:
                foreign_port = int(foreign_port_raw)
            except (ValueError, TypeError):
                foreign_port = 0

            if foreign_port == 0:
                continue

            pid_is_suspicious = pid in suspicious_pids
            is_rare_port = foreign_port in RARE_PORTS
            is_uncommon_port = foreign_port not in COMMON_LEGITIMATE_PORTS
            is_private = _is_private_ip(foreign_ip)

            if is_private and not pid_is_suspicious and not is_rare_port:
                continue

            if owner in self._network_whitelist and not pid_is_suspicious:
                if foreign_port in COMMON_LEGITIMATE_PORTS:
                    continue

            foreign_ip_counts[foreign_ip] = foreign_ip_counts.get(foreign_ip, 0) + 1

            reasons: List[str] = []
            confidence = 0.50

            if is_rare_port:
                reasons.append("rare_port")
                confidence = 0.90
            elif is_uncommon_port:
                reasons.append("uncommon_port")
                confidence = 0.65

            if state == "ESTABLISHED":
                confidence = min(confidence + 0.10, 0.95)
                reasons.append("established")

            if pid_is_suspicious:
                confidence = min(confidence + 0.20, 0.97)
                reasons.append("pid_in_malfind")

            if is_private and (pid_is_suspicious or is_rare_port):
                reasons.append("private_ip_suspicious_context")

            iocs.append(IOC(
                ioc_type=IOCType.IPV4,
                value=foreign_ip,
                confidence=confidence,
                source_plugin="windows.netscan.NetScan",
                context={
                    "process": owner,
                    "pid": pid,
                    "remote_port": foreign_port,
                    "local_port": local_port_raw,
                    "state": state,
                    "proto": proto,
                    "reasons": reasons,
                    "is_private": is_private,
                    "technique": "T1071",
                    "category": "network",
                },
                extracted_at=datetime.now(),
            ))

        beaconing_threshold = 3
        for ioc in iocs:
            ip = ioc.value
            if foreign_ip_counts.get(ip, 0) >= beaconing_threshold:
                ioc.context["beaconing"] = True
                ioc.context["connection_count"] = foreign_ip_counts[ip]
                ioc.confidence = min(ioc.confidence + 0.10, 0.97)
                if "beaconing_pattern" not in ioc.context.get("reasons", []):
                    ioc.context["reasons"].append("beaconing_pattern")

        return iocs


    def analyze_sockstat(self, sockstat_data: List[Dict[str, Any]]) -> List[IOC]:
        iocs: List[IOC] = []

        for conn in sockstat_data:
            process     = str(_get(conn, "Owner", "Process", "process", "name")).lower()
            remote_ip   = str(_get(conn, "ForeignAddr", "RemoteAddr", "remote_addr", "Foreign"))
            remote_port_raw = _get(conn, "ForeignPort", "RemotePort", "remote_port", "FPort")
            local_port_raw  = _get(conn, "LocalPort",   "local_port",  "LPort")
            state       = str(_get(conn, "State", "state"))
            family      = str(_get(conn, "Family", "family", "Proto"))

            if not remote_ip or remote_ip in ("", "0.0.0.0", "None", "*"):
                continue
            if _is_private_ip(remote_ip):
                continue

            try:
                remote_port = int(remote_port_raw)
            except (ValueError, TypeError):
                remote_port = 0

            if process in self._network_whitelist:
                if remote_port in COMMON_LEGITIMATE_PORTS:
                    continue

            reasons: List[str] = []
            confidence = 0.55

            if remote_port in RARE_PORTS:
                reasons.append("rare_port")
                confidence = 0.85
            elif remote_port not in COMMON_LEGITIMATE_PORTS:
                reasons.append("uncommon_port")
                confidence = 0.65

            if state.upper() == "ESTABLISHED":
                confidence = min(confidence + 0.10, 0.95)
                reasons.append("established_connection")

            iocs.append(IOC(
                ioc_type=IOCType.IPV4,
                value=remote_ip,
                confidence=confidence,
                source_plugin="linux.sockstat.Sockstat",
                context={
                    "process":     process,
                    "remote_port": remote_port,
                    "local_port":  local_port_raw,
                    "state":       state,
                    "family":      family,
                    "reasons":     reasons,
                    "technique":   "T1071",
                    "category":    "network",
                },
                extracted_at=datetime.now(),
            ))

        return iocs


    def analyze_hollowprocesses(self, hollow_data: List[Dict[str, Any]]) -> List[IOC]:
        """Dedicated analyzer for windows.malware.hollowprocesses.HollowProcesses (T1055.012).

        HollowProcesses flags processes where the in-memory PE header differs from
        the on-disk image — classic process hollowing indicator.
        Fields: PID, Process, VirtualAddress (or Base), Status, File Output.
        """
        iocs: List[IOC] = []
        for entry in hollow_data:
            pid     = _get(entry, "PID", "pid", "Pid")
            process = str(_get(entry, "Process", "process", "Name", "name", "ImageFileName"))
            status  = str(_get(entry, "Status", "status", "Hollowed", "hollowed", "Result"))
            vaddr   = str(_get(entry, "VirtualAddress", "Base", "base", "Offset", "offset"))

            # Skip entries that explicitly say not hollowed
            if status.lower() in ("false", "0", "not hollowed", "clean"):
                continue

            iocs.append(IOC(
                ioc_type=IOCType.INJECTION,
                value=f"PID {pid} ({process}) @ {vaddr}",
                confidence=0.88,
                source_plugin="windows.malware.hollowprocesses.HollowProcesses",
                context={
                    "pid":       pid,
                    "process":   process,
                    "vaddr":     vaddr,
                    "status":    status,
                    "technique": "T1055.012",
                    "details":   "Process hollowing — in-memory PE differs from on-disk image",
                    "category":  "host",
                },
                extracted_at=datetime.now(),
            ))
        return iocs


    def analyze_svcscan(self, svcscan_data: List[Dict[str, Any]]) -> List[IOC]:
        """Detect suspicious Windows services (T1543.003).

        Only flags services that have at least ONE strong signal:
          - binary path in a suspicious directory (Temp, AppData, etc.)
          - non-.exe extension (.bat, .ps1, .vbs, ...)
          - running with no binary path at all

        The previous 'non_system_root' standalone rule was generating hundreds
        of false positives for legitimate third-party vendor services.
        """
        iocs: List[IOC] = []
        _suspicious_path = re.compile(
            r"(?i)(\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\"
            r"|\\Windows\\Temp\\|\\tmp\\|%temp%|%appdata%)",
        )
        _non_exe = re.compile(r"(?i)\.(bat|cmd|vbs|ps1|js|hta|scr|com|pif)")
        # Kernel/filesystem drivers are legit with .sys extension anywhere
        _driver_type = re.compile(r"(?i)(kernel|filesys|recognizer|adapter)", re.IGNORECASE)

        for entry in svcscan_data:
            svc_name     = str(_get(entry, "ServiceName", "Name", "name"))
            display_name = str(_get(entry, "DisplayName", "display_name"))
            binary_path  = str(_get(entry, "BinaryPath", "ImagePath", "binary_path", "Binary"))
            state        = str(_get(entry, "State", "state")).upper()
            pid          = _get(entry, "PID", "pid", "Pid")
            svc_type     = str(_get(entry, "Type", "type"))

            # Skip kernel/filesystem driver services — they live in non-standard paths legitimately
            if _driver_type.search(svc_type):
                continue

            if not binary_path or binary_path in ("", "None"):
                # Running service with no binary path is always suspicious
                if state == "RUNNING":
                    iocs.append(IOC(
                        ioc_type=IOCType.PROCESS,
                        value=svc_name,
                        confidence=0.75,
                        source_plugin="windows.svcscan.SvcScan",
                        context={
                            "service_name":  svc_name,
                            "display_name":  display_name,
                            "binary_path":   "(empty)",
                            "state":         state,
                            "pid":           pid,
                            "technique":     "T1543.003",
                            "reason":        "running_service_no_binary",
                            "category":      "host",
                        },
                        extracted_at=datetime.now(),
                    ))
                continue

            reasons: List[str] = []
            confidence = 0.0

            if _suspicious_path.search(binary_path):
                reasons.append("suspicious_path")
                confidence = max(confidence, 0.85)

            if _non_exe.search(binary_path):
                reasons.append("non_exe_extension")
                confidence = max(confidence, 0.80)

            # REMOVED: non_system_root standalone — too many false positives
            # Only emit an IOC when at least one strong signal fires
            if not reasons or confidence == 0.0:
                continue

            # Boost confidence if the service is actively running
            if state == "RUNNING":
                confidence = min(confidence + 0.10, 0.95)
                reasons.append("service_running")

            iocs.append(IOC(
                ioc_type=IOCType.PROCESS,
                value=svc_name,
                confidence=confidence,
                source_plugin="windows.svcscan.SvcScan",
                context={
                    "service_name":  svc_name,
                    "display_name":  display_name,
                    "binary_path":   binary_path,
                    "state":         state,
                    "pid":           pid,
                    "svc_type":      svc_type,
                    "reasons":       reasons,
                    "technique":     "T1543.003",
                    "category":      "host",
                },
                extracted_at=datetime.now(),
            ))

        return iocs


    def analyze_hidden_processes(
        self,
        pslist_data: List[Dict[str, Any]],
        psscan_data: List[Dict[str, Any]],
    ) -> List[IOC]:
        """Detect rootkit-hidden processes by diffing pslist vs psscan (T1564.001).

        Skips processes that have a non-null ExitTime — these are terminated
        processes still in RAM, not rootkit-hidden ones.
        """
        iocs: List[IOC] = []

        pslist_pids: Set[Any] = set()
        for proc in pslist_data:
            pid = _get(proc, "PID", "pid", "Pid")
            if pid is not None:
                pslist_pids.add(str(pid))

        for proc in psscan_data:
            pid      = _get(proc, "PID", "pid", "Pid")
            process  = str(_get(proc, "ImageFileName", "Name", "name", "process"))
            offset   = str(_get(proc, "Offset", "offset", "PhysOffset"))
            # ExitTime non-null/non-zero means the process terminated normally
            exit_time = str(_get(proc, "ExitTime", "exit_time", "Exited", default=""))

            if pid is None:
                continue
            if str(pid) in pslist_pids:
                continue  # visible in pslist — normal

            # Terminated process still in physical memory — NOT rootkit-hidden
            if exit_time and exit_time not in ("", "None", "0", "N/A",
                                               "1970-01-01 00:00:00",
                                               "1970-01-01T00:00:00"):
                continue

            iocs.append(IOC(
                ioc_type=IOCType.PROCESS,
                value=f"{process} (PID {pid})",
                confidence=0.92,
                source_plugin="windows.psscan.PsScan",
                context={
                    "pid":       pid,
                    "process":   process,
                    "offset":    offset,
                    "technique": "T1564.001",
                    "details":   "Process in psscan but not pslist — likely DKOM-hidden by rootkit",
                    "category":  "host",
                },
                extracted_at=datetime.now(),
            ))

        return iocs


class ExtractionPipeline:
    def __init__(self, os_type: str) -> None:
        self.os_type = os_type
        self.regex_extractor    = IOCExtractor()
        self.context_extractor  = ContextAwareExtractor(os_type)
        self._registry_analyzer = RegistryAnalyzer()

    def _find(self, plugin_results: Dict[str, Any], *keywords: str) -> Optional[List[Dict[str, Any]]]:
        kw_lower = [k.lower() for k in keywords]
        for key, value in plugin_results.items():
            # Strip the args-hash suffix (e.g. "windows.handles.Handles#abc123" → "windows.handles.Handles")
            key_normalized = key.lower().split("#")[0]
            if any(kw in key_normalized for kw in kw_lower):
                if isinstance(value, list):
                    return value
                if isinstance(value, dict):
                    return [value]
        return None

    async def extract(self, plugin_results: Dict[str, Any]) -> List[IOC]:
        self.regex_extractor.reset()
        all_iocs: List[IOC] = []

        for plugin_name, data in plugin_results.items():
            if not data:
                continue
            plugin_short = plugin_name.lower().split(".")[-1]
            if not any(k in plugin_short for k in REGEX_SCAN_PLUGINS):
                continue
            text_data = json.dumps(data) if isinstance(data, (list, dict)) else str(data)
            all_iocs.extend(self.regex_extractor.extract_from_text(text_data, plugin_name))

        pslist_data = self._find(plugin_results, "pslist")
        pstree_data = self._find(plugin_results, "pstree") or []
        if pslist_data:
            all_iocs.extend(
                self.context_extractor.analyze_processes(pslist_data, pstree_data)
            )

        cmdline_data = self._find(plugin_results, "cmdline", "bash")
        if cmdline_data:
            all_iocs.extend(self.context_extractor.analyze_cmdlines(cmdline_data))

        malfind_data = self._find(plugin_results, "malfind")
        if malfind_data:
            all_iocs.extend(self.context_extractor.analyze_malfind(malfind_data))

        # Hollow processes get a dedicated analyzer (T1055.012) rather than
        # being lumped in with malfind — different output fields, different confidence.
        hollow_data = self._find(plugin_results, "hollowprocesses")
        if hollow_data:
            all_iocs.extend(self.context_extractor.analyze_hollowprocesses(hollow_data))

        if self.os_type == "windows":
            suspicious_pids: Set[Any] = set()
            malfind_iocs = [i for i in all_iocs if i.ioc_type == IOCType.INJECTION]
            for mi in malfind_iocs:
                if mi.context.get("pid") is not None:
                    suspicious_pids.add(mi.context["pid"])

            netscan_data = self._find(plugin_results, "netscan")
            if netscan_data:
                all_iocs.extend(self.context_extractor.analyze_netscan(netscan_data, suspicious_pids))

            netstat_data = self._find(plugin_results, "netstat")
            if netstat_data:
                all_iocs.extend(self.context_extractor.analyze_netscan(netstat_data, suspicious_pids))

            # Vol3 2.5+: netscan/netstat are unavailable; use handles-based network extraction
            # as the primary fallback. Always run this — it captures sockets netscan misses.
            handles_data = self._find(plugin_results, "handles")
            if handles_data:
                all_iocs.extend(self.context_extractor.analyze_handles_network(handles_data))

            # Hidden process detection: psscan PIDs not in pslist = rootkit (T1564.001)
            psscan_data = self._find(plugin_results, "psscan")
            if pslist_data and psscan_data:
                all_iocs.extend(
                    self.context_extractor.analyze_hidden_processes(pslist_data, psscan_data)
                )

            # Service-based persistence (T1543.003)
            svcscan_data = self._find(plugin_results, "svcscan")
            if svcscan_data:
                all_iocs.extend(self.context_extractor.analyze_svcscan(svcscan_data))

        else:
            sockstat_data = self._find(plugin_results, "sockstat", "sockscan")
            if sockstat_data:
                all_iocs.extend(self.context_extractor.analyze_sockstat(sockstat_data))

        registry_entries: List[Dict[str, Any]] = []
        for key, value in plugin_results.items():
            if "registry" in key.lower() or "printkey" in key.lower():
                if value:
                    entries = value if isinstance(value, list) else [value]
                    registry_entries.extend(entries)

        if registry_entries:
            findings = self._registry_analyzer.analyze(registry_entries)
            all_iocs.extend(self._convert_registry_findings(findings))

        return self._deduplicate(all_iocs)

    def _convert_registry_findings(self, findings: List[Dict[str, Any]]) -> List[IOC]:
        iocs: List[IOC] = []
        for finding in findings:
            ioc_type = _CATEGORY_TO_IOC_TYPE.get(finding["category"], IOCType.REGISTRY_CONFIG)
            iocs.append(IOC(
                ioc_type=ioc_type,
                value=f"{finding['key']}\\{finding['value']}",
                confidence=finding["confidence"],
                source_plugin="windows.registry",
                context={
                    "key":          finding["key"],
                    "value_name":   finding["value"],
                    "data":         finding["data"],
                    "technique":    finding["mitre"],
                    "severity":     finding["severity"],
                    "reasons":      ", ".join(finding["reasons"]),
                    "description":  finding["description"],
                    "category":     "host",
                },
                extracted_at=datetime.now(),
            ))
        return iocs

    def _deduplicate(self, iocs: List[IOC]) -> List[IOC]:
        seen: Dict[str, IOC] = {}
        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.value}"
            if key not in seen or ioc.confidence > seen[key].confidence:
                seen[key] = ioc
        return list(seen.values())

    def reset(self) -> None:
        self.regex_extractor.reset()


# ---------------------------------------------------------------------------
# Per-Process IOC Grouping
# ---------------------------------------------------------------------------

from dataclasses import dataclass as _dc, field as _field

@_dc
class ProcessGroup:
    """All IOCs attributed to a single process (PID + name).

    Computed properties give the analyst a one-glance threat verdict:
      - threat_score   — highest confidence IOC in this group
      - threat_level   — HIGH / MEDIUM / LOW
      - techniques     — deduplicated, sorted MITRE technique list
    """
    pid:          Any
    process_name: str
    iocs:         List[IOC] = _field(default_factory=list)

    @property
    def threat_score(self) -> float:
        return max((i.confidence for i in self.iocs), default=0.0)

    @property
    def threat_level(self) -> str:
        s = self.threat_score
        if s >= 0.75:  return "HIGH"
        if s >= 0.50:  return "MEDIUM"
        return "LOW"

    @property
    def techniques(self) -> List[str]:
        seen: Set[str] = set()
        result: List[str] = []
        for ioc in self.iocs:
            t = str(ioc.context.get("technique", "")).strip()
            if t and t not in seen:
                seen.add(t)
                result.append(t)
        return sorted(result)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "process":     self.process_name,
            "pid":         self.pid,
            "threat_level": self.threat_level,
            "threat_score": round(self.threat_score, 3),
            "techniques":  self.techniques,
            "ioc_count":   len(self.iocs),
            "iocs": [
                {
                    "type":       str(i.ioc_type),
                    "value":      i.value,
                    "confidence": round(i.confidence, 3),
                    "technique":  i.context.get("technique", ""),
                    "source":     i.source_plugin or "",
                    "reason":     i.context.get("reason", "")
                                  or ", ".join(i.context.get("reasons", [])),
                }
                for i in sorted(self.iocs, key=lambda x: -x.confidence)
            ],
        }


def group_iocs_by_process(
    iocs: List[IOC],
) -> tuple:  # (List[ProcessGroup], List[IOC])
    """Group IOCs by the process that produced them.

    Returns
    -------
    (process_groups, unattributed_iocs)
        process_groups    — sorted by threat_score descending
        unattributed_iocs — IOCs with no PID/process context
                            (e.g. regex-scanned hashes from filescan)
    """
    groups: Dict[str, "ProcessGroup"] = {}
    unattributed: List[IOC] = []

    for ioc in iocs:
        ctx = ioc.context or {}
        pid     = ctx.get("pid") or ctx.get("PID")
        process = (
            ctx.get("process")
            or ctx.get("service_name")
            or ctx.get("proc")
            or ""
        ).strip()

        if not pid and not process:
            unattributed.append(ioc)
            continue

        # Normalise: "svchost.exe" + PID 1234 → key "svchost.exe::1234"
        key = f"{process}::{pid}" if pid else f"{process}::?"
        if key not in groups:
            groups[key] = ProcessGroup(
                pid=pid,
                process_name=process or f"PID {pid}",
            )
        groups[key].iocs.append(ioc)

    sorted_groups = sorted(groups.values(), key=lambda g: g.threat_score, reverse=True)
    return sorted_groups, unattributed
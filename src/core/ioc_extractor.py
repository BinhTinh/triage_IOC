import re
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from src.models.ioc import IOC, IOCType
from src.core.registry_analyzer import RegistryAnalyzer

IOC_PATTERNS: Dict[str, Dict[str, Any]] = {
    IOCType.IPV4: {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
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
    IOCType.SHA256: {
        "pattern": r"\b[a-fA-F0-9]{64}\b",
        "exclude": [],
        "source_gate": {"amcache", "filescan", "dumpfiles", "ldrmodules", "shimcachemem"},
    },

    IOCType.FILEPATH: {
        "pattern": r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*",
        "exclude": [
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
    return ip.startswith(("0.", "127.", "10.", "192.168.", "172.16.", "172.17.",
                          "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                          "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                          "172.28.", "172.29.", "172.30.", "172.31.", "169.254.",
                          "::1", "fe80:"))


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
                    context={"raw_match": True, "from_plugin": source},
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
            r"\\Device\\(?:Tcp|Udp|RawIp|Afd)|\\Device\\NetBT_Tcpip",
            re.IGNORECASE,
        )
        _ip_port = re.compile(
            r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d+)",
        )

        for entry in handles_data:
            handle_type = str(_get(entry, "Type", "type"))
            name        = str(_get(entry, "Name", "name"))
            process     = str(_get(entry, "Process", "process")).lower()
            pid         = _get(entry, "PID", "pid")

            if not _socket_types.match(handle_type):
                continue
            if not _socket_name.search(name):
                continue
            if process in self._network_whitelist:
                continue

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


class ExtractionPipeline:
    def __init__(self, os_type: str) -> None:
        self.os_type = os_type
        self.regex_extractor    = IOCExtractor()
        self.context_extractor  = ContextAwareExtractor(os_type)
        self._registry_analyzer = RegistryAnalyzer()

    def _find(self, plugin_results: Dict[str, Any], *keywords: str) -> Optional[List[Dict[str, Any]]]:
        kw_lower = [k.lower() for k in keywords]
        for key, value in plugin_results.items():
            key_lower = key.lower()
            if any(kw in key_lower for kw in kw_lower):
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

        malfind_data = self._find(plugin_results, "malfind", "hollowprocesses")
        if malfind_data:
            all_iocs.extend(self.context_extractor.analyze_malfind(malfind_data))

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
        else:
            sockstat_data = self._find(plugin_results, "sockstat", "sockscan")
            if sockstat_data:
                all_iocs.extend(self.context_extractor.analyze_sockstat(sockstat_data))

        registry_entries: List[Dict[str, Any]] = []
        for key, value in plugin_results.items():
            if "registry" in key.lower() or "printkey" in key.lower() or "amcache" in key.lower():
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
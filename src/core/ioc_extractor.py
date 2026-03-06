import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Set, Tuple, Optional
import json

from src.models.ioc import IOC

IOC_PATTERNS = {
    "ipv4": {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "exclude": [
            r"^0\.0\.0\.0$",
            r"^127\.",
            r"^10\.",
            r"^172\.(1[6-9]|2[0-9]|3[01])\.",
            r"^192\.168\.",
            r"^255\."
        ]
    },
    "domain": {
        "pattern": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
        "exclude": [
            r"\.microsoft\.com$",
            r"\.windows\.com$",
            r"\.google\.com$",
            r"\.googleapis\.com$",
            r"\.exe$",
            r"\.dll$",
            r"\.sys$",
            r"\.scr$",
            r"\.vbs$",
            r"\.bat$",
            r"\.cmd$",
            r"^[A-Za-z]:\\",
            r"\\Device\\",
            r"\\SystemRoot\\",
        ]
    },
    "md5": {
        "pattern": r"\b[a-fA-F0-9]{32}\b",
        "exclude": []
    },
    "sha256": {
        "pattern": r"\b[a-fA-F0-9]{64}\b",
        "exclude": []
    },
    "filepath_windows": {
        "pattern": r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*",
        "exclude": [
            r"^C:\\Windows\\System32\\",
            r"^C:\\Windows\\SysWOW64\\",
            r"^C:\\Program Files\\"
        ]
    },
    "registry": {
        "pattern": r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s]+",
        "exclude": []
    }
}


SUSPICIOUS_PATTERNS = {
    "windows": {
        "process_relationships": [
            {"parent": "winword.exe", "child": "cmd.exe", "technique": "T1059"},
            {"parent": "winword.exe", "child": "powershell.exe", "technique": "T1059.001"},
            {"parent": "excel.exe", "child": "cmd.exe", "technique": "T1059"},
            {"parent": "excel.exe", "child": "powershell.exe", "technique": "T1059.001"},
            {"parent": "outlook.exe", "child": "cmd.exe", "technique": "T1059"},
            {"parent": "services.exe", "child": "cmd.exe", "technique": "T1543.003"},
            {"parent": "wmiprvse.exe", "child": "powershell.exe", "technique": "T1047"},
        ],
        "suspicious_commands": [
            {"pattern": r"-enc\s+[A-Za-z0-9+/=]+", "technique": "T1059.001", "name": "encoded_powershell"},
            {"pattern": r"-nop\s+-w\s+hidden", "technique": "T1059.001", "name": "hidden_powershell"},
            {"pattern": r"certutil.*-urlcache", "technique": "T1105", "name": "certutil_download"},
            {"pattern": r"bitsadmin.*\/transfer", "technique": "T1105", "name": "bitsadmin_download"},
            {"pattern": r"regsvr32.*\/s.*\/n.*\/u.*\/i:", "technique": "T1218.010", "name": "regsvr32_bypass"},
        ]
    },
    "linux": {
        "process_relationships": [
            {"parent": "nginx", "child": "bash", "technique": "T1505.003"},
            {"parent": "nginx", "child": "sh", "technique": "T1505.003"},
            {"parent": "apache2", "child": "bash", "technique": "T1505.003"},
            {"parent": "httpd", "child": "bash", "technique": "T1505.003"},
        ],
        "suspicious_commands": [
            {"pattern": r"\/dev\/tcp\/\d+\.\d+\.\d+\.\d+\/\d+", "technique": "T1059.004", "name": "bash_reverse_shell"},
            {"pattern": r"nc\s+-e\s+\/bin\/(ba)?sh", "technique": "T1059.004", "name": "netcat_shell"},
            {"pattern": r"curl.*\|\s*(ba)?sh", "technique": "T1059.004", "name": "curl_pipe_shell"},
            {"pattern": r"wget.*-O\s*-.*\|\s*(ba)?sh", "technique": "T1059.004", "name": "wget_pipe_shell"},
        ]
    }
}

LINUX_NETWORK_WHITELIST = {
    "sshd", "systemd", "networkmanager", "dhclient", "dhcpcd",
    "chronyd", "ntpd", "resolved", "avahi-daemon", "cups",
    "nginx", "apache2", "httpd", "lighttpd",
    "python3", "python", "node", "ruby", "java",
    "curl", "wget", "apt", "apt-get", "dpkg",
    "chrome", "firefox", "chromium",
}

WINDOWS_NETWORK_WHITELIST = {
    "svchost.exe", "lsass.exe", "services.exe", "system",
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "outlook.exe", "teams.exe", "onedrive.exe",
    "wuauclt.exe", "wusa.exe", "msiexec.exe",
}

COMMON_LEGITIMATE_PORTS = {
    80, 443, 53, 22, 21, 25, 587, 993, 995,
    8080, 8443,  # phổ biến cho web proxy/dev
    3389, 5900,  # RDP, VNC — suspicious nếu outbound
}

RARE_PORTS = {
    4444, 5555, 6666, 1337, 31337,
    9001, 9030,  # Tor
    6667, 6697,  # IRC
}

SYSTEM_DOMAIN_WHITELIST = {
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
}

VALID_TLDS = {
    "com", "net", "org", "io", "gov", "edu",
    "ru", "cn", "tk", "top", "xyz", "info",
    "biz", "cc", "pw", "su", "to", "onion",
    "co", "uk", "de", "fr", "jp", "br",
}

REGEX_SCAN_PLUGINS = {
    "cmdline", "bash", "malfind", "netscan", "netstat",
    "dlllist", "handles", "mftparser", "filescan",
    "svcscan", "sockscan", "sockstat", "lsof",      
    "userassist", "printkey",                         
}
class IOCExtractor:
    def __init__(self):
        self.patterns = IOC_PATTERNS
        self.seen: Set[str] = set()
        self.process_names = {
            "smss.exe", "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe",
            "svchost.exe", "explorer.exe", "dwm.exe", "spoolsv.exe", "MsMpEng.exe",
            "NisSrv.exe", "ctfmon.exe", "taskhostw.exe", "sihost.exe", "SearchHost.exe",
            "WUDFHost.exe", "dllhost.exe", "msdtc.exe", "WmiPrvSE.exe", "fontdrvhost.exe",
            "userinit.exe", "wininit.exe", "vm3dservice.exe", "vmtoolsd.exe", "OneDrive.exe",
            "Widgets.exe"
        }

    def _is_valid_domain(self, value: str) -> bool:
        value_lower = value.lower()
        
        if len(value) < 6:
            return False
        
        parts = value_lower.split(".")
        if len(parts) < 2:
            return False
        
        tld = parts[-1]
        
        if tld not in VALID_TLDS:
            return False
        
        for whitelist_domain in SYSTEM_DOMAIN_WHITELIST:
            if value_lower == whitelist_domain or value_lower.endswith("." + whitelist_domain):
                return False
        
        if any(len(p) > 50 for p in parts):
            return False
        
        return True
    
    def extract_from_text(self, text: str, source: str) -> List[IOC]:
        iocs = []
        
        for ioc_type, config in self.patterns.items():
            matches = re.findall(config["pattern"], text)
            
            for match in matches:
                if self._should_exclude(match, config["exclude"]):
                    continue
                
                if ioc_type == "domain":
                    if not self._is_valid_domain(match):
                        continue
                
                if ioc_type == "domain" and match.lower() in self.process_names:
                    continue

                if ioc_type == "md5" and not any(
                    k in source.lower() for k in ["filescan", "dumpfiles", "ldrmodules"]
                ):
                    continue
                
                if match in self.seen:
                    continue
                self.seen.add(match)
                
                confidence = 0.5
                if ioc_type == "domain":
                    if any(k in source.lower() for k in ["cmdline", "malfind", "netscan"]):
                        confidence = 0.75
                    else:
                        confidence = 0.3
                
                normalized_type = ioc_type.split("_")[0]
                if normalized_type == "filepath":
                    normalized_type = "filepath"
                
                iocs.append(IOC(
                    ioc_type=normalized_type,
                    value=match,
                    confidence=confidence,
                    source_plugin=source,
                    context={"raw_match": True, "from_plugin": source},
                    extracted_at=datetime.now()
                ))
        
        return iocs
    
    def _should_exclude(self, value: str, exclude_patterns: List[str]) -> bool:
        for pattern in exclude_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True
        return False
    def reset(self) -> None:
        """Clear seen set — gọi trước mỗi extraction để tránh cross-dump dedup."""
        self.seen.clear()


class ContextAwareExtractor:
    def __init__(self, os_type: str):
        self.os_type = os_type
        self.patterns = SUSPICIOUS_PATTERNS.get(os_type, {})
    
    def analyze_processes(
        self,
        pslist_data: List[Dict[str, Any]],
        pstree_data: List[Dict[str, Any]]
    ) -> List[IOC]:
        iocs = []
        
        process_map = {}
        for proc in pslist_data:
            pid = proc.get("PID") or proc.get("pid") or proc.get("Pid")
            if pid:
                process_map[pid] = proc
        
        for proc in pslist_data:
            ppid = proc.get("PPID") or proc.get("ppid") or proc.get("PPid")
            if ppid and ppid in process_map:
                parent = process_map[ppid]
                parent_name = (parent.get("ImageFileName") or parent.get("name") or parent.get("Name") or "").lower()
                child_name = (proc.get("ImageFileName") or proc.get("name") or proc.get("Name") or "").lower()
                
                for rel in self.patterns.get("process_relationships", []):
                    if rel["parent"] in parent_name and rel["child"] in child_name:
                        iocs.append(IOC(
                            ioc_type="process",
                            value=f"{parent_name} -> {child_name}",
                            confidence=0.8,
                            source_plugin="pstree",
                            context={
                                "parent_pid": ppid,
                                "child_pid": proc.get("PID") or proc.get("pid") or proc.get("Pid"),
                                "technique": rel["technique"],
                                "relationship": "suspicious_parent_child"
                            },
                            extracted_at=datetime.now()
                        ))
        
        return iocs
    
    def analyze_cmdlines(self, cmdline_data: List[Dict[str, Any]]) -> List[IOC]:
        iocs = []
        
        for entry in cmdline_data:
            cmdline = entry.get("Args") or entry.get("cmdline") or entry.get("CommandLine") or ""
            process_name = entry.get("ImageFileName") or entry.get("name") or entry.get("Name") or ""
            pid = entry.get("PID") or entry.get("pid") or entry.get("Pid")
            
            for cmd_pattern in self.patterns.get("suspicious_commands", []):
                if re.search(cmd_pattern["pattern"], cmdline, re.IGNORECASE):
                    iocs.append(IOC(
                        ioc_type="command",
                        value=cmdline[:500],
                        confidence=0.85,
                        source_plugin="cmdline",
                        context={
                            "process": process_name,
                            "pid": pid,
                            "technique": cmd_pattern["technique"],
                            "pattern_name": cmd_pattern["name"]
                        },
                        extracted_at=datetime.now()
                    ))
        
        return iocs
    
    def analyze_malfind(self, malfind_data: List[Dict[str, Any]]) -> List[IOC]:
        iocs = []
        
        for entry in malfind_data:
            protection = entry.get("Protection") or entry.get("protection") or ""
            if "PAGE_EXECUTE_READWRITE" in protection or "rwx" in protection.lower():
                hexdump = entry.get("Hexdump") or entry.get("hexdump") or entry.get("HexDump") or ""
                has_mz = hexdump and ("MZ" in hexdump[:20] or "4D5A" in hexdump[:20].upper())
                
                pid = entry.get("PID") or entry.get("pid") or entry.get("Pid")
                process = entry.get("Process") or entry.get("name") or entry.get("Name") or ""
                start_vpn = entry.get("Start VPN") or entry.get("start") or entry.get("StartVPN") or ""
                
                iocs.append(IOC(
                    ioc_type="injection",
                    value=f"PID {pid} @ {start_vpn}",
                    confidence=0.9 if has_mz else 0.7,
                    source_plugin="malfind",
                    context={
                        "pid": pid,
                        "process": process,
                        "start_vpn": start_vpn,
                        "protection": protection,
                        "has_pe_header": has_mz,
                        "technique": "T1055"
                    },
                    extracted_at=datetime.now()
                ))
        
        return iocs
    
    def analyze_network(self, network_data: List[Dict[str, Any]]) -> List[IOC]:
        iocs = []
        
        suspicious_processes = ["notepad.exe", "calc.exe", "mspaint.exe"]
        suspicious_ports = [4444, 5555, 6666, 1337, 31337, 8080, 8443]
        
        for conn in network_data:
            process = (conn.get("Owner") or conn.get("name") or conn.get("Name") or "").lower()
            remote_port = conn.get("ForeignPort") or conn.get("remote_port") or conn.get("RemotePort") or 0
            remote_ip = conn.get("ForeignAddr") or conn.get("remote_ip") or conn.get("RemoteAddr") or ""
            state = conn.get("State") or conn.get("state") or ""
            
            is_suspicious = False
            reason = []
            
            if any(p in process for p in suspicious_processes):
                is_suspicious = True
                reason.append("suspicious_process_with_network")
            
            if remote_port in suspicious_ports:
                is_suspicious = True
                reason.append("suspicious_port")
            
            if state.upper() == "ESTABLISHED" and remote_ip:
                if not remote_ip.startswith(("0.", "127.", "10.", "192.168.", "172.")):
                    if is_suspicious:
                        iocs.append(IOC(
                            ioc_type="ip",
                            value=remote_ip,
                            confidence=0.75,
                            source_plugin="network",
                            context={
                                "process": process,
                                "remote_port": remote_port,
                                "state": state,
                                "reason": reason,
                                "technique": "T1071"
                            },
                            extracted_at=datetime.now()
                        ))
        
        return iocs


class ExtractionPipeline:
    def __init__(self, os_type: str):
        self.os_type = os_type
        self.regex_extractor = IOCExtractor()
        self.context_extractor = ContextAwareExtractor(os_type)
    

    
    async def extract(self, plugin_results: Dict[str, Any]) -> List[IOC]:
        self.regex_extractor.reset()
        all_iocs = []
        for plugin_name, data in plugin_results.items():
            if not data:
                continue

            plugin_short = plugin_name.lower().split(".")[-1]
            if not any(k in plugin_short for k in REGEX_SCAN_PLUGINS):
                continue

            text_data = json.dumps(data) if isinstance(data, (list, dict)) else str(data)
            regex_iocs = self.regex_extractor.extract_from_text(text_data, plugin_name)
            all_iocs.extend(regex_iocs)

        def find_plugin_data(plugin_keywords: List[str]) -> Optional[Any]:
            for key in plugin_results.keys():
                key_lower = key.lower()
                if any(keyword.lower() in key_lower for keyword in plugin_keywords):
                    return plugin_results[key]
            return None
        
        pslist_data  = find_plugin_data(["pslist"])
        pstree_data  = find_plugin_data(["pstree"])
        if pslist_data:
            all_iocs.extend(
                self.context_extractor.analyze_processes(pslist_data, pstree_data or [])
            )

        cmdline_data = find_plugin_data(["cmdline", "bash"])
        if cmdline_data:
            all_iocs.extend(self.context_extractor.analyze_cmdlines(cmdline_data))

        malfind_data = find_plugin_data(["malfind", "hollowprocesses"])
        if malfind_data:
            all_iocs.extend(self.context_extractor.analyze_malfind(malfind_data))

        network_data = find_plugin_data(["netscan", "netstat", "sockstat"])
        if network_data:
            all_iocs.extend(self.context_extractor.analyze_network(network_data))

        registry_entries = []
        for key, value in plugin_results.items():
            if "registry" in key.lower() and value:
                entries = value if isinstance(value, list) else [value]
                registry_entries.extend(entries)

        if registry_entries:
            from src.core.registry_analyzer import RegistryAnalyzer
            registry_findings = RegistryAnalyzer().analyze(registry_entries)
            all_iocs.extend(self._convert_registry_findings(registry_findings))

        return self._deduplicate(all_iocs)
    
    def _deduplicate(self, iocs: List[IOC]) -> List[IOC]:
        seen = {}
        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.value}"
            if key not in seen or ioc.confidence > seen[key].confidence:
                seen[key] = ioc
        return list(seen.values())
    
    def _convert_registry_findings(self, findings: List[Dict]) -> List[IOC]:
        """Convert registry findings to IOC objects"""
        iocs = []
        
        category_to_type = {
            "persistence": "registry_persistence",
            "defense_evasion": "registry_defense_evasion",
            "credential_access": "registry_credential_access",
            "execution": "registry_execution",
            "configuration": "registry_config"
        }
        
        for finding in findings:
            ioc_type = category_to_type.get(finding["category"], "registry_config")
            
            ioc = IOC(
                ioc_type=ioc_type,
                value=f"{finding['key']}\\{finding['value']}",
                confidence=finding["confidence"],
                source_plugin="windows.registry",
                extracted_at=datetime.now(),
                context={
                    "key": finding["key"],
                    "value_name": finding["value"],
                    "data": finding["data"],
                    "technique": finding["mitre"],
                    "severity": finding["severity"],
                    "reasons": ", ".join(finding["reasons"]),
                    "description": finding["description"],
                    "category": finding["category"]
                }
            )
            iocs.append(ioc)
        
        return iocs
    
    def reset(self) -> None:
        """Reset state cho phép reuse pipeline trên nhiều dump."""
        self.regex_extractor.seen.clear()


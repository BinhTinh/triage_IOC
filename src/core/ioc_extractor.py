import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Set, Tuple
import json

from src.models.ioc import IOC
from src.core.registry_analyzer import RegistryAnalyzer

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
            r"\.googleapis\.com$"
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


class IOCExtractor:
    def __init__(self):
        self.patterns = IOC_PATTERNS
        self.seen: Set[str] = set()
    
    def extract_from_text(self, text: str, source: str) -> List[IOC]:
        iocs = []
        
        for ioc_type, config in self.patterns.items():
            matches = re.findall(config["pattern"], text)
            
            for match in matches:
                if self._should_exclude(match, config["exclude"]):
                    continue
                
                if match in self.seen:
                    continue
                self.seen.add(match)
                
                normalized_type = ioc_type.split("_")[0]
                if normalized_type == "filepath":
                    normalized_type = "filepath"
                
                iocs.append(IOC(
                    ioc_type=normalized_type,
                    value=match,
                    confidence=0.5,
                    source_plugin=source,
                    context={"raw_match": True},
                    extracted_at=datetime.now()
                ))
        
        return iocs
    
    def _should_exclude(self, value: str, exclude_patterns: List[str]) -> bool:
        for pattern in exclude_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True
        return False


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
            pid = proc.get("PID") or proc.get("pid")
            if pid:
                process_map[pid] = proc
        
        for proc in pslist_data:
            ppid = proc.get("PPID") or proc.get("ppid")
            if ppid and ppid in process_map:
                parent = process_map[ppid]
                parent_name = (parent.get("ImageFileName") or parent.get("name", "")).lower()
                child_name = (proc.get("ImageFileName") or proc.get("name", "")).lower()
                
                for rel in self.patterns.get("process_relationships", []):
                    if rel["parent"] in parent_name and rel["child"] in child_name:
                        iocs.append(IOC(
                            ioc_type="process",
                            value=f"{parent_name} -> {child_name}",
                            confidence=0.8,
                            source_plugin="pstree",
                            context={
                                "parent_pid": ppid,
                                "child_pid": proc.get("PID") or proc.get("pid"),
                                "technique": rel["technique"],
                                "relationship": "suspicious_parent_child"
                            },
                            extracted_at=datetime.now()
                        ))
        
        return iocs
    
    def analyze_cmdlines(self, cmdline_data: List[Dict[str, Any]]) -> List[IOC]:
        iocs = []
        
        for entry in cmdline_data:
            cmdline = entry.get("Args") or entry.get("cmdline", "")
            process_name = entry.get("ImageFileName") or entry.get("name", "")
            pid = entry.get("PID") or entry.get("pid")
            
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
            protection = entry.get("Protection", "")
            if "PAGE_EXECUTE_READWRITE" in protection or "rwx" in protection.lower():
                hexdump = entry.get("Hexdump", "") or entry.get("hexdump", "")
                has_mz = hexdump and ("MZ" in hexdump[:20] or "4D5A" in hexdump[:20].upper())
                
                pid = entry.get("PID") or entry.get("pid")
                process = entry.get("Process") or entry.get("name", "")
                start_vpn = entry.get("Start VPN") or entry.get("start", "")
                
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
            process = (conn.get("Owner") or conn.get("name", "")).lower()
            remote_port = conn.get("ForeignPort") or conn.get("remote_port", 0)
            remote_ip = conn.get("ForeignAddr") or conn.get("remote_ip", "")
            state = conn.get("State") or conn.get("state", "")
            
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
        all_iocs = []
        
        for plugin_name, data in plugin_results.items():
            if not data:
                continue
            
            text_data = json.dumps(data) if isinstance(data, (list, dict)) else str(data)
            regex_iocs = self.regex_extractor.extract_from_text(text_data, plugin_name)
            all_iocs.extend(regex_iocs)
        
        pslist_keys = ["windows.pslist", "linux.pslist", "pslist"]
        pstree_keys = ["windows.pstree", "linux.pstree", "pstree"]
        
        pslist_data = None
        pstree_data = None
        
        for key in pslist_keys:
            if key in plugin_results and plugin_results[key]:
                pslist_data = plugin_results[key]
                break
        
        for key in pstree_keys:
            if key in plugin_results and plugin_results[key]:
                pstree_data = plugin_results[key]
                break
        
        if pslist_data:
            process_iocs = self.context_extractor.analyze_processes(
                pslist_data, pstree_data or []
            )
            all_iocs.extend(process_iocs)
        
        cmdline_keys = ["windows.cmdline", "linux.bash", "cmdline", "bash"]
        for key in cmdline_keys:
            if key in plugin_results and plugin_results[key]:
                cmdline_iocs = self.context_extractor.analyze_cmdlines(plugin_results[key])
                all_iocs.extend(cmdline_iocs)
        
        malfind_keys = ["windows.malware.malfind", "linux.malware.malfind", "malfind"]
        for key in malfind_keys:
            if key in plugin_results and plugin_results[key]:
                injection_iocs = self.context_extractor.analyze_malfind(plugin_results[key])
                all_iocs.extend(injection_iocs)
        
        network_keys = ["windows.netscan", "linux.sockstat", "sockstat", "handles"]
        for key in network_keys:
            if key in plugin_results and plugin_results[key]:
                network_iocs = self.context_extractor.analyze_network(plugin_results[key])
                all_iocs.extend(network_iocs)

        registry_analyzer = RegistryAnalyzer()
        registry_entries = []
        
        registry_keys = [
            "windows.registry.printkey",
            "windows.registry.userassist",
            "windows.registry.hivelist"
        ]
        
        for key in registry_keys:
            if key in plugin_results and plugin_results[key]:
                registry_entries.extend(plugin_results[key])
        
        if registry_entries:
            registry_findings = registry_analyzer.analyze(registry_entries)
            registry_iocs = self._convert_registry_findings(registry_findings)
            all_iocs.extend(registry_iocs)
        
        return self._deduplicate(all_iocs)
        
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
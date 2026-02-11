from datetime import datetime
from typing import Dict, List, Any, Optional
from dateutil import parser as date_parser
from src.models.timeline import Timeline, TimelineEvent, EventType, EventSeverity

class TimelineBuilder:
    def __init__(self, os_type: str):
        self.os_type = os_type
        self.events: List[TimelineEvent] = []
        
    def build(self, plugin_results: Dict[str, dict]) -> Timeline:
        self.events = []
        
        self._extract_process_events(plugin_results)
        self._extract_network_events(plugin_results)
        self._extract_injection_events(plugin_results)
        self._extract_file_events(plugin_results)
        self._extract_cmdline_events(plugin_results)
        
        real_timestamp_events = [e for e in self.events if e.timestamp and e.timestamp.year > 2000]
        no_timestamp_events = [e for e in self.events if not e.timestamp or e.timestamp.year <= 2000]
        
        sorted_real = sorted(real_timestamp_events, key=lambda x: x.timestamp)
        
        all_events = sorted_real + no_timestamp_events
        
        start_time = sorted_real[0].timestamp if sorted_real else None
        end_time = sorted_real[-1].timestamp if sorted_real else None
        
        event_types = {}
        for event in all_events:
            event_types[event.event_type.value] = event_types.get(event.event_type.value, 0) + 1
        
        return Timeline(
            events=all_events,
            start_time=start_time,
            end_time=end_time,
            total_events=len(all_events),
            event_types=event_types
        )
    
    def _extract_process_events(self, plugin_results: Dict[str, dict]):
        pslist_keys = ["windows.pslist", "linux.pslist", "pslist"]
        
        for key in pslist_keys:
            if key not in plugin_results or not plugin_results[key].get("data"):
                continue
                
            data = plugin_results[key]["data"]
            for proc in data:
                timestamp = self._parse_timestamp(
                    proc.get("CreateTime") or proc.get("start_time")
                )
                
                if not timestamp:
                    timestamp = datetime(1970, 1, 1)
                
                pid = proc.get("PID") or proc.get("pid")
                name = proc.get("ImageFileName") or proc.get("name", "")
                ppid = proc.get("PPID") or proc.get("ppid")
                
                if "winrar" in name.lower():
                    severity = EventSeverity.CRITICAL
                elif "dumpit" in name.lower():
                    severity = EventSeverity.INFO
                else:
                    severity = self._assess_process_severity(name, proc)
                
                self.events.append(TimelineEvent(
                    timestamp=timestamp,
                    event_type=EventType.PROCESS_CREATE,
                    severity=severity,
                    source_plugin=key,
                    entity_type="process",
                    entity_id=f"PID:{pid}",
                    description=f"Process {name} created (PID {pid}, PPID {ppid})",
                    details={
                        "pid": pid,
                        "ppid": ppid,
                        "name": name,
                        "threads": proc.get("Threads") or proc.get("threads"),
                        "handles": proc.get("Handles") or proc.get("handles"),
                        "create_time": str(proc.get("CreateTime") or proc.get("start_time", ""))
                    },
                    related_entities=[f"PID:{ppid}"] if ppid else []
                ))
    
    def _extract_network_events(self, plugin_results: Dict[str, dict]):
        network_keys = ["windows.netscan", "linux.sockstat", "netscan"]
        
        for key in network_keys:
            if key not in plugin_results or not plugin_results[key].get("data"):
                continue
                
            data = plugin_results[key]["data"]
            for conn in data:
                timestamp = self._parse_timestamp(conn.get("CreateTime"))
                
                if not timestamp:
                    timestamp = datetime(1970, 1, 1)
                
                pid = conn.get("PID") or conn.get("pid")
                process = conn.get("Owner") or conn.get("name", "")
                remote_ip = conn.get("ForeignAddr") or conn.get("remote_ip", "")
                remote_port = conn.get("ForeignPort") or conn.get("remote_port")
                state = conn.get("State") or conn.get("state", "")
                
                severity = self._assess_network_severity(process, remote_ip, remote_port)
                
                self.events.append(TimelineEvent(
                    timestamp=timestamp,
                    event_type=EventType.NETWORK_CONNECT,
                    severity=severity,
                    source_plugin=key,
                    entity_type="network",
                    entity_id=f"{remote_ip}:{remote_port}",
                    description=f"{process} connected to {remote_ip}:{remote_port}",
                    details={
                        "pid": pid,
                        "process": process,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state
                    },
                    related_entities=[f"PID:{pid}"] if pid else []
                ))
    
    def _extract_injection_events(self, plugin_results: Dict[str, dict]):
        malfind_keys = ["windows.malware.malfind", "linux.malware.malfind", "malfind"]
        
        for key in malfind_keys:
            if key not in plugin_results or not plugin_results[key].get("data"):
                continue
                
            data = plugin_results[key]["data"]
            for entry in data:
                pid = entry.get("PID") or entry.get("pid")
                process = entry.get("Process") or entry.get("name", "")
                start_vpn = entry.get("Start VPN") or entry.get("start", "")
                protection = entry.get("Protection", "")
                
                self.events.append(TimelineEvent(
                    timestamp=datetime(1970, 1, 1),
                    event_type=EventType.CODE_INJECTION,
                    severity=EventSeverity.HIGH,
                    source_plugin=key,
                    entity_type="injection",
                    entity_id=f"PID:{pid}@{start_vpn}",
                    description=f"Code injection in {process} (PID {pid}) at {start_vpn}",
                    details={
                        "pid": pid,
                        "process": process,
                        "address": start_vpn,
                        "protection": protection
                    },
                    related_entities=[f"PID:{pid}"],
                    mitre_technique="T1055"
                ))
    
    def _extract_file_events(self, plugin_results: Dict[str, dict]):
        filescan_keys = ["windows.filescan", "filescan"]
        
        for key in filescan_keys:
            if key not in plugin_results or not plugin_results[key].get("data"):
                continue
                
            data = plugin_results[key]["data"]
            
            suspicious_patterns = [
                "flag", "password", "ransom", ".encrypted", ".locked", ".crypt"
            ]
            
            for file_entry in data:
                name = file_entry.get("Name", "").lower()
                
                is_suspicious = any(pattern in name for pattern in suspicious_patterns)
                
                if is_suspicious:
                    offset = file_entry.get("Offset")
                    
                    file_name = name.split("\\")[-1] if "\\" in name else name
                    
                    if "flag" in name or "password" in name:
                        severity = EventSeverity.HIGH
                    else:
                        severity = EventSeverity.MEDIUM
                    
                    self.events.append(TimelineEvent(
                        timestamp=datetime(1970, 1, 1),
                        event_type=EventType.FILE_ACCESS,
                        severity=severity,
                        source_plugin=key,
                        entity_type="file",
                        entity_id=f"offset:{offset}",
                        description=f"Suspicious file: {file_name}",
                        details={
                            "name": file_name,
                            "offset": offset,
                            "full_path": file_entry.get("Name", "")
                        }
                    ))
    
    def _extract_cmdline_events(self, plugin_results: Dict[str, dict]):
        cmdline_keys = ["windows.cmdline", "linux.bash", "cmdline", "bash"]
        
        for key in cmdline_keys:
            if key not in plugin_results or not plugin_results[key].get("data"):
                continue
                
            data = plugin_results[key]["data"]
            
            for entry in data:
                cmdline = entry.get("Args") or entry.get("cmdline", "")
                pid = entry.get("PID") or entry.get("pid")
                process = entry.get("ImageFileName") or entry.get("name", "")
                
                suspicious_keywords = [
                    "-enc", "invoke-expression", "downloadstring",
                    "certutil", "bitsadmin", "bypass", "winrar", "flag.rar"
                ]
                
                is_suspicious = any(kw in cmdline.lower() for kw in suspicious_keywords)
                
                if "winrar" in process.lower() or "winrar" in cmdline.lower():
                    is_suspicious = True
                
                if is_suspicious or len(cmdline) > 200:
                    cmdline_preview = cmdline[:100] + "..." if len(cmdline) > 100 else cmdline
                    
                    if "winrar" in cmdline.lower() or "flag" in cmdline.lower():
                        severity = EventSeverity.CRITICAL
                    else:
                        severity = EventSeverity.HIGH
                    
                    self.events.append(TimelineEvent(
                        timestamp=datetime(1970, 1, 1),
                        event_type=EventType.PROCESS_CREATE,
                        severity=severity,
                        source_plugin=key,
                        entity_type="command",
                        entity_id=f"PID:{pid}",
                        description=f"{process}: {cmdline_preview}",
                        details={
                            "pid": pid,
                            "process": process,
                            "cmdline": cmdline,
                            "cmdline_length": len(cmdline)
                        },
                        related_entities=[f"PID:{pid}"]
                    ))
    
    def _parse_timestamp(self, ts: Any) -> Optional[datetime]:
        if not ts:
            return None
        
        if isinstance(ts, datetime):
            return ts
        
        if isinstance(ts, str):
            try:
                dt = date_parser.isoparse(ts)
                return dt.replace(tzinfo=None)
            except:
                pass
            
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f"
            ]
            
            ts_clean = ts.split('+')[0].split('.')[0].replace('T', ' ')
            
            for fmt in formats:
                try:
                    return datetime.strptime(ts_clean, fmt)
                except:
                    continue
        
        return None
    
    def _assess_process_severity(self, name: str, proc: dict) -> EventSeverity:
        suspicious_names = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]
        
        if any(s in name.lower() for s in suspicious_names):
            return EventSeverity.MEDIUM
        
        return EventSeverity.INFO
    
    def _assess_network_severity(self, process: str, remote_ip: str, remote_port: int) -> EventSeverity:
        suspicious_processes = ["notepad.exe", "calc.exe", "mspaint.exe"]
        suspicious_ports = [4444, 5555, 1337, 6666, 31337]
        
        if any(p in process.lower() for p in suspicious_processes):
            return EventSeverity.HIGH
        
        if remote_port in suspicious_ports:
            return EventSeverity.HIGH
        
        if remote_ip and not remote_ip.startswith(("0.", "127.", "10.", "192.168.", "172.")):
            return EventSeverity.MEDIUM
        
        return EventSeverity.INFO

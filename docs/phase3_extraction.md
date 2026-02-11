# Phase 3: IOC Extraction

## Overview

Phase 3 extracts structured IOCs from raw Volatility3 plugin output using regex patterns and context-aware rules.

## Components

### 3.1 IOC Data Model

```python
@dataclass
class IOC:
    ioc_type: str
    value: str
    confidence: float
    source_plugin: str
    context: dict
    extracted_at: datetime
    
    def to_dict(self) -> dict:
        return {
            "type": self.ioc_type,
            "value": self.value,
            "confidence": self.confidence,
            "source": self.source_plugin,
            "context": self.context,
            "extracted_at": self.extracted_at.isoformat()
        }
```

### 3.2 Regex Patterns

```python
IOC_PATTERNS = {
    'ipv4': {
        'pattern': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'exclude': [
            r'^0\.0\.0\.0$',
            r'^127\.',
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^255\.'
        ]
    },
    'ipv6': {
        'pattern': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'exclude': [r'^::1$', r'^fe80:']
    },
    'domain': {
        'pattern': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'exclude': [
            r'\.microsoft\.com$',
            r'\.windows\.com$',
            r'\.google\.com$',
            r'\.googleapis\.com$',
            r'\.gstatic\.com$'
        ]
    },
    'md5': {
        'pattern': r'\b[a-fA-F0-9]{32}\b',
        'exclude': []
    },
    'sha1': {
        'pattern': r'\b[a-fA-F0-9]{40}\b',
        'exclude': []
    },
    'sha256': {
        'pattern': r'\b[a-fA-F0-9]{64}\b',
        'exclude': []
    },
    'filepath_windows': {
        'pattern': r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        'exclude': [
            r'^C:\\Windows\\System32\\',
            r'^C:\\Windows\\SysWOW64\\',
            r'^C:\\Program Files\\',
            r'^C:\\Program Files \(x86\)\\'
        ]
    },
    'filepath_linux': {
        'pattern': r'\/(?:[^\/\0]+\/)*[^\/\0]+',
        'exclude': [
            r'^\/usr\/bin\/',
            r'^\/usr\/sbin\/',
            r'^\/lib\/',
            r'^\/proc\/'
        ]
    },
    'registry': {
        'pattern': r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s]+',
        'exclude': []
    }
}
```

### 3.3 Pattern Extractor

```python
class IOCExtractor:
    def __init__(self):
        self.patterns = IOC_PATTERNS
        self.seen = set()
    
    def extract_from_text(self, text: str, source: str) -> List[IOC]:
        iocs = []
        
        for ioc_type, config in self.patterns.items():
            matches = re.findall(config['pattern'], text)
            
            for match in matches:
                if self._should_exclude(match, config['exclude']):
                    continue
                
                if match in self.seen:
                    continue
                self.seen.add(match)
                
                iocs.append(IOC(
                    ioc_type=ioc_type.split('_')[0],
                    value=match,
                    confidence=0.5,
                    source_plugin=source,
                    context={'raw_match': True},
                    extracted_at=datetime.now()
                ))
        
        return iocs
    
    def _should_exclude(self, value: str, exclude_patterns: List[str]) -> bool:
        for pattern in exclude_patterns:
            if re.match(pattern, value):
                return True
        return False
```

### 3.4 Context-Aware Extraction

```python
SUSPICIOUS_PATTERNS = {
    'windows': {
        'process_relationships': [
            {'parent': 'winword.exe', 'child': 'cmd.exe', 'technique': 'T1059'},
            {'parent': 'winword.exe', 'child': 'powershell.exe', 'technique': 'T1059.001'},
            {'parent': 'excel.exe', 'child': 'cmd.exe', 'technique': 'T1059'},
            {'parent': 'excel.exe', 'child': 'powershell.exe', 'technique': 'T1059.001'},
            {'parent': 'outlook.exe', 'child': 'cmd.exe', 'technique': 'T1059'},
            {'parent': 'services.exe', 'child': 'cmd.exe', 'technique': 'T1543.003'},
            {'parent': 'wmiprvse.exe', 'child': 'powershell.exe', 'technique': 'T1047'},
        ],
        'suspicious_commands': [
            {'pattern': r'-enc\s+[A-Za-z0-9+/=]+', 'technique': 'T1059.001', 'name': 'encoded_powershell'},
            {'pattern': r'-nop\s+-w\s+hidden', 'technique': 'T1059.001', 'name': 'hidden_powershell'},
            {'pattern': r'certutil.*-urlcache', 'technique': 'T1105', 'name': 'certutil_download'},
            {'pattern': r'bitsadmin.*\/transfer', 'technique': 'T1105', 'name': 'bitsadmin_download'},
            {'pattern': r'regsvr32.*\/s.*\/n.*\/u.*\/i:', 'technique': 'T1218.010', 'name': 'regsvr32_bypass'},
            {'pattern': r'mshta.*vbscript:', 'technique': 'T1218.005', 'name': 'mshta_execution'},
            {'pattern': r'rundll32.*javascript:', 'technique': 'T1218.011', 'name': 'rundll32_bypass'},
        ],
        'suspicious_paths': [
            {'pattern': r'\\Users\\[^\\]+\\AppData\\Local\\Temp\\', 'risk': 'medium'},
            {'pattern': r'\\ProgramData\\', 'risk': 'medium'},
            {'pattern': r'\\Users\\Public\\', 'risk': 'high'},
            {'pattern': r'\\Windows\\Temp\\', 'risk': 'medium'},
            {'pattern': r'\\Recycle', 'risk': 'high'},
        ]
    },
    'linux': {
        'process_relationships': [
            {'parent': 'nginx', 'child': 'bash', 'technique': 'T1505.003'},
            {'parent': 'nginx', 'child': 'sh', 'technique': 'T1505.003'},
            {'parent': 'apache2', 'child': 'bash', 'technique': 'T1505.003'},
            {'parent': 'apache2', 'child': 'sh', 'technique': 'T1505.003'},
            {'parent': 'httpd', 'child': 'bash', 'technique': 'T1505.003'},
            {'parent': 'java', 'child': 'bash', 'technique': 'T1059.004'},
        ],
        'suspicious_commands': [
            {'pattern': r'\/dev\/tcp\/\d+\.\d+\.\d+\.\d+\/\d+', 'technique': 'T1059.004', 'name': 'bash_reverse_shell'},
            {'pattern': r'nc\s+-e\s+\/bin\/(ba)?sh', 'technique': 'T1059.004', 'name': 'netcat_shell'},
            {'pattern': r'curl.*\|\s*(ba)?sh', 'technique': 'T1059.004', 'name': 'curl_pipe_shell'},
            {'pattern': r'wget.*-O\s*-.*\|\s*(ba)?sh', 'technique': 'T1059.004', 'name': 'wget_pipe_shell'},
            {'pattern': r'python.*-c.*import\s+socket', 'technique': 'T1059.006', 'name': 'python_reverse_shell'},
            {'pattern': r'perl.*-e.*socket', 'technique': 'T1059', 'name': 'perl_reverse_shell'},
        ],
        'suspicious_paths': [
            {'pattern': r'\/tmp\/\.', 'risk': 'high'},
            {'pattern': r'\/var\/tmp\/', 'risk': 'medium'},
            {'pattern': r'\/dev\/shm\/', 'risk': 'high'},
        ]
    }
}

class ContextAwareExtractor:
    def __init__(self, os_type: str):
        self.os_type = os_type
        self.patterns = SUSPICIOUS_PATTERNS.get(os_type, {})
    
    def analyze_processes(self, pslist_data: List[dict], pstree_data: List[dict]) -> List[IOC]:
        iocs = []
        
        process_map = {p['PID']: p for p in pslist_data}
        
        for proc in pslist_data:
            ppid = proc.get('PPID')
            if ppid and ppid in process_map:
                parent = process_map[ppid]
                parent_name = parent.get('ImageFileName', '').lower()
                child_name = proc.get('ImageFileName', '').lower()
                
                for rel in self.patterns.get('process_relationships', []):
                    if rel['parent'] in parent_name and rel['child'] in child_name:
                        iocs.append(IOC(
                            ioc_type='process',
                            value=f"{parent_name} -> {child_name}",
                            confidence=0.8,
                            source_plugin='pstree',
                            context={
                                'parent_pid': ppid,
                                'child_pid': proc['PID'],
                                'technique': rel['technique'],
                                'relationship': 'suspicious_parent_child'
                            },
                            extracted_at=datetime.now()
                        ))
        
        return iocs
    
    def analyze_cmdlines(self, cmdline_data: List[dict]) -> List[IOC]:
        iocs = []
        
        for entry in cmdline_data:
            cmdline = entry.get('Args', '')
            process_name = entry.get('ImageFileName', '')
            
            for cmd_pattern in self.patterns.get('suspicious_commands', []):
                if re.search(cmd_pattern['pattern'], cmdline, re.IGNORECASE):
                    iocs.append(IOC(
                        ioc_type='command',
                        value=cmdline[:500],
                        confidence=0.85,
                        source_plugin='cmdline',
                        context={
                            'process': process_name,
                            'pid': entry.get('PID'),
                            'technique': cmd_pattern['technique'],
                            'pattern_name': cmd_pattern['name']
                        },
                        extracted_at=datetime.now()
                    ))
        
        return iocs
    
    def analyze_malfind(self, malfind_data: List[dict]) -> List[IOC]:
        iocs = []
        
        for entry in malfind_data:
            protection = entry.get('Protection', '')
            if 'PAGE_EXECUTE_READWRITE' in protection:
                disasm = entry.get('Disasm', '')
                hexdump = entry.get('Hexdump', '')
                
                has_mz = hexdump and 'MZ' in hexdump[:10] if hexdump else False
                
                iocs.append(IOC(
                    ioc_type='injection',
                    value=f"PID {entry.get('PID')} @ {entry.get('Start VPN')}",
                    confidence=0.9 if has_mz else 0.7,
                    source_plugin='malfind',
                    context={
                        'pid': entry.get('PID'),
                        'process': entry.get('Process'),
                        'start_vpn': entry.get('Start VPN'),
                        'end_vpn': entry.get('End VPN'),
                        'protection': protection,
                        'has_pe_header': has_mz,
                        'technique': 'T1055'
                    },
                    extracted_at=datetime.now()
                ))
        
        return iocs
    
    def analyze_network(self, network_data: List[dict]) -> List[IOC]:
        iocs = []
        
        suspicious_processes = ['notepad.exe', 'calc.exe', 'mspaint.exe']
        suspicious_ports = [4444, 5555, 6666, 1337, 31337, 8080, 8443]
        
        for conn in network_data:
            process = conn.get('Owner', '').lower()
            remote_port = conn.get('ForeignPort', 0)
            remote_ip = conn.get('ForeignAddr', '')
            state = conn.get('State', '')
            
            is_suspicious = False
            reason = []
            
            if any(p in process for p in suspicious_processes):
                is_suspicious = True
                reason.append('suspicious_process_with_network')
            
            if remote_port in suspicious_ports:
                is_suspicious = True
                reason.append('suspicious_port')
            
            if state == 'ESTABLISHED' and remote_ip and not remote_ip.startswith(('0.', '127.', '10.', '192.168.')):
                if is_suspicious:
                    iocs.append(IOC(
                        ioc_type='ip',
                        value=remote_ip,
                        confidence=0.75,
                        source_plugin='network',
                        context={
                            'process': process,
                            'remote_port': remote_port,
                            'state': state,
                            'reason': reason,
                            'technique': 'T1071'
                        },
                        extracted_at=datetime.now()
                    ))
        
        return iocs
```

### 3.5 Extraction Pipeline

```python
class ExtractionPipeline:
    def __init__(self, os_type: str):
        self.os_type = os_type
        self.regex_extractor = IOCExtractor()
        self.context_extractor = ContextAwareExtractor(os_type)
    
    async def extract(self, plugin_results: Dict[str, PluginResult]) -> List[IOC]:
        all_iocs = []
        
        for plugin_name, result in plugin_results.items():
            if not result.success or not result.data:
                continue
            
            text_data = json.dumps(result.data)
            regex_iocs = self.regex_extractor.extract_from_text(text_data, plugin_name)
            all_iocs.extend(regex_iocs)
        
        if 'pslist' in plugin_results and 'pstree' in plugin_results:
            pslist_data = plugin_results['pslist'].data or []
            pstree_data = plugin_results['pstree'].data or []
            process_iocs = self.context_extractor.analyze_processes(pslist_data, pstree_data)
            all_iocs.extend(process_iocs)
        
        if 'cmdline' in plugin_results:
            cmdline_data = plugin_results['cmdline'].data or []
            cmdline_iocs = self.context_extractor.analyze_cmdlines(cmdline_data)
            all_iocs.extend(cmdline_iocs)
        
        malfind_key = 'windows.malware.malfind' if self.os_type == 'windows' else 'linux.malware.malfind'
        if malfind_key in plugin_results:
            malfind_data = plugin_results[malfind_key].data or []
            injection_iocs = self.context_extractor.analyze_malfind(malfind_data)
            all_iocs.extend(injection_iocs)
        
        network_keys = ['sockstat', 'handles']
        for key in network_keys:
            if key in plugin_results:
                network_data = plugin_results[key].data or []
                network_iocs = self.context_extractor.analyze_network(network_data)
                all_iocs.extend(network_iocs)
        
        return self._deduplicate(all_iocs)
    
    def _deduplicate(self, iocs: List[IOC]) -> List[IOC]:
        seen = {}
        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.value}"
            if key not in seen or ioc.confidence > seen[key].confidence:
                seen[key] = ioc
        return list(seen.values())
```

## MCP Tool: extract_iocs

```python
@mcp.tool()
async def extract_iocs(
    plugin_results: dict,
    os_type: str = "windows"
) -> dict:
    """
    Extract IOCs from Volatility3 plugin results.
    
    Args:
        plugin_results: Results from batch_plugins tool
        os_type: Operating system type (windows/linux)
    
    Returns:
        Extracted IOCs with confidence scores and context
    """
    results = {
        name: PluginResult(
            plugin=name,
            success=data.get('success', False),
            error=data.get('error'),
            data=data.get('data')
        )
        for name, data in plugin_results.get('data', {}).items()
    }
    
    pipeline = ExtractionPipeline(os_type)
    iocs = await pipeline.extract(results)
    
    by_type = {}
    for ioc in iocs:
        if ioc.ioc_type not in by_type:
            by_type[ioc.ioc_type] = []
        by_type[ioc.ioc_type].append(ioc.to_dict())
    
    high_confidence = [i for i in iocs if i.confidence >= 0.7]
    medium_confidence = [i for i in iocs if 0.4 <= i.confidence < 0.7]
    low_confidence = [i for i in iocs if i.confidence < 0.4]
    
    return {
        "total": len(iocs),
        "by_confidence": {
            "high": len(high_confidence),
            "medium": len(medium_confidence),
            "low": len(low_confidence)
        },
        "by_type": {k: len(v) for k, v in by_type.items()},
        "iocs": [ioc.to_dict() for ioc in sorted(iocs, key=lambda x: -x.confidence)],
        "next_action": "Call validate_iocs to verify against threat intelligence"
    }
```

## Output Schema

```json
{
  "total": 45,
  "by_confidence": {
    "high": 8,
    "medium": 22,
    "low": 15
  },
  "by_type": {
    "ip": 12,
    "domain": 5,
    "process": 8,
    "command": 4,
    "injection": 3,
    "filepath": 10,
    "registry": 3
  },
  "iocs": [
    {
      "type": "injection",
      "value": "PID 1234 @ 0x7ff00000",
      "confidence": 0.9,
      "source": "malfind",
      "context": {
        "pid": 1234,
        "process": "svchost.exe",
        "protection": "PAGE_EXECUTE_READWRITE",
        "has_pe_header": true,
        "technique": "T1055"
      },
      "extracted_at": "2026-01-28T14:30:00Z"
    }
  ],
  "next_action": "Call validate_iocs to verify against threat intelligence"
}
```
# Phase 5: Presentation & Reporting

## Overview

Phase 5 generates structured reports with MITRE ATT&CK mapping and actionable recommendations.

## Components

### 5.1 MITRE ATT&CK Mapper

```python
MITRE_MAPPINGS = {
    'T1055': {
        'name': 'Process Injection',
        'tactic': 'Defense Evasion',
        'description': 'Adversaries may inject code into processes to evade defenses',
        'indicators': ['malfind_rwx', 'hollow_process', 'dll_injection'],
        'recommendations': [
            'Analyze injected memory regions',
            'Dump suspicious process memory',
            'Check for known injection signatures'
        ]
    },
    'T1055.001': {
        'name': 'Dynamic-link Library Injection',
        'tactic': 'Defense Evasion',
        'description': 'Adversaries may inject DLLs into processes',
        'indicators': ['suspicious_dll_load', 'ldrmodules_unlinked'],
        'recommendations': [
            'Review loaded DLLs for anomalies',
            'Check DLL paths against known-good'
        ]
    },
    'T1059': {
        'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
        'description': 'Adversaries may abuse command interpreters',
        'indicators': ['suspicious_cmdline', 'script_execution'],
        'recommendations': [
            'Review command line arguments',
            'Check for encoded commands',
            'Analyze script contents'
        ]
    },
    'T1059.001': {
        'name': 'PowerShell',
        'tactic': 'Execution',
        'description': 'Adversaries may abuse PowerShell',
        'indicators': ['encoded_powershell', 'hidden_window', 'bypass_policy'],
        'recommendations': [
            'Decode base64 commands',
            'Check PowerShell logs',
            'Review script block logging'
        ]
    },
    'T1059.004': {
        'name': 'Unix Shell',
        'tactic': 'Execution',
        'description': 'Adversaries may abuse Unix shell',
        'indicators': ['bash_reverse_shell', 'curl_wget_execution'],
        'recommendations': [
            'Review bash history',
            'Check for reverse shell patterns',
            'Analyze cron jobs'
        ]
    },
    'T1071': {
        'name': 'Application Layer Protocol',
        'tactic': 'Command and Control',
        'description': 'Adversaries may communicate using application layer protocols',
        'indicators': ['suspicious_network', 'c2_connection'],
        'recommendations': [
            'Block identified C2 IPs',
            'Analyze network traffic',
            'Check for beaconing patterns'
        ]
    },
    'T1071.001': {
        'name': 'Web Protocols',
        'tactic': 'Command and Control',
        'description': 'Adversaries may use HTTP/HTTPS for C2',
        'indicators': ['http_c2', 'suspicious_user_agent'],
        'recommendations': [
            'Review HTTP traffic logs',
            'Check for unusual domains',
            'Analyze SSL certificates'
        ]
    },
    'T1105': {
        'name': 'Ingress Tool Transfer',
        'tactic': 'Command and Control',
        'description': 'Adversaries may transfer tools from external systems',
        'indicators': ['certutil_download', 'bitsadmin_download', 'powershell_download'],
        'recommendations': [
            'Block download URLs',
            'Check downloaded file hashes',
            'Review download locations'
        ]
    },
    'T1547.001': {
        'name': 'Registry Run Keys / Startup Folder',
        'tactic': 'Persistence',
        'description': 'Adversaries may achieve persistence via Registry Run keys',
        'indicators': ['run_key_modification', 'startup_folder'],
        'recommendations': [
            'Review Run key entries',
            'Check startup folder contents',
            'Compare against baseline'
        ]
    },
    'T1053.005': {
        'name': 'Scheduled Task',
        'tactic': 'Persistence',
        'description': 'Adversaries may abuse scheduled tasks',
        'indicators': ['scheduled_task_creation'],
        'recommendations': [
            'Review scheduled tasks',
            'Check task actions and triggers',
            'Compare against baseline'
        ]
    },
    'T1543.003': {
        'name': 'Windows Service',
        'tactic': 'Persistence',
        'description': 'Adversaries may create services for persistence',
        'indicators': ['service_creation', 'service_modification'],
        'recommendations': [
            'Review new services',
            'Check service binaries',
            'Validate service configurations'
        ]
    },
    'T1505.003': {
        'name': 'Web Shell',
        'tactic': 'Persistence',
        'description': 'Adversaries may install web shells on servers',
        'indicators': ['webshell_process', 'web_server_spawns_shell'],
        'recommendations': [
            'Review web server directories',
            'Check for new/modified files',
            'Analyze web server logs'
        ]
    },
    'T1218.010': {
        'name': 'Regsvr32',
        'tactic': 'Defense Evasion',
        'description': 'Adversaries may abuse Regsvr32 to proxy execution',
        'indicators': ['regsvr32_scriptlet'],
        'recommendations': [
            'Review Regsvr32 executions',
            'Block scriptlet execution',
            'Monitor COM object registration'
        ]
    },
    'T1218.005': {
        'name': 'Mshta',
        'tactic': 'Defense Evasion',
        'description': 'Adversaries may abuse mshta.exe to proxy execution',
        'indicators': ['mshta_execution'],
        'recommendations': [
            'Review mshta.exe usage',
            'Block HTA file execution',
            'Monitor script execution'
        ]
    },
    'T1218.011': {
        'name': 'Rundll32',
        'tactic': 'Defense Evasion',
        'description': 'Adversaries may abuse rundll32.exe to proxy execution',
        'indicators': ['rundll32_javascript'],
        'recommendations': [
            'Review rundll32.exe calls',
            'Check for unusual DLL loading',
            'Monitor script execution'
        ]
    },
    'T1036': {
        'name': 'Masquerading',
        'tactic': 'Defense Evasion',
        'description': 'Adversaries may masquerade as legitimate processes',
        'indicators': ['process_path_mismatch', 'name_spoofing'],
        'recommendations': [
            'Verify process paths',
            'Check digital signatures',
            'Compare against known-good hashes'
        ]
    },
    'T1047': {
        'name': 'Windows Management Instrumentation',
        'tactic': 'Execution',
        'description': 'Adversaries may abuse WMI for execution',
        'indicators': ['wmi_execution', 'wmiprvse_spawns_process'],
        'recommendations': [
            'Review WMI subscriptions',
            'Check WMI activity logs',
            'Monitor wmiprvse.exe children'
        ]
    }
}

@dataclass
class MITREReport:
    techniques: Dict[str, dict]
    tactics: Dict[str, List[dict]]
    total_techniques: int

class MITREMapper:
    def __init__(self):
        self.mappings = MITRE_MAPPINGS
    
    def map_iocs(self, validated_iocs: List[ValidatedIOC]) -> MITREReport:
        technique_map = {}
        
        for ioc in validated_iocs:
            if ioc.verdict == 'benign':
                continue
            
            technique_id = ioc.ioc.context.get('technique')
            if technique_id and technique_id in self.mappings:
                if technique_id not in technique_map:
                    technique_map[technique_id] = {
                        'technique': self.mappings[technique_id],
                        'iocs': []
                    }
                technique_map[technique_id]['iocs'].append(ioc)
        
        tactics = {}
        for tid, data in technique_map.items():
            tactic = data['technique']['tactic']
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append({
                'id': tid,
                'name': data['technique']['name'],
                'ioc_count': len(data['iocs']),
                'recommendations': data['technique']['recommendations']
            })
        
        return MITREReport(
            techniques=technique_map,
            tactics=tactics,
            total_techniques=len(technique_map)
        )
    
    def generate_matrix(self, mitre_report: MITREReport) -> dict:
        matrix = {
            'Reconnaissance': [],
            'Resource Development': [],
            'Initial Access': [],
            'Execution': [],
            'Persistence': [],
            'Privilege Escalation': [],
            'Defense Evasion': [],
            'Credential Access': [],
            'Discovery': [],
            'Lateral Movement': [],
            'Collection': [],
            'Command and Control': [],
            'Exfiltration': [],
            'Impact': []
        }
        
        for tactic, techniques in mitre_report.tactics.items():
            if tactic in matrix:
                matrix[tactic] = techniques
        
        return matrix
```

### 5.2 Report Generator

```python
@dataclass
class ForensicReport:
    case_id: str
    generated_at: datetime
    os_info: OSInfo
    summary: dict
    iocs: dict
    mitre: dict
    recommendations: List[str]
    timeline: List[dict]

class ReportGenerator:
    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(
        self,
        case: Case,
        validated_iocs: List[ValidatedIOC],
        mitre_report: MITREReport
    ) -> ForensicReport:
        malicious = [i for i in validated_iocs if i.verdict == 'malicious']
        suspicious = [i for i in validated_iocs if i.verdict == 'suspicious']
        
        threat_level = 'CRITICAL' if len(malicious) > 5 else \
                       'HIGH' if len(malicious) > 0 else \
                       'MEDIUM' if len(suspicious) > 5 else 'LOW'
        
        recommendations = self._generate_recommendations(malicious, suspicious, mitre_report)
        timeline = self._generate_timeline(validated_iocs)
        
        return ForensicReport(
            case_id=case.id,
            generated_at=datetime.now(),
            os_info=case.os_info,
            summary={
                'threat_level': threat_level,
                'total_iocs': len(validated_iocs),
                'malicious': len(malicious),
                'suspicious': len(suspicious),
                'techniques_detected': mitre_report.total_techniques,
                'analysis_duration_minutes': (datetime.now() - case.created_at).seconds // 60
            },
            iocs={
                'malicious': [self._ioc_to_dict(i) for i in malicious],
                'suspicious': [self._ioc_to_dict(i) for i in suspicious]
            },
            mitre={
                'matrix': MITREMapper().generate_matrix(mitre_report),
                'techniques': [
                    {
                        'id': tid,
                        'name': data['technique']['name'],
                        'tactic': data['technique']['tactic'],
                        'ioc_count': len(data['iocs'])
                    }
                    for tid, data in mitre_report.techniques.items()
                ]
            },
            recommendations=recommendations,
            timeline=timeline
        )
    
    def _generate_recommendations(
        self,
        malicious: List[ValidatedIOC],
        suspicious: List[ValidatedIOC],
        mitre_report: MITREReport
    ) -> List[str]:
        recommendations = []
        
        malicious_ips = [i.ioc.value for i in malicious if i.ioc.ioc_type == 'ip']
        if malicious_ips:
            recommendations.append(f"IMMEDIATE: Block the following IPs at firewall: {', '.join(malicious_ips[:5])}")
        
        malicious_domains = [i.ioc.value for i in malicious if i.ioc.ioc_type == 'domain']
        if malicious_domains:
            recommendations.append(f"IMMEDIATE: Block domains in DNS/proxy: {', '.join(malicious_domains[:5])}")
        
        malicious_hashes = [i.ioc.value for i in malicious if i.ioc.ioc_type in ['md5', 'sha256', 'hash']]
        if malicious_hashes:
            recommendations.append("HIGH: Add file hashes to EDR blocklist")
        
        injections = [i for i in malicious if i.ioc.ioc_type == 'injection']
        if injections:
            recommendations.append("HIGH: Isolate affected hosts - active code injection detected")
        
        for tid, data in mitre_report.techniques.items():
            for rec in data['technique']['recommendations'][:2]:
                recommendations.append(f"MEDIUM: {rec}")
        
        recommendations.append("STANDARD: Collect additional artifacts (event logs, prefetch, etc.)")
        recommendations.append("STANDARD: Document findings and preserve evidence chain")
        
        return recommendations[:15]
    
    def _generate_timeline(self, validated_iocs: List[ValidatedIOC]) -> List[dict]:
        events = []
        
        for ioc in validated_iocs:
            if ioc.verdict == 'benign':
                continue
            
            events.append({
                'timestamp': ioc.ioc.extracted_at.isoformat(),
                'type': ioc.ioc.ioc_type,
                'value': ioc.ioc.value[:100],
                'verdict': ioc.verdict,
                'source': ioc.ioc.source_plugin,
                'technique': ioc.ioc.context.get('technique', 'N/A')
            })
        
        return sorted(events, key=lambda x: x['timestamp'])
    
    def _ioc_to_dict(self, validated: ValidatedIOC) -> dict:
        return {
            'type': validated.ioc.ioc_type,
            'value': validated.ioc.value,
            'confidence': validated.final_confidence,
            'verdict': validated.verdict,
            'reason': validated.reason,
            'source': validated.ioc.source_plugin,
            'context': validated.ioc.context,
            'technique': validated.ioc.context.get('technique')
        }
    
    def save_json(self, report: ForensicReport) -> str:
        filename = f"{report.case_id}_{report.generated_at.strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        
        return str(filepath)
    
    def save_markdown(self, report: ForensicReport) -> str:
        filename = f"{report.case_id}_{report.generated_at.strftime('%Y%m%d_%H%M%S')}.md"
        filepath = self.output_dir / filename
        
        md_content = self._generate_markdown(report)
        
        with open(filepath, 'w') as f:
            f.write(md_content)
        
        return str(filepath)
    
    def _generate_markdown(self, report: ForensicReport) -> str:
        md = f"""# Forensic Analysis Report

## Case Information
- **Case ID**: {report.case_id}
- **Generated**: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}
- **OS**: {report.os_info.os_type} {report.os_info.version} ({report.os_info.arch})

## Executive Summary

| Metric | Value |
|--------|-------|
| **Threat Level** | {report.summary['threat_level']} |
| **Total IOCs** | {report.summary['total_iocs']} |
| **Malicious** | {report.summary['malicious']} |
| **Suspicious** | {report.summary['suspicious']} |
| **ATT&CK Techniques** | {report.summary['techniques_detected']} |
| **Analysis Duration** | {report.summary['analysis_duration_minutes']} minutes |

## Recommendations

"""
        for i, rec in enumerate(report.recommendations, 1):
            md += f"{i}. {rec}\n"
        
        md += "\n## Malicious Indicators\n\n"
        if report.iocs['malicious']:
            md += "| Type | Value | Confidence | Technique |\n"
            md += "|------|-------|------------|----------|\n"
            for ioc in report.iocs['malicious'][:20]:
                md += f"| {ioc['type']} | `{ioc['value'][:50]}` | {ioc['confidence']:.2f} | {ioc.get('technique', 'N/A')} |\n"
        else:
            md += "*No malicious indicators found*\n"
        
        md += "\n## Suspicious Indicators\n\n"
        if report.iocs['suspicious']:
            md += "| Type | Value | Confidence | Technique |\n"
            md += "|------|-------|------------|----------|\n"
            for ioc in report.iocs['suspicious'][:20]:
                md += f"| {ioc['type']} | `{ioc['value'][:50]}` | {ioc['confidence']:.2f} | {ioc.get('technique', 'N/A')} |\n"
        else:
            md += "*No suspicious indicators found*\n"
        
        md += "\n## MITRE ATT&CK Coverage\n\n"
        for tactic, techniques in report.mitre['matrix'].items():
            if techniques:
                md += f"### {tactic}\n"
                for tech in techniques:
                    md += f"- **{tech['id']}**: {tech['name']} ({tech['ioc_count']} IOCs)\n"
                md += "\n"
        
        md += "\n## Timeline\n\n"
        if report.timeline:
            md += "| Timestamp | Type | Value | Verdict | Technique |\n"
            md += "|-----------|------|-------|---------|----------|\n"
            for event in report.timeline[:30]:
                md += f"| {event['timestamp']} | {event['type']} | `{event['value'][:30]}` | {event['verdict']} | {event['technique']} |\n"
        
        md += "\n---\n*Report generated by Volatility3 IOC Extraction System*\n"
        
        return md
```

### 5.3 MCP Tools

```python
@mcp.tool()
async def map_mitre(
    validated_iocs: dict
) -> dict:
    """
    Map validated IOCs to MITRE ATT&CK techniques.
    
    Args:
        validated_iocs: Output from validate_iocs tool
    
    Returns:
        MITRE ATT&CK mapping with techniques and tactics
    """
    iocs = []
    for verdict in ['malicious', 'suspicious']:
        for ioc_data in validated_iocs.get(verdict, []):
            iocs.append(ValidatedIOC(
                ioc=IOC(
                    ioc_type=ioc_data['type'],
                    value=ioc_data['value'],
                    confidence=ioc_data.get('confidence', 0.5),
                    source_plugin=ioc_data.get('source', 'unknown'),
                    context=ioc_data.get('context', {}),
                    extracted_at=datetime.now()
                ),
                final_confidence=ioc_data.get('confidence', 0.5),
                verdict=verdict,
                validation_results=[],
                reason=ioc_data.get('reason', '')
            ))
    
    mapper = MITREMapper()
    mitre_report = mapper.map_iocs(iocs)
    matrix = mapper.generate_matrix(mitre_report)
    
    active_tactics = {k: v for k, v in matrix.items() if v}
    
    return {
        "total_techniques": mitre_report.total_techniques,
        "tactics_involved": list(active_tactics.keys()),
        "matrix": matrix,
        "techniques": [
            {
                "id": tid,
                "name": data['technique']['name'],
                "tactic": data['technique']['tactic'],
                "description": data['technique']['description'],
                "ioc_count": len(data['iocs']),
                "recommendations": data['technique']['recommendations']
            }
            for tid, data in mitre_report.techniques.items()
        ],
        "next_action": "Call generate_report to create final report"
    }


@mcp.tool()
async def generate_report(
    case_id: str,
    validated_iocs: dict,
    mitre_mapping: dict,
    format: str = "both"
) -> dict:
    """
    Generate forensic analysis report.
    
    Args:
        case_id: Case identifier
        validated_iocs: Output from validate_iocs tool
        mitre_mapping: Output from map_mitre tool
        format: Output format (json, markdown, both)
    
    Returns:
        Report paths and summary
    """
    case = await get_case(case_id)
    if not case:
        raise ValueError(f"Case not found: {case_id}")
    
    iocs = []
    for verdict in ['malicious', 'suspicious', 'benign']:
        for ioc_data in validated_iocs.get(verdict, []):
            iocs.append(ValidatedIOC(
                ioc=IOC(
                    ioc_type=ioc_data['type'],
                    value=ioc_data['value'],
                    confidence=ioc_data.get('confidence', 0.5),
                    source_plugin=ioc_data.get('source', 'unknown'),
                    context=ioc_data.get('context', {}),
                    extracted_at=datetime.now()
                ),
                final_confidence=ioc_data.get('confidence', 0.5),
                verdict=verdict,
                validation_results=[],
                reason=ioc_data.get('reason', '')
            ))
    
    technique_map = {}
    for tech in mitre_mapping.get('techniques', []):
        technique_map[tech['id']] = {
            'technique': {
                'name': tech['name'],
                'tactic': tech['tactic'],
                'description': tech.get('description', ''),
                'recommendations': tech.get('recommendations', [])
            },
            'iocs': [i for i in iocs if i.ioc.context.get('technique') == tech['id']]
        }
    
    tactics = {}
    for tech in mitre_mapping.get('techniques', []):
        tactic = tech['tactic']
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append({
            'id': tech['id'],
            'name': tech['name'],
            'ioc_count': tech['ioc_count'],
            'recommendations': tech.get('recommendations', [])
        })
    
    mitre_report = MITREReport(
        techniques=technique_map,
        tactics=tactics,
        total_techniques=mitre_mapping.get('total_techniques', 0)
    )
    
    generator = ReportGenerator()
    report = generator.generate(case, iocs, mitre_report)
    
    paths = {}
    if format in ['json', 'both']:
        paths['json'] = generator.save_json(report)
        await ctx.info(f"JSON report saved: {paths['json']}")
    
    if format in ['markdown', 'both']:
        paths['markdown'] = generator.save_markdown(report)
        await ctx.info(f"Markdown report saved: {paths['markdown']}")
    
    await update_case_status(case_id, 'completed')
    
    return {
        "case_id": case_id,
        "status": "completed",
        "threat_level": report.summary['threat_level'],
        "summary": report.summary,
        "report_paths": paths,
        "top_recommendations": report.recommendations[:5],
        "techniques_detected": [
            {"id": t['id'], "name": t['name']}
            for t in mitre_mapping.get('techniques', [])[:10]
        ]
    }
```

## Output Schema

### map_mitre Output

```json
{
  "total_techniques": 5,
  "tactics_involved": ["Execution", "Defense Evasion", "Command and Control"],
  "matrix": {
    "Execution": [
      {"id": "T1059.001", "name": "PowerShell", "ioc_count": 3}
    ],
    "Defense Evasion": [
      {"id": "T1055", "name": "Process Injection", "ioc_count": 2}
    ],
    "Command and Control": [
      {"id": "T1071", "name": "Application Layer Protocol", "ioc_count": 4}
    ]
  },
  "techniques": [
    {
      "id": "T1055",
      "name": "Process Injection",
      "tactic": "Defense Evasion",
      "description": "Adversaries may inject code into processes",
      "ioc_count": 2,
      "recommendations": [
        "Analyze injected memory regions",
        "Dump suspicious process memory"
      ]
    }
  ],
  "next_action": "Call generate_report to create final report"
}
```

### generate_report Output

```json
{
  "case_id": "CASE-20260128-143052",
  "status": "completed",
  "threat_level": "HIGH",
  "summary": {
    "threat_level": "HIGH",
    "total_iocs": 45,
    "malicious": 8,
    "suspicious": 15,
    "techniques_detected": 5,
    "analysis_duration_minutes": 8
  },
  "report_paths": {
    "json": "data/reports/CASE-20260128-143052_20260128_143852.json",
    "markdown": "data/reports/CASE-20260128-143052_20260128_143852.md"
  },
  "top_recommendations": [
    "IMMEDIATE: Block the following IPs at firewall: 192.0.2.100, 198.51.100.50",
    "IMMEDIATE: Block domains in DNS/proxy: evil.com, malware.net",
    "HIGH: Isolate affected hosts - active code injection detected",
    "HIGH: Add file hashes to EDR blocklist",
    "MEDIUM: Decode base64 commands"
  ],
  "techniques_detected": [
    {"id": "T1055", "name": "Process Injection"},
    {"id": "T1059.001", "name": "PowerShell"},
    {"id": "T1071", "name": "Application Layer Protocol"}
  ]
}
```

## Complete Pipeline Example

```python
async def full_analysis_pipeline(dump_path: str, goal: str = "malware_detection"):
    """Complete forensic analysis pipeline."""
    
    triage_result = await smart_triage(dump_path, goal)
    case_id = triage_result['case_id']
    plugins = triage_result['plan']['plugins']
    
    execution_result = await batch_plugins(dump_path, plugins)
    
    extraction_result = await extract_iocs(
        execution_result,
        triage_result['os']['type']
    )
    
    validation_result = await validate_iocs(
        extraction_result['iocs'],
        triage_result['os']['type']
    )
    
    mitre_result = await map_mitre(validation_result)
    
    report_result = await generate_report(
        case_id,
        validation_result,
        mitre_result,
        format="both"
    )
    
    return report_result
```

## Sample Markdown Report

```markdown
# Forensic Analysis Report

## Case Information
- **Case ID**: CASE-20260128-143052
- **Generated**: 2026-01-28 14:38:52
- **OS**: windows 10 (x64)

## Executive Summary

| Metric | Value |
|--------|-------|
| **Threat Level** | HIGH |
| **Total IOCs** | 45 |
| **Malicious** | 8 |
| **Suspicious** | 15 |
| **ATT&CK Techniques** | 5 |
| **Analysis Duration** | 8 minutes |

## Recommendations

1. IMMEDIATE: Block the following IPs at firewall: 192.0.2.100, 198.51.100.50
2. IMMEDIATE: Block domains in DNS/proxy: evil.com, malware.net
3. HIGH: Isolate affected hosts - active code injection detected
4. HIGH: Add file hashes to EDR blocklist
5. MEDIUM: Decode base64 commands
6. MEDIUM: Check PowerShell logs
7. MEDIUM: Analyze injected memory regions
8. STANDARD: Collect additional artifacts (event logs, prefetch, etc.)
9. STANDARD: Document findings and preserve evidence chain

## Malicious Indicators

| Type | Value | Confidence | Technique |
|------|-------|------------|----------|
| injection | `PID 1234 @ 0x7ff00000` | 0.90 | T1055 |
| ip | `192.0.2.100` | 0.85 | T1071 |
| command | `powershell -enc JABjAGwAaQBlAG4AdAA...` | 0.88 | T1059.001 |

## MITRE ATT&CK Coverage

### Execution
- **T1059.001**: PowerShell (3 IOCs)

### Defense Evasion
- **T1055**: Process Injection (2 IOCs)

### Command and Control
- **T1071**: Application Layer Protocol (4 IOCs)

## Timeline

| Timestamp | Type | Value | Verdict | Technique |
|-----------|------|-------|---------|----------|
| 2026-01-28T14:30:00Z | injection | `PID 1234 @ 0x7ff00000` | malicious | T1055 |
| 2026-01-28T14:30:01Z | command | `powershell -enc JABjAG...` | malicious | T1059.001 |
| 2026-01-28T14:30:02Z | ip | `192.0.2.100` | malicious | T1071 |

---
*Report generated by Volatility3 IOC Extraction System*
```
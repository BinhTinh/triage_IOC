from dataclasses import dataclass, field
from typing import List, Dict, Any
from pathlib import Path
import yaml

from src.models.ioc import ValidatedIOC
from src.config.settings import settings


@dataclass
class MITREReport:
    techniques: Dict[str, dict]
    tactics: Dict[str, List[dict]]
    total_techniques: int


MITRE_MAPPINGS = {
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "description": "Adversaries may inject code into processes to evade defenses",
        "recommendations": [
            "Analyze injected memory regions",
            "Dump suspicious process memory",
            "Check for known injection signatures"
        ]
    },
    "T1055.001": {
        "name": "Dynamic-link Library Injection",
        "tactic": "Defense Evasion",
        "description": "Adversaries may inject DLLs into processes",
        "recommendations": [
            "Review loaded DLLs for anomalies",
            "Check DLL paths against known-good"
        ]
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command interpreters",
        "recommendations": [
            "Review command line arguments",
            "Check for encoded commands",
            "Analyze script contents"
        ]
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell",
        "recommendations": [
            "Decode base64 commands",
            "Check PowerShell logs",
            "Review script block logging"
        ]
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse Unix shell",
        "recommendations": [
            "Review bash history",
            "Check for reverse shell patterns",
            "Analyze cron jobs"
        ]
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols",
        "recommendations": [
            "Block identified C2 IPs",
            "Analyze network traffic",
            "Check for beaconing patterns"
        ]
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may use HTTP/HTTPS for C2",
        "recommendations": [
            "Review HTTP traffic logs",
            "Check for unusual domains",
            "Analyze SSL certificates"
        ]
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools from external systems",
        "recommendations": [
            "Block download URLs",
            "Check downloaded file hashes",
            "Review download locations"
        ]
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversaries may achieve persistence via Registry Run keys",
        "recommendations": [
            "Review Run key entries",
            "Check startup folder contents",
            "Compare against baseline"
        ]
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "Persistence",
        "description": "Adversaries may abuse scheduled tasks",
        "recommendations": [
            "Review scheduled tasks",
            "Check task actions and triggers",
            "Compare against baseline"
        ]
    },
    "T1543.003": {
        "name": "Windows Service",
        "tactic": "Persistence",
        "description": "Adversaries may create services for persistence",
        "recommendations": [
            "Review new services",
            "Check service binaries",
            "Validate service configurations"
        ]
    },
    "T1505.003": {
        "name": "Web Shell",
        "tactic": "Persistence",
        "description": "Adversaries may install web shells on servers",
        "recommendations": [
            "Review web server directories",
            "Check for new/modified files",
            "Analyze web server logs"
        ]
    },
    "T1036": {
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": "Adversaries may masquerade as legitimate processes",
        "recommendations": [
            "Verify process paths",
            "Check digital signatures",
            "Compare against known-good hashes"
        ]
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "description": "Adversaries may abuse WMI for execution",
        "recommendations": [
            "Review WMI subscriptions",
            "Check WMI activity logs",
            "Monitor wmiprvse.exe children"
        ]
    },
    "T1218.010": {
        "name": "Regsvr32",
        "tactic": "Defense Evasion",
        "description": "Adversaries may abuse Regsvr32 to proxy execution",
        "recommendations": [
            "Review Regsvr32 executions",
            "Block scriptlet execution"
        ]
    },
    "T1218.005": {
        "name": "Mshta",
        "tactic": "Defense Evasion",
        "description": "Adversaries may abuse mshta.exe for execution",
        "recommendations": [
            "Review mshta.exe usage",
            "Block HTA file execution"
        ]
    },
    "T1218.011": {
        "name": "Rundll32",
        "tactic": "Defense Evasion",
        "description": "Adversaries may abuse rundll32.exe for execution",
        "recommendations": [
            "Review rundll32.exe calls",
            "Check for unusual DLL loading"
        ]
    }
}


class MITREMapper:
    def __init__(self):
        self.mappings = self._load_mappings()
    
    def _load_mappings(self) -> dict:
        mapping_path = Path(settings.config_dir) / "mitre_mappings.yaml"
        if mapping_path.exists():
            with open(mapping_path) as f:
                data = yaml.safe_load(f)
                return data.get("techniques", MITRE_MAPPINGS)
        return MITRE_MAPPINGS
    
    def map_iocs(self, validated_iocs: List[ValidatedIOC]) -> MITREReport:
        technique_map = {}
        
        for ioc in validated_iocs:
            if ioc.verdict == "benign":
                continue
            
            technique_id = ioc.ioc.context.get("technique")
            if technique_id and technique_id in self.mappings:
                if technique_id not in technique_map:
                    technique_map[technique_id] = {
                        "technique": self.mappings[technique_id],
                        "iocs": []
                    }
                technique_map[technique_id]["iocs"].append(ioc)
        
        tactics = {}
        for tid, data in technique_map.items():
            tactic = data["technique"]["tactic"]
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append({
                "id": tid,
                "name": data["technique"]["name"],
                "ioc_count": len(data["iocs"]),
                "recommendations": data["technique"]["recommendations"]
            })
        
        return MITREReport(
            techniques=technique_map,
            tactics=tactics,
            total_techniques=len(technique_map)
        )
    
    def generate_matrix(self, mitre_report: MITREReport) -> dict:
        matrix = {
            "Reconnaissance": [],
            "Resource Development": [],
            "Initial Access": [],
            "Execution": [],
            "Persistence": [],
            "Privilege Escalation": [],
            "Defense Evasion": [],
            "Credential Access": [],
            "Discovery": [],
            "Lateral Movement": [],
            "Collection": [],
            "Command and Control": [],
            "Exfiltration": [],
            "Impact": []
        }
        
        for tactic, techniques in mitre_report.tactics.items():
            if tactic in matrix:
                matrix[tactic] = techniques
        
        return matrix
    
    def get_technique_info(self, technique_id: str) -> dict:
        if technique_id in self.mappings:
            return {
                "id": technique_id,
                **self.mappings[technique_id]
            }
        return {"id": technique_id, "name": "Unknown", "tactic": "Unknown"}
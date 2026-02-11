from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
from dataclasses import dataclass
import re

class RegistryCategory(Enum):
    PERSISTENCE = "persistence"
    CONFIGURATION = "configuration"
    CREDENTIAL_ACCESS = "credential_access"
    DEFENSE_EVASION = "defense_evasion"
    EXECUTION = "execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"

@dataclass
class RegistryIndicator:
    key_pattern: str
    category: RegistryCategory
    mitre_technique: str
    severity: str
    description: str
    check_function: str
    malware_families: List[str]

class RegistryAnalyzer:
    def __init__(self):
        self.indicators = self._build_indicators()
        self.findings = []
    
    def _build_indicators(self) -> List[RegistryIndicator]:
        return [
            RegistryIndicator(
                key_pattern=r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                category=RegistryCategory.PERSISTENCE,
                mitre_technique="T1547.001",
                severity="critical",
                description="Autostart via Run key",
                check_function="check_run_key",
                malware_families=["ALL"]
            ),
            RegistryIndicator(
                key_pattern=r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                category=RegistryCategory.PERSISTENCE,
                mitre_technique="T1547.001",
                severity="high",
                description="One-time autostart",
                check_function="check_run_key",
                malware_families=["ALL"]
            ),
            RegistryIndicator(
                key_pattern=r"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                category=RegistryCategory.PERSISTENCE,
                mitre_technique="T1547.001",
                severity="critical",
                description="32-bit persistence on 64-bit system",
                check_function="check_run_key",
                malware_families=["ALL"]
            ),
            RegistryIndicator(
                key_pattern=r"System\\CurrentControlSet\\Services",
                category=RegistryCategory.PERSISTENCE,
                mitre_technique="T1543.003",
                severity="critical",
                description="Windows service creation",
                check_function="check_service_key",
                malware_families=["RAT", "Backdoor", "Rootkit", "Ransomware"]
            ),
            RegistryIndicator(
                key_pattern=r"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                category=RegistryCategory.PERSISTENCE,
                mitre_technique="T1547.004",
                severity="critical",
                description="Winlogon helper DLL",
                check_function="check_winlogon_key",
                malware_families=["Rootkit", "Backdoor"]
            ),
            RegistryIndicator(
                key_pattern=r"Software\\Microsoft\\Windows Defender\\Exclusions",
                category=RegistryCategory.DEFENSE_EVASION,
                mitre_technique="T1562.001",
                severity="critical",
                description="Windows Defender exclusion",
                check_function="check_defender_exclusion",
                malware_families=["Ransomware", "Stealer", "RAT", "Miner"]
            ),
            RegistryIndicator(
                key_pattern=r"System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy",
                category=RegistryCategory.DEFENSE_EVASION,
                mitre_technique="T1562.004",
                severity="high",
                description="Firewall rule modification",
                check_function="check_firewall_key",
                malware_families=["RAT", "Backdoor", "Banker"]
            ),
            RegistryIndicator(
                key_pattern=r"System\\CurrentControlSet\\Control\\SafeBoot",
                category=RegistryCategory.DEFENSE_EVASION,
                mitre_technique="T1562",
                severity="critical",
                description="Safe Mode modification",
                check_function="check_safeboot_key",
                malware_families=["Ransomware"]
            ),
            RegistryIndicator(
                key_pattern=r"Software\\Policies\\Google\\Chrome",
                category=RegistryCategory.CREDENTIAL_ACCESS,
                mitre_technique="T1555.003",
                severity="high",
                description="Chrome policy modification",
                check_function="check_browser_policy",
                malware_families=["Stealer", "Banker"]
            ),
            RegistryIndicator(
                key_pattern=r"Software\\Policies\\Microsoft\\Edge",
                category=RegistryCategory.CREDENTIAL_ACCESS,
                mitre_technique="T1555.003",
                severity="high",
                description="Edge policy modification",
                check_function="check_browser_policy",
                malware_families=["Stealer", "Banker"]
            ),
            RegistryIndicator(
                key_pattern=r"Software\\Microsoft\\Office\\.*\\Outlook\\Profiles",
                category=RegistryCategory.CREDENTIAL_ACCESS,
                mitre_technique="T1114",
                severity="high",
                description="Outlook profile access",
                check_function="check_outlook_key",
                malware_families=["Stealer", "APT"]
            ),
            RegistryIndicator(
                key_pattern=r"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                category=RegistryCategory.EXECUTION,
                mitre_technique="T1546.012",
                severity="critical",
                description="Image hijacking debugger",
                check_function="check_ifeo_key",
                malware_families=["Rootkit", "Backdoor"]
            ),
            RegistryIndicator(
                key_pattern=r"Software\\Classes\\.*\\shell\\open\\command",
                category=RegistryCategory.EXECUTION,
                mitre_technique="T1546.001",
                severity="high",
                description="File association hijacking",
                check_function="check_file_association",
                malware_families=["ALL"]
            ),
            RegistryIndicator(
                key_pattern=r"Software\\[A-Za-z0-9]{8,}",
                category=RegistryCategory.CONFIGURATION,
                mitre_technique="T1112",
                severity="medium",
                description="Suspicious software key",
                check_function="check_suspicious_software_key",
                malware_families=["ALL"]
            ),
            RegistryIndicator(
                key_pattern=r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                category=RegistryCategory.EXECUTION,
                mitre_technique="T1070.009",
                severity="medium",
                description="UserAssist execution history",
                check_function="check_userassist_key",
                malware_families=["ALL"]
            ),
        ]
    
    def check_run_key(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        suspicious = False
        confidence = 0.5
        reasons = []
        
        suspicious_paths = [
            r"AppData\Local\Temp",
            r"AppData\Roaming",
            r"\Users\Public",
            r"\ProgramData",
            r"%TEMP%",
        ]
        
        for path in suspicious_paths:
            if path.lower() in data.lower():
                suspicious = True
                confidence += 0.2
                reasons.append(f"Suspicious path: {path}")
        
        if any(ext in data.lower() for ext in [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr"]):
            confidence += 0.1
        
        if any(char in data for char in ["^", "%", "`"]):
            suspicious = True
            confidence += 0.2
            reasons.append("Command obfuscation")
        
        if re.search(r"[a-zA-Z0-9]{8,}\.exe", data):
            confidence += 0.15
            reasons.append("Random executable name")
        
        return {
            "suspicious": suspicious or confidence > 0.7,
            "confidence": min(confidence, 1.0),
            "reasons": reasons
        }
    
    def check_service_key(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        suspicious = False
        confidence = 0.6
        reasons = []
        
        if "ImagePath" in value_name:
            suspicious_locs = [r"\Temp", r"\AppData", r"\Users\Public"]
            if any(loc in data for loc in suspicious_locs):
                suspicious = True
                confidence = 0.9
                reasons.append("Service in suspicious location")
        
        return {
            "suspicious": suspicious,
            "confidence": confidence,
            "reasons": reasons
        }
    
    def check_defender_exclusion(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        return {
            "suspicious": True,
            "confidence": 0.95,
            "reasons": ["Windows Defender exclusion added"]
        }
    
    def check_winlogon_key(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        suspicious = False
        confidence = 0.7
        reasons = []
        
        suspicious_values = ["Shell", "Userinit", "Notify"]
        if any(val in value_name for val in suspicious_values):
            suspicious = True
            confidence = 0.85
            reasons.append(f"Winlogon {value_name} modification")
        
        return {
            "suspicious": suspicious,
            "confidence": confidence,
            "reasons": reasons
        }
    
    def check_firewall_key(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        return {
            "suspicious": True,
            "confidence": 0.8,
            "reasons": ["Firewall policy modification"]
        }
    
    def check_safeboot_key(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        return {
            "suspicious": True,
            "confidence": 0.95,
            "reasons": ["Safe Mode modification (Ransomware indicator)"]
        }
    
    def check_browser_policy(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        return {
            "suspicious": True,
            "confidence": 0.75,
            "reasons": ["Browser policy modification"]
        }
    
    def check_outlook_key(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        return {
            "suspicious": True,
            "confidence": 0.8,
            "reasons": ["Outlook profile access (email theft)"]
        }
    
    def check_ifeo_key(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        suspicious = False
        confidence = 0.7
        reasons = []
        
        if "Debugger" in value_name:
            suspicious = True
            confidence = 0.95
            reasons.append("Image hijacking via debugger")
        
        return {
            "suspicious": suspicious,
            "confidence": confidence,
            "reasons": reasons
        }
    
    def check_file_association(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        suspicious = False
        confidence = 0.6
        reasons = []
        
        if any(ext in key.lower() for ext in [".exe", ".bat", ".cmd"]):
            suspicious = True
            confidence = 0.85
            reasons.append("Executable file association hijack")
        
        return {
            "suspicious": suspicious,
            "confidence": confidence,
            "reasons": reasons
        }
    
    def check_suspicious_software_key(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        suspicious = False
        confidence = 0.4
        reasons = []
        
        match = re.search(r"Software\\([^\\]+)", key)
        if match:
            key_name = match.group(1)
            
            if re.match(r"^[a-zA-Z0-9]{8,}$", key_name):
                suspicious = True
                confidence = 0.7
                reasons.append(f"Random key name: {key_name}")
            
            malware_patterns = ["update", "svc", "service", "system", "microsoft", "windows"]
            if any(pattern in key_name.lower() for pattern in malware_patterns):
                confidence += 0.15
        
        return {
            "suspicious": suspicious,
            "confidence": confidence,
            "reasons": reasons
        }
    
    def check_userassist_key(self, key: str, value_name: str, data: str) -> Dict[str, Any]:
        return {
            "suspicious": False,
            "confidence": 0.3,
            "reasons": ["Execution history (forensic value)"]
        }
    
    def analyze(self, registry_data: List[Dict]) -> List[Dict]:
        findings = []
        
        for entry in registry_data:
            key = entry.get("Key", "")
            value_name = entry.get("Value", "")
            data = entry.get("Data", "")
            
            for indicator in self.indicators:
                if self._matches_pattern(key, indicator.key_pattern):
                    check_func = getattr(self, indicator.check_function, None)
                    if check_func:
                        result = check_func(key, value_name, data)
                        
                        if result["suspicious"]:
                            findings.append({
                                "key": key,
                                "value": value_name,
                                "data": str(data)[:200],
                                "category": indicator.category.value,
                                "mitre": indicator.mitre_technique,
                                "severity": indicator.severity,
                                "confidence": result["confidence"],
                                "reasons": result["reasons"],
                                "description": indicator.description,
                                "malware_families": indicator.malware_families
                            })
        
        return findings
    
    def _matches_pattern(self, key: str, pattern: str) -> bool:
        try:
            return bool(re.search(pattern, key, re.IGNORECASE))
        except:
            return pattern.lower() in key.lower()

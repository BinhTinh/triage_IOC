import re
from datetime import datetime
from typing import Any, Dict, List

REGISTRY_RULES: List[Dict[str, Any]] = [
    {
        "key_pattern": r"\\CurrentVersion\\Run(Once)?$",
        "value_pattern": None,
        "data_patterns": [
            r"\\Temp\\",
            r"\\AppData\\Roaming\\",
            r"\\AppData\\Local\\Temp\\",
            r"\\Users\\Public\\",
            r"\\ProgramData\\",
            r"powershell",
            r"cmd\.exe\s+/[cC]",
            r"wscript|cscript",
            r"mshta",
            r"regsvr32",
            r"rundll32",
        ],
        "category": "persistence",
        "mitre": "T1547.001",
        "severity": "high",
        "description": "Suspicious executable in Run/RunOnce key",
        "confidence": 0.85,
        "malware_families": ["generic_persistence"],
    },
    {
        "key_pattern": r"\\CurrentVersion\\Run(Once)?$",
        "value_pattern": None,
        "data_patterns": None,
        "category": "persistence",
        "mitre": "T1547.001",
        "severity": "medium",
        "description": "Entry in Run/RunOnce key",
        "confidence": 0.55,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\CurrentVersion\\RunServices(Once)?$",
        "value_pattern": None,
        "data_patterns": None,
        "category": "persistence",
        "mitre": "T1547.001",
        "severity": "high",
        "description": "Entry in RunServices key",
        "confidence": 0.80,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\Winlogon$",
        "value_pattern": r"^(Userinit|Shell|TaskMan|AppSetup)$",
        "data_patterns": [r"[^,]*(,\s*[^,]+)+", r"cmd\.exe", r"powershell", r"rundll32", r"\\Temp\\"],
        "category": "persistence",
        "mitre": "T1547.004",
        "severity": "critical",
        "description": "Winlogon value hijack",
        "confidence": 0.90,
        "malware_families": ["winlogon_hijack"],
    },
    {
        "key_pattern": r"\\AppInit_DLLs$",
        "value_pattern": None,
        "data_patterns": [r".+"],
        "category": "persistence",
        "mitre": "T1546.010",
        "severity": "critical",
        "description": "AppInit_DLLs set — DLL loaded into every GUI process",
        "confidence": 0.90,
        "malware_families": ["dll_hijack"],
    },
    {
        "key_pattern": r"\\Image File Execution Options\\",
        "value_pattern": r"^Debugger$",
        "data_patterns": [r".+"],
        "category": "persistence",
        "mitre": "T1546.012",
        "severity": "critical",
        "description": "IFEO Debugger hijack",
        "confidence": 0.92,
        "malware_families": ["ifeo_hijack"],
    },
    {
        "key_pattern": r"\\SYSTEM\\CurrentControlSet\\Services\\",
        "value_pattern": r"^(ImagePath|ServiceDLL)$",
        "data_patterns": [
            r"\\Temp\\",
            r"\\AppData\\",
            r"\\Users\\Public\\",
            r"\\ProgramData\\",
        ],
        "category": "persistence",
        "mitre": "T1543.003",
        "severity": "critical",
        "description": "Service pointing to suspicious path",
        "confidence": 0.88,
        "malware_families": ["malicious_service"],
    },
    {
        "key_pattern": r"\\CurrentVersion\\Policies\\System$",
        "value_pattern": r"^(EnableLUA|ConsentPromptBehaviorAdmin|PromptOnSecureDesktop)$",
        "data_patterns": [r"^0$"],
        "category": "defense_evasion",
        "mitre": "T1548.002",
        "severity": "high",
        "description": "UAC disabled via registry",
        "confidence": 0.85,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\Microsoft\\Windows Defender\\",
        "value_pattern": r"^(DisableAntiSpyware|DisableRealtimeMonitoring|DisableAntiVirus)$",
        "data_patterns": [r"^1$"],
        "category": "defense_evasion",
        "mitre": "T1562.001",
        "severity": "critical",
        "description": "Windows Defender disabled via registry",
        "confidence": 0.92,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\Windows Defender\\Exclusions\\",
        "value_pattern": None,
        "data_patterns": None,
        "category": "defense_evasion",
        "mitre": "T1562.001",
        "severity": "high",
        "description": "Windows Defender exclusion added",
        "confidence": 0.80,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU$",
        "value_pattern": r"^(NoAutoUpdate|AUOptions)$",
        "data_patterns": [r"^[14]$"],
        "category": "defense_evasion",
        "mitre": "T1112",
        "severity": "medium",
        "description": "Windows Update disabled via registry",
        "confidence": 0.70,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\CurrentVersion\\Policies\\System$",
        "value_pattern": r"^(DisableRegistryTools|DisableTaskMgr|NoDesktop)$",
        "data_patterns": [r"^1$"],
        "category": "defense_evasion",
        "mitre": "T1112",
        "severity": "high",
        "description": "System tool disabled via registry",
        "confidence": 0.80,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\LSA$",
        "value_pattern": r"^(Security Packages|Authentication Packages|Notification Packages)$",
        "data_patterns": [r"(?!^(msv1_0|kerberos|wdigest|tspkg|pku2u|livessp|cloudap)$).+"],
        "category": "credential_access",
        "mitre": "T1547.005",
        "severity": "critical",
        "description": "Unknown LSA security package",
        "confidence": 0.90,
        "malware_families": ["lsa_injection"],
    },
    {
        "key_pattern": r"\\Control\\SecurityProviders\\WDigest$",
        "value_pattern": r"^UseLogonCredential$",
        "data_patterns": [r"^1$"],
        "category": "credential_access",
        "mitre": "T1003.001",
        "severity": "critical",
        "description": "WDigest plaintext credential caching enabled",
        "confidence": 0.95,
        "malware_families": ["credential_harvesting"],
    },
    {
        "key_pattern": r"\\CurrentVersion\\Authentication\\Credential Providers\\",
        "value_pattern": None,
        "data_patterns": None,
        "category": "credential_access",
        "mitre": "T1556.002",
        "severity": "high",
        "description": "Custom credential provider registered",
        "confidence": 0.75,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\CurrentVersion\\ShellServiceObjectDelayLoad$",
        "value_pattern": None,
        "data_patterns": None,
        "category": "persistence",
        "mitre": "T1547.001",
        "severity": "high",
        "description": "Shell service object registered for delayed load",
        "confidence": 0.78,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\Policies\\Explorer\\Run$",
        "value_pattern": None,
        "data_patterns": None,
        "category": "persistence",
        "mitre": "T1547.001",
        "severity": "high",
        "description": "Entry in Policies\\Explorer\\Run key",
        "confidence": 0.82,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\CurrentVersion\\Explorer\\Shell Folders$",
        "value_pattern": r"^Startup$",
        "data_patterns": [r"(?!.*Microsoft.*).*"],
        "category": "persistence",
        "mitre": "T1547.001",
        "severity": "medium",
        "description": "Startup folder redirection",
        "confidence": 0.72,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\",
        "value_pattern": None,
        "data_patterns": None,
        "category": "persistence",
        "mitre": "T1053.005",
        "severity": "medium",
        "description": "Scheduled task in registry",
        "confidence": 0.60,
        "malware_families": [],
    },
    {
        "key_pattern": r"\\Environment$",
        "value_pattern": r"^(Path|PATHEXT|COMSPEC)$",
        "data_patterns": [r"\\Temp\\", r"\\AppData\\", r"\\Users\\Public\\"],
        "category": "execution",
        "mitre": "T1574.007",
        "severity": "high",
        "description": "System environment variable pointing to suspicious path",
        "confidence": 0.82,
        "malware_families": [],
    },
]

_SEVERITY_RANK: Dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1}

_HIVE_PREFIXES = (
    "HKEY_LOCAL_MACHINE\\", "HKLM\\",
    "HKEY_CURRENT_USER\\", "HKCU\\",
    "HKEY_CLASSES_ROOT\\", "HKCR\\",
    "HKEY_USERS\\", "HKU\\",
    "HKEY_CURRENT_CONFIG\\", "HKCC\\",
)


def _normalize_key(raw: Any) -> str:
    if not raw:
        return ""
    s = str(raw)
    for prefix in _HIVE_PREFIXES:
        if s.upper().startswith(prefix.upper()):
            return s[len(prefix):]
    return s


def _get_field(entry: Dict[str, Any], *candidates: str) -> str:
    for c in candidates:
        v = entry.get(c)
        if v is not None:
            return str(v)
    return ""


class RegistryAnalyzer:
    def analyze(self, registry_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        seen: set = set()

        for entry in registry_data:
            raw_key   = _get_field(entry, "Key", "key", "KeyName", "key_name", "Hive", "hive")
            raw_value = _get_field(entry, "Value", "value", "ValueName", "value_name", "Name", "name")
            raw_data  = _get_field(entry, "Data", "data", "ValueData", "value_data", "RegData", "reg_data")

            if not raw_key:
                continue

            normalized_key = _normalize_key(raw_key)

            for rule in REGISTRY_RULES:
                if not re.search(rule["key_pattern"], normalized_key, re.IGNORECASE):
                    continue

                if rule["value_pattern"] and raw_value:
                    if not re.search(rule["value_pattern"], raw_value, re.IGNORECASE):
                        continue

                matched_data = False
                reasons: List[str] = []

                if rule["data_patterns"] and raw_data:
                    for dp in rule["data_patterns"]:
                        if re.search(dp, raw_data, re.IGNORECASE):
                            reasons.append(f"data_matches:{dp[:40]}")
                            matched_data = True
                            break
                elif rule["data_patterns"] is None:
                    matched_data = True

                if not matched_data and rule["data_patterns"] is not None:
                    continue

                confidence = rule["confidence"]
                if matched_data and rule["data_patterns"]:
                    confidence = min(confidence + 0.05, 1.0)

                dedup_key = f"{normalized_key}|{raw_value}|{rule['mitre']}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append({
                    "key":              raw_key,
                    "value":            raw_value,
                    "data":             raw_data[:200] if raw_data else "",
                    "category":         rule["category"],
                    "mitre":            rule["mitre"],
                    "severity":         rule["severity"],
                    "description":      rule["description"],
                    "confidence":       confidence,
                    "reasons":          reasons or [f"key_matches:{rule['key_pattern'][:40]}"],
                    "malware_families": rule["malware_families"],
                    "analyzed_at":      datetime.now().isoformat(),
                })
                break

        findings.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], 0), reverse=True)
        return findings
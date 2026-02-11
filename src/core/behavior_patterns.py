from src.models.behavior import BehaviorPattern, MalwareFamily

BEHAVIOR_PATTERNS = [
    # Ransomware Patterns
    BehaviorPattern(
        pattern_id="RANSOM_001",
        name="File Encryption Activity",
        description="Mass file modification with suspicious extensions",
        malware_families=[MalwareFamily.RANSOMWARE],
        indicators=[
            "file_extension:.encrypted",
            "file_extension:.locked",
            "file_extension:.crypt",
            "file_access:ransom",
            "cmdline:vssadmin delete shadows"
        ],
        weight=2.0,
        mitre_techniques=["T1486", "T1490"]
    ),
    
    BehaviorPattern(
        pattern_id="RANSOM_002",
        name="Shadow Copy Deletion",
        description="Deleting volume shadow copies to prevent recovery",
        malware_families=[MalwareFamily.RANSOMWARE],
        indicators=[
            "cmdline:vssadmin delete",
            "cmdline:wmic shadowcopy delete",
            "cmdline:bcdedit /set {default} recoveryenabled no"
        ],
        weight=1.8,
        mitre_techniques=["T1490"]
    ),
    
    # RAT Patterns
    BehaviorPattern(
        pattern_id="RAT_001",
        name="Remote Desktop Activity",
        description="Remote access and control capabilities",
        malware_families=[MalwareFamily.RAT, MalwareFamily.BACKDOOR],
        indicators=[
            "network:suspicious_port:4444",
            "network:suspicious_port:5555",
            "process:mstsc.exe",
            "registry:HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        ],
        weight=1.5,
        mitre_techniques=["T1219", "T1021"]
    ),
    
    BehaviorPattern(
        pattern_id="RAT_002",
        name="Keylogging Behavior",
        description="Keystroke capture and monitoring",
        malware_families=[MalwareFamily.RAT, MalwareFamily.STEALER],
        indicators=[
            "api:GetAsyncKeyState",
            "api:SetWindowsHookEx",
            "file_access:keylog",
            "registry:Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ],
        weight=1.7,
        mitre_techniques=["T1056.001"]
    ),
    
    # Stealer Patterns
    BehaviorPattern(
        pattern_id="STEAL_001",
        name="Credential Harvesting",
        description="Accessing credential stores and password databases",
        malware_families=[MalwareFamily.STEALER, MalwareFamily.BANKER],
        indicators=[
            "file_access:password",
            "file_access:credential",
            "file_access:Login Data",
            "process:lsass.exe",
            "cmdline:mimikatz"
        ],
        weight=1.8,
        mitre_techniques=["T1003", "T1555"]
    ),
    
    BehaviorPattern(
        pattern_id="STEAL_002",
        name="Browser Data Theft",
        description="Stealing browser cookies, passwords, and history",
        malware_families=[MalwareFamily.STEALER],
        indicators=[
            "file_access:Cookies",
            "file_access:Login Data",
            "file_access:Web Data",
            "file_access:History",
            "path:AppData\\Local\\Google\\Chrome",
            "path:AppData\\Roaming\\Mozilla\\Firefox"
        ],
        weight=1.6,
        mitre_techniques=["T1555.003"]
    ),
    
    # Process Injection
    BehaviorPattern(
        pattern_id="INJECT_001",
        name="Process Injection",
        description="Code injection into legitimate processes",
        malware_families=[
            MalwareFamily.RAT, 
            MalwareFamily.BACKDOOR, 
            MalwareFamily.STEALER,
            MalwareFamily.ROOTKIT
        ],
        indicators=[
            "injection:explorer.exe",
            "injection:svchost.exe",
            "injection:chrome.exe",
            "protection:PAGE_EXECUTE_READWRITE"
        ],
        weight=1.9,
        mitre_techniques=["T1055"]
    ),
    
    # Persistence
    BehaviorPattern(
        pattern_id="PERSIST_001",
        name="Registry Persistence",
        description="Adding startup entries for persistence",
        malware_families=[
            MalwareFamily.RAT,
            MalwareFamily.BACKDOOR,
            MalwareFamily.STEALER,
            MalwareFamily.BANKER
        ],
        indicators=[
            "registry:Run",
            "registry:RunOnce",
            "registry:Startup",
            "path:Startup"
        ],
        weight=1.3,
        mitre_techniques=["T1547.001"]
    ),
    
    # Command & Control
    BehaviorPattern(
        pattern_id="C2_001",
        name="Suspicious Network Communication",
        description="Outbound connections to suspicious IPs/domains",
        malware_families=[
            MalwareFamily.RAT,
            MalwareFamily.BACKDOOR,
            MalwareFamily.BANKER,
            MalwareFamily.STEALER
        ],
        indicators=[
            "network:external_ip",
            "network:non_standard_port",
            "process:notepad.exe:network",
            "process:calc.exe:network"
        ],
        weight=1.4,
        mitre_techniques=["T1071", "T1573"]
    ),
    
    # Cryptomining
    BehaviorPattern(
        pattern_id="CRYPTO_001",
        name="Cryptocurrency Mining",
        description="High CPU usage and mining pool connections",
        malware_families=[MalwareFamily.CRYPTOMINER],
        indicators=[
            "cmdline:xmrig",
            "cmdline:minerd",
            "network:stratum",
            "network:pool"
        ],
        weight=1.7,
        mitre_techniques=["T1496"]
    ),
    
    # Loader/Dropper
    BehaviorPattern(
        pattern_id="LOAD_001",
        name="Payload Dropping",
        description="Downloading and executing additional payloads",
        malware_families=[MalwareFamily.LOADER, MalwareFamily.DROPPER],
        indicators=[
            "cmdline:powershell",
            "cmdline:DownloadString",
            "cmdline:certutil -urlcache",
            "cmdline:bitsadmin /transfer",
            "network:download"
        ],
        weight=1.6,
        mitre_techniques=["T1105", "T1059.001"]
    ),
    BehaviorPattern(
        pattern_id="REGISTRY_001",
        name="Registry Persistence Mechanism",
        description="Malware establishes persistence via registry Run keys",
        malware_families=[
            MalwareFamily.RAT,
            MalwareFamily.STEALER,
            MalwareFamily.BACKDOOR,
            MalwareFamily.RANSOMWARE,
            MalwareFamily.BANKER
        ],
        indicators=[
            "registry_persistence:",
            "CurrentVersion\\Run"
        ],
        weight=1.8,
        mitre_techniques=["T1547.001"]
    ),
    
    BehaviorPattern(
        pattern_id="REGISTRY_002",
        name="Windows Defender Tampering",
        description="Disabling Windows Defender via registry exclusions",
        malware_families=[
            MalwareFamily.RANSOMWARE,
            MalwareFamily.STEALER,
            MalwareFamily.RAT,
            MalwareFamily.CRYPTOMINER
        ],
        indicators=[
            "registry_defense_evasion:",
            "Windows Defender\\Exclusions"
        ],
        weight=2.0,
        mitre_techniques=["T1562.001"]
    ),
    
    BehaviorPattern(
        pattern_id="REGISTRY_003",
        name="Service Installation",
        description="Malware installs system service for persistence",
        malware_families=[
            MalwareFamily.RAT,
            MalwareFamily.BACKDOOR,
            MalwareFamily.ROOTKIT,
            MalwareFamily.RANSOMWARE
        ],
        indicators=[
            "registry_persistence:",
            "CurrentControlSet\\Services"
        ],
        weight=1.9,
        mitre_techniques=["T1543.003"]
    ),
    
    BehaviorPattern(
        pattern_id="REGISTRY_004",
        name="Browser Policy Modification",
        description="Modifying browser policies for credential theft",
        malware_families=[
            MalwareFamily.STEALER,
            MalwareFamily.BANKER
        ],
        indicators=[
            "registry_credential_access:",
            "Policies\\Google\\Chrome",
            "Policies\\Microsoft\\Edge"
        ],
        weight=1.7,
        mitre_techniques=["T1555.003"]
    ),
    
    # Archive/Compression
    BehaviorPattern(
        pattern_id="ARCHIVE_001",
        name="Data Archiving",
        description="Compressing files before exfiltration",
        malware_families=[
            MalwareFamily.STEALER,
            MalwareFamily.RANSOMWARE,
            MalwareFamily.RAT
        ],
        indicators=[
            "process:WinRAR.exe",
            "process:7z.exe",
            "process:zip.exe",
            "cmdline:.rar",
            "cmdline:.zip",
            "cmdline:.7z"
        ],
        weight=1.2,
        mitre_techniques=["T1560"]
    )
]

def get_patterns_by_family(family: MalwareFamily) -> list:
    return [p for p in BEHAVIOR_PATTERNS if family in p.malware_families]

def get_pattern_by_id(pattern_id: str) -> BehaviorPattern:
    for pattern in BEHAVIOR_PATTERNS:
        if pattern.pattern_id == pattern_id:
            return pattern
    return None

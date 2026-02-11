# FILE 1: src/models/behavior.py (NEW FILE - CREATE)

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

class MalwareFamily(Enum):
    RANSOMWARE = "ransomware"
    RAT = "remote_access_trojan"
    STEALER = "information_stealer"
    BANKER = "banking_trojan"
    BACKDOOR = "backdoor"
    CRYPTOMINER = "cryptominer"
    WORM = "worm"
    ROOTKIT = "rootkit"
    LOADER = "loader"
    DROPPER = "dropper"
    UNKNOWN = "unknown"

@dataclass
class BehaviorPattern:
    pattern_id: str
    name: str
    description: str
    malware_families: List[MalwareFamily]
    indicators: List[str]
    weight: float = 1.0
    mitre_techniques: List[str] = field(default_factory=list)

@dataclass
class BehaviorMatch:
    pattern: BehaviorPattern
    confidence: float
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "pattern_id": self.pattern.pattern_id,
            "pattern_name": self.pattern.name,
            "confidence": self.confidence,
            "evidence_count": len(self.evidence),
            "families": [f.value for f in self.pattern.malware_families]
        }

@dataclass
class MalwareClassification:
    primary_family: MalwareFamily
    confidence: float
    secondary_families: List[MalwareFamily] = field(default_factory=list)
    matched_patterns: List[BehaviorMatch] = field(default_factory=list)
    behavioral_summary: str = ""
    capabilities: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "primary_family": self.primary_family.value,
            "confidence": self.confidence,
            "secondary_families": [f.value for f in self.secondary_families],
            "matched_patterns": [m.to_dict() for m in self.matched_patterns],
            "behavioral_summary": self.behavioral_summary,
            "capabilities": self.capabilities
        }

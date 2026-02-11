# FILE 1: src/models/attack_chain.py (NEW FILE - CREATE)

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum

class KillChainStage(Enum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"

class AttackStage(Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

@dataclass
class ProcessNode:
    pid: int
    ppid: int
    name: str
    cmdline: str
    create_time: Optional[datetime]
    children: List['ProcessNode'] = field(default_factory=list)
    is_suspicious: bool = False
    is_malicious: bool = False
    injections: List[Dict[str, Any]] = field(default_factory=list)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    file_operations: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "cmdline": self.cmdline[:100] if self.cmdline else "",
            "create_time": self.create_time.isoformat() if self.create_time else None,
            "is_suspicious": self.is_suspicious,
            "is_malicious": self.is_malicious,
            "children_count": len(self.children),
            "injections_count": len(self.injections),
            "network_count": len(self.network_connections)
        }

@dataclass
class AttackStageInfo:
    stage: AttackStage
    kill_chain_stage: KillChainStage
    timestamp: Optional[datetime]
    events: List[Dict[str, Any]] = field(default_factory=list)
    processes: List[int] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    description: str = ""
    confidence: float = 0.5
    
    def to_dict(self) -> dict:
        return {
            "stage": self.stage.value,
            "kill_chain_stage": self.kill_chain_stage.value,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_count": len(self.events),
            "processes": self.processes,
            "techniques": self.techniques,
            "description": self.description,
            "confidence": self.confidence
        }

@dataclass
class AttackChain:
    initial_vector: Optional[str] = None
    entry_point_pid: Optional[int] = None
    stages: Dict[AttackStage, AttackStageInfo] = field(default_factory=dict)
    process_tree: List[ProcessNode] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    narrative: str = ""
    confidence: float = 0.5
    
    def to_dict(self) -> dict:
        return {
            "initial_vector": self.initial_vector,
            "entry_point_pid": self.entry_point_pid,
            "stages": {k.value: v.to_dict() for k, v in self.stages.items()},
            "process_tree": [p.to_dict() for p in self.process_tree],
            "timeline": self.timeline,
            "narrative": self.narrative,
            "confidence": self.confidence
        }

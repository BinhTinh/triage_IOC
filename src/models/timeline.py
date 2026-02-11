from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum

class EventType(Enum):
    PROCESS_CREATE = "process_create"
    NETWORK_CONNECT = "network_connect"
    FILE_ACCESS = "file_access"
    CODE_INJECTION = "code_injection"
    REGISTRY_MODIFY = "registry_modify"
    DRIVER_LOAD = "driver_load"

class EventSeverity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class TimelineEvent:
    timestamp: datetime
    event_type: EventType
    severity: EventSeverity
    source_plugin: str
    entity_type: str
    entity_id: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    related_entities: List[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "source_plugin": self.source_plugin,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "description": self.description,
            "details": self.details,
            "related_entities": self.related_entities,
            "mitre_technique": self.mitre_technique
        }

@dataclass
class Timeline:
    events: List[TimelineEvent]
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    total_events: int
    event_types: Dict[str, int] = field(default_factory=dict)
    
    def get_events_by_type(self, event_type: EventType) -> List[TimelineEvent]:
        return [e for e in self.events if e.event_type == event_type]
    
    def get_events_by_severity(self, severity: EventSeverity) -> List[TimelineEvent]:
        return [e for e in self.events if e.severity == severity]
    
    def to_dict(self) -> dict:
        return {
            "events": [e.to_dict() for e in self.events],
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "total_events": self.total_events,
            "event_types": self.event_types
        }

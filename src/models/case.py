from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid



class CaseStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Case:
    dump_path: str
    dump_hash: str
    os_type: str
    os_version: str
    os_arch: str
    goal: str
    id: str = field(default_factory=lambda: f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}")
    status: CaseStatus = CaseStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    findings_count: int = 0
    iocs_count: int = 0
    
    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "dump_path":       self.dump_path,
            "dump_hash":       self.dump_hash,
            "os_type":         self.os_type,
            "os_version":      self.os_version,
            "os_arch":         self.os_arch,
            "goal":            self.goal,
            "status":          self.status.value,
            "created_at":      self.created_at.isoformat(),
            "updated_at":      self.updated_at.isoformat(),
            "findings_count":  self.findings_count,
            "iocs_count":      self.iocs_count,
            "metadata":        self.metadata,
        }
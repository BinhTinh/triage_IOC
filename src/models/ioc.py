from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional

from enum import Enum


@dataclass
class IOC:
    ioc_type: str
    value: str
    confidence: float
    source_plugin: str
    context: Dict[str, Any]
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
    
    @classmethod
    def from_dict(cls, data: dict) -> "IOC":
        return cls(
            ioc_type=data["type"],
            value=data["value"],
            confidence=data.get("confidence", 0.5),
            source_plugin=data.get("source", "unknown"),
            context=data.get("context", {}),
            extracted_at=datetime.fromisoformat(data["extracted_at"]) if "extracted_at" in data else datetime.now()
        )


@dataclass
class ValidationResult:
    source: str
    is_malicious: bool
    score: float
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_whitelisted: bool = False
    raw_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "is_malicious": self.is_malicious,
            "score": self.score,
            "reason": self.reason,
            "is_whitelisted": self.is_whitelisted
        }


@dataclass
class ValidatedIOC:
    ioc: IOC
    final_confidence: float
    verdict: str
    validation_results: List[ValidationResult]
    reason: str
    
    def to_dict(self) -> dict:
        return {
            "ioc": self.ioc.to_dict(),
            "final_confidence": self.final_confidence,
            "verdict": self.verdict,
            "reason": self.reason,
            "validation_results": [r.to_dict() for r in self.validation_results]
        }
    
@dataclass
class IOCType(Enum):
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILEPATH = "filepath"
    MUTEX = "mutex"
    EMAIL = "email"
    INJECTION = "injection"

    REGISTRY_PERSISTENCE = "registry_persistence"
    REGISTRY_CONFIG = "registry_config"
    REGISTRY_DEFENSE_EVASION = "registry_defense_evasion"
    REGISTRY_CREDENTIAL_ACCESS = "registry_credential_access"
    REGISTRY_EXECUTION = "registry_execution"
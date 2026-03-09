from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class IOCCategory(str, Enum):
    NETWORK = "network"
    HOST = "host"


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILEPATH = "filepath"
    MUTEX = "mutex"
    PROCESS = "process"
    COMMAND = "command"
    INJECTION = "injection"
    REGISTRY_PERSISTENCE = "registry_persistence"
    REGISTRY_DEFENSE_EVASION = "registry_defense_evasion"
    REGISTRY_CREDENTIAL_ACCESS = "registry_credential_access"
    REGISTRY_EXECUTION = "registry_execution"
    REGISTRY_CONFIG = "registry_config"


_NETWORK_TYPES: frozenset = frozenset({
    IOCType.IPV4,
    IOCType.IPV6,
    IOCType.DOMAIN,
    IOCType.URL,
    IOCType.EMAIL,
})

_HOST_TYPES: frozenset = frozenset({
    IOCType.MD5,
    IOCType.SHA1,
    IOCType.SHA256,
    IOCType.FILEPATH,
    IOCType.MUTEX,
    IOCType.PROCESS,
    IOCType.COMMAND,
    IOCType.INJECTION,
    IOCType.REGISTRY_PERSISTENCE,
    IOCType.REGISTRY_DEFENSE_EVASION,
    IOCType.REGISTRY_CREDENTIAL_ACCESS,
    IOCType.REGISTRY_EXECUTION,
    IOCType.REGISTRY_CONFIG,
})


def _resolve_category(ioc_type: str) -> str:
    try:
        t = IOCType(ioc_type)
    except ValueError:
        return IOCCategory.HOST
    if t in _NETWORK_TYPES:
        return IOCCategory.NETWORK
    return IOCCategory.HOST


@dataclass
class IOC:
    ioc_type: str
    value: str
    confidence: float
    source_plugin: str
    context: Dict[str, Any]
    extracted_at: datetime
    category: str = field(init=False)

    def __post_init__(self) -> None:
        self.category = _resolve_category(self.ioc_type)

    def to_dict(self) -> dict:
        return {
            "type": self.ioc_type,
            "category": self.category,
            "value": self.value,
            "confidence": self.confidence,
            "source": self.source_plugin,
            "context": self.context,
            "extracted_at": self.extracted_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IOC":
        return cls(
            ioc_type=data["type"],
            value=data["value"],
            confidence=data.get("confidence", 0.5),
            source_plugin=data.get("source", "unknown"),
            context=data.get("context", {}),
            extracted_at=(
                datetime.fromisoformat(data["extracted_at"])
                if "extracted_at" in data
                else datetime.now()
            ),
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
            "is_whitelisted": self.is_whitelisted,
        }


@dataclass
class ValidatedIOC:
    ioc: IOC
    final_confidence: float
    verdict: str
    validation_results: List[ValidationResult]
    reason: str

    def to_dict(self) -> dict:
        ioc_dict = self.ioc.to_dict()
        return {
            "type": ioc_dict["type"],
            "category": ioc_dict["category"],
            "value": ioc_dict["value"],
            "confidence": ioc_dict["confidence"],
            "source": ioc_dict["source"],
            "context": ioc_dict["context"],
            "extracted_at": ioc_dict["extracted_at"],
            "final_confidence": self.final_confidence,
            "verdict": self.verdict,
            "reason": self.reason,
            "validation_results": [r.to_dict() for r in self.validation_results],
        }
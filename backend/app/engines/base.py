from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from app.schemas import FindingItem, XAIFactor

@dataclass
class ScanContext:
    raw_url: str
    normalized_url: str
    domain: str
    url_hash: str
    page_title: Optional[str] = None
    referrer: Optional[str] = None
    dom_signals: Dict[str, Any] = field(default_factory=dict)
    client_ip: Optional[str] = None
    correlation_id: Optional[str] = None

@dataclass
class EngineResult:
    engine_id: str
    engine_name: str
    is_threat: bool
    confidence: float  # 0.0 to 1.0
    risk_score_contribution: int  # 0 to 100
    attack_types: List[str] = field(default_factory=list)
    findings: List[FindingItem] = field(default_factory=list)
    xai_factors: List[XAIFactor] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0
    error: Optional[str] = None

class BaseDetectionEngine(ABC):
    """
    Abstract base class for all FraudShield AI threat detection engines.
    Ensures modularity, uniform interfaces, and independent testability.
    """
    def __init__(self, engine_id: str, name: str, version: str = "1.0.0"):
        self.engine_id = engine_id
        self.name = name
        self.version = version
        self.enabled = True

    @abstractmethod
    async def analyze(self, context: ScanContext) -> EngineResult:
        """
        Executes engine analysis against the provided scan context.
        Must handle its own internal errors gracefully and return an EngineResult.
        """
        pass

    def is_healthy(self) -> bool:
        """Returns True if the engine is operational and ready for requests."""
        return self.enabled


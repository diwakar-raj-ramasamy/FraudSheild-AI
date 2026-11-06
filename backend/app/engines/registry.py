import asyncio
import time
import logging
from typing import Dict, List, Optional, Any
from app.engines.base import BaseDetectionEngine, ScanContext, EngineResult

logger = logging.getLogger("fraudshield.engines")

class DetectionEngineRegistry:
    """
    Centralized registry for modular threat detection engines.
    Provides dynamic engine registration, health checking, and fault-tolerant parallel execution.
    """
    def __init__(self):
        self._engines: Dict[str, BaseDetectionEngine] = {}

    def register(self, engine: BaseDetectionEngine) -> None:
        """Registers a detection engine."""
        self._engines[engine.engine_id] = engine
        logger.info(f"Registered detection engine: {engine.name} ({engine.engine_id}) v{engine.version}")

    def unregister(self, engine_id: str) -> Optional[BaseDetectionEngine]:
        """Unregisters a detection engine by ID."""
        return self._engines.pop(engine_id, None)

    def get_engine(self, engine_id: str) -> Optional[BaseDetectionEngine]:
        """Retrieves an engine instance by ID."""
        return self._engines.get(engine_id)

    def list_engines(self) -> List[Dict[str, Any]]:
        """Returns metadata for all registered engines."""
        return [
            {
                "id": e.engine_id,
                "name": e.name,
                "version": e.version,
                "enabled": e.enabled,
                "healthy": e.is_healthy()
            }
            for e in self._engines.values()
        ]

    async def execute_engine(self, engine: BaseDetectionEngine, context: ScanContext, timeout: float = 3.0) -> EngineResult:
        """
        Executes a single engine with an enforced timeout and isolated exception safety.
        """
        start = time.perf_counter()
        if not engine.enabled:
            return EngineResult(
                engine_id=engine.engine_id,
                engine_name=engine.name,
                is_threat=False,
                confidence=0.0,
                risk_score_contribution=0,
                error="Engine disabled"
            )

        try:
            result = await asyncio.wait_for(engine.analyze(context), timeout=timeout)
            result.execution_time_ms = round((time.perf_counter() - start) * 1000, 2)
            return result
        except asyncio.TimeoutError:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            logger.warning(f"Engine {engine.name} ({engine.engine_id}) timed out after {timeout}s")
            return EngineResult(
                engine_id=engine.engine_id,
                engine_name=engine.name,
                is_threat=False,
                confidence=0.0,
                risk_score_contribution=0,
                execution_time_ms=duration_ms,
                error=f"Timeout after {timeout}s"
            )
        except Exception as ex:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            logger.error(f"Engine {engine.name} failed with unhandled error: {ex}", exc_info=True)
            return EngineResult(
                engine_id=engine.engine_id,
                engine_name=engine.name,
                is_threat=False,
                confidence=0.0,
                risk_score_contribution=0,
                execution_time_ms=duration_ms,
                error=str(ex)
            )

    async def execute_all(self, context: ScanContext, timeout_per_engine: float = 3.0) -> List[EngineResult]:
        """
        Executes all active registered engines concurrently with fault isolation.
        """
        tasks = [
            self.execute_engine(engine, context, timeout=timeout_per_engine)
            for engine in self._engines.values()
            if engine.enabled
        ]
        if not tasks:
            return []
        return await asyncio.gather(*tasks)

# Global engine registry singleton
engine_registry = DetectionEngineRegistry()

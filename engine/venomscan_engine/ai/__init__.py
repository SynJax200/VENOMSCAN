"""AI intelligence layer: provider adapters, grounding, deterministic fallback.

The engine stays fully functional with no LLM configured; every feature degrades to
the deterministic builders in :mod:`venomscan_engine.ai.fallback`.
"""

from venomscan_engine.ai.assistant import REFUSAL, answer, out_of_scope
from venomscan_engine.ai.features import AnalysisResult, analyze
from venomscan_engine.ai.provider import LLMError, LLMProvider, build_provider

__all__ = [
    "AnalysisResult",
    "LLMError",
    "LLMProvider",
    "REFUSAL",
    "analyze",
    "answer",
    "build_provider",
    "out_of_scope",
]

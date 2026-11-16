from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, Field


class ScanEvent(BaseModel):
    phase: str
    type: str
    message: str = ""
    progress: int = Field(default=0, ge=0, le=100)
    payload: dict[str, Any] = Field(default_factory=dict)


class EventSink(Protocol):
    async def emit(self, event: ScanEvent) -> None: ...


class CollectingSink:
    """In-memory sink for CLI runs and tests."""

    def __init__(self) -> None:
        self.events: list[ScanEvent] = []

    async def emit(self, event: ScanEvent) -> None:
        self.events.append(event)


class NullSink:
    async def emit(self, event: ScanEvent) -> None:
        return None

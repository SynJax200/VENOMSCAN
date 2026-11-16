from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from venomscan_engine.events import EventSink, ScanEvent
from venomscan_engine.models import EndpointRecord, Finding, Technology
from venomscan_engine.safety.http import ResponseBundle, SafeHttpClient
from venomscan_engine.safety.scope import Scope


@dataclass
class ScanContext:
    scan_id: str
    target_url: str
    scope: Scope
    profile: str
    sink: EventSink
    client: SafeHttpClient
    max_seconds: float
    started: float = field(default_factory=time.monotonic)
    artifacts: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    endpoints: list[EndpointRecord] = field(default_factory=list)

    async def emit(
        self,
        phase: str,
        type_: str,
        message: str = "",
        *,
        progress: int = 0,
        payload: dict[str, Any] | None = None,
    ) -> None:
        await self.sink.emit(
            ScanEvent(
                phase=phase,
                type=type_,
                message=message,
                progress=progress,
                payload=payload or {},
            )
        )

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_technology(self, tech: Technology) -> None:
        if all(existing.name != tech.name for existing in self.technologies):
            self.technologies.append(tech)

    def add_endpoint(self, endpoint: EndpointRecord) -> None:
        for existing in self.endpoints:
            if existing.url == endpoint.url and existing.method == endpoint.method:
                for name in endpoint.parameters:
                    if name not in existing.parameters:
                        existing.parameters.append(name)
                return
        self.endpoints.append(endpoint)

    @property
    def root(self) -> ResponseBundle | None:
        return self.artifacts.get("root")

    @root.setter
    def root(self, bundle: ResponseBundle) -> None:
        self.artifacts["root"] = bundle

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.max_seconds - (time.monotonic() - self.started))

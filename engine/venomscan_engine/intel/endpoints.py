from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from venomscan_engine.models import EndpointRecord

_MAX_CLUSTERS = 40
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LONG_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,}$")
_HEX = re.compile(r"^[0-9a-fA-F]{12,}$")
_PLACEHOLDER = re.compile(r"^(?:\$\{[^{}]+\}|:[A-Za-z_][\w-]*|\{[A-Za-z_][\w-]*\})$")


def _is_identifier(segment: str) -> bool:
    if _PLACEHOLDER.match(segment):
        return True
    if segment.isdigit() or _UUID.match(segment):
        return True
    if _HEX.match(segment):
        return True
    return bool(_LONG_TOKEN.match(segment)) and any(char.isdigit() for char in segment)


def template_path(url: str) -> str:
    parts = urlsplit(url)
    segments = [("{id}" if _is_identifier(segment) else segment) for segment in parts.path.split("/")]
    path = "/".join(segments) or "/"
    return f"{parts.scheme}://{parts.netloc}{path}"


@dataclass
class EndpointCluster:
    template: str
    methods: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    parameters: set[str] = field(default_factory=set)
    samples: list[str] = field(default_factory=list)
    count: int = 0

    def add(self, endpoint: EndpointRecord) -> None:
        self.count += 1
        self.methods.add(endpoint.method.upper())
        self.sources.add(endpoint.source)
        self.parameters.update(endpoint.parameters)
        for name, _ in parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True):
            self.parameters.add(name)
        if len(self.samples) < 3 and endpoint.url not in self.samples:
            self.samples.append(endpoint.url)

    def as_dict(self) -> dict:
        api_like = "/api" in urlsplit(self.template).path.lower()
        return {
            "template": self.template,
            "count": self.count,
            "methods": sorted(self.methods),
            "sources": sorted(self.sources),
            "parameters": sorted(self.parameters)[:12],
            "samples": self.samples,
            "api_like": api_like,
        }


def cluster_endpoints(endpoints: list[EndpointRecord]) -> dict:
    clusters: dict[str, EndpointCluster] = {}
    for endpoint in endpoints:
        key = template_path(endpoint.url)
        cluster = clusters.setdefault(key, EndpointCluster(template=key))
        cluster.add(endpoint)
    ordered = sorted(clusters.values(), key=lambda item: (-item.count, item.template))
    payload = [cluster.as_dict() for cluster in ordered[:_MAX_CLUSTERS]]
    return {
        "cluster_count": len(clusters),
        "endpoint_count": len(endpoints),
        "templated": sum(1 for cluster in clusters.values() if "{id}" in cluster.template),
        "api_clusters": sum(1 for cluster in clusters.values() if "/api" in urlsplit(cluster.template).path.lower()),
        "clusters": payload,
    }


__all__ = ["EndpointCluster", "cluster_endpoints", "template_path"]

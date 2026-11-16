from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_SCHEMES = frozenset({"http", "https"})


class ScopeViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class Scope:
    """Allowlist of hosts that may be contacted during a scan."""

    hosts: frozenset[str]
    include_subdomains: bool = False
    schemes: frozenset[str] = field(default=DEFAULT_SCHEMES)

    @classmethod
    def from_target(
        cls,
        base_url: str,
        *,
        include_subdomains: bool = False,
        extra_hosts: tuple[str, ...] = (),
    ) -> Scope:
        parts = urlsplit(base_url)
        if not parts.hostname:
            raise ValueError("target URL must include a hostname")
        hosts = {parts.hostname.lower(), *(h.lower() for h in extra_hosts if h)}
        return cls(hosts=frozenset(hosts), include_subdomains=include_subdomains)

    def host_allowed(self, host: str) -> bool:
        host = host.lower()
        if host in self.hosts:
            return True
        return self.include_subdomains and any(host.endswith("." + h) for h in self.hosts)

    def check(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in self.schemes:
            raise ScopeViolation(f"scheme {parts.scheme!r} is outside scan scope")
        if not parts.hostname:
            raise ScopeViolation("URL has no hostname")
        if not self.host_allowed(parts.hostname):
            raise ScopeViolation(f"host {parts.hostname!r} is outside scan scope")

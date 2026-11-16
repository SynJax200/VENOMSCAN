from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit


def _compile(pattern: str) -> re.Pattern[str]:
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    regex = re.escape(body).replace(r"\*", ".*")
    return re.compile("^" + regex + ("$" if anchored else ""))


def _matches(pattern: str, target: str) -> bool:
    try:
        return _compile(pattern).match(target) is not None
    except re.error:
        return False


@dataclass(frozen=True)
class RobotsPolicy:
    """Allow/Disallow rules for the scanning user agent (longest match wins)."""

    allow: tuple[str, ...] = ()
    disallow: tuple[str, ...] = ()
    sitemaps: tuple[str, ...] = ()
    crawl_delay: float | None = None

    def allows(self, url: str) -> bool:
        parts = urlsplit(url)
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        best_len = -1
        allowed = True
        for pattern in self.allow:
            if _matches(pattern, target) and len(pattern) >= best_len:
                best_len, allowed = len(pattern), True
        for pattern in self.disallow:
            if _matches(pattern, target) and len(pattern) > best_len:
                best_len, allowed = len(pattern), False
        return allowed


ALLOW_ALL = RobotsPolicy()


@dataclass
class _Group:
    agents: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    disallow: list[str] = field(default_factory=list)
    crawl_delay: float | None = None


def parse_robots(text: str, user_agent: str = "venomscan") -> RobotsPolicy:
    groups: list[_Group] = []
    current = _Group()
    sitemaps: list[str] = []
    seen_rule = False

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if seen_rule and current.agents:
                groups.append(current)
                current = _Group()
                seen_rule = False
            current.agents.append(value.lower())
        elif key in {"allow", "disallow"}:
            seen_rule = True
            if value:
                getattr(current, key).append(value)
        elif key == "crawl-delay":
            try:
                current.crawl_delay = float(value)
            except ValueError:
                pass
        elif key == "sitemap":
            if value:
                sitemaps.append(value)

    if current.agents:
        groups.append(current)

    ua = user_agent.lower()
    best: _Group | None = None
    best_score = -1
    for group in groups:
        for agent in group.agents:
            if agent == "*":
                score = 0
            elif agent in ua or ua in agent:
                score = len(agent) + 1
            else:
                score = -1
            if score > best_score:
                best, best_score = group, score

    if best is None:
        return RobotsPolicy(sitemaps=tuple(sitemaps))
    return RobotsPolicy(
        allow=tuple(best.allow),
        disallow=tuple(best.disallow),
        sitemaps=tuple(sitemaps),
        crawl_delay=best.crawl_delay,
    )

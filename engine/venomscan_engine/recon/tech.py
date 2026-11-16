from __future__ import annotations

import re

from venomscan_engine.models import Technology
from venomscan_engine.safety.http import ResponseBundle


def _version(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.IGNORECASE)
    if match is None or not match.groups():
        return None
    return match.group(1) or None


def detect_technologies(bundle: ResponseBundle) -> list[Technology]:
    found: list[Technology] = []
    headers = bundle.headers
    body = bundle.body
    cookies = " ".join(bundle.set_cookies)

    server = headers.get("server", "")
    if server:
        if "cloudflare" in server.lower():
            found.append(
                Technology(
                    name="Cloudflare", category="cdn", confidence=0.95, evidence="Server header"
                )
            )
        for name, pattern, category in (
            ("Nginx", r"nginx(?:/([\d.]+))?", "web-server"),
            ("Apache", r"apache(?:/([\d.]+))?", "web-server"),
            ("LiteSpeed", r"litespeed", "web-server"),
            ("Microsoft IIS", r"microsoft-iis(?:/([\d.]+))?", "web-server"),
            ("Caddy", r"caddy", "web-server"),
            ("Uvicorn", r"uvicorn(?:/([\d.]+))?", "app-server"),
            ("Gunicorn", r"gunicorn(?:/([\d.]+))?", "app-server"),
            ("Werkzeug", r"werkzeug(?:/([\d.]+))?", "app-server"),
        ):
            if re.search(pattern, server, re.IGNORECASE):
                found.append(
                    Technology(
                        name=name,
                        version=_version(pattern, server),
                        category=category,
                        confidence=0.85,
                        evidence=f"Server: {server}",
                    )
                )

    powered = headers.get("x-powered-by", "")
    if powered:
        if "php" in powered.lower():
            found.append(
                Technology(
                    name="PHP",
                    version=_version(r"php/([\d.]+)", powered),
                    category="language",
                    confidence=0.9,
                    evidence=f"X-Powered-By: {powered}",
                )
            )
        elif "express" in powered.lower():
            found.append(
                Technology(
                    name="Express", category="framework", confidence=0.85, evidence="X-Powered-By"
                )
            )
        elif "asp.net" in powered.lower():
            found.append(
                Technology(
                    name="ASP.NET", category="framework", confidence=0.9, evidence="X-Powered-By"
                )
            )

    if headers.get("x-aspnet-version"):
        found.append(
            Technology(
                name="ASP.NET",
                version=headers["x-aspnet-version"],
                category="framework",
                confidence=0.9,
                evidence="X-AspNet-Version",
            )
        )

    cookie_markers = (
        ("PHPSESSID", "PHP", "language"),
        ("JSESSIONID", "Java", "language"),
        ("ASP.NET_SessionId", "ASP.NET", "framework"),
        ("laravel_session", "Laravel", "framework"),
        ("csrftoken", "Django", "framework"),
    )
    for marker, name, category in cookie_markers:
        if marker.lower() in cookies.lower():
            found.append(
                Technology(
                    name=name, category=category, confidence=0.7, evidence=f"Cookie {marker}"
                )
            )

    body_rules = (
        (
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)',
            "WordPress",
            "cms",
        ),
        (r"/wp-content/", "WordPress", "cms"),
        (r"__NEXT_DATA__", "Next.js", "framework"),
        (r"/_next/static/", "Next.js", "framework"),
        (r"ng-version=", "Angular", "framework"),
        (r"data-reactroot", "React", "library"),
        (r"csrfmiddlewaretoken", "Django", "framework"),
        (r"Drupal\.settings", "Drupal", "cms"),
        (r"cdn\.shopify\.com", "Shopify", "platform"),
    )
    for pattern, name, category in body_rules:
        if re.search(pattern, body, re.IGNORECASE):
            version = _version(pattern, body)
            found.append(
                Technology(
                    name=name,
                    version=version or None,
                    category=category,
                    confidence=0.75,
                    evidence=f"Body marker: {pattern}",
                )
            )

    unique: dict[str, Technology] = {}
    for tech in found:
        unique.setdefault(tech.name, tech)
    return list(unique.values())

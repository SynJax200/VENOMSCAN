"""Example VENOMSCAN plugin: flag software versions disclosed in response headers.

Plugins receive a read-only analysis payload and never touch the network. This one
only reads headers that the engine already collected. See docs/PLUGIN_AUTHORING.md.
"""

from __future__ import annotations

CHECK_ID = "venom.plugin.version_banner"
NAME = "Software version disclosed in response headers"
CATEGORY = "disclosure"
SEVERITY = "low"
PROFILE = "safe"
TIMEOUT_SECONDS = 10
MEMORY_MB = 128

_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


def run(payload: dict) -> list[dict]:
    root = payload.get("root") or {}
    headers = {str(key).lower(): str(value) for key, value in (root.get("headers") or {}).items()}
    disclosed = {name: headers[name] for name in _HEADERS if headers.get(name)}
    versioned = {name: value for name, value in disclosed.items() if any(ch.isdigit() for ch in value)}
    if not versioned:
        return []
    detail = ", ".join(f"{name}: {value}" for name, value in versioned.items())
    return [
        {
            "title": "Software version disclosed in response headers",
            "description": f"The response advertises software versions ({detail}).",
            "impact": (
                "Version banners let an attacker map the target to known CVEs without "
                "probing. This is informational and does not confirm exploitability."
            ),
            "remediation": (
                "Remove or genericise version details from Server and X-Powered-By headers."
            ),
            "url": str(payload.get("target_url") or ""),
            "severity": "info",
            "confidence": 8,
            "references": ["https://owasp.org/www-project-top-ten/"],
        }
    ]

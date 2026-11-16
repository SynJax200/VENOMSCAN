from __future__ import annotations

from dataclasses import dataclass, field

from venomscan_engine.safety.http import ResponseBundle

MAX_VENDORS = 5
MAX_EVIDENCE = 4

# (vendor, category, confidence, header names, cookie prefixes, server terms)
_RULES: tuple[tuple[str, str, float, tuple[str, ...], tuple[str, ...], tuple[str, ...]], ...] = (
    (
        "Cloudflare",
        "cdn",
        0.95,
        ("cf-ray", "cf-cache-status", "cf-mitigated"),
        ("__cf_bm", "_cfuvid"),
        ("cloudflare",),
    ),
    (
        "Akamai",
        "cdn",
        0.9,
        ("akamai-grn", "x-akamai-transformed", "x-akamai-request-id"),
        ("ak_bmsc", "_abck", "bm_sv"),
        ("akamaighost",),
    ),
    (
        "AWS edge",
        "cdn",
        0.85,
        ("x-amz-cf-id", "x-amz-cf-pop"),
        ("awsalb", "awsalbcors"),
        ("awselb", "cloudfront"),
    ),
    (
        "Imperva",
        "waf",
        0.9,
        ("x-iinfo",),
        ("incap_ses_", "visid_incap_", "nlbi_"),
        (),
    ),
    (
        "F5 BIG-IP",
        "waf",
        0.85,
        ("x-wa-info",),
        ("bigipserver", "ts01", "ts013"),
        ("big-ip",),
    ),
    (
        "Sucuri",
        "waf",
        0.9,
        ("x-sucuri-id", "x-sucuri-cache"),
        (),
        ("sucuri",),
    ),
    (
        "Azure edge",
        "cdn",
        0.8,
        ("x-azure-ref", "x-fd-request-id"),
        (),
        ("microsoft-azure-application-gateway",),
    ),
    (
        "Fastly",
        "cdn",
        0.8,
        ("x-fastly-request-id", "x-served-by"),
        (),
        ("fastly",),
    ),
    (
        "Barracuda",
        "waf",
        0.75,
        (),
        ("barra_counter_session", "bni_persistence"),
        ("barracuda",),
    ),
    (
        "Vercel",
        "cdn",
        0.8,
        ("x-vercel-id", "x-vercel-cache"),
        (),
        ("vercel",),
    ),
)


@dataclass
class WAFVendor:
    name: str
    category: str
    confidence: float
    evidence: list[str] = field(default_factory=list)


@dataclass
class WAFReport:
    vendors: list[WAFVendor] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return bool(self.vendors)

    def summary(self) -> str:
        if not self.vendors:
            return "No WAF or edge fingerprint matched"
        return "Possible " + ", ".join(vendor.name for vendor in self.vendors) + " in front"

    def as_dict(self) -> dict:
        return {
            "detected": self.detected,
            "vendors": [
                {
                    "name": vendor.name,
                    "category": vendor.category,
                    "confidence": vendor.confidence,
                    "evidence": vendor.evidence,
                }
                for vendor in self.vendors
            ],
            "summary": self.summary(),
        }


def detect_waf(bundle: ResponseBundle) -> WAFReport:
    """Fingerprint WAF/CDN vendors from headers, cookies and the server banner."""

    headers = bundle.headers
    server = (headers.get("server") or "").lower()
    cookies = " ".join(bundle.set_cookies).lower()
    found: dict[str, WAFVendor] = {}

    def note(name: str, category: str, confidence: float, evidence: str) -> None:
        vendor = found.get(name)
        if vendor is None:
            vendor = WAFVendor(name=name, category=category, confidence=confidence)
            found[name] = vendor
        vendor.confidence = max(vendor.confidence, confidence)
        if evidence not in vendor.evidence and len(vendor.evidence) < MAX_EVIDENCE:
            vendor.evidence.append(evidence)

    for name, category, confidence, header_names, cookie_prefixes, server_terms in _RULES:
        for header in header_names:
            if header in headers:
                note(name, category, confidence, f"header {header}")
        for prefix in cookie_prefixes:
            if prefix in cookies:
                note(name, category, confidence * 0.9, f"cookie {prefix}*")
        for term in server_terms:
            if term in server:
                note(name, category, confidence, f"server {headers.get('server')}")

    ranked = sorted(found.values(), key=lambda vendor: vendor.confidence, reverse=True)
    return WAFReport(vendors=ranked[:MAX_VENDORS])


__all__ = ["WAFReport", "WAFVendor", "detect_waf"]

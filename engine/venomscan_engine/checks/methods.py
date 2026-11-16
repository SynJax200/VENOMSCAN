from __future__ import annotations

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity
from venomscan_engine.safety.http import TargetUnreachable, TooManyRedirects

_RISKY_ADVERTISED = {"PUT", "DELETE", "PATCH", "CONNECT"}
_MAX_METHODS = 8


@register
class HTTPMethodsCheck:
    id = "venom.methods"
    name = "HTTP method exposure"
    category = "config"
    default_severity = Severity.LOW
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.root
        if root is None or ctx.client is None or ctx.remaining_seconds < 3:
            return []

        advertised: list[str] = []
        try:
            options = await ctx.client.request("OPTIONS", root.url)
            allow = options.header("allow") or options.header("access-control-allow-methods") or ""
            advertised = [item.strip().upper() for item in allow.split(",") if item.strip()]
        except (TargetUnreachable, TooManyRedirects):
            return []

        trace_enabled = False
        if "TRACE" in advertised and ctx.remaining_seconds > 2:
            try:
                trace = await ctx.client.request("TRACE", root.url)
                trace_enabled = trace.status_code == 200 and "message/http" in (
                    trace.header("content-type") or ""
                ).lower()
            except (TargetUnreachable, TooManyRedirects):
                trace_enabled = False

        risky = [method for method in advertised if method in _RISKY_ADVERTISED]
        if not trace_enabled and not risky:
            return []

        described = []
        if trace_enabled:
            described.append("TRACE")
        described.extend(method for method in risky if method != "TRACE")
        severity = Severity.MEDIUM if trace_enabled else Severity.LOW
        return [
            Finding(
                check_id=self.id,
                title=f"Risky HTTP methods enabled: {', '.join(described[:_MAX_METHODS])}",
                category=self.category,
                severity=severity,
                confidence=9 if trace_enabled else 7,
                url=root.url,
                description=(
                    "The server advertises or answers methods that are rarely required: "
                    + ", ".join(described[:_MAX_METHODS])
                    + (
                        ". TRACE echoes the request back and can be abused with cross-site "
                        "tracing (XST)."
                        if trace_enabled
                        else ". Writable verbs on a public path widen the attack surface if "
                        "authorization is inconsistent."
                    )
                ),
                impact="Unnecessary methods increase the chance that one code path misses "
                "authentication or logging.",
                remediation="Allow only the methods the route actually implements. Disable TRACE "
                "and reject PUT/DELETE at the edge for public HTML paths.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                cwe=["CWE-650"],
                owasp=["A05:2021 Security Misconfiguration"],
                request_evidence={"method": "OPTIONS", "url": root.url},
                response_evidence={
                    "status_code": 200,
                    "allow": advertised,
                    "trace_enabled": trace_enabled,
                },
            )
        ]

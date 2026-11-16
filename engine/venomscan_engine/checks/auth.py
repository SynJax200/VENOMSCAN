from __future__ import annotations

from urllib.parse import urlsplit

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity

_SAFE_AUTOCOMPLETE = {"off", "new-password", "current-password"}


@register
class AuthPagesCheck:
    id = "venom.auth.pages"
    name = "Authentication page hygiene"
    category = "auth"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.root
        forms = ctx.artifacts.get("forms") or []
        if root is None or not isinstance(forms, list):
            return []

        findings: list[Finding] = []
        for form in forms:
            if not isinstance(form, dict):
                continue
            fields = form.get("fields") or []
            passwords = [field for field in fields if field.get("type") == "password"]
            if not passwords:
                continue
            action = form.get("action") or form.get("page") or root.url
            path = urlsplit(action).path or "/"
            method = str(form.get("method", "")).upper() or "GET"
            page = form.get("page") or root.url

            if method == "GET":
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"Password field submitted with GET on {path}",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=9,
                        url=page,
                        parameter=action,
                        description="A form containing a password field uses GET, which places "
                        "credentials in the URL. URLs reach server logs, browser history and "
                        "Referer headers.",
                        impact="Credential leakage to logs, proxies and third-party referrers.",
                        remediation="Submit credentials with POST over HTTPS and never place "
                        "secrets in query strings.",
                        references=[
                            "https://cwe.mitre.org/data/definitions/598.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                        ],
                        cwe=["CWE-598"],
                        owasp=["A04:2021 Insecure Design"],
                        request_evidence={"method": "GET", "url": action},
                        response_evidence={"page": page, "field_types": ["password"]},
                    )
                )

            weak = [
                field
                for field in passwords
                if str(field.get("autocomplete", "")).strip().lower() not in _SAFE_AUTOCOMPLETE
            ]
            if weak and method == "POST":
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"Password field on {path} lacks explicit autocomplete policy",
                        category=self.category,
                        severity=Severity.LOW,
                        confidence=6,
                        url=page,
                        parameter=action,
                        description="The password input does not declare autocomplete=off, "
                        "current-password or new-password. Browsers may autofill or offer to store "
                        "the credential in ways the application cannot control.",
                        impact="Reduced control over credential storage on shared devices.",
                        remediation="Declare autocomplete=current-password on login and "
                        "new-password on registration forms.",
                        references=[
                            "https://developer.mozilla.org/docs/Web/HTML/Attributes/autocomplete"
                        ],
                        cwe=["CWE-522"],
                        owasp=["A07:2021 Identification and Authentication Failures"],
                        request_evidence={"method": "POST", "url": action},
                        response_evidence={"page": page, "autocomplete": "missing-or-unsafe"},
                    )
                )
        return findings

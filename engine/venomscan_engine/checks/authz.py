from __future__ import annotations

import re
from urllib.parse import urlsplit

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import EndpointRecord, Finding, Severity, VerificationStatus
from venomscan_engine.safety.http import BudgetExceeded, TargetUnreachable, TooManyRedirects
from venomscan_engine.safety.scope import ScopeViolation

MAX_OBJECTS = 2
MAX_ADMIN_ENDPOINTS = 2
_ID_SEGMENT = re.compile(
    r"^(?:[0-9]{1,12}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)
_ID_PARAMS = {
    "id",
    "user",
    "user_id",
    "account",
    "account_id",
    "order",
    "order_id",
    "invoice",
    "invoice_id",
    "customer",
    "customer_id",
    "profile",
    "profile_id",
    "document",
    "document_id",
    "file",
    "file_id",
}
_ADMIN_PATH = re.compile(
    r"(?i)/(?:admin|administrator|internal|manage|management|staff|superuser)(?:/|$|\.)"
)
_SKIP_PATHS = re.compile(
    r"(?i)(logout|signout|delete|remove|unsubscribe|checkout|purchase|pay|subscribe)"
)
_LOGIN_BODY = re.compile(r'(?i)(type=["\']password["\']|sign[ -]?in|log[ -]?in)')


def _accounts(ctx: ScanContext) -> list[dict]:
    raw = ctx.artifacts.get("accounts") or []
    return [
        account
        for account in raw
        if isinstance(account, dict)
        and account.get("headers")
        and account.get("label")
    ]


def _same_scope(ctx: ScanContext, url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        return False
    try:
        ctx.scope.check(url)
    except ScopeViolation:
        return False
    return True


async def _request(ctx: ScanContext, url: str, headers: dict[str, str]):
    try:
        return await ctx.client.get(url, headers=headers)
    except BudgetExceeded:
        raise
    except (TargetUnreachable, TooManyRedirects):
        return None


def _object_targets(ctx: ScanContext) -> list[tuple[EndpointRecord, str]]:
    targets: list[tuple[EndpointRecord, str]] = []
    seen: set[str] = set()
    for endpoint in ctx.endpoints:
        if len(targets) >= MAX_OBJECTS:
            break
        if endpoint.method.upper() != "GET" or endpoint.url in seen or endpoint.state != "live":
            continue
        if _SKIP_PATHS.search(endpoint.url) or not _same_scope(ctx, endpoint.url):
            continue
        parts = urlsplit(endpoint.url)
        segments = [segment for segment in parts.path.split("/") if segment]
        named = next(
            (name for name in endpoint.parameters if name.lower() in _ID_PARAMS), None
        )
        if any(_ID_SEGMENT.match(segment) for segment in segments):
            targets.append((endpoint, named or "path"))
            seen.add(endpoint.url)
        elif named is not None:
            targets.append((endpoint, named))
            seen.add(endpoint.url)
    return targets


@register
class IdorCheck:
    id = "venom.idor"
    name = "Broken object-level authorization (IDOR)"
    category = "api"
    default_severity = Severity.HIGH
    profile = "active"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        accounts = _accounts(ctx)
        if len(accounts) < 2:
            await ctx.emit(
                "analyzing",
                "warning",
                "IDOR skipped: configure at least two test accounts in Settings",
                payload={"check_id": self.id},
            )
            return []
        if ctx.root is None or ctx.remaining_seconds < 8:
            return []

        owner, other = accounts[0], accounts[1]
        identity = str(owner.get("identity") or "")
        if not identity:
            return []

        findings: list[Finding] = []
        for endpoint, parameter in _object_targets(ctx):
            if ctx.remaining_seconds < 6:
                break
            try:
                owner_response = await _request(ctx, endpoint.url, owner["headers"])
            except BudgetExceeded:
                break
            if owner_response is None or owner_response.status_code // 100 != 2:
                continue
            if identity.lower() not in owner_response.body.lower():
                continue
            try:
                other_response = await _request(ctx, endpoint.url, other["headers"])
            except BudgetExceeded:
                break
            if other_response is None or other_response.status_code // 100 != 2:
                continue
            if identity.lower() not in other_response.body.lower():
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title="Object-level authorization missing: another account sees the owner's data",
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=9,
                    verification_status=VerificationStatus.VERIFIED,
                    url=endpoint.url,
                    method="GET",
                    parameter=parameter,
                    payload=None,
                    description=(
                        f"{endpoint.url} returned {owner['label']}'s data to {owner['label']} and "
                        f"then served the same object to {other['label']}. The response still "
                        f"carried the owner's identity marker ({identity}), so the server never "
                        "checked that the object belongs to the requesting account."
                    ),
                    impact=(
                        "Sequential object references let any authenticated user read (and often "
                        "modify) records that belong to other users, tenants or customers."
                    ),
                    remediation=(
                        "Authorize every object access against the authenticated principal "
                        "(server-side owner/tenant check), use unguessable identifiers as "
                        "defence in depth, and add automated tests for cross-account reads."
                    ),
                    references=[
                        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                    ],
                    cwe=["CWE-639"],
                    owasp=["A01:2021 Broken Access Control"],
                    request_evidence={
                        "method": "GET",
                        "url": endpoint.url,
                        "as_owner": owner["label"],
                        "as_other": other["label"],
                        "parameter": parameter,
                    },
                    response_evidence={
                        "owner_status": owner_response.status_code,
                        "other_status": other_response.status_code,
                        "identity_marker": identity,
                        "identity_exposed_to_other": True,
                        "body_stored": False,
                    },
                )
            )
        return findings


@register
class FunctionAuthzCheck:
    id = "venom.authz.function"
    name = "Missing function-level authorization"
    category = "api"
    default_severity = Severity.MEDIUM
    profile = "active"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        accounts = _accounts(ctx)
        if not accounts:
            await ctx.emit(
                "analyzing",
                "warning",
                "Function-level authorization skipped: no test accounts configured",
                payload={"check_id": self.id},
            )
            return []
        if ctx.root is None or ctx.remaining_seconds < 6:
            return []

        low = next((account for account in accounts if account.get("role") != "admin"), accounts[0])
        findings: list[Finding] = []
        checked = 0
        for endpoint in ctx.endpoints:
            if checked >= MAX_ADMIN_ENDPOINTS or ctx.remaining_seconds < 4:
                break
            if endpoint.method.upper() != "GET" or endpoint.state != "live":
                continue
            if not _ADMIN_PATH.search(urlsplit(endpoint.url).path):
                continue
            if _SKIP_PATHS.search(endpoint.url) or not _same_scope(ctx, endpoint.url):
                continue
            checked += 1
            try:
                response = await _request(ctx, endpoint.url, low["headers"])
            except BudgetExceeded:
                break
            if response is None or response.status_code // 100 != 2:
                continue
            if _LOGIN_BODY.search(response.body[:4000]):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title="Privileged endpoint answered a low-privilege test account",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=6,
                    verification_status=VerificationStatus.SUSPECTED,
                    url=endpoint.url,
                    method="GET",
                    parameter=None,
                    payload=None,
                    description=(
                        f"{endpoint.url} looks like a privileged surface, yet it returned HTTP "
                        f"{response.status_code} to the {low['role']!r} test account "
                        f"({low['label']}). Nothing in the response asked for stronger "
                        "authentication, so the route may rely on client-side hiding alone."
                    ),
                    impact=(
                        "Missing function-level checks expose administrative actions, user "
                        "management or internal tooling to any authenticated account."
                    ),
                    remediation=(
                        "Enforce role/privilege checks on the server for every privileged route, "
                        "deny by default, and return 403 (not a redirect to a rendered page) to "
                        "accounts without the required role."
                    ),
                    references=[
                        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
                    ],
                    cwe=["CWE-862"],
                    owasp=["A01:2021 Broken Access Control"],
                    request_evidence={
                        "method": "GET",
                        "url": endpoint.url,
                        "as_account": low["label"],
                        "role": low["role"],
                    },
                    response_evidence={
                        "status_code": response.status_code,
                        "content_type": response.header("content-type") or "",
                        "login_page_detected": False,
                        "body_stored": False,
                    },
                )
            )
        return findings

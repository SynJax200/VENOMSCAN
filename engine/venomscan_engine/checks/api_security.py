from __future__ import annotations

import json
import re
from collections.abc import Iterator
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.crawl.js import is_static_asset
from venomscan_engine.intel.api import graphql_candidates
from venomscan_engine.intel.jwt import collect
from venomscan_engine.models import Finding, Severity, VerificationStatus
from venomscan_engine.safety.http import (
    BudgetExceeded,
    TargetUnreachable,
    TooManyRedirects,
)
from venomscan_engine.safety.scope import ScopeViolation

MAX_DOCUMENTS = 3
MAX_SAMPLES = 6
MAX_MATCHES_PER_SAMPLE = 3
MAX_BURST = 6
MAX_UNAUTH_PROBES = 4
MAX_GRAPHQL_ENDPOINTS = 3
GRAPHQL_TYPENAME_QUERY = "{__typename}"
GRAPHQL_INTROSPECTION = (
    "query{__schema{queryType{name} mutationType{name} subscriptionType{name} "
    "types{name kind}}}"
)
GRAPHQL_IDE_MARKERS = (
    "graphiql",
    "graphql-playground",
    "graphql playground",
    "apollo sandbox",
    "apollo-server-landing-page",
)

# High-signal secret shapes only; a hit here is unambiguous.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_secret", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
)


def _documents(ctx: ScanContext) -> list[dict]:
    artifact = ctx.artifacts.get("openapi")
    if not isinstance(artifact, dict):
        return []
    documents = artifact.get("documents")
    if not isinstance(documents, list):
        return []
    return [doc for doc in documents[:MAX_DOCUMENTS] if isinstance(doc, dict)]


def _mask(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) <= 8:
        return f"{cleaned[:2]}… (len {len(cleaned)})"
    return f"{cleaned[:4]}…{cleaned[-2:]} (len {len(cleaned)})"


def _walk(node, path: str = "$", depth: int = 0) -> Iterator[tuple[str, str]]:
    if depth > 6:
        return
    if isinstance(node, dict):
        for key, value in list(node.items())[:50]:
            yield from _walk(value, f"{path}.{key}", depth + 1)
    elif isinstance(node, list):
        for index, value in enumerate(node[:20]):
            yield from _walk(value, f"{path}[{index}]", depth + 1)
    elif isinstance(node, str):
        yield path, node


@register
class ApiDocsExposedCheck:
    id = "venom.api.docs"
    name = "API documentation exposure"
    category = "api"
    default_severity = Severity.LOW
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        documents = [doc for doc in _documents(ctx) if int(doc.get("paths") or 0) > 0]
        if not documents:
            return []
        primary = documents[0]
        routes = sum(int(doc.get("paths") or 0) for doc in documents)
        return [
            Finding(
                check_id=self.id,
                title=f"Public API specification exposes {primary['paths']} route(s)",
                category=self.category,
                severity=Severity.LOW,
                confidence=9,
                verification_status=VerificationStatus.VERIFIED,
                url=str(primary.get("url") or ctx.target_url),
                description=(
                    "An OpenAPI/Swagger document was served without authentication through the "
                    "normal crawl probes. It lists the API route table, parameter shapes and "
                    "authentication schemes, which gives an attacker the map before any request "
                    "is guessed."
                ),
                impact=(
                    "Faster attack planning and quieter enumeration: the spec reveals endpoints "
                    "that are not linked from the UI and may include internal or deprecated "
                    "versions."
                ),
                remediation=(
                    "Restrict documentation to internal networks or authenticated users. If it is "
                    "public by design, keep internal server URLs and non-public routes out of the "
                    "published document."
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
                ],
                cwe=["CWE-200"],
                owasp=["API9:2023 Improper Inventory Management"],
                request_evidence={"method": "GET", "url": str(primary.get("url") or "")},
                response_evidence={
                    "documents": [str(doc.get("url") or "") for doc in documents],
                    "routes": routes,
                    "spec_versions": [str(doc.get("spec_version") or "") for doc in documents],
                    "security_schemes": list(primary.get("security_schemes") or []),
                },
            )
        ]


@register
class ApiAuthConfigCheck:
    id = "venom.api.auth"
    name = "API authentication configuration"
    category = "api"
    default_severity = Severity.LOW
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        documents = [doc for doc in _documents(ctx) if int(doc.get("paths") or 0) > 0]
        if not documents:
            return []
        primary = documents[0]
        url = str(primary.get("url") or ctx.target_url)
        findings: list[Finding] = []

        insecure = [
            server
            for server in primary.get("servers") or []
            if isinstance(server, str) and server.lower().startswith("http://")
        ]
        if insecure and ctx.target_url.lower().startswith("https://"):
            findings.append(
                Finding(
                    check_id=self.id,
                    title="API specification advertises a plaintext server",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=9,
                    verification_status=VerificationStatus.VERIFIED,
                    url=url,
                    parameter="servers",
                    description=(
                        "The API document advertises at least one http:// base URL while the "
                        "target itself is served over HTTPS. Clients that follow the spec will "
                        "send credentials and data without transport encryption."
                    ),
                    impact=(
                        "Tokens and request bodies can be read or modified on the path between "
                        "client and server."
                    ),
                    remediation=(
                        "Publish only https:// server URLs and redirect plaintext requests at "
                        "the edge."
                    ),
                    references=["https://owasp.org/www-project-api-security/"],
                    cwe=["CWE-319"],
                    owasp=["A02:2021 Cryptographic Failures"],
                    request_evidence={"method": "GET", "url": url},
                    response_evidence={
                        "spec": url,
                        "servers": list(primary.get("servers") or []),
                    },
                )
            )

        if not primary.get("declared_auth"):
            findings.append(
                Finding(
                    check_id=self.id,
                    title="API specification declares no authentication scheme",
                    category=self.category,
                    severity=Severity.LOW,
                    confidence=7,
                    verification_status=VerificationStatus.VERIFIED,
                    url=url,
                    parameter="securitySchemes",
                    description=(
                        "The published API document defines no security scheme and no global "
                        "security requirement. Either every route is public, or the "
                        "authentication contract is undocumented."
                    ),
                    impact=(
                        "Reviewers and clients cannot tell which routes require credentials, and "
                        "publicly reachable routes may be missing authentication entirely."
                    ),
                    remediation=(
                        "Declare the authentication schemes (bearer, OAuth2, API key) and apply a "
                        "global security requirement; mark intentionally public operations with "
                        "an explicit empty security list."
                    ),
                    references=[
                        "https://swagger.io/docs/specification/authentication/",
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    ],
                    cwe=["CWE-306"],
                    owasp=["API2:2023 Broken Authentication"],
                    request_evidence={"method": "GET", "url": url},
                    response_evidence={
                        "spec": url,
                        "declared_auth": bool(primary.get("declared_auth")),
                        "security_schemes": list(primary.get("security_schemes") or []),
                        "global_security": bool(primary.get("global_security")),
                    },
                )
            )

        return findings


@register
class ApiSensitiveDataCheck:
    id = "venom.api.sensitive"
    name = "Sensitive data in API responses"
    category = "api"
    default_severity = Severity.HIGH
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        samples = ctx.artifacts.get("api_samples")
        if not isinstance(samples, list):
            return []
        findings: list[Finding] = []
        for sample in samples[:MAX_SAMPLES]:
            if not isinstance(sample, dict):
                continue
            content_type = str(sample.get("content_type") or "").lower()
            body = str(sample.get("body") or "")
            if "json" not in content_type and not body.lstrip().startswith(("{", "[")):
                continue
            try:
                payload = json.loads(body)
            except (ValueError, TypeError):
                continue
            matches: list[tuple[str, str, str]] = []
            for path, value in _walk(payload):
                for label, pattern in _SECRET_PATTERNS:
                    match = pattern.search(value)
                    if match:
                        matches.append((path, label, match.group(0)))
                if len(matches) >= MAX_MATCHES_PER_SAMPLE:
                    break
            for path, label, secret in matches[:MAX_MATCHES_PER_SAMPLE]:
                url = str(sample.get("url") or ctx.target_url)
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"API response contains a {label.replace('_', ' ')}",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=9,
                        verification_status=VerificationStatus.VERIFIED,
                        url=url,
                        parameter=path,
                        description=(
                            f"A JSON response from {url} contained a credential-shaped value at "
                            f"{path}. The value is masked in the evidence; its raw form is never "
                            "stored by VENOMSCAN."
                        ),
                        impact=(
                            "A token or key exposed to any client that can read this response may "
                            "grant access beyond the intended user or service."
                        ),
                        remediation=(
                            "Remove credentials from response bodies. Return opaque, short-lived, "
                            "per-user tokens and rotate anything that has already been exposed."
                        ),
                        references=["https://cwe.mitre.org/data/definitions/200.html"],
                        cwe=["CWE-200", "CWE-798"],
                        owasp=["A01:2021 Broken Access Control"],
                        request_evidence={"method": "GET", "url": url},
                        response_evidence={
                            "url": url,
                            "json_path": path,
                            "pattern": label,
                            "masked_value": _mask(secret),
                            "body_stored": False,
                        },
                    )
                )
        return findings


@register
class ApiRateLimitCheck:
    id = "venom.api.ratelimit"
    name = "API rate limiting (bounded burst)"
    category = "api"
    default_severity = Severity.LOW
    profile = "active"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.client is None or ctx.remaining_seconds < 3:
            return []
        endpoint = self._candidate(ctx)
        if endpoint is None:
            return []

        statuses: list[int] = []
        throttled = False
        for _ in range(MAX_BURST):
            if ctx.remaining_seconds < 3:
                return []
            try:
                response = await ctx.client.get(endpoint.url)
            except (TargetUnreachable, TooManyRedirects):
                return []
            statuses.append(response.status_code)
            if response.status_code == 429 or response.header("retry-after"):
                throttled = True
                break
        if throttled or len(statuses) < MAX_BURST:
            return []

        counts: dict[str, int] = {}
        for code in statuses:
            counts[str(code)] = counts.get(str(code), 0) + 1
        return [
            Finding(
                check_id=self.id,
                title="No rate limiting observed on an API endpoint",
                category=self.category,
                severity=Severity.LOW,
                confidence=5,
                verification_status=VerificationStatus.SUSPECTED,
                url=endpoint.url,
                description=(
                    f"A bounded burst of {MAX_BURST} consecutive GET requests to "
                    f"{urlsplit(endpoint.url).path or '/'} returned no 429 and no Retry-After "
                    f"header (statuses: {counts}). A small burst cannot prove that rate limiting "
                    "is absent; confirm the threshold and scope with the API owner."
                ),
                impact=(
                    "If the endpoint is genuinely unlimited, automated enumeration, credential "
                    "stuffing and data scraping become cheaper for an attacker."
                ),
                remediation=(
                    "Apply per-identity and per-IP rate limits with a 429 response and an honest "
                    "Retry-After header; log repeated throttling as a security signal."
                ),
                references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
                cwe=["CWE-770"],
                owasp=["API4:2023 Unrestricted Resource Consumption"],
                request_evidence={"method": "GET", "url": endpoint.url, "burst": MAX_BURST},
                response_evidence={
                    "url": endpoint.url,
                    "status_codes": counts,
                    "retry_after": False,
                    "body_stored": False,
                },
            )
        ]

    def _candidate(self, ctx: ScanContext):
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET" or endpoint.status_code != 200:
                continue
            if endpoint.parameters or endpoint.source == "api-spec":
                continue
            if is_static_asset(endpoint.url):
                continue
            parts = urlsplit(endpoint.url)
            if not parts.path or parts.path == "/":
                continue
            content_type = (endpoint.content_type or "").lower()
            if "/api" in parts.path.lower() or "json" in content_type:
                return endpoint
        return None


@register
class ApiSpecRiskCheck:
    id = "venom.api.spec"
    name = "API specification authorization posture"
    category = "api"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        documents = [doc for doc in _documents(ctx) if int(doc.get("paths") or 0) > 0]
        if not documents:
            return []
        findings: list[Finding] = []

        public_writes: list[tuple[dict, dict]] = [
            (document, operation)
            for document in documents
            if document.get("declared_auth")
            for operation in (document.get("public_writes") or [])
            if isinstance(operation, dict)
        ]
        if public_writes:
            primary = public_writes[0][0]
            url = str(primary.get("url") or ctx.target_url)
            operations = [
                {"method": str(operation.get("method") or ""), "path": str(operation.get("path") or "")}
                for _, operation in public_writes[:10]
            ]
            findings.append(
                Finding(
                    check_id=self.id,
                    title=(
                        f"API specification declares {len(public_writes)} state-changing "
                        "operation(s) without authentication"
                    ),
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=8,
                    verification_status=VerificationStatus.VERIFIED,
                    url=url,
                    parameter="security",
                    payload="public_writes",
                    description=(
                        "The API document uses an authentication scheme elsewhere, but these "
                        "write operations either carry an explicit empty security list or omit "
                        "the requirement while no global security is declared. The published "
                        "contract tells clients those routes are unauthenticated."
                    ),
                    impact=(
                        "If the implementation matches the contract, anyone who can reach the API "
                        "can create, modify or delete data without credentials."
                    ),
                    remediation=(
                        "Require authentication on every state-changing operation, or document "
                        "the compensating controls where a route is intentionally public. Review "
                        "the listed operations before confirming the contract matches the code."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        "https://swagger.io/docs/specification/authentication/",
                    ],
                    cwe=["CWE-306"],
                    owasp=["API2:2023 Broken Authentication"],
                    request_evidence={"method": "GET", "url": url},
                    response_evidence={
                        "operations": operations,
                        "operation_count": len(public_writes),
                        "spec": url,
                    },
                )
            )

        query_schemes = sorted(
            {
                str(name)
                for document in documents
                for name in document.get("api_key_query_schemes") or []
            }
        )
        if query_schemes:
            url = str(documents[0].get("url") or ctx.target_url)
            findings.append(
                Finding(
                    check_id=self.id,
                    title="API key is accepted in the query string",
                    category=self.category,
                    severity=Severity.LOW,
                    confidence=8,
                    verification_status=VerificationStatus.VERIFIED,
                    url=url,
                    parameter="securitySchemes",
                    payload="api_key_query",
                    description=(
                        "The published specification declares an API key transported as a query "
                        f"parameter ({', '.join(query_schemes)}). Query strings are written to "
                        "access logs, proxies and browser history."
                    ),
                    impact=(
                        "Keys leak into infrastructure that was never meant to hold credentials, "
                        "and shared links can expose a working key."
                    ),
                    remediation=(
                        "Move API keys to an Authorization header (or a scoped cookie with "
                        "HttpOnly) and rotate any key that has travelled in a URL."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
                    ],
                    cwe=["CWE-598"],
                    owasp=["API2:2023 Broken Authentication"],
                    request_evidence={"method": "GET", "url": url},
                    response_evidence={"schemes": query_schemes},
                )
            )

        implicit = sorted(
            {
                str(name)
                for document in documents
                for name in document.get("oauth_implicit") or []
            }
        )
        if implicit:
            url = str(documents[0].get("url") or ctx.target_url)
            findings.append(
                Finding(
                    check_id=self.id,
                    title="API specification declares the OAuth implicit grant",
                    category=self.category,
                    severity=Severity.LOW,
                    confidence=7,
                    verification_status=VerificationStatus.VERIFIED,
                    url=url,
                    parameter="securitySchemes",
                    payload="oauth_implicit",
                    description=(
                        "OAuth 2.0 implicitly returns access tokens in the URL fragment "
                        f"({', '.join(implicit)}), which browsers and intermediaries can log or "
                        "leak through the Referer header."
                    ),
                    impact=(
                        "Access tokens become readable wherever URLs are stored, and the flow "
                        "cannot authenticate the client."
                    ),
                    remediation=(
                        "Replace the implicit grant with authorization code + PKCE for public "
                        "clients and keep tokens out of URLs."
                    ),
                    references=[
                        "https://oauth.net/2/grant-types/implicit/",
                        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                    ],
                    cwe=["CWE-598"],
                    owasp=["API2:2023 Broken Authentication"],
                    request_evidence={"method": "GET", "url": url},
                    response_evidence={"schemes": implicit},
                )
            )
        return findings


def _colon_parameter(path: str) -> bool:
    return any(segment.startswith(":") for segment in path.split("/") if segment)


@register
class ApiUnauthenticatedCheck:
    id = "venom.api.unauth"
    name = "API operation answers without authentication"
    category = "api"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.client is None or ctx.remaining_seconds < 5:
            return []
        candidates: list[tuple[str, dict]] = []
        seen: set[str] = set()
        for document in _documents(ctx):
            if int(document.get("paths") or 0) == 0 or not document.get("declared_auth"):
                continue
            spec_url = str(document.get("url") or ctx.target_url)
            for operation in document.get("protected_gets") or []:
                if len(candidates) >= MAX_UNAUTH_PROBES:
                    break
                path = str(operation.get("path") or "")
                if not path or "{" in path or "}" in path or _colon_parameter(path):
                    continue
                url = urljoin(spec_url, path)
                parts = urlsplit(url)
                if parts.scheme not in {"http", "https"} or not parts.path or parts.path == "/":
                    continue
                if url in seen:
                    continue
                seen.add(url)
                candidates.append((url, document))

        findings: list[Finding] = []
        for url, document in candidates:
            if ctx.remaining_seconds < 3:
                break
            try:
                response = await ctx.client.get(url, headers={"Accept": "application/json"})
            except BudgetExceeded:
                break
            except (TargetUnreachable, TooManyRedirects, ScopeViolation):
                continue
            if not 200 <= response.status_code < 300:
                continue
            content_type = (response.header("content-type") or "").lower()
            body = response.body.lstrip()
            if "json" not in content_type and not body.startswith(("{", "[")):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title="API operation answers without authentication",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=6,
                    verification_status=VerificationStatus.SUSPECTED,
                    url=url,
                    description=(
                        f"The specification marks GET {urlsplit(url).path or '/'} as requiring "
                        "authentication, but the route returned a successful response to an "
                        "unauthenticated request. A single sample cannot prove the route is "
                        "authorization-free; confirm whether the data is meant to be public."
                    ),
                    impact=(
                        "Data intended for authenticated users may be readable by anyone who can "
                        "reach the API, which is the entry point for object enumeration."
                    ),
                    remediation=(
                        "Enforce the declared authentication requirement on the route, or update "
                        "the specification if the data is intentionally public."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                    ],
                    cwe=["CWE-306"],
                    owasp=["API2:2023 Broken Authentication"],
                    request_evidence={"method": "GET", "url": url, "credentials": "none"},
                    response_evidence={
                        "status_code": response.status_code,
                        "content_type": content_type,
                        "spec": str(document.get("url") or ""),
                        "body_stored": False,
                    },
                )
            )
        return findings


_JWT_FLAG_FINDINGS: dict[str, dict] = {
    "alg_none": {
        "severity": Severity.HIGH,
        "confidence": 9,
        "title": "JWT uses alg=none (unsigned token)",
        "description": (
            "A token observed by the scanner carries alg=none in its header. Any party that "
            "receives such a token is asked to accept it without a signature."
        ),
        "impact": (
            "If any service in the trust chain honours the token, an attacker can mint an "
            "arbitrary identity by editing the claims."
        ),
        "remediation": (
            "Reject alg=none in every verifier, pin the accepted algorithms per issuer and "
            "rotate keys for tokens already issued."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/347.html"],
        "cwe": ["CWE-347", "CWE-798"],
        "owasp": ["API2:2023 Broken Authentication"],
    },
    "sensitive_claims": {
        "severity": Severity.HIGH,
        "confidence": 8,
        "title": "JWT carries credential-shaped claims",
        "description": (
            "The token's claims include names such as password, secret, api_key or "
            "refresh_token. Claims are readable by anyone who holds the token."
        ),
        "impact": (
            "A leaked token exposes reusable credentials rather than a scoped, short-lived "
            "identity assertion."
        ),
        "remediation": (
            "Keep credentials out of tokens; reference server-side state by id and rotate any "
            "value that has been embedded in a token."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/522.html"],
        "cwe": ["CWE-522"],
        "owasp": ["API2:2023 Broken Authentication"],
    },
    "external_key_url": {
        "severity": Severity.MEDIUM,
        "confidence": 8,
        "title": "JWT header points at an external key URL",
        "description": (
            "The token header carries a jku or x5u URL on another host. Verifiers that follow "
            "it fetch key material from a location the attacker may control."
        ),
        "impact": (
            "Key-injection attacks become possible when the verifier trusts an attacker-supplied "
            "key URL, and the fetch itself can reach internal services."
        ),
        "remediation": (
            "Pin verification keys locally or allowlist trusted key hosts; reject tokens whose "
            "jku/x5u host is not the issuer's own."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
        "cwe": ["CWE-918", "CWE-347"],
        "owasp": ["API2:2023 Broken Authentication"],
    },
    "url_exposure": {
        "severity": Severity.MEDIUM,
        "confidence": 8,
        "title": "JWT transported in a URL query string",
        "description": (
            "A token was harvested from a URL query string. URLs are logged by servers, proxies "
            "and analytics, and leak through Referer and browser history."
        ),
        "impact": (
            "A token that reaches logs or third-party analytics can be replayed by anyone who "
            "can read those stores."
        ),
        "remediation": (
            "Send bearer tokens in the Authorization header over TLS, keep them out of URLs and "
            "rotate tokens that travelled in query strings."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/598.html"],
        "cwe": ["CWE-598"],
        "owasp": ["API2:2023 Broken Authentication"],
    },
    "missing_exp": {
        "severity": Severity.MEDIUM,
        "confidence": 7,
        "title": "JWT has no expiry claim",
        "description": (
            "The observed token carries no exp claim. Without an expiry the credential stays "
            "valid until the signing key is rotated or the token is revoked explicitly."
        ),
        "impact": (
            "A stolen non-expiring token keeps working indefinitely, and revocation depends on "
            "state the verifier may not keep."
        ),
        "remediation": (
            "Issue short-lived access tokens with exp and iat, and pair them with refresh tokens "
            "that can be revoked."
        ),
        "references": ["https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4"],
        "cwe": ["CWE-613"],
        "owasp": ["API2:2023 Broken Authentication"],
    },
    "long_lifetime": {
        "severity": Severity.LOW,
        "confidence": 7,
        "title": "JWT lifetime exceeds 30 days",
        "description": (
            "The token's exp claim is more than 30 days after its use. Long-lived bearer tokens "
            "widen the replay window for anyone who captures them."
        ),
        "impact": (
            "A leaked token remains usable for weeks, and revocation has to reach every service "
            "that accepted it."
        ),
        "remediation": (
            "Reduce access-token lifetimes to minutes or hours and refresh them; keep long "
            "sessions in revocable server-side state."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/613.html"],
        "cwe": ["CWE-613"],
        "owasp": ["API2:2023 Broken Authentication"],
    },
}


@register
class JwtCheck:
    id = "venom.api.jwt"
    name = "JWT hygiene (offline analysis)"
    category = "api"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        intel = ctx.artifacts.get("api_intel")
        if not isinstance(intel, dict):
            intel = {}
            ctx.artifacts["api_intel"] = intel
        jwt_intel = intel.setdefault("jwt", {})
        tokens = jwt_intel.get("tokens")
        if not isinstance(tokens, list) or not tokens:
            tokens = collect(
                ctx.artifacts.get("api_samples") or [],
                ctx.endpoints,
                ctx.root.set_cookies if ctx.root is not None else [],
            )
            jwt_intel["tokens"] = tokens

        findings: list[Finding] = []
        for token in tokens:
            if not isinstance(token, dict):
                continue
            flags = [flag for flag in token.get("flags") or [] if flag in _JWT_FLAG_FINDINGS]
            for flag in flags:
                template = _JWT_FLAG_FINDINGS[flag]
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=str(template["title"]),
                        category=self.category,
                        severity=template["severity"],
                        confidence=int(template["confidence"]),
                        verification_status=VerificationStatus.VERIFIED,
                        url=str(token.get("source") or ctx.target_url),
                        parameter=str(token.get("location") or "token"),
                        payload=f"{token.get('fingerprint')}:{flag}",
                        description=(
                            f"{template['description']} The token (fingerprint "
                            f"{token.get('fingerprint')}, prefix {token.get('prefix')}…) is "
                            "stored only as a hash."
                        ),
                        impact=str(template["impact"]),
                        remediation=str(template["remediation"]),
                        references=list(template["references"]),
                        cwe=list(template["cwe"]),
                        owasp=list(template["owasp"]),
                        request_evidence={
                            "method": "GET",
                            "url": str(token.get("source") or ""),
                            "location": str(token.get("location") or ""),
                        },
                        response_evidence={
                            "fingerprint": str(token.get("fingerprint") or ""),
                            "prefix": str(token.get("prefix") or ""),
                            "alg": str(token.get("alg") or ""),
                            "claims": list(token.get("claims") or []),
                            "lifetime_days": token.get("lifetime_days"),
                            "flags": flags,
                            "token_stored": False,
                        },
                    )
                )
        return findings


def _with_query(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _graphql_payload(body: str) -> dict | None:
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _schema_counts(schema: dict) -> dict:
    raw_types = schema.get("types") if isinstance(schema.get("types"), list) else []
    types = [item for item in raw_types if isinstance(item, dict) and item.get("name")]
    objects = [item for item in types if str(item.get("kind") or "").upper() == "OBJECT"]
    names = [str(item["name"]) for item in objects if not str(item["name"]).startswith("__")]
    return {
        "type_count": len(types),
        "object_count": len(objects),
        "mutation_available": bool(schema.get("mutationType")),
        "sample_types": names[:6],
    }


@register
class GraphqlCheck:
    id = "venom.api.graphql"
    name = "GraphQL surface (introspection and IDE)"
    category = "api"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        intel = ctx.artifacts.get("api_intel")
        if not isinstance(intel, dict):
            intel = {}
            ctx.artifacts["api_intel"] = intel
        graphql = intel.setdefault("graphql", {})
        candidates = graphql.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            candidates = graphql_candidates(
                ctx.endpoints,
                ctx.artifacts.get("js_intel") or {},
                target_host=urlsplit(ctx.target_url).hostname or "",
            )
            graphql["candidates"] = candidates
        if ctx.client is None or not candidates:
            return []

        findings: list[Finding] = []
        confirmed: list[str] = []
        introspection = False
        ide = False
        probed = 0
        counts: dict = {}
        for endpoint in candidates[:MAX_GRAPHQL_ENDPOINTS]:
            if ctx.remaining_seconds < 6:
                break
            probed += 1
            try:
                landing = await ctx.client.get(endpoint)
            except BudgetExceeded:
                break
            except (TargetUnreachable, TooManyRedirects, ScopeViolation):
                continue
            if any(marker in landing.body.lower() for marker in GRAPHQL_IDE_MARKERS):
                ide = True
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="GraphQL IDE is exposed",
                        category=self.category,
                        severity=Severity.LOW,
                        confidence=6,
                        verification_status=VerificationStatus.VERIFIED,
                        url=endpoint,
                        payload="graphql_ide",
                        description=(
                            "The GraphQL endpoint served an interactive IDE (GraphiQL, "
                            "Playground or Apollo Sandbox) to an unauthenticated request. The "
                            "console makes schema exploration and query crafting one click away."
                        ),
                        impact=(
                            "An exposed console lowers the effort needed to enumerate the schema "
                            "and test queries against production data."
                        ),
                        remediation=(
                            "Disable the in-browser IDE in production or require authentication "
                            "before it is served."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
                        ],
                        cwe=["CWE-200"],
                        owasp=["API9:2023 Improper Inventory Management"],
                        request_evidence={"method": "GET", "url": endpoint},
                        response_evidence={"status_code": landing.status_code, "ide": True},
                    )
                )

            schema: dict | None = None
            method_used = "GET"
            try:
                probe = await ctx.client.get(_with_query(endpoint, "query", GRAPHQL_TYPENAME_QUERY))
            except BudgetExceeded:
                break
            except (TargetUnreachable, TooManyRedirects, ScopeViolation):
                continue
            payload = _graphql_payload(probe.body)
            data = payload.get("data") if payload else None
            is_graphql = isinstance(data, dict) and "__typename" in data
            if is_graphql:
                confirmed.append(endpoint)
                if ctx.remaining_seconds > 4:
                    try:
                        introspected = await ctx.client.get(
                            _with_query(endpoint, "query", GRAPHQL_INTROSPECTION)
                        )
                    except BudgetExceeded:
                        break
                    except (TargetUnreachable, TooManyRedirects, ScopeViolation):
                        introspected = None
                    if introspected is not None:
                        intro_payload = _graphql_payload(introspected.body)
                        intro_data = intro_payload.get("data") if intro_payload else None
                        if isinstance(intro_data, dict) and isinstance(intro_data.get("__schema"), dict):
                            schema = intro_data["__schema"]
            elif ctx.profile == "active" and probe.status_code in {400, 405, 415}:
                if ctx.remaining_seconds > 4:
                    try:
                        posted = await ctx.client.request(
                            "POST",
                            endpoint,
                            headers={"Accept": "application/json"},
                            json={"query": GRAPHQL_INTROSPECTION},
                        )
                    except BudgetExceeded:
                        break
                    except (TargetUnreachable, TooManyRedirects, ScopeViolation):
                        posted = None
                    if posted is not None:
                        post_payload = _graphql_payload(posted.body)
                        post_data = post_payload.get("data") if post_payload else None
                        if isinstance(post_data, dict) and isinstance(post_data.get("__schema"), dict):
                            schema = post_data["__schema"]
                            method_used = "POST"
                            confirmed.append(endpoint)
            if schema is None:
                continue
            introspection = True
            counts = _schema_counts(schema)
            findings.append(
                Finding(
                    check_id=self.id,
                    title="GraphQL introspection is enabled",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=9,
                    verification_status=VerificationStatus.VERIFIED,
                    url=endpoint,
                    method=method_used,
                    payload="introspection",
                    description=(
                        "The endpoint answered the standard introspection query with a schema "
                        f"containing {counts['type_count']} type(s) and "
                        f"{counts['object_count']} object type(s). Sample types: "
                        f"{', '.join(counts['sample_types']) or 'none'}."
                    ),
                    impact=(
                        "The complete API schema (types, fields, arguments, mutations) can be "
                        "pulled in one request, removing the guesswork from finding sensitive "
                        "queries and mutation inputs."
                    ),
                    remediation=(
                        "Disable introspection in production (allow it only for trusted clients "
                        "or in development) and keep schema details behind the same auth boundary "
                        "as the data."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                        "https://graphql.org/learn/introspection/",
                    ],
                    cwe=["CWE-200"],
                    owasp=["API9:2023 Improper Inventory Management"],
                    request_evidence={"method": method_used, "url": endpoint, "query": "introspection"},
                    response_evidence={
                        **counts,
                        "introspection": True,
                        "body_stored": False,
                    },
                )
            )

        graphql.update(
            {
                "probed": probed,
                "confirmed": list(dict.fromkeys(confirmed)),
                "introspection": introspection,
                "ide": ide,
                **counts,
            }
        )
        return findings


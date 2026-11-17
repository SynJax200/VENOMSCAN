from __future__ import annotations

from urllib.parse import urlsplit

from .model import ReportFinding


def _host(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    return parts.hostname or parts.netloc or url


def _port(url: str) -> int:
    try:
        parts = urlsplit(url)
        return parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return 443


def _header_probe(url: str) -> str:
    return f"curl -sS -D - -o /dev/null '{url}'"


def _replay(url: str, method: str = "GET") -> str:
    if method.upper() == "GET":
        return f"curl -sS '{url}'"
    return f"curl -sS -X {method.upper()} '{url}'"


def _evidence(finding: ReportFinding, key: str, default: object = "") -> object:
    for source in (finding.request_evidence, finding.response_evidence):
        if key in source:
            return source[key]
    return default


def _tls_steps(finding: ReportFinding) -> list[str]:
    host = _host(finding.url)
    port = _port(finding.url)
    command = f"openssl s_client -connect {host}:{port} -servername {host} </dev/null"
    checks = {
        "venom.tls.expired": "the 'Not After' date in the certificate chain is in the past",
        "venom.tls.expiring": "the 'Not After' date is within the next 30 days",
        "venom.tls.protocol": "the negotiated 'Protocol' line shows TLS 1.0 or TLS 1.1",
        "venom.tls.cipher": "the negotiated 'Cipher' line names a weak or export-grade suite",
        "venom.tls.untrusted": "the 'Verify return code' line is non-zero (chain or hostname validation failed)",
    }
    detail = checks.get(finding.check_id, "the certificate chain or negotiated parameters are weak")
    return [
        f"Connect to the TLS endpoint: {command}",
        f"Inspect the output — {detail}.",
    ]


def _headers_steps(finding: ReportFinding) -> list[str]:
    url = finding.url
    lookups = {
        "venom.headers.csp": "Content-Security-Policy is absent from the response headers",
        "venom.headers.hsts": "Strict-Transport-Security is absent from the HTTPS response headers",
        "venom.headers.hardening": (
            "one or more of X-Content-Type-Options, Referrer-Policy, Permissions-Policy and "
            "Cross-Origin-Opener-Policy is absent (the finding lists each missing header)"
        ),
    }
    detail = lookups.get(finding.check_id, "the header named in the finding is absent")
    return [
        f"Fetch the response headers: {_header_probe(url)}",
        f"Confirm that {detail}.",
    ]


def _cookie_steps(finding: ReportFinding) -> list[str]:
    steps = [f"Fetch the response headers: {_header_probe(finding.url)}"]
    if finding.check_id == "venom.session":
        cookie = finding.parameter or "the session cookie"
        domain = _evidence(finding, "domain", "")
        scope = f"Domain={domain}" if domain else "a Domain attribute"
        steps.append(
            f"Inspect Set-Cookie for '{cookie}': it declares {scope}, so sibling hosts under "
            "the parent domain also receive it."
        )
        return steps
    cookie = f"the cookie '{finding.parameter}'" if finding.parameter else "each Set-Cookie line"
    steps.append(
        f"Inspect {cookie}: at least one of Secure, HttpOnly or SameSite is missing, as recorded "
        "in the finding evidence."
    )
    return steps


def _cors_steps(finding: ReportFinding) -> list[str]:
    origin = _evidence(finding, "origin", "https://venomscan-canary.invalid")
    steps = [
        f"Send a cross-origin request: curl -sS -H 'Origin: {origin}' -D - -o /dev/null "
        f"'{finding.url}'",
        f"The response reflects Access-Control-Allow-Origin: {origin}",
    ]
    if _evidence(finding, "access_control_allow_credentials", False):
        steps[-1] += " together with Access-Control-Allow-Credentials: true"
    steps[-1] += ", so any website can read the response."
    return steps


def _account_steps(finding: ReportFinding) -> list[str]:
    url = finding.url
    owner = _evidence(finding, "as_owner") or _evidence(finding, "as_account") or "the owning account"
    other = _evidence(finding, "as_other") or "a different account"
    steps = [
        f"Sign in as {owner} and request {url}; note the object identifier in the response.",
    ]
    if finding.check_id == "venom.authz.function":
        role = _evidence(finding, "role", "")
        suffix = f" (role: {role})" if role else ""
        steps.append(
            f"Repeat the request as a lower-privileged account{suffix} without the required role; "
            f"{url} still returns the privileged action response."
        )
    else:
        steps.append(
            f"Repeat the request as {other} substituting the identifier; the same object is "
            "returned instead of 403/404."
        )
    return steps


def _active_probe_steps(finding: ReportFinding) -> list[str]:
    replay_url = _evidence(finding, "url", finding.url) or finding.url
    parameter = finding.parameter or "the injected parameter"
    checks = {
        "venom.xss.reflected": "the payload is reflected unencoded in the response body",
        "venom.xss.dom": f"client-side script creates the marker element '{_evidence(finding, 'marker', '')}'",
        "venom.sqli.error": f"the body shows the database error family '{_evidence(finding, 'error_family', '')}' "
        "while the benign control value returns a clean page",
        "venom.sqli.time": "the response is delayed past the injection delay threshold "
        "while the benign control value returns immediately",
        "venom.ssti": f"the body contains the evaluated result '{_evidence(finding, 'evaluated', '')}'",
        "venom.ssrf": f"the out-of-band listener at '{_evidence(finding, 'callback_host', '')}' receives a hit",
        "venom.lfi.path": f"the body contains the marker for '{_evidence(finding, 'matched_file', '')}' "
        "while the benign control value is clean",
        "venom.xxe": "the response contains the expanded entity from the recorded XML body",
        "venom.redirect.open": f"the Location header points at the off-scope canary "
        f"'{_evidence(finding, 'canary', '')}'",
    }
    detail = checks.get(finding.check_id, "the recorded response shows the reported behaviour")
    steps = [
        f"Replay the captured request in an authorized client (proxy repeater or shell): "
        f"{_replay(str(replay_url), finding.method)}",
    ]
    if finding.payload:
        steps.append(f"The request carried the payload '{finding.payload}' in {parameter}.")
    steps.append(f"Confirm that {detail}.")
    return steps


def _api_steps(finding: ReportFinding) -> list[str]:
    url = _evidence(finding, "url", finding.url) or finding.url
    if finding.check_id == "venom.api.ratelimit":
        return [
            f"Send a bounded burst of 20 requests: for i in $(seq 1 20); do curl -s -o /dev/null "
            f"-w '%{{http_code}}\\n' '{url}'; done",
            "Every response returned a normal status — no 429 and no Retry-After header appeared.",
        ]
    if finding.check_id in {"venom.api.spec", "venom.api.docs"}:
        return [
            f"Fetch the API description document: {_replay(str(url))}",
            "The document is served without authentication and lists routes and parameters "
            "(see the evidence block for the parsed inventory).",
        ]
    return [
        f"Send the request without session credentials: {_replay(str(url), finding.method)}",
        "The endpoint answers with data instead of 401/403, confirming the finding.",
    ]


def reproduction_steps(finding: ReportFinding) -> list[str]:
    """Deterministic, evidence-derived replication steps for one finding.

    Steps only restate what the scanner observed (URL, payload, account labels,
    header values); they never invent behaviour the evidence does not show.
    """
    check = finding.check_id
    if check.startswith("venom.headers."):
        return _headers_steps(finding)
    if check.startswith("venom.tls."):
        return _tls_steps(finding)
    if check in {"venom.cookies.flags", "venom.session"}:
        return _cookie_steps(finding)
    if check == "venom.cors.misconfig":
        return _cors_steps(finding)
    if check in {"venom.idor", "venom.authz.function"}:
        return _account_steps(finding)
    if check.startswith("venom.api.") and check != "venom.api.auth":
        return _api_steps(finding)
    if check in {
        "venom.xss.reflected",
        "venom.xss.dom",
        "venom.sqli.error",
        "venom.sqli.time",
        "venom.ssti",
        "venom.ssrf",
        "venom.lfi.path",
        "venom.xxe",
        "venom.redirect.open",
    }:
        return _active_probe_steps(finding)

    steps = [f"Request the affected endpoint: {_replay(finding.url, finding.method)}"]
    if check == "venom.clickjacking":
        steps.append(
            "Load the URL inside an <iframe> on a page from another origin; the target frame "
            "renders because X-Frame-Options and CSP frame-ancestors are absent."
        )
    elif check == "venom.methods":
        steps = [
            f"Ask the server which methods it allows: curl -sS -X OPTIONS -D - -o /dev/null "
            f"'{finding.url}'",
            "The Allow header advertises a risky method (see evidence); replay it with "
            "curl -sS -X <method> to confirm the handler responds.",
        ]
    elif check == "venom.info.server":
        steps = [
            f"Fetch the response headers: {_header_probe(finding.url)}",
            "The Server or X-Powered-By header discloses the software stack to every visitor.",
        ]
    elif check == "venom.info.version":
        steps = [
            f"Fetch the response headers: {_header_probe(finding.url)}",
            "A version banner is present in Server, X-Powered-By or a generator meta tag, "
            "matching the evidence excerpt.",
        ]
    elif check == "venom.info.errors":
        signature = _evidence(finding, "signature", "")
        steps.append(
            f"The response body contains the '{signature}' signature recorded in the evidence "
            "(verbatim body redacted in this report)."
        )
    elif check == "venom.info.dirlist":
        steps.append(
            "The body is a generated directory index ('Index of …') that lists every file in "
            "the folder."
        )
    elif check == "venom.transport.plaintext":
        plain = finding.url.replace("https://", "http://", 1)
        steps = [
            f"Request the plaintext URL: curl -sS -I '{plain}'",
            "The server answers over HTTP instead of redirecting to HTTPS.",
        ]
    elif check == "venom.secrets.js":
        pattern = _evidence(finding, "pattern", finding.parameter or "the secret pattern")
        masked = _evidence(finding, "masked_value", "«redacted»")
        steps = [
            f"Download the script delivered to the browser: {_replay(finding.url)}",
            f"Search the body for {pattern}; the matched value {masked} is shipped to every visitor.",
        ]
    elif check == "venom.cache":
        steps = [
            f"Fetch the authenticated page: {_header_probe(finding.url)}",
            "The response sets a cookie but sends neither Cache-Control: no-store/private nor "
            "Pragma: no-cache, so shared caches may store the body.",
        ]
    elif check == "venom.csrf.token":
        action = _evidence(finding, "url", finding.url) or finding.url
        page = _evidence(finding, "page", "")
        steps = [
            f"Open the form page{f' ({page})' if page else ''} and inspect its fields; no CSRF "
            "token input is present.",
            f"Submit the form to {action} from a page on another origin; the action is processed.",
        ]
    elif check == "venom.files.exposed":
        steps.append(
            "The server returns the file with HTTP 200 (see the evidence status code and "
            "content type); the path should not be reachable in production."
        )
    elif check == "venom.auth.pages":
        steps.append(
            "The page is reachable without authenticating (see the evidence status code); "
            "restrict it before production."
        )
    else:
        steps.append(
            f"Re-run the '{check}' check in VENOMSCAN against this authorized target and compare "
            "the result with this report."
        )
    return steps

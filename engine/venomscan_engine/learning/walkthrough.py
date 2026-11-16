from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_HINTS = (
    "authorization",
    "cookie",
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "set-cookie",
    "session",
    "credential",
)

SAFETY = (
    "Stay inside the authorization on file: one request at a time, no payloads beyond the "
    "platform's safe profile, and never point a probe at internal, third-party or out-of-scope hosts."
)

_MAX_ITEMS = 8
_CLIP = 200


def _clip(value: Any, limit: int = _CLIP) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(hint in lowered for hint in SENSITIVE_HINTS)


def _flatten(evidence: dict | None, *, redact: bool) -> dict[str, str]:
    rows: dict[str, str] = {}

    def walk(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            for key, inner in value.items():
                walk(f"{prefix}.{key}" if prefix else str(key), inner)
            return
        if isinstance(value, (list, tuple)):
            if not value:
                return
            rendered = ", ".join(_clip(item, 60) for item in value[:_MAX_ITEMS])
            rows[prefix] = ("[redacted]" if redact and _sensitive(prefix) else rendered)
            return
        if value is None or value == "":
            return
        rows[prefix] = "[redacted]" if redact and _sensitive(prefix) else _scrub(_clip(value), prefix)

    walk("", evidence or {})
    return rows


def _scrub(text: str, key: str) -> str:
    if "url" not in key.lower():
        return text
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    if not parts.query:
        return text
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not any(_sensitive(name) for name, _ in pairs):
        return text
    scrubbed = [(name, "[redacted]" if _sensitive(name) else value) for name, value in pairs]
    return urlunsplit(parts._replace(query=urlencode(scrubbed, safe="[]")))


def _path(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    return parts.path or "/"


def build_walkthrough(finding: dict, learning: dict | None = None) -> dict:
    """Turn a stored finding into an ordered, evidence-grounded study walkthrough."""
    url = str(finding.get("url") or "")
    method = str(finding.get("method") or "GET")
    status = str(finding.get("verification_status") or "suspected")
    confidence = finding.get("confidence")
    risk = finding.get("risk_score")
    request_rows = _flatten(finding.get("request_evidence"), redact=True)
    response_rows = _flatten(finding.get("response_evidence"), redact=True)
    path = _path(url)

    steps = [
        {
            "key": "scope",
            "title": "Confirm scope",
            "detail": (
                f"The platform recorded a {method} request to {path}. Re-read the authorization for "
                "this target before touching anything: host, ports, protocols and windows must all "
                "match. If any part is outside scope, stop here and report it instead."
            ),
            "evidence": {"method": method, "url": _scrub(url, "url")},
        },
        {
            "key": "reproduce",
            "title": "Reproduce once",
            "detail": (
                "Replay the exact request a single time with your own client, keeping only headers "
                "you own. Sensitive values are redacted below; supply them from your test account, "
                "never from a real user."
            ),
            "evidence": request_rows,
        },
        {
            "key": "signal",
            "title": "Read the signal",
            "detail": (
                f"The scan claims \"{_clip(finding.get('title') or 'a finding', 120)}\". Compare each "
                "field below against a benign control request. A signal only counts when it changes "
                "reproducibly."
            ),
            "evidence": response_rows,
        },
        {
            "key": "judge",
            "title": "Judge the evidence",
            "detail": (
                f"Verification status is {status}; confidence {confidence if confidence is not None else 'n/a'}"
                f"/10 and risk score {risk if risk is not None else 'n/a'}. A verified finding needs a "
                "second independent signal; a suspected one needs your manual check before you report it."
            ),
            "evidence": {
                "verification": status,
                "confidence": str(confidence if confidence is not None else "n/a"),
                "risk_score": str(risk if risk is not None else "n/a"),
            },
        },
        {
            "key": "fix",
            "title": "Remediate and re-test",
            "detail": (
                "Read the remediation as a root-cause statement, propose the smallest fix, then re-run "
                "the same request plus a control. The finding is closed only when the signal is gone "
                "and the control still behaves as before."
            ),
            "evidence": {"remediation": _clip(finding.get("remediation") or "Not recorded", 400)},
        },
    ]

    questions = [
        f"Which response field would change if the defect at {path} were fixed?",
        "What does a benign control request look like, and why is it required before reporting?",
        "Could a different check explain the same evidence? Which one, and how would you tell them apart?",
    ]

    references = [str(ref) for ref in (finding.get("references") or []) if ref][:6]
    return {
        "finding_id": finding.get("id", ""),
        "check_id": finding.get("check_id", ""),
        "title": finding.get("title", ""),
        "severity": finding.get("severity", ""),
        "url": _scrub(url, "url"),
        "method": method,
        "verification_status": status,
        "confidence": confidence,
        "risk_score": risk,
        "learning": learning or {},
        "steps": steps,
        "questions": questions,
        "safety": SAFETY,
        "references": references,
    }

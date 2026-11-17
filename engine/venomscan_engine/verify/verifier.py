from __future__ import annotations

from typing import Any

from venomscan_engine.models import Finding, VerificationStatus

# Passive configuration checks read state we directly observed in a response we
# fetched ourselves, so they can be verified when that response is stored.
DETERMINISTIC_CHECK_PREFIXES = (
    "venom.headers.",
    "venom.cookies.",
    "venom.tls.",
    "venom.transport.",
    "venom.info.",
    "venom.clickjacking",
    "venom.files.",
    "venom.methods",
    "venom.cors.",
    "venom.cache.",
    "venom.session.",
    "venom.redirect.",
)
DETERMINISTIC_CHECK_IDS = {"venom.tls.weak", "venom.cache", "venom.methods", "venom.session"}

# Heuristic observations cannot be promoted: they describe a pattern, not a
# confirmed behaviour, even when the evidence dictionary is populated.
HEURISTIC_CHECK_PREFIXES = ("venom.auth.", "venom.secrets.", "venom.csrf.")
HEURISTIC_CHECK_IDS = {
    "venom.api.unauth",
    "venom.api.ratelimit",
    "venom.authz.function",
}

EXTERNAL_CHECK_PREFIXES = ("nuclei.", "burp.", "plugin.")

# Exploit findings may only stay VERIFIED when the check recorded the proof it
# claims. Missing keys mean the confirmation path regressed, so the finding is
# downgraded instead of silently trusted.
REQUIRED_RESPONSE_EVIDENCE: dict[str, tuple[str, ...]] = {
    "venom.xss.reflected": ("reflection", "variants_reflected"),
    "venom.xss.dom": ("sink",),
    "venom.sqli.error": ("error_family", "control_clean"),
    "venom.sqli.time": ("baseline_ms", "attempt_ms", "delayed_attempts"),
    "venom.ssrf": ("callback_received",),
    "venom.xxe": ("external_entity_fetched",),
    "venom.ssti": ("evaluated", "variants_evaluated"),
    "venom.lfi.path": ("matched_file", "control_clean"),
    "venom.idor": ("identity_exposed_to_other",),
}

# A check may emit findings with different proof shapes. Each outer entry is an
# any-of list of groups; every key inside a group must be present. False is a
# valid value for keys in PRESENCE_KEYS (for example declared_auth=False).
OBSERVED_RESPONSE_EVIDENCE: dict[str, tuple[tuple[str, ...], ...]] = {
    "venom.api.docs": (("documents", "routes"),),
    "venom.api.auth": (("declared_auth",), ("servers",)),
    "venom.api.sensitive": (("json_path", "pattern", "masked_value"),),
    "venom.api.spec": (("operations",), ("schemes",)),
    "venom.api.jwt": (("fingerprint", "alg", "flags"),),
    "venom.api.graphql": (("ide",), ("introspection",)),
    "venom.files.exposed": (("signature", "status_code"),),
    "venom.methods": (("allow",),),
    "venom.cors.misconfig": (("access_control_allow_origin",),),
    "venom.cache": (("set_cookie",),),
    "venom.session": (("cookie", "domain"),),
    "venom.redirect.open": (("location", "canary"),),
}

OBSERVED_GENERIC_KEYS = (
    "url",
    "status_code",
    "headers",
    "tls",
    "page",
    "cookie",
    "location",
    "signature",
    "allow",
    "set_cookie",
    "cache_control",
)

PRESENCE_KEYS = {"declared_auth", "global_security", "ide", "introspection", "set_cookie"}

DOWNGRADED_CONFIDENCE_CAP = 5
DOWNGRADE_NOTE = "evidence contract incomplete"


def is_deterministic(check_id: str) -> bool:
    return check_id in DETERMINISTIC_CHECK_IDS or check_id.startswith(DETERMINISTIC_CHECK_PREFIXES)


def is_heuristic(check_id: str) -> bool:
    return check_id in HEURISTIC_CHECK_IDS or check_id.startswith(HEURISTIC_CHECK_PREFIXES)


def is_external(check_id: str) -> bool:
    return check_id.startswith(EXTERNAL_CHECK_PREFIXES)


def evidence_category(check_id: str) -> str:
    if check_id in REQUIRED_RESPONSE_EVIDENCE:
        return "exploit"
    if is_heuristic(check_id):
        return "heuristic"
    if is_deterministic(check_id) or check_id.startswith(("venom.api.", "venom.idor")):
        return "observed"
    if is_external(check_id):
        return "external"
    return "unknown"


def _value_present(key: str, value: Any) -> bool:
    if key in PRESENCE_KEYS:
        return value is not None and value != ""
    if isinstance(value, bool):
        return value is True
    if isinstance(value, (int, float)):
        return value > 0
    return value not in (None, "", [], {})


def _groups_met(response: dict[str, Any], groups: tuple[tuple[str, ...], ...]) -> bool:
    return any(all(_value_present(key, response.get(key)) for key in group) for group in groups)


def _validate(check_id: str, request: dict[str, Any], response: dict[str, Any]) -> str | None:
    if not request.get("url"):
        return "request evidence has no URL"
    if not response:
        return "response evidence is empty"

    if check_id in REQUIRED_RESPONSE_EVIDENCE:
        required = REQUIRED_RESPONSE_EVIDENCE[check_id]
        if not all(_value_present(key, response.get(key)) for key in required):
            return DOWNGRADE_NOTE
        return None

    contract = OBSERVED_RESPONSE_EVIDENCE.get(check_id)
    if contract is not None:
        if _groups_met(response, contract):
            return None
        return DOWNGRADE_NOTE

    category = evidence_category(check_id)
    if category == "observed":
        if any(key in response for key in OBSERVED_GENERIC_KEYS):
            return None
        return DOWNGRADE_NOTE
    if category in {"heuristic", "external"}:
        return f"{category} checks cannot be independently verified"
    return "check has no evidence contract"


def evidence_complete(finding: Finding) -> bool:
    return _validate(finding.check_id, finding.request_evidence, finding.response_evidence) is None


def effective_verification(
    check_id: str,
    declared: VerificationStatus | str,
    request_evidence: dict[str, Any] | None,
    response_evidence: dict[str, Any] | None,
) -> tuple[VerificationStatus, str | None]:
    """Return the status that the stored evidence actually supports."""
    status = VerificationStatus(str(declared))
    if status is VerificationStatus.REJECTED:
        return status, None
    if status is VerificationStatus.SUSPECTED:
        return status, None
    reason = _validate(check_id, request_evidence or {}, response_evidence or {})
    if reason is None:
        return VerificationStatus.VERIFIED, None
    return VerificationStatus.SUSPECTED, reason


def _downgrade(finding: Finding, reason: str) -> None:
    finding.verification_status = VerificationStatus.SUSPECTED
    finding.confidence = min(finding.confidence, DOWNGRADED_CONFIDENCE_CAP)
    finding.response_evidence["verification_note"] = DOWNGRADE_NOTE
    finding.response_evidence["verification_reason"] = reason


def mark_verified(findings: list[Finding]) -> dict[str, int]:
    summary = {"verified": 0, "suspected": 0, "rejected": 0, "downgraded": 0}
    for finding in findings:
        if finding.verification_status is VerificationStatus.VERIFIED:
            status, reason = effective_verification(
                finding.check_id,
                finding.verification_status,
                finding.request_evidence,
                finding.response_evidence,
            )
            if status is not VerificationStatus.VERIFIED:
                _downgrade(finding, reason or DOWNGRADE_NOTE)
                summary["downgraded"] += 1
        elif (
            finding.verification_status is VerificationStatus.SUSPECTED
            and is_deterministic(finding.check_id)
        ):
            status, _ = effective_verification(
                finding.check_id,
                VerificationStatus.VERIFIED,
                finding.request_evidence,
                finding.response_evidence,
            )
            if status is VerificationStatus.VERIFIED:
                finding.verification_status = VerificationStatus.VERIFIED
        summary[finding.verification_status.value] += 1
    return summary

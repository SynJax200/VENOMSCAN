from __future__ import annotations

from venomscan_engine.models import Finding, VerificationStatus

# Passive configuration checks read state we directly observed in a response we
# fetched ourselves, so they are verified rather than suspected. Active checks
# must opt in explicitly via their own evidence handling.
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

DETERMINISTIC_CHECK_IDS = {"venom.tls.weak"}

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

DOWNGRADED_CONFIDENCE_CAP = 5


def is_deterministic(check_id: str) -> bool:
    return check_id in DETERMINISTIC_CHECK_IDS or check_id.startswith(DETERMINISTIC_CHECK_PREFIXES)


def evidence_complete(finding: Finding) -> bool:
    request = finding.request_evidence
    response = finding.response_evidence
    if not request.get("url") or not response:
        return False
    required = REQUIRED_RESPONSE_EVIDENCE.get(finding.check_id, ())
    return all(response.get(key) not in (None, "", False, 0) for key in required)


def _downgrade(finding: Finding) -> None:
    finding.verification_status = VerificationStatus.SUSPECTED
    finding.confidence = min(finding.confidence, DOWNGRADED_CONFIDENCE_CAP)
    finding.response_evidence["verification_note"] = "evidence contract incomplete"


def mark_verified(findings: list[Finding]) -> dict[str, int]:
    summary = {"verified": 0, "suspected": 0, "rejected": 0, "downgraded": 0}
    for finding in findings:
        if finding.verification_status is VerificationStatus.VERIFIED and not is_deterministic(
            finding.check_id
        ):
            if not evidence_complete(finding):
                _downgrade(finding)
                summary["downgraded"] += 1
        if finding.verification_status is VerificationStatus.SUSPECTED and is_deterministic(
            finding.check_id
        ):
            finding.verification_status = VerificationStatus.VERIFIED
        summary[finding.verification_status.value] += 1
    return summary

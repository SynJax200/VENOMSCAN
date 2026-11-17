from __future__ import annotations

import math

# CVSS v3.1 base metrics for the built-in checks. These are reference vectors
# per check family (mirroring the check registry's default severity); Nuclei
# findings keep the vector emitted by the template.
_VECTORS: dict[str, str] = {
    "venom.headers.csp": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "venom.headers.hsts": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.headers.hardening": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.clickjacking": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "venom.cookies.flags": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "venom.session": "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "venom.cors.misconfig": "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
    "venom.info.server": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.info.version": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.info.errors": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.info.dirlist": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.transport.plaintext": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "venom.methods": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "venom.redirect.open": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "venom.tls.expired": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "venom.tls.expiring": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.tls.protocol": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "venom.tls.cipher": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "venom.tls.untrusted": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "venom.tls.weak": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "venom.secrets.js": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "venom.idor": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "venom.authz.function": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "venom.auth.pages": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.cache": "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "venom.csrf.token": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "venom.xss.reflected": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "venom.xss.dom": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "venom.sqli.error": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "venom.sqli.time": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "venom.ssti": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "venom.ssrf": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "venom.lfi.path": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "venom.xxe": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "venom.files.exposed": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "venom.api.auth": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "venom.api.spec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.api.docs": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.api.unauth": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "venom.api.sensitive": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "venom.api.jwt": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "venom.api.graphql": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.api.ratelimit": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
}

_PREFIX_DEFAULTS: dict[str, str] = {
    "venom.headers.": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.tls.": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "venom.api.": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "venom.info.": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest one-decimal number >= value."""
    scaled = value * 10
    if math.isclose(scaled, round(scaled), abs_tol=1e-9):
        return round(scaled) / 10
    return math.ceil(scaled) / 10


def base_score(vector: str) -> float:
    """CVSS v3.1 base score for an AV/AC/PR/UI/S/C/I/A metric string."""
    metrics: dict[str, str] = {}
    for part in vector.removeprefix("CVSS:3.1/").split("/"):
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    scope_changed = metrics["S"] == "C"
    iss = 1 - (
        (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        privilege = _PR_CHANGED[metrics["PR"]]
    else:
        impact = 6.42 * iss
        privilege = _PR_UNCHANGED[metrics["PR"]]
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * privilege * _UI[metrics["UI"]]
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def cvss_for(check_id: str) -> tuple[str, float] | None:
    """Reference (vector, base score) for a built-in check, if one is mapped."""
    vector = _VECTORS.get(check_id)
    if vector is None:
        for prefix, fallback in _PREFIX_DEFAULTS.items():
            if check_id.startswith(prefix):
                vector = fallback
                break
    if vector is None:
        return None
    return f"CVSS:3.1/{vector}", base_score(vector)

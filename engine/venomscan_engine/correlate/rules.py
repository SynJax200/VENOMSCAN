from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CorrelationRule:
    """A deterministic attack-path rule: a gate finding enables a trigger finding.

    Patterns are fnmatch globs matched against ``Finding.check_id``. When at
    least one gate and one trigger are present in the same scan, every trigger
    is re-scored with ``multiplier``: context makes the same technical flaw
    materially more dangerous. No rule guesses; both sides must be observed.
    """

    id: str
    title: str
    multiplier: float
    gate: tuple[str, ...]
    trigger: tuple[str, ...]
    surface: str
    narrative: str
    url_fragments: tuple[str, ...] = ()


RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        id="credentialed-injection",
        title="Injection reachable through a weak authentication surface",
        multiplier=1.25,
        gate=(
            "venom.auth.*",
            "venom.session*",
            "venom.csrf.*",
            "venom.cookies.*",
        ),
        trigger=(
            "venom.sqli.*",
            "venom.xss.*",
            "venom.ssti*",
            "venom.lfi.*",
            "venom.ssrf*",
            "venom.xxe*",
            "venom.redirect.*",
        ),
        surface="authentication surface",
        narrative=(
            "The scan observed a session/authentication weakness ({gate}) together with an "
            "injection-class signal ({trigger}). An attacker who can fixate a session, skip "
            "anti-CSRF checks or ride a long-lived cookie can usually reach the injectable "
            "input more reliably, so the injection finding is re-scored upward."
        ),
    ),
    CorrelationRule(
        id="admin-surface",
        title="Injection or authorization gap on an administrative surface",
        multiplier=1.2,
        gate=(
            "venom.auth.*",
            "venom.authz.*",
            "venom.idor",
            "venom.csrf.*",
        ),
        trigger=(
            "venom.sqli.*",
            "venom.xss.*",
            "venom.ssti*",
            "venom.lfi.*",
            "venom.ssrf*",
            "venom.xxe*",
            "venom.authz.*",
            "venom.idor",
        ),
        surface="administrative surface",
        narrative=(
            "Administrative URLs carry both an authorization/authentication weakness ({gate}) "
            "and a directly exploitable finding ({trigger}). Compromise there typically means "
            "control of the tenant, not just one object."
        ),
        url_fragments=("admin", "manage", "internal", "console", "staff", "backoffice"),
    ),
    CorrelationRule(
        id="unauth-api",
        title="API exposure without an authentication boundary",
        multiplier=1.15,
        gate=("venom.cors.*", "venom.api.docs", "venom.api.auth"),
        trigger=(
            "venom.authz.*",
            "venom.idor",
            "venom.api.sensitive",
            "venom.secrets.js",
            "venom.sqli.*",
            "venom.xss.*",
            "venom.ssrf*",
        ),
        surface="API surface",
        narrative=(
            "The API surface advertises an authentication or CORS weakness ({gate}) while a "
            "data or injection finding lives on an API route ({trigger}). Machine-readable "
            "endpoints widen the blast radius of that flaw."
        ),
        url_fragments=("/api/", "/v1/", "/v2/", "/graphql", "/rest/"),
    ),
    CorrelationRule(
        id="secret-exposure-chain",
        title="Leaked JavaScript secrets next to exposed files or verbose errors",
        multiplier=1.15,
        gate=("venom.secrets.js",),
        trigger=("venom.files.exposed", "venom.info.errors", "venom.api.sensitive"),
        surface="client-side surface",
        narrative=(
            "Hardcoded secrets in shipped JavaScript ({gate}) combine with exposed files or "
            "verbose errors ({trigger}); together they hand an attacker credentials and the "
            "map needed to use them."
        ),
    ),
)


__all__ = ["CorrelationRule", "RULES"]

from __future__ import annotations

from venomscan_engine.checks import check_catalog

TRACKS: tuple[dict, ...] = (
    {
        "id": "surface",
        "title": "Attack surface fundamentals",
        "level": "beginner",
        "focus": (
            "Before testing anything, learn to describe what a target exposes: banners, allowed "
            "verbs, verbose errors, open directories and stray files. Every later lesson depends "
            "on reading these signals without over-claiming impact."
        ),
        "outcome": "You can map a host's surface and explain which observations are leads versus proof.",
        "lessons": {
            "venom.info.server": "Read a Server header as a lead, not a version claim - confirm what it actually exposes.",
            "venom.methods": "Recognise the HTTP verbs a server advertises and why an allow-list beats a block-list.",
            "venom.info.errors": "Spot stack traces and verbose errors without ever triggering them yourself.",
            "venom.info.dirlist": "Tell a directory listing apart from an application page.",
            "venom.files.exposed": "Identify backup and dot-file exposure and prove it with a single benign GET.",
        },
    },
    {
        "id": "transport",
        "title": "Transport and session integrity",
        "level": "beginner",
        "focus": (
            "TLS, cookies, session identifiers and caching decide whether a valid login survives a "
            "network attacker. These checks are passive or safe, so you can practise on any target "
            "you are authorised to view."
        ),
        "outcome": "You can audit a session end to end and connect each weakness to an attacker capability.",
        "lessons": {
            "venom.tls.weak": "Explain why protocol and cipher strength still matter even behind a CDN.",
            "venom.cookies.flags": "Audit cookie flags and map each missing flag to a concrete attack.",
            "venom.session": "Inspect session identifiers for predictability and poor rotation.",
            "venom.cache": "Distinguish cacheable public content from per-user private data.",
        },
    },
    {
        "id": "browser",
        "title": "Browser-side defences",
        "level": "intermediate",
        "focus": (
            "Headers, framing rules, CORS policy, CSRF tokens and redirects are the contract between "
            "a site and the browser. Learn to read the contract and test it with local harnesses "
            "instead of live payloads."
        ),
        "outcome": "You can decide whether a missing control changes impact or is merely hygiene.",
        "lessons": {
            "venom.headers.missing": "Turn missing security headers into impact, not a checklist.",
            "venom.clickjacking": "Test frameability with a local harness instead of guessing.",
            "venom.cors.misconfig": "Read an Access-Control-Allow-Origin decision tree correctly.",
            "venom.csrf.token": "Compare token presence, binding and SameSite before calling CSRF.",
            "venom.redirect.open": "Trace a redirect parameter to an external origin safely.",
        },
    },
    {
        "id": "access",
        "title": "Authentication and access control",
        "level": "intermediate",
        "focus": (
            "Most real breaches are broken authorization. Learn to separate 'auth is configured' "
            "from 'auth is enforced', and to test object- and function-level access with two "
            "identities you own."
        ),
        "outcome": "You can prove or dismiss an access-control defect with paired requests.",
        "lessons": {
            "venom.auth.pages": "Map login, reset and logout flows and find the missing transitions.",
            "venom.api.jwt": "Decode a JWT and judge each structural weakness separately.",
            "venom.api.auth": "Separate 'auth is configured' from 'auth is enforced'.",
            "venom.api.unauth": "Compare authenticated and anonymous responses for the same route.",
            "venom.api.ratelimit": "Measure login throttling without locking real accounts.",
            "venom.idor": "Test object-level authorization with two owned identities.",
            "venom.authz.function": "Test function-level authorization across roles you own.",
        },
    },
    {
        "id": "discovery",
        "title": "API and secret discovery",
        "level": "intermediate",
        "focus": (
            "APIs advertise themselves in docs, specs, GraphQL schemas and JavaScript bundles. Learn "
            "to turn those artefacts into a scope-checked endpoint list and to triage secrets "
            "instead of pasting them anywhere."
        ),
        "outcome": "You can build a reviewable API inventory and explain which exposures are real.",
        "lessons": {
            "venom.api.docs": "Read documentation endpoints as a map, not a vulnerability.",
            "venom.api.spec": "Turn an OpenAPI document into a scope-checked endpoint list.",
            "venom.api.graphql": "Probe introspection and field suggestions within scope.",
            "venom.api.sensitive": "Recognise sensitive fields in API responses and prove exposure.",
            "venom.secrets.js": "Extract candidate secrets from JavaScript and triage public keys.",
        },
    },
    {
        "id": "injection",
        "title": "Injection and input handling",
        "level": "advanced",
        "focus": (
            "Injection findings are the easiest to report badly. Learn to confirm reflection "
            "context, boolean deltas, timing noise and out-of-band callbacks before you claim a "
            "vulnerability, always inside an active profile you own."
        ),
        "outcome": "You can verify or reject an injection finding with a repeatable, benign procedure.",
        "lessons": {
            "venom.xss.reflected": "Confirm reflection, context and encoding before claiming XSS.",
            "venom.xss.dom": "Trace a DOM sink back to a controllable source.",
            "venom.sqli.error": "Use error signals as a lead and verify with boolean deltas.",
            "venom.sqli.time": "Distinguish timing noise from real blind injection.",
            "venom.ssrf": "Prove SSRF with an out-of-band callback, never internal probing.",
            "venom.ssti": "Differentiate template evaluation from plain reflection.",
            "venom.xxe": "Test XML parsers with an external entity to your own listener.",
            "venom.lfi.path": "Confirm traversal with a single canary file read.",
        },
    },
)

LEVEL_PROFILES: dict[str, dict[str, str]] = {
    "beginner": {
        "scan_profile": "passive",
        "consent": (
            "Passive profile only reads what the target already returns to a normal visitor; "
            "no extra requests are sent. Start here on a site you own."
        ),
    },
    "intermediate": {
        "scan_profile": "safe",
        "consent": (
            "Safe profile sends standard GET/OPTIONS requests under rate limits. Only run it "
            "against targets you own or have written permission to test."
        ),
    },
    "advanced": {
        "scan_profile": "active",
        "consent": (
            "Active profile sends crafted, non-destructive requests (reflected payloads, header "
            "probes). Enable it only on authorized targets with recorded consent."
        ),
    },
}

_EXTENDED_TRACK = {
    "id": "extended",
    "title": "New and experimental checks",
    "level": "advanced",
    "focus": (
        "Checks that landed after the curated curriculum. Each lesson still carries the registry "
        "explanation, so you can learn the check before it joins a themed track."
    ),
    "outcome": "You stay current as the platform adds detection coverage.",
}


def curriculum() -> dict:
    """Build learner-facing tracks, failing loudly if the curated ids drift from the registry."""
    catalog = {entry["id"]: entry for entry in check_catalog()}
    tracks: list[dict] = []
    covered: list[str] = []
    for track in TRACKS:
        lessons = []
        for check_id, objective in track["lessons"].items():
            entry = catalog.get(check_id)
            if entry is None:
                raise ValueError(f"learning track {track['id']!r} references unknown check {check_id!r}")
            lessons.append(
                {
                    "id": entry["id"],
                    "name": entry["name"],
                    "category": entry["category"],
                    "profile": entry["profile"],
                    "severity": entry["severity"],
                    "objective": objective,
                    "what": entry["learning"]["what"],
                    "why": entry["learning"]["why"],
                    "verify": entry["learning"]["verify"],
                }
            )
            covered.append(check_id)
        duplicates = sorted({check_id for check_id in track["lessons"] if covered.count(check_id) > 1})
        if duplicates:
            raise ValueError(f"learning track {track['id']!r} duplicates checks: {duplicates}")
        tracks.append(
            {
                "id": track["id"],
                "title": track["title"],
                "level": track["level"],
                "focus": track["focus"],
                "outcome": track["outcome"],
                "check_ids": list(track["lessons"]),
                "lessons": lessons,
                **LEVEL_PROFILES[track["level"]],
            }
        )
    uncovered = sorted(set(catalog) - set(covered))
    if uncovered:
        lessons = [
            {
                "id": catalog[check_id]["id"],
                "name": catalog[check_id]["name"],
                "category": catalog[check_id]["category"],
                "profile": catalog[check_id]["profile"],
                "severity": catalog[check_id]["severity"],
                "objective": "Explain what this new check detects, its evidence and how to verify it manually.",
                "what": catalog[check_id]["learning"]["what"],
                "why": catalog[check_id]["learning"]["why"],
                "verify": catalog[check_id]["learning"]["verify"],
            }
            for check_id in uncovered
        ]
        tracks.append(
            {
                **_EXTENDED_TRACK,
                "check_ids": uncovered,
                "lessons": lessons,
                **LEVEL_PROFILES[_EXTENDED_TRACK["level"]],
            }
        )
    return {"tracks": tracks, "check_count": len(catalog)}

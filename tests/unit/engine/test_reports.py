from __future__ import annotations

import json

from venomscan_engine.reports import (
    ReportAi,
    ReportAuthorization,
    ReportEndpoint,
    ReportFinding,
    ReportModel,
    ReportScan,
    ReportTechnology,
    canonical_json,
    render_html,
    render_json,
    render_markdown,
    render_pdf,
)


def _model() -> ReportModel:
    return ReportModel(
        generated_at="2026-11-15T12:00:00+00:00",
        scan=ReportScan(
            id="scan-1",
            target_name="Demo",
            target_url="https://demo.example.test/",
            host="demo.example.test",
            profile="safe",
            status="completed",
            summary="3 findings (1 high, 2 low). Highest risk: Missing CSP.",
            stats={"requests": 42},
        ),
        authorization=ReportAuthorization(
            method="well_known",
            verified_at="2026-11-14T09:00:00+00:00",
            expires_at="2026-11-21T09:00:00+00:00",
            operator="analyst@example.com",
        ),
        findings=[
            ReportFinding(
                id="f1",
                check_id="venom.headers.csp",
                title="Missing Content-Security-Policy <script>alert(1)</script>",
                category="headers",
                severity="high",
                verification_status="verified",
                confidence=8,
                risk_score=8.0,
                url="https://demo.example.test/",
                description="No CSP header was observed.",
                impact="Injected script executes.",
                remediation="Send a strict CSP.",
                references=["https://owasp.org/www-project-secure-headers/"],
                cwe=["CWE-693"],
                request_evidence={"url": "https://demo.example.test/", "status_code": 200},
                ai_summary="A strict CSP limits injected script execution.",
            )
        ],
        technologies=[ReportTechnology(name="nginx", version="1.25.3", category="server")],
        endpoints=[ReportEndpoint(url="https://demo.example.test/", status_code=200)],
        ai_analyses=[
            ReportAi(kind="summary", summary="One high finding needs attention.", fallback=True)
        ],
    )


def test_canonical_json_is_stable() -> None:
    model = _model()
    first = canonical_json(model)
    second = canonical_json(ReportModel.model_validate(json.loads(first)))
    assert first == second


def test_render_json_roundtrip() -> None:
    payload = json.loads(render_json(_model()))
    assert payload["scan"]["id"] == "scan-1"
    assert payload["findings"][0]["severity"] == "high"
    assert payload["report_version"] == "1"


def test_render_markdown_contains_all_findings() -> None:
    text = render_markdown(_model()).decode()
    assert "# Security assessment — Demo" in text
    assert "### 1. [HIGH] Missing Content-Security-Policy" in text
    assert "CWE-693" in text
    assert "nginx" in text
    assert "AI intelligence" in text


def test_render_surfaces_per_finding_reproduction_steps() -> None:
    model = _model()
    model.findings[0].reproduction = [
        "curl -sS -D - -o /dev/null 'https://demo.example.test/'",
        "Confirm Content-Security-Policy is absent <and> no allowlist applies.",
    ]

    text = render_markdown(model).decode()
    assert "**Reproduction (authorized target only).**" in text
    assert "1. curl -sS -D - -o /dev/null 'https://demo.example.test/'" in text
    assert "2. Confirm Content-Security-Policy is absent" in text

    page = render_html(model)
    assert "<h4>Reproduction (authorized target only)</h4>" in page
    assert "<li>curl -sS -D - -o /dev/null &#x27;https://demo.example.test/&#x27;</li>" in page
    assert "&lt;and&gt;" in page

    payload = json.loads(render_json(model))
    assert payload["findings"][0]["reproduction"] == model.findings[0].reproduction


def test_report_ai_section_carries_citations_and_raw_recon_appendix() -> None:
    model = _model()
    model.ai_analyses[0].citations = ["scan:scan-1", "finding:f1"]
    model.scan.recon = {"subdomains": {"count": 2, "names": ["a.example.test", "b.example.test"]}}

    page = render_html(model)
    assert "AI intelligence" in page
    assert "Citations:" in page
    assert "scan:scan-1" in page
    assert "Reconnaissance appendix (raw)" in page
    assert "subdomains" in page

    text = render_markdown(model).decode()
    assert "- **Citations:** `scan:scan-1`" in text
    assert "## Reconnaissance appendix (raw)" in text
    assert "a.example.test" in text


def test_render_surfaces_extended_recon_intelligence() -> None:
    model = _model()
    model.scan.recon = {
        "dns": {
            "host": "demo.example.test",
            "records": {"A": ["1.2.3.4"], "DKIM": ["google → rsa, key 300 chars"]},
            "mail": {
                "spf": "v=spf1 -all",
                "dmarc": {
                    "policy": "reject",
                    "subdomain_policy": "quarantine",
                    "percentage": "100",
                    "report_uris": ["mailto:d@example.test"],
                },
                "dkim": [{"selector": "google", "key_type": "rsa", "revoked": False}],
            },
        },
        "history": {
            "count": 1,
            "urls": [
                {
                    "url": "https://demo.example.test/api/users",
                    "kind": "api",
                    "last_seen": "2025-01-01",
                }
            ],
        },
        "exposure": [
            {
                "address": "1.2.3.4",
                "source": "Shodan",
                "ports": [443],
                "hostnames": ["demo.example.test"],
                "vulns": ["CVE-2024-0001"],
            }
        ],
        "neighbours": {
            "prefix": "1.2.3.0/24",
            "queried": 4,
            "hosts": [{"address": "1.2.3.5", "ptr": "mail.example.test"}],
        },
        "js_intel": {
            "scripts": 2,
            "api_calls": 4,
            "post_calls": 1,
            "source_maps": [
                {"url": "https://demo.example.test/app.js.map", "same_origin": True}
            ],
            "graphql_endpoints": ["https://demo.example.test/graphql"],
            "sensitive_paths": ["/admin"],
            "third_party_hosts": ["cdn.example.net"],
            "parameters": ["id", "slug"],
        },
        "endpoint_intel": {
            "cluster_count": 2,
            "endpoint_count": 3,
            "templated": 1,
            "api_clusters": 1,
            "clusters": [
                {
                    "template": "https://demo.example.test/api/orders/{id}",
                    "count": 2,
                    "methods": ["GET", "POST"],
                    "sources": ["crawl", "js"],
                }
            ],
        },
        "api_intel": {
            "spec": {
                "documents": 1,
                "routes": 2,
                "operations": 3,
                "public_write_count": 1,
                "public_writes": [{"path": "/items", "method": "POST"}],
                "public_reads": 1,
                "api_key_query_schemes": ["apiKeyAuth"],
                "oauth_implicit": [],
                "cross_origin_servers": ["https://api.example.test"],
                "deprecated_count": 1,
                "operations_by_method": {"GET": 2, "POST": 1},
            },
            "jwt": {
                "tokens": [
                    {
                        "fingerprint": "abc123def456",
                        "prefix": "eyJhbGciOi",
                        "alg": "none",
                        "claims": ["sub"],
                        "lifetime_days": None,
                        "flags": ["alg_none", "missing_exp"],
                        "location": "response body",
                        "source": "https://demo.example.test/api/session",
                    }
                ]
            },
            "graphql": {
                "candidates": ["https://demo.example.test/graphql"],
                "probed": 1,
                "confirmed": ["https://demo.example.test/graphql"],
                "introspection": True,
                "ide": False,
                "type_count": 4,
                "object_count": 3,
                "mutation_available": True,
                "sample_types": ["Query", "User"],
            },
        },
        "verification": {"verified": 9, "suspected": 2, "rejected": 0, "downgraded": 1},
    }

    text = render_markdown(model).decode()
    assert "**Verification:** 9 verified · 2 suspected · 1 downgraded for incomplete evidence" in text
    assert "**Email authentication**" in text
    assert "DMARC: policy reject" in text
    assert "DKIM selectors: google (rsa)" in text
    assert "Historical URLs (archives, 1; api 1)" in text
    assert "Internet exposure (third-party OSINT, not scanned)" in text
    assert "Reverse-DNS neighbours" in text
    assert "**JavaScript intelligence**" in text
    assert "Source maps exposed: 1" in text
    assert "app.js.map" in text
    assert "**Endpoint clusters (2 patterns, 1 parameterised)**" in text
    assert "api/orders/{id}" in text
    assert "**API security intelligence**" in text
    assert "Public write operations: 1 · public reads: 1" in text
    assert "POST `/items` without auth" in text
    assert "API keys in query: apiKeyAuth" in text
    assert "JWT tokens observed: 1 · flagged: 1" in text
    assert "alg_none" in text
    assert "GraphQL endpoints confirmed: 1 of 1 probed · introspection: enabled" in text
    assert "Schema types: 4" in text

    document = render_html(model, integrity="abc123")
    assert "Email authentication" in document
    assert "Internet exposure (third-party OSINT, not scanned)" in document
    assert "Reverse-DNS neighbours" in document
    assert "JavaScript intelligence" in document
    assert "Endpoint clusters (2 patterns, 1 parameterised)" in document
    assert "API security intelligence" in document
    assert "Public operation" in document
    assert "apiKeyAuth" in document
    assert "alg_none, missing_exp" in document
    assert "app.js.map" in document
    assert "mail.example.test" in document
    assert "9 verified" in document
    assert "1 downgraded for incomplete evidence" in document


def test_render_html_escapes_target_controlled_text() -> None:
    document = render_html(_model(), integrity="abc123")
    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document
    assert "SHA-256" in document
    assert "abc123" in document
    assert document.count('class="finding"') == 2


def test_render_pdf_has_pdf_header() -> None:
    document = render_pdf(_model(), "abc123")
    assert document.startswith(b"%PDF-")
    assert len(document) > 2000


def test_render_marks_unverified_endpoints() -> None:
    model = _model()
    model.scan.stats = {
        "requests": 42,
        "endpoints": 2,
        "endpoints_live": 1,
        "endpoints_unverified": 1,
    }
    model.endpoints.append(
        ReportEndpoint(
            url="https://demo.example.test/api/users",
            method="GET",
            source="js",
        )
    )

    markdown = render_markdown(model).decode()
    assert "1 live · 1 unverified" in markdown
    assert "1 live (scanner received a response), 1 unverified" in markdown
    assert "unverified, not fetched" in markdown

    html = render_html(model)
    assert "<th>Surface</th>" in html
    assert "1 live (scanner received a response), 1 unverified" in html


def test_report_api_inventory_next_steps_and_endpoint_links() -> None:
    model = _model()
    model.scan.recon = {
        "auth_map": {
            "flows": [
                {
                    "type": "login",
                    "method": "GET",
                    "url": "https://demo.example.test/login",
                    "state": "live",
                }
            ]
        },
        "bola_matrix": {
            "candidates": [
                {
                    "method": "GET",
                    "template": "https://demo.example.test/api/orders/{id}",
                    "roles": ["anonymous", "user", "admin"],
                    "status": "candidate",
                }
            ],
            "note": "Non-destructive scaffold; no requests performed.",
        },
        "endpoint_verification": {"probed": 3, "verified": 2, "not_found": 1, "stopped": None},
    }
    model.endpoints.append(
        ReportEndpoint(
            url="https://demo.example.test/api/orders/42",
            method="GET",
            source="js",
            status_code=200,
        )
    )
    model.ai_analyses.append(
        ReportAi(
            kind="next_steps",
            summary="Two grounded actions.",
            steps=["Fix CSP — send a strict header.", "Review API ownership checks."],
            fallback=True,
        )
    )

    markdown = render_markdown(model).decode()
    assert "## API inventory" in markdown
    assert "Authentication flows" in markdown
    assert "BOLA / tenant candidates" in markdown
    assert "## Recommended next steps" in markdown
    assert "Fix CSP — send a strict header." in markdown
    assert "source: deterministic fallback" in markdown
    assert "surface record](#endpoint-" in markdown
    assert "Endpoint verification:** 2 verified from 3 probe(s)" in markdown

    document = render_html(model)
    assert "API inventory" in document
    assert "Recommended next steps" in document
    assert 'id="endpoint-' in document
    assert 'href="#endpoint-' in document
    assert "BOLA / tenant candidates" in document


def test_report_next_steps_fall_back_to_findings() -> None:
    model = _model()
    markdown = render_markdown(model).decode()
    assert "## Recommended next steps" in markdown
    assert "Fix Missing Content-Security-Policy" in markdown
    assert "source: deterministic" in markdown

from __future__ import annotations

from venomscan_engine.intel import lookup, snapshot_version


def test_snapshot_is_loadable() -> None:
    assert snapshot_version() == "2026-11-15"


def test_nginx_range_match_and_newer_version_is_clean() -> None:
    affected = lookup([("nginx", "1.18.0")])
    assert [match.cve.id for match in affected.matches] == ["CVE-2021-23017"]
    assert lookup([("nginx", "1.25.3")]).matches == []


def test_apache_matches_two_traversal_cves() -> None:
    matches = lookup([("Apache HTTP Server", "2.4.49")])
    ids = {match.cve.id for match in matches.matches}
    assert ids == {"CVE-2021-41773", "CVE-2021-42013"}


def test_jquery_exclusive_upper_bound() -> None:
    assert len(lookup([("jQuery", "3.4.1")]).matches) == 2
    assert lookup([("jQuery", "3.5.0")]).matches == []


def test_missing_version_still_matches_with_flag() -> None:
    report = lookup([("log4j", None)])
    assert len(report.matches) == 1
    assert report.matches[0].version_unknown is True
    assert report.matches[0].cve.severity == "critical"


def test_unrelated_technology_has_no_matches() -> None:
    assert lookup([("UnknownAppliance", "1.0")]).matches == []

from __future__ import annotations

import pytest
from venomscan_engine.checks import check_catalog
from venomscan_engine.reports import base_score, cvss_for


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
        ("AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
        ("AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_score_matches_cvss_31_spec(vector: str, expected: float) -> None:
    assert base_score(vector) == expected


def test_base_score_accepts_full_prefix() -> None:
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_every_registered_check_has_a_reference_vector() -> None:
    for entry in check_catalog():
        reference = cvss_for(entry["id"])
        assert reference is not None, entry["id"]
        vector, score = reference
        assert vector.startswith("CVSS:3.1/AV:"), entry["id"]
        assert 0.0 < score <= 10.0, entry["id"]


def test_unknown_check_has_no_reference_vector() -> None:
    assert cvss_for("plugin.custom.check") is None
    assert cvss_for("venom.headers.custom") is not None

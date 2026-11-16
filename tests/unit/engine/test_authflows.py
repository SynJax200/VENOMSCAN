from __future__ import annotations

from venomscan_engine.intel.authflows import build_auth_map, classify_path
from venomscan_engine.intel.bola import build_bola_matrix
from venomscan_engine.models import EndpointRecord


def test_classify_auth_paths():
    assert classify_path("https://app.test/login") == "login"
    assert classify_path("https://app.test/auth/signin") == "login"
    assert classify_path("https://app.test/logout") == "logout"
    assert classify_path("https://app.test/account/register") == "register"
    assert classify_path("https://app.test/forgot-password") == "password_reset"
    assert classify_path("https://app.test/verify/otp") == "mfa"
    assert classify_path("https://app.test/oauth/token") == "token"
    assert classify_path("https://app.test/api/session") == "session"
    assert classify_path("https://app.test/api/orders") is None


def test_auth_map_deduplicates_and_counts_states():
    endpoints = [
        EndpointRecord(url="https://app.test/login", source="crawl", status_code=200),
        EndpointRecord(url="https://app.test/login", source="spa", status_code=200),
        EndpointRecord(url="https://app.test/logout", method="POST", source="js"),
        EndpointRecord(url="https://app.test/oauth/token", method="POST", source="js"),
        EndpointRecord(url="https://app.test/api/orders", source="crawl", status_code=200),
    ]
    mapping = build_auth_map(endpoints)
    assert mapping["count"] == 3
    assert mapping["live"] == 1
    assert mapping["types"] == {"login": 1, "logout": 1, "token": 1}
    assert "3 authentication flow" in mapping["summary"]


def test_bola_matrix_flags_object_routes_without_traffic():
    endpoints = [
        EndpointRecord(
            url="https://app.test/api/orders/42",
            method="GET",
            source="js",
            status_code=200,
        ),
        EndpointRecord(
            url="https://app.test/api/users?user_id=7",
            method="DELETE",
            source="js",
            status_code=403,
        ),
        EndpointRecord(
            url="https://app.test/api/health",
            method="GET",
            source="crawl",
            status_code=200,
        ),
        EndpointRecord(
            url="https://app.test/api/orders",
            method="POST",
            source="js",
            status_code=201,
        ),
        EndpointRecord(
            url="https://app.test/api/orders/43",
            method="GET",
            source="js",
            status_code=200,
        ),
    ]
    matrix = build_bola_matrix(
        endpoints, [{"role": "admin"}, {"role": "user"}, {"role": "user"}]
    )
    assert matrix["roles"] == ["admin", "user"]
    assert matrix["count"] == 2
    templates = [row["template"] for row in matrix["candidates"]]
    assert "https://app.test/api/orders/{id}" in templates
    assert all(row["status"] == "candidate" for row in matrix["candidates"])
    assert all("anonymous" in row["roles"] for row in matrix["candidates"])
    assert "Non-destructive" in matrix["note"]
    delete_row = next(row for row in matrix["candidates"] if row["method"] == "DELETE")
    assert delete_row["authorization_observed"] is True


def test_bola_matrix_caps_candidates():
    endpoints = [
        EndpointRecord(
            url=f"https://app.test/api/order-{index}/42", method="GET", source="js", status_code=200
        )
        for index in range(30)
    ]
    matrix = build_bola_matrix(endpoints)
    assert matrix["count"] == 20
    assert len(matrix["candidates"]) == 20

from __future__ import annotations

from venomscan_engine.intel.endpoints import cluster_endpoints, template_path
from venomscan_engine.models import EndpointRecord


def test_template_path_replaces_identifiers_not_names():
    assert (
        template_path("https://shop.example.com/api/orders/123")
        == "https://shop.example.com/api/orders/{id}"
    )
    assert (
        template_path("https://shop.example.com/api/orders/550e8400-e29b-41d4-a716-446655440000")
        == "https://shop.example.com/api/orders/{id}"
    )
    assert (
        template_path("https://shop.example.com/api/sessions/8f14e45fceea167a5a36dedd4bea2543")
        == "https://shop.example.com/api/sessions/{id}"
    )
    assert (
        template_path("https://shop.example.com/certificate-verification")
        == "https://shop.example.com/certificate-verification"
    )
    assert template_path("https://shop.example.com") == "https://shop.example.com/"


def test_cluster_endpoints_groups_parameterised_paths():
    endpoints = [
        EndpointRecord(url="https://shop.example.com/api/orders/1?expand=items", status_code=200),
        EndpointRecord(url="https://shop.example.com/api/orders/2", status_code=200),
        EndpointRecord(
            url="https://shop.example.com/api/orders/3",
            method="POST",
            status_code=201,
            parameters=["total"],
        ),
        EndpointRecord(url="https://shop.example.com/about", status_code=200),
        EndpointRecord(url="https://shop.example.com/api/users/${id}", source="js"),
    ]
    payload = cluster_endpoints(endpoints)

    assert payload["endpoint_count"] == 5
    assert payload["cluster_count"] == 3
    assert payload["api_clusters"] == 2
    assert payload["templated"] == 2
    orders = next(
        cluster for cluster in payload["clusters"] if cluster["template"].endswith("/api/orders/{id}")
    )
    assert orders["count"] == 3
    assert orders["methods"] == ["GET", "POST"]
    assert orders["parameters"] == ["expand", "total"]
    assert orders["api_like"] is True
    assert len(orders["samples"]) == 3
    assert payload["clusters"][0]["count"] == 3

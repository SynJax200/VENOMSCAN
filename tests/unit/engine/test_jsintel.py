from __future__ import annotations

from venomscan_engine.crawl.jsintel import (
    analyze_script,
    call_methods,
    merge_script_intel,
    sensitive_paths,
    source_maps,
    summarize,
    template_parameters,
)


def test_source_maps_are_provenance_only():
    body = "//# sourceMappingURL=app.js.map\n/*# sourceMappingURL=https://cdn.example.net/x.map */"
    maps = source_maps(body, "https://shop.example.com/static/app.js")

    assert maps == [
        {"url": "https://shop.example.com/static/app.js.map", "same_origin": True},
        {"url": "https://cdn.example.net/x.map", "same_origin": False},
    ]


def test_inline_data_source_maps_are_not_reported():
    body = "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ=="

    assert source_maps(body, "https://shop.example.com/app.js") == []


def test_source_map_capture_strips_escaped_newline_noise():
    escaped_noise = "\\n\\n;\\n"
    body = (
        f"//# sourceMappingURL=/static/chunks/a.js.map{escaped_noise}\n"
        "//# sourceMappingURL=/static/chunks/b.js.map/\n"
        "//# sourceMappingURL=/static/chunks/c.js.map//# sourceMappingURL=/static/chunks/d.js.map"
    )
    maps = source_maps(body, "https://shop.example.com/app.js")

    assert [entry["url"] for entry in maps] == [
        "https://shop.example.com/static/chunks/a.js.map",
        "https://shop.example.com/static/chunks/b.js.map",
        "https://shop.example.com/static/chunks/c.js.map",
    ]


def test_call_methods_extracts_verbs_from_common_clients():
    body = """
    fetch("/api/items", {method: "GET"});
    axios.get("/api/profile");
    axios.post("/api/save", data);
    const xhr = new XMLHttpRequest(); xhr.open("PUT", "/api/settings");
    """
    methods = call_methods(body, "https://shop.example.com/app/main.js")

    assert methods["https://shop.example.com/api/items"] == "GET"
    assert methods["https://shop.example.com/api/profile"] == "GET"
    assert methods["https://shop.example.com/api/save"] == "POST"
    assert methods["https://shop.example.com/api/settings"] == "PUT"


def test_template_parameters_normalize_common_placeholders():
    url = "https://shop.example.com/api/users/${userId}/orders/:orderId/files/{fileId}?x=1"

    assert template_parameters(url) == ["userId", "orderId", "fileId"]


def test_template_parameters_ignore_expressions():
    assert template_parameters("https://shop.example.com/api/${a+b}/x/:1bad") == []


def test_sensitive_paths_are_reported_without_duplicates():
    urls = [
        "https://shop.example.com/admin",
        "https://shop.example.com/admin/users",
        "https://shop.example.com/internal/config",
        "https://shop.example.com/about",
        "https://shop.example.com/graphql",
    ]

    assert sensitive_paths(urls) == ["/admin", "/internal/config", "/graphql"]


def test_summarize_folds_js_surface_into_artifact():
    artifact: dict = {}
    merge_script_intel(
        artifact,
        analyze_script(
            "https://shop.example.com/app.js",
            'axios.post("/api/save"); //# sourceMappingURL=app.js.map',
        ),
    )
    urls = [
        "https://shop.example.com/api/users/${id}/posts",
        "https://shop.example.com/graphql",
        "https://shop.example.com/admin",
        "https://cdn.example.net/collect",
        "https://shop.example.com/about",
    ]
    payload = summarize(artifact, urls, "https://shop.example.com/")

    assert payload["scripts"] == 1
    assert payload["api_calls"] == 1
    assert payload["graphql_endpoints"] == ["https://shop.example.com/graphql"]
    assert payload["third_party_hosts"] == ["cdn.example.net"]
    assert payload["sensitive_paths"] == ["/admin", "/graphql"]
    assert payload["parameters"] == ["id"]
    assert payload["post_calls"] == 1
    assert payload["source_maps"][0]["same_origin"] is True

from __future__ import annotations

import xml.etree.ElementTree as ElementTree


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def looks_like_xml(text: str) -> bool:
    head = text.lstrip()[:120].lower()
    return head.startswith("<?xml") or "<urlset" in head or "<sitemapindex" in head


def parse_sitemap(text: str, base_url: str, limit: int = 200) -> tuple[list[str], int]:
    """Return (locations, total) from a sitemap/urlset document.

    Only ``<loc>`` values are used; sitemap indexes and URL sets share that tag,
    so one walk covers both. Locations are resolved against ``base_url``.
    """
    from venomscan_engine.crawl.html_extract import normalize_url

    if limit <= 0 or "<" not in text:
        return [], 0
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return [], 0

    found: list[str] = []
    total = 0
    for element in root.iter():
        if _local(element.tag) != "loc" or not element.text:
            continue
        total += 1
        if len(found) >= limit:
            continue
        normalized = normalize_url(base_url, element.text.strip())
        if normalized and normalized not in found:
            found.append(normalized)
    return found, total

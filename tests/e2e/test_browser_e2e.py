from __future__ import annotations

import os
import re
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

BASE_URL = os.environ.get("VENOMSCAN_E2E_BASE_URL", "").rstrip("/")
TARGET_URL = os.environ.get("VENOMSCAN_E2E_TARGET_URL", "http://127.0.0.1:33000/")

pytestmark = pytest.mark.skipif(
    not BASE_URL,
    reason="browser E2E needs VENOMSCAN_E2E_BASE_URL plus a running web, API and worker",
)


@pytest.fixture(scope="module")
def page() -> Iterator[Any]:
    sync_api = pytest.importorskip("playwright.sync_api")

    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        current = context.new_page()
        current.set_default_timeout(60_000)
        yield current
        browser.close()


def test_register_attest_scan_and_findings(page: Any) -> None:
    email = f"e2e-{uuid.uuid4().hex[:10]}@venomscan.local"

    page.goto(f"{BASE_URL}/login")
    page.get_by_role("button", name="Create account").click()
    page.fill("#name", "E2E Analyst")
    page.fill("#email", email)
    page.fill("#password", "E2e-browser-pass-123")
    page.locator("form").get_by_role("button", name="Create account").click()
    page.wait_for_url(re.compile(r"/dashboard$"))

    page.goto(f"{BASE_URL}/targets")
    page.get_by_role("button", name="Add target", exact=True).click()
    add_dialog = page.get_by_role("dialog")
    add_dialog.locator("#target-name").fill("E2E Juice Shop")
    add_dialog.locator("#target-url").fill(TARGET_URL)
    add_dialog.get_by_role("button", name="Add target").click()
    page.wait_for_url(re.compile(r"/targets/[0-9a-f-]{36}$"))

    page.get_by_role("button", name="Manual attestation").click()
    page.get_by_label("I accept the authorization statement above.").check()
    page.fill("#attestation", "I own this lab target and authorize the automated E2E check.")
    page.get_by_role("button", name="Record attestation").click()
    page.get_by_text(re.compile(r"Verified via")).first.wait_for()

    page.get_by_role("button", name="Start scan", exact=True).click()
    scan_dialog = page.get_by_role("dialog")
    scan_dialog.get_by_role("button", name="Start scan").click()
    page.wait_for_url(re.compile(r"/scans/[0-9a-f-]{36}$"))
    page.get_by_text("completed", exact=True).first.wait_for(timeout=240_000)

    caption = page.get_by_text(re.compile(r"\d+ result\(s\)")).first
    caption.wait_for()
    total = int(re.search(r"\d+", caption.inner_text()).group())
    assert total >= 1, "scan completed but the findings list stayed empty"

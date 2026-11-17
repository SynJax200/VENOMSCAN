from __future__ import annotations

import os

CHROMIUM_ENV = "PLAYWRIGHT_CHROMIUM_EXECUTABLE"


def chromium_launch_kwargs(*, headless: bool = True) -> dict:
    """Launch options for Playwright's Chromium.

    Operators can point PLAYWRIGHT_CHROMIUM_EXECUTABLE at a distro Chromium when
    the bundled build is unavailable for the host platform (e.g. some arm64 hosts).
    """
    kwargs: dict = {"headless": headless}
    executable = os.environ.get(CHROMIUM_ENV, "").strip()
    if executable:
        kwargs["executable_path"] = executable
    return kwargs

from __future__ import annotations

from venomscan_engine.browser import chromium_launch_kwargs


def test_default_launch_is_headless_without_override(monkeypatch):
    monkeypatch.delenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", raising=False)
    assert chromium_launch_kwargs() == {"headless": True}


def test_override_is_forwarded(monkeypatch):
    monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", " /usr/bin/chromium ")
    assert chromium_launch_kwargs(headless=False) == {
        "headless": False,
        "executable_path": "/usr/bin/chromium",
    }


def test_blank_override_is_ignored(monkeypatch):
    monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", "   ")
    assert "executable_path" not in chromium_launch_kwargs()

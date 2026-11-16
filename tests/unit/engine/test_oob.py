from __future__ import annotations

import asyncio
import time

import httpx
import pytest
from venomscan_engine.oob import OobListener

TOKEN = "abcdef1234"


def test_listener_records_only_token_paths():
    with OobListener() as oob:
        assert oob.base_url is not None and oob.base_url.startswith("http://127.0.0.1:")
        httpx.get(oob.base_url + "/not-an-oob-path", trust_env=False)
        assert oob.hits_for(TOKEN) == []

        response = httpx.get(
            oob.url_for(TOKEN) + "/extra?probe=1",
            headers={"User-Agent": "venom-canary"},
            trust_env=False,
        )
        assert response.status_code == 204
        hits = oob.hits_for(TOKEN)
        assert len(hits) == 1
        assert hits[0].token == TOKEN
        assert hits[0].method == "GET"
        assert hits[0].user_agent == "venom-canary"
        assert hits[0].path.startswith(f"/oob/{TOKEN}")
        assert oob.hits_for("deadbeef") == []


def test_listener_records_post_and_drains_body():
    with OobListener() as oob:
        httpx.post(oob.url_for(TOKEN), content=b"x" * 512, trust_env=False)
        hits = oob.hits_for(TOKEN)
        assert len(hits) == 1
        assert hits[0].method == "POST"


@pytest.mark.asyncio
async def test_wait_for_honours_since_and_timeout():
    with OobListener() as oob:
        await asyncio.to_thread(httpx.get, oob.url_for(TOKEN), trust_env=False)
        await asyncio.sleep(0.05)
        since = time.time()
        assert await oob.wait_for(TOKEN, 0.3, since=since) is None

        await asyncio.to_thread(httpx.get, oob.url_for(TOKEN), trust_env=False)
        hit = await oob.wait_for(TOKEN, 2, since=since)
        assert hit is not None and hit.received_at >= since

        assert await oob.wait_for("0123456789", 0.2) is None


def test_listener_caps_stored_hits():
    with OobListener(max_hits=3) as oob:
        for _ in range(5):
            httpx.get(oob.url_for(TOKEN), trust_env=False)
        assert len(oob.hits_for(TOKEN)) == 3

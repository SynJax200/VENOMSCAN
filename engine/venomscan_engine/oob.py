"""Out-of-band HTTP listener used to verify SSRF and similar callbacks.

The listener binds loopback by default and only records requests whose path
carries an issued token. Request bodies are drained, never read into storage,
and every hit is capped in size so a hostile target cannot flood a scan.
"""

from __future__ import annotations

import asyncio
import re
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

_TOKEN_PATH = re.compile(r"/oob/([0-9a-f]{8,32})(?:/|$)")
_MAX_BODY_DRAIN = 64 * 1024


@dataclass(frozen=True)
class OobHit:
    token: str
    method: str
    path: str
    source_ip: str
    user_agent: str
    received_at: float


class OobListener:
    """Thread-backed HTTP listener with token-scoped hit lookup."""

    def __init__(
        self,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        public_base_url: str | None = None,
        max_hits: int = 200,
    ) -> None:
        self._bind_host = bind_host or "127.0.0.1"
        self._bind_port = bind_port
        self._public_base_url = (public_base_url or "").rstrip("/") or None
        self._max_hits = max_hits
        self._hits: list[OobHit] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.base_url: str | None = None

    def start(self) -> OobListener:
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                if 0 < length <= _MAX_BODY_DRAIN:
                    self.rfile.read(length)
                match = _TOKEN_PATH.search(urlsplit(self.path).path)
                if match:
                    listener._record(
                        OobHit(
                            token=match.group(1),
                            method=self.command,
                            path=self.path[:200],
                            source_ip=self.client_address[0],
                            user_agent=(self.headers.get("user-agent") or "")[:120],
                            received_at=time.time(),
                        )
                    )
                self.send_response(204)
                self.end_headers()

            do_GET = _handle  # noqa: N815
            do_HEAD = _handle  # noqa: N815
            do_POST = _handle  # noqa: N815
            do_PUT = _handle  # noqa: N815

            def log_message(self, *args) -> None:
                return

        server = ThreadingHTTPServer((self._bind_host, self._bind_port), Handler)
        server.daemon_threads = True
        port = server.server_address[1]
        exposed_host = "127.0.0.1" if self._bind_host in {"0.0.0.0", "::", ""} else self._bind_host
        self.base_url = self._public_base_url or f"http://{exposed_host}:{port}"
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever,
            name="venomscan-oob-listener",
            daemon=True,
        )
        self._thread.start()
        return self

    def _record(self, hit: OobHit) -> None:
        with self._lock:
            self._hits.append(hit)
            if len(self._hits) > self._max_hits:
                del self._hits[: len(self._hits) - self._max_hits]

    def url_for(self, token: str) -> str:
        if not self.base_url:
            raise RuntimeError("OOB listener is not started")
        return f"{self.base_url}/oob/{token}"

    def hits_for(self, token: str, since: float | None = None) -> list[OobHit]:
        with self._lock:
            hits = [hit for hit in self._hits if hit.token == token]
        if since is not None:
            hits = [hit for hit in hits if hit.received_at >= since]
        return hits

    async def wait_for(
        self, token: str, wait_seconds: float, since: float | None = None
    ) -> OobHit | None:
        deadline = time.monotonic() + max(0.0, wait_seconds)
        while True:
            hits = self.hits_for(token, since=since)
            if hits:
                return hits[0]
            if time.monotonic() >= deadline:
                return None
            await asyncio.sleep(0.1)

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None
        self.base_url = None

    def __enter__(self) -> OobListener:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()

"""
HTTP/3 (QUIC) benchmarker using aioquic.

HTTP/3 runs over QUIC — a UDP-based transport that eliminates TCP head-of-line
blocking. Each HTTP/3 stream is independent at the transport layer, so packet
loss on one stream does not stall others.

aioquic is the reference Python implementation of QUIC and HTTP/3.
"""

from __future__ import annotations

import asyncio
import ssl
import time
import urllib.parse
from collections import deque
from typing import Deque

from .metrics import RequestResult, ScenarioResult

try:
    import aioquic.asyncio as quic_asyncio
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import (
        DataReceived,
        H3Event,
        HeadersReceived,
        PushPromiseReceived,
    )
    from aioquic.quic.configuration import QuicConfiguration
    _AIOQUIC_AVAILABLE = True
except ImportError:
    _AIOQUIC_AVAILABLE = False


class _H3Client(quic_asyncio.QuicConnectionProtocol if _AIOQUIC_AVAILABLE else object):
    """
    Minimal HTTP/3 client protocol handler built on top of aioquic.
    Manages multiple concurrent streams and resolves their futures on completion.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3:      H3Connection | None = None
        self._streams: dict[int, asyncio.Future] = {}  # stream_id → future
        self._headers: dict[int, list] = {}
        self._bodies:  dict[int, bytearray] = {}

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            self._headers[event.stream_id] = event.headers
            if event.stream_id not in self._bodies:
                self._bodies[event.stream_id] = bytearray()
        elif isinstance(event, DataReceived):
            if event.stream_id in self._bodies:
                self._bodies[event.stream_id].extend(event.data)
            if event.stream_ended:
                fut = self._streams.get(event.stream_id)
                if fut and not fut.done():
                    fut.set_result((
                        self._headers.get(event.stream_id, []),
                        bytes(self._bodies.get(event.stream_id, b"")),
                    ))

    def quic_event_received(self, event) -> None:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic, enable_webtransport=False)
        for h3_event in self._h3.handle_event(event):
            self.http_event_received(h3_event)

    async def get(self, url: str) -> tuple[int, bytes]:
        parsed   = urllib.parse.urlparse(url)
        path     = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        authority = parsed.netloc

        stream_id = self._quic.get_next_available_stream_id()
        self._h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method",    b"GET"),
                (b":scheme",    b"https"),
                (b":authority", authority.encode()),
                (b":path",      path.encode()),
                (b"user-agent", b"http-perf-analyzer/1.0"),
            ],
            end_stream=True,
        )
        self.transmit()

        loop         = asyncio.get_event_loop()
        fut          = loop.create_future()
        self._streams[stream_id] = fut

        headers_list, body = await fut
        status = int(dict(headers_list).get(b":status", b"0"))
        return status, body


class HTTP3Benchmarker:
    """
    HTTP/3 benchmarker.

    Issues all requests as independent QUIC streams over a single UDP connection.
    """

    PROTOCOL = "HTTP/3"

    def __init__(self, base_url: str, cert_path: str | None = None):
        self.base_url  = base_url.rstrip("/")
        self.cert_path = cert_path

    def _quic_config(self) -> "QuicConfiguration":
        config = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
            verify_peer=False,
        )
        return config

    async def run(
        self,
        paths:       list[str],
        scenario:    str,
        concurrency: int = 100,
    ) -> ScenarioResult:
        if not _AIOQUIC_AVAILABLE:
            # Return a placeholder result if aioquic is not installed
            return ScenarioResult(
                protocol=self.PROTOCOL,
                scenario=scenario,
                concurrency=concurrency,
                n_requests=len(paths),
                requests=[
                    RequestResult(
                        protocol=self.PROTOCOL,
                        url=self.base_url + p,
                        status=0,
                        request_id=i,
                        start_time=time.time(),
                        ttfb=0.0,
                        total_time=0.0,
                        bytes_received=0,
                        error="aioquic not installed — pip install aioquic",
                    )
                    for i, p in enumerate(paths)
                ],
                wall_time=0.0,
                errors=len(paths),
            )

        parsed = urllib.parse.urlparse(self.base_url)
        host   = parsed.hostname or "localhost"
        port   = parsed.port or 443
        config = self._quic_config()

        batch_start = time.perf_counter()
        results: list[RequestResult] = []

        async with quic_asyncio.connect(
            host, port,
            configuration=config,
            create_protocol=_H3Client,
        ) as client:
            tasks = [
                self._fetch(client, path, idx, host, port)
                for idx, path in enumerate(paths)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)

        wall   = time.perf_counter() - batch_start
        errors = sum(1 for r in results if r.error)
        return ScenarioResult(
            protocol=self.PROTOCOL,
            scenario=scenario,
            concurrency=concurrency,
            n_requests=len(paths),
            requests=list(results),
            wall_time=wall,
            errors=errors,
        )

    async def _fetch(self, client: "_H3Client", path: str, idx: int, host: str, port: int) -> RequestResult:
        url   = f"https://{host}:{port}{path}" if not path.startswith("http") else path
        start = time.perf_counter()
        try:
            status, body = await client.get(url)
            ttfb  = time.perf_counter() - start   # approximate for H3
            total = time.perf_counter() - start
            return RequestResult(
                protocol=self.PROTOCOL,
                url=url,
                status=status,
                request_id=idx,
                start_time=time.time() - total,
                ttfb=ttfb,
                total_time=total,
                bytes_received=len(body),
            )
        except Exception as exc:
            total = time.perf_counter() - start
            return RequestResult(
                protocol=self.PROTOCOL,
                url=url,
                status=0,
                request_id=idx,
                start_time=time.time() - total,
                ttfb=total,
                total_time=total,
                bytes_received=0,
                error=str(exc)[:200],
            )

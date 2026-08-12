from __future__ import annotations

import asyncio
import ssl
import time

import httpx

from .metrics import RequestResult, ScenarioResult


class HTTP1Benchmarker:
    """
    HTTP/1.1 benchmarker.

    Simulates browser-like behaviour: up to `max_connections` parallel TCP
    connections to the same origin, requests serialised within each connection.
    """

    PROTOCOL = "HTTP/1.1"

    def __init__(self, base_url: str, ssl_context: ssl.SSLContext | None = None, max_connections: int = 6):
        self.base_url        = base_url.rstrip("/")
        self.ssl_context     = ssl_context
        self.max_connections = max_connections

    async def run(
        self,
        paths:       list[str],
        scenario:    str,
        concurrency: int = 6,
    ) -> ScenarioResult:
        limits  = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
        timeout = httpx.Timeout(30.0)

        async with httpx.AsyncClient(
            base_url=self.base_url,
            http2=False,
            verify=self.ssl_context or False,
            limits=limits,
            timeout=timeout,
        ) as client:
            batch_start = time.perf_counter()
            tasks       = [
                self._fetch(client, path, idx)
                for idx, path in enumerate(paths)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)
            wall    = time.perf_counter() - batch_start

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

    async def _fetch(self, client: httpx.AsyncClient, path: str, idx: int) -> RequestResult:
        url   = path if path.startswith("http") else self.base_url + path
        start = time.perf_counter()
        ttfb  = start
        try:
            async with client.stream("GET", url) as resp:
                ttfb = time.perf_counter()
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
            total = time.perf_counter() - start
            return RequestResult(
                protocol=self.PROTOCOL,
                url=url,
                status=resp.status_code,
                request_id=idx,
                start_time=time.time() - total,
                ttfb=ttfb - start,
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

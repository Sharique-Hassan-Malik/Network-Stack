from __future__ import annotations

import asyncio
import ssl
import time

import httpx

from .metrics import RequestResult, ScenarioResult


class HTTP2Benchmarker:
    """
    HTTP/2 benchmarker.

    All requests share a single TCP connection and are multiplexed as
    independent streams. This removes the head-of-line blocking that affects
    HTTP/1.1 at the HTTP layer (though TCP HOL blocking remains).
    """

    PROTOCOL = "HTTP/2"

    def __init__(self, base_url: str, ssl_context: ssl.SSLContext | None = None):
        self.base_url    = base_url.rstrip("/")
        self.ssl_context = ssl_context

    async def run(
        self,
        paths:       list[str],
        scenario:    str,
        concurrency: int = 100,   # HTTP/2 supports many concurrent streams
    ) -> ScenarioResult:
        # One shared client = one TCP connection = true stream multiplexing
        limits  = httpx.Limits(max_connections=1, max_keepalive_connections=1)
        timeout = httpx.Timeout(30.0)

        async with httpx.AsyncClient(
            base_url=self.base_url,
            http2=True,
            verify=self.ssl_context or False,
            limits=limits,
            timeout=timeout,
        ) as client:
            batch_start = time.perf_counter()
            tasks       = [self._fetch(client, path, idx) for idx, path in enumerate(paths)]
            results     = await asyncio.gather(*tasks, return_exceptions=False)
            wall        = time.perf_counter() - batch_start

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
        try:
            async with client.stream("GET", url) as resp:
                ttfb = time.perf_counter() - start
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

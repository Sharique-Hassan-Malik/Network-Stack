"""
Orchestrates benchmark runs across HTTP/1.1, HTTP/2 and HTTP/3.

Scenarios
---------
single_request      One request for each payload size (small, medium, large).
                    Measures baseline TTFB and transfer time.

concurrent_small    N concurrent requests for a small resource.
                    Shows HTTP/1.1 connection-limit bottleneck vs H2/H3 multiplexing.

hol_blocking        One large + N small resources issued concurrently.
                    Head-of-line blocking causes small requests to stall behind
                    the large one in HTTP/1.1; HTTP/2 and HTTP/3 isolate streams.

sequential          N requests issued one-after-another on the same connection.
                    Measures per-request overhead and keep-alive re-use.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from pathlib import Path

from .http1 import HTTP1Benchmarker
from .http2 import HTTP2Benchmarker
from .http3 import HTTP3Benchmarker
from .metrics import ScenarioResult


_WARMUP_PATHS = ["/small"] * 3


class BenchmarkRunner:
    def __init__(
        self,
        h1_url:    str,
        h2_url:    str,
        h3_url:    str | None = None,
        cert_path: str | None = None,
    ):
        ssl_ctx = _make_ssl_context(cert_path) if cert_path else None

        self.h1 = HTTP1Benchmarker(h1_url, ssl_context=ssl_ctx)
        self.h2 = HTTP2Benchmarker(h2_url, ssl_context=ssl_ctx)
        self.h3 = HTTP3Benchmarker(h3_url or h2_url, cert_path=cert_path) if h3_url else None

    async def warmup(self) -> None:
        """Issue a few throwaway requests to establish connections before timing."""
        await asyncio.gather(
            self.h1.run(_WARMUP_PATHS, scenario="warmup", concurrency=3),
            self.h2.run(_WARMUP_PATHS, scenario="warmup", concurrency=3),
        )

    async def run_all(
        self,
        n_concurrent: int = 20,
        progress_cb=None,
    ) -> list[ScenarioResult]:
        """
        Run all benchmark scenarios and return the full result list.
        progress_cb(message: str) is called before each scenario if provided.
        """
        results: list[ScenarioResult] = []

        def _cb(msg: str) -> None:
            if progress_cb:
                progress_cb(msg)

        _cb("Warming up connections…")
        await self.warmup()

        # --- single request ---
        for label, path in [("small (1 KB)", "/small"), ("medium (100 KB)", "/medium"), ("large (1 MB)", "/large")]:
            _cb(f"Scenario: single_request — {label}")
            results += await self._run_scenario(
                scenario=f"single_{label.split()[0]}",
                paths=[path],
                concurrency=1,
            )

        # --- concurrent small ---
        paths = ["/small"] * n_concurrent
        _cb(f"Scenario: concurrent_small — {n_concurrent} concurrent")
        results += await self._run_scenario(
            scenario="concurrent_small",
            paths=paths,
            concurrency=n_concurrent,
        )

        # --- HOL blocking ---
        # One large resource followed by many small ones
        hol_paths = ["/large"] + ["/small"] * (n_concurrent - 1)
        _cb(f"Scenario: hol_blocking — 1 large + {n_concurrent - 1} small")
        results += await self._run_scenario(
            scenario="hol_blocking",
            paths=hol_paths,
            concurrency=n_concurrent,
        )

        # --- sequential ---
        seq_paths = ["/small"] * 10
        _cb("Scenario: sequential — 10 requests in series")
        results += await self._run_scenario_sequential(
            scenario="sequential",
            paths=seq_paths,
        )

        # --- mixed sizes ---
        mixed = ["/small"] * 8 + ["/medium"] * 4 + ["/large"]
        _cb(f"Scenario: mixed_sizes — {len(mixed)} requests")
        results += await self._run_scenario(
            scenario="mixed_sizes",
            paths=mixed,
            concurrency=len(mixed),
        )

        return results

    async def _run_scenario(
        self,
        scenario:    str,
        paths:       list[str],
        concurrency: int,
    ) -> list[ScenarioResult]:
        coros = [
            self.h1.run(paths, scenario=scenario, concurrency=min(concurrency, 6)),
            self.h2.run(paths, scenario=scenario, concurrency=concurrency),
        ]
        if self.h3:
            coros.append(self.h3.run(paths, scenario=scenario, concurrency=concurrency))
        return list(await asyncio.gather(*coros))

    async def _run_scenario_sequential(
        self,
        scenario: str,
        paths:    list[str],
    ) -> list[ScenarioResult]:
        """Issue requests one at a time on each protocol."""
        results = []
        for benchmarker in filter(None, [self.h1, self.h2, self.h3]):
            batch_start = time.perf_counter()
            reqs = []
            for idx, path in enumerate(paths):
                r = await benchmarker.run([path], scenario="single", concurrency=1)
                req = r.requests[0]
                req.request_id = idx
                reqs.append(req)
            wall   = time.perf_counter() - batch_start
            errors = sum(1 for r in reqs if r.error)
            from .metrics import ScenarioResult
            results.append(ScenarioResult(
                protocol=benchmarker.PROTOCOL,
                scenario=scenario,
                concurrency=1,
                n_requests=len(paths),
                requests=reqs,
                wall_time=wall,
                errors=errors,
            ))
        return results


def _make_ssl_context(cert_path: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx

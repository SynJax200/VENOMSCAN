"""Latency/throughput probe for a locally running VENOMSCAN control plane.

Run it against your own installation (never a third-party host):

    uv run python scripts/load_test.py --email demo@venomscan.local --password Venom-demo-123

It logs in, hammers the dashboard/list endpoints, then launches concurrent scans
against an already verified target. Exits non-zero when the dashboard p95 exceeds
the budget (default 300 ms) or any request fails.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time

import httpx

DEFAULT_EMAIL = "demo@venomscan.local"
DEFAULT_PASSWORD = "Venom-demo-123"


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def _summary(label: str, samples: list[float], failures: int) -> dict:
    return {
        "label": label,
        "count": len(samples),
        "failures": failures,
        "p50_ms": round(statistics.median(samples), 1) if samples else 0.0,
        "p95_ms": round(_percentile(samples, 0.95), 1),
        "p99_ms": round(_percentile(samples, 0.99), 1),
        "max_ms": round(max(samples), 1) if samples else 0.0,
    }


async def _login(client: httpx.AsyncClient, base: str, email: str, password: str) -> str:
    csrf = (await client.get(f"{base}/api/auth/csrf")).json()["csrf_token"]
    response = await client.post(
        f"{base}/api/auth/login",
        json={"email": email, "password": password},
        headers={"x-csrf-token": csrf},
    )
    response.raise_for_status()
    return response.json()["csrf_token"]


async def _hammer(
    client: httpx.AsyncClient,
    base: str,
    paths: list[str],
    total: int,
    concurrency: int,
) -> list[tuple[str, float, bool]]:
    semaphore = asyncio.Semaphore(concurrency)
    results: list[tuple[str, float, bool]] = []

    async def one(index: int) -> None:
        path = paths[index % len(paths)]
        async with semaphore:
            started = time.perf_counter()
            try:
                response = await client.get(f"{base}{path}")
                ok = response.status_code < 400
            except httpx.HTTPError:
                ok = False
            results.append((path, (time.perf_counter() - started) * 1000, ok))

    await asyncio.gather(*(one(index) for index in range(total)))
    return results


async def _concurrent_scans(
    client: httpx.AsyncClient, base: str, csrf: str, count: int
) -> list[dict]:
    targets = (await client.get(f"{base}/api/targets")).json()
    verified = [
        target
        for target in targets
        if target.get("verification", {}).get("verified") and target.get("scan_count") is not None
    ]
    if not verified:
        print("no verified target found; create and verify one before the scan burst")
        return []

    payload = {"target_id": verified[0]["id"], "profile": "safe"}
    headers = {"x-csrf-token": csrf}
    started = time.perf_counter()
    responses = await asyncio.gather(
        *(
            client.post(f"{base}/api/scans", json=payload, headers=headers)
            for _ in range(count)
        )
    )
    created = [row.json() for row in responses if row.status_code < 400]
    launch_ms = (time.perf_counter() - started) * 1000
    print(
        f"launched {len(created)}/{count} scans in {launch_ms:.0f} ms "
        f"(profile=safe, target={verified[0]['name']})"
    )

    deadline = time.monotonic() + 900
    finished: dict[str, str] = {}
    while created and time.monotonic() < deadline:
        pending = [scan for scan in created if scan["id"] not in finished]
        if not pending:
            break
        for scan in pending:
            detail = (await client.get(f"{base}/api/scans/{scan['id']}")).json()
            if detail.get("status") in {"completed", "failed", "cancelled"}:
                finished[scan["id"]] = detail["status"]
        await asyncio.sleep(2)

    outcomes: dict[str, int] = {}
    for status in finished.values():
        outcomes[status] = outcomes.get(status, 0) + 1
    print(f"scan outcomes: {outcomes or 'still running after 900 s'}")
    return [
        {"id": scan["id"], "status": finished.get(scan["id"], "timeout")} for scan in created
    ]


async def run(args: argparse.Namespace) -> int:
    async with httpx.AsyncClient(timeout=30.0, trust_env=False) as client:
        csrf = await _login(client, args.base, args.email, args.password)
        print(f"logged in as {args.email}")

        paths = ["/api/dashboard", "/api/scans?limit=50", "/api/targets"]
        results = await _hammer(client, args.base, paths, args.requests, args.concurrency)

        summaries = []
        for path in paths:
            samples = [latency for name, latency, ok in results if name == path and ok]
            failures = sum(1 for name, _, ok in results if name == path and not ok)
            summaries.append(_summary(path, samples, failures))
        for summary in summaries:
            print(
                f"{summary['label']:<22} n={summary['count']:<4} "
                f"p50={summary['p50_ms']:>7.1f} ms p95={summary['p95_ms']:>7.1f} ms "
                f"p99={summary['p99_ms']:>7.1f} ms max={summary['max_ms']:>7.1f} ms "
                f"failures={summary['failures']}"
            )

        scans: list[dict] = []
        if args.scans:
            scans = await _concurrent_scans(client, args.base, csrf, args.scans)

        if args.json:
            print(
                json.dumps(
                    {"latency": summaries, "scans": scans},
                    indent=2,
                )
            )

        dashboard = next(row for row in summaries if row["label"] == "/api/dashboard")
        failed = sum(row["failures"] for row in summaries)
        if failed:
            print(f"FAIL: {failed} request(s) errored")
            return 1
        if dashboard["p95_ms"] > args.budget_ms:
            print(
                f"FAIL: dashboard p95 {dashboard['p95_ms']} ms exceeds "
                f"the {args.budget_ms} ms budget"
            )
            return 1
        print(f"PASS: dashboard p95 {dashboard['p95_ms']} ms within {args.budget_ms} ms budget")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--email", default=DEFAULT_EMAIL)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--scans", type=int, default=0, help="concurrent scans to launch")
    parser.add_argument("--budget-ms", type=float, default=300.0)
    parser.add_argument("--json", action="store_true")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())

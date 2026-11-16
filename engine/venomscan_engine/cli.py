from __future__ import annotations

import argparse
import asyncio
import json
import sys

from venomscan_engine.events import ScanEvent
from venomscan_engine.pipeline.orchestrator import run_scan


class _StderrSink:
    """Print progress lines while keeping stdout clean for the JSON result."""

    async def emit(self, event: ScanEvent) -> None:
        line = f"[{event.progress:3d}%] {event.phase:<12} {event.message}"
        print(line, file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="venomscan-engine",
        description="VENOMSCAN standalone scanning engine (authorized targets only).",
    )
    parser.add_argument("url", help="authorized target URL")
    parser.add_argument("--profile", choices=["passive", "safe", "active"], default="safe")
    parser.add_argument("--max-requests", type=int, default=120)
    parser.add_argument("--max-seconds", type=float, default=90.0)
    parser.add_argument("--rps", type=float, default=4.0)
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="allow private/loopback targets (local lab only)",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    return parser


async def _main_async(args: argparse.Namespace) -> int:
    sink = None if args.quiet else _StderrSink()
    try:
        result = await run_scan(
            "cli",
            args.url,
            profile=args.profile,
            sink=sink,
            allow_private=args.allow_private,
            max_requests=args.max_requests,
            max_seconds=args.max_seconds,
            rps=args.rps,
        )
    except Exception as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        return 1
    payload = result.model_dump(mode="json")
    print(json.dumps(payload, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return asyncio.run(_main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())

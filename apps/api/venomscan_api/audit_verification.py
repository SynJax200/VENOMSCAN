"""Revalidate persisted findings against their stored evidence.

Scans completed before the evidence-bound verifier existed may contain rows marked
VERIFIED with no proof. This tool writes a JSON backup of every affected row, then
downgrades the row to SUSPECTED with the same confidence cap and notes the live
verifier applies. Run it once after upgrading, then rely on the per-scan verifier.

    python -m venomscan_api.audit_verification --dry-run
    python -m venomscan_api.audit_verification
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select

from venomscan_api.db import session_factory
from venomscan_api.models import Finding
from venomscan_api.services.finding_integrity import effective_finding_status

NOTE = "evidence contract incomplete"


def _snapshot(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "check_id": finding.check_id,
        "verification_status": finding.verification_status,
        "confidence": finding.confidence,
        "request_evidence": finding.request_evidence or {},
        "response_evidence": finding.response_evidence or {},
    }


def audit(dry_run: bool = False, backup_dir: Path | None = None) -> dict[str, int]:
    with session_factory()() as db:
        rows = db.scalars(
            select(Finding).where(Finding.verification_status == "verified")
        ).all()
        affected: list[dict[str, Any]] = []
        unknown = 0
        for finding in rows:
            try:
                status, reason = effective_finding_status(finding)
            except ValueError:
                unknown += 1
                continue
            if status == "verified":
                continue
            snapshot = _snapshot(finding)
            snapshot["verification_reason"] = reason
            affected.append(snapshot)
            if dry_run:
                continue
            evidence = dict(finding.response_evidence or {})
            evidence["verification_note"] = NOTE
            evidence["verification_reason"] = reason or NOTE
            finding.response_evidence = evidence
            finding.verification_status = "suspected"
            finding.confidence = min(finding.confidence, 5)

        backup_path = None
        if affected and not dry_run:
            target_dir = backup_dir or Path(".")
            target_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            backup_path = target_dir / f"verification-audit-{stamp}.json"
            backup_path.write_text(
                json.dumps({"generated_at": stamp, "rows": affected}, indent=2),
                encoding="utf-8",
            )
        if not dry_run:
            db.commit()
    result = {
        "checked": len(rows),
        "downgraded": len(affected),
        "unknown_status": unknown,
        "dry_run": int(dry_run),
    }
    if backup_path is not None:
        print(f"backup: {backup_path}")
    print(json.dumps(result, sort_keys=True))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=Path("."),
        help="directory for the JSON backup written before any update",
    )
    args = parser.parse_args()
    audit(dry_run=args.dry_run, backup_dir=args.backup_dir)


if __name__ == "__main__":
    main()

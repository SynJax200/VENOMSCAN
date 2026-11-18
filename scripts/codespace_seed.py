from __future__ import annotations

import json
import os
import sys
import time
from urllib.parse import urlsplit

import httpx

BASE = os.environ["VG_URL"].rstrip("/")
EMAIL = os.environ.get("VG_EMAIL", "demo@venomscan.local")
PASSWORD = os.environ["VG_PASSWORD"]
ATTESTATION = (
    "I own and operate this VENOMSCAN deployment and authorize a safe self-scan of its public URL."
)


def die(step: str, detail: object) -> None:
    print(f"seed FAIL at {step}: {detail}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    host = urlsplit(BASE).hostname or ""
    with httpx.Client(base_url=BASE, timeout=90, follow_redirects=True, trust_env=False) as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        register = client.post(
            "/api/auth/register",
            json={"email": EMAIL, "password": PASSWORD, "name": "Demo Analyst"},
            headers={"X-CSRF-Token": token},
        )
        if register.status_code == 409:
            register = client.post(
                "/api/auth/login",
                json={"email": EMAIL, "password": PASSWORD},
                headers={"X-CSRF-Token": token},
            )
        if register.status_code not in (200, 201):
            die("register/login", f"{register.status_code} {register.text[:300]}")
        token = register.json().get("csrf_token", token)
        headers = {"X-CSRF-Token": token}

        targets = client.get("/api/targets").json()
        target = next((row for row in targets if host in row.get("url", "")), None)
        if target is None:
            created = client.post(
                "/api/targets",
                json={
                    "name": "VENOMSCAN self demo",
                    "url": f"{BASE}/",
                    "scope_notes": "Operator-owned deployment; demo self-scan target.",
                },
                headers=headers,
            )
            if created.status_code != 201:
                die("target create", f"{created.status_code} {created.text[:300]}")
            target = created.json()

        verification = client.get(f"/api/targets/{target['id']}").json().get("verification") or {}
        if not verification.get("verified"):
            attested = client.post(
                f"/api/targets/{target['id']}/verify/attest",
                json={"attestation": ATTESTATION, "accepted": True},
                headers=headers,
            )
            if attested.status_code != 200:
                die("attest", f"{attested.status_code} {attested.text[:300]}")

        scans = client.get("/api/scans").json()
        scan = next(
            (row for row in scans if row.get("target_id") == target["id"] and row.get("status") == "completed"),
            None,
        )
        if scan is None:
            created_scan = client.post(
                "/api/scans",
                json={"target_id": target["id"], "profile": "safe"},
                headers=headers,
            )
            if created_scan.status_code != 201:
                die("scan create", f"{created_scan.status_code} {created_scan.text[:300]}")
            scan = created_scan.json()
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                time.sleep(4)
                scan = client.get(f"/api/scans/{scan['id']}").json()
                if scan["status"] in {"completed", "failed", "cancelled"}:
                    break
            if scan["status"] != "completed":
                die("scan run", json.dumps(scan)[:400])

        findings = client.get(f"/api/scans/{scan['id']}/findings").json()
        pdf_bytes = 0
        report = client.post(
            f"/api/scans/{scan['id']}/reports",
            json={"format": "pdf"},
            headers=headers,
        )
        if report.status_code == 201:
            download = client.get(report.json()["signed_url"])
            pdf_bytes = len(download.content) if download.status_code == 200 else 0

        print(
            json.dumps(
                {
                    "target": target["id"],
                    "scan": scan["id"],
                    "status": scan["status"],
                    "findings": len(findings),
                    "pdf_bytes": pdf_bytes,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()

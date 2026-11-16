from __future__ import annotations

from sqlalchemy import select

from venomscan_api import security
from venomscan_api.config import get_settings
from venomscan_api.db import init_db, init_engine, session_factory, utcnow
from venomscan_api.models import Authorization, Scan, Target, User
from venomscan_api.services import verification
from venomscan_api.services.runner import execute_scan

DEMO_EMAIL = "demo@venomscan.local"
DEMO_PASSWORD = "Venom-demo-123"


def main() -> None:
    settings = get_settings()
    init_engine(settings)
    init_db()
    with session_factory()() as db:
        user = db.scalar(select(User).where(User.email == DEMO_EMAIL))
        if user is None:
            user = User(
                email=DEMO_EMAIL,
                name="Demo Analyst",
                password_hash=security.hash_password(DEMO_PASSWORD),
            )
            db.add(user)
            db.flush()
            print(f"created user {DEMO_EMAIL} / {DEMO_PASSWORD}")

        target = db.scalar(select(Target).where(Target.owner_id == user.id))
        if target is None:
            target_url = settings.seed_target_url or settings.api_base.rstrip("/") + "/demo"
            target = Target(
                owner_id=user.id,
                name="VENOMSCAN self-check",
                url=target_url,
                host=verification.host_from_url(target_url),
                scope_notes="Local demo fixture served by the VENOMSCAN API itself.",
            )
            db.add(target)
            db.flush()
            auth = Authorization(
                target_id=target.id,
                method="manual_attestation",
                token=verification.new_verification_token(),
                attestation="Local lab target owned by the operator of this installation.",
                verified_at=utcnow(),
                expires_at=verification.verified_until(),
            )
            db.add(auth)
            db.flush()
            print(f"created target {target.name} -> {target.url}")

        existing = db.scalar(select(Scan).where(Scan.target_id == target.id))
        scan = None
        if existing is None:
            auth = target.latest_authorization
            scan = Scan(
                target_id=target.id,
                authorization_id=auth.id if auth else None,
                profile="safe",
                status="queued",
                phase="queued",
                options={},
            )
            db.add(scan)
        db.commit()
        scan_id = scan.id if scan else None

    if scan_id is None:
        print("seed complete; a scan already exists for the demo target")
        return
    if not settings.allow_private_targets:
        print(
            "skipping demo scan: set ALLOW_PRIVATE_TARGETS=true to let the engine reach the "
            "local API instance (loopback targets stay blocked otherwise)"
        )
        return
    print(f"running demo scan {scan_id} against {settings.api_base}/demo")
    execute_scan(scan_id)
    with session_factory()() as db:
        scan = db.get(Scan, scan_id)
        print(f"seed scan finished with status {scan.status if scan else 'missing'}")


if __name__ == "__main__":
    main()

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from venomscan_api.config import Settings, get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_sessionmaker: sessionmaker[Session] | None = None


def init_engine(settings: Settings | None = None) -> None:
    global _engine, _sessionmaker
    settings = settings or get_settings()
    if _engine is not None:
        _engine.dispose()
    connect_args = {}
    if settings.database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    _engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)
    _sessionmaker = sessionmaker(bind=_engine, expire_on_commit=False, autoflush=False)


def session_factory() -> sessionmaker[Session]:
    if _sessionmaker is None:
        init_engine()
    assert _sessionmaker is not None
    return _sessionmaker


def init_db() -> None:
    from venomscan_api import models  # noqa: F401  (register tables)

    assert _engine is not None, "init_engine() must run before init_db()"
    Base.metadata.create_all(bind=_engine)
    _upgrade_columns(_engine)
    _bootstrap_admin(_engine)
    _ensure_indexes(_engine)


# Columns added after the first release. create_all() never alters existing
# tables, so self-hosted databases need an explicit additive upgrade.
_ADDED_COLUMNS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "users": (("role", "VARCHAR(16)", "user"),),
    "test_credentials": (
        ("owner_id", "VARCHAR(36)", "NULL"),
        ("target_id", "VARCHAR(36)", "NULL"),
    ),
    "scans": (("recon", "JSON", "{}"),),
    "endpoints": (("depth", "INTEGER", "0"), ("parameters", "JSON", "[]")),
}


def _upgrade_columns(engine) -> None:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    with engine.begin() as connection:
        for table, columns in _ADDED_COLUMNS.items():
            if table not in tables:
                continue
            present = {column["name"] for column in inspector.get_columns(table)}
            for name, sql_type, default in columns:
                if name in present:
                    continue
                if engine.dialect.name == "postgresql" and sql_type == "JSON":
                    rendered = "'{}'::json" if default == "{}" else f"'{default}'::json"
                elif default == "NULL":
                    rendered = "NULL"
                else:
                    rendered = f"'{default}'"
                connection.execute(
                    text(
                        f'ALTER TABLE "{table}" ADD COLUMN "{name}" {sql_type} '
                        f"DEFAULT {rendered}"
                    )
                )


def _bootstrap_admin(engine) -> None:
    """Promote one existing account after the RBAC upgrade so settings stay reachable.

    New installations make the first registered account the administrator instead.
    """
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if "users" not in tables:
        return
    columns = {column["name"] for column in inspector.get_columns("users")}
    if "role" not in columns:
        return
    with engine.begin() as connection:
        has_admin = connection.execute(
            text("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1")
        ).first()
        if has_admin:
            return
        oldest = connection.execute(
            text("SELECT id FROM users ORDER BY created_at ASC LIMIT 1")
        ).first()
        if oldest:
            connection.execute(
                text("UPDATE users SET role = 'admin' WHERE id = :id"), {"id": oldest[0]}
            )


# Additive covering indexes for the list/dashboard/report queries. They are created
# after create_all() so existing self-hosted databases pick them up without a migration.
_INDEXES: tuple[tuple[str, str], ...] = (
    ("ix_findings_scan_id_risk", "findings", '("scan_id", "risk_score")'),
    ("ix_findings_dedup_key", "findings", '("dedup_key")'),
    ("ix_scans_target_id_created", "scans", '("target_id", "created_at")'),
    ("ix_endpoints_scan_id_url", "endpoints", '("scan_id", "url")'),
    ("ix_technologies_scan_id_name", "technologies", '("scan_id", "name")'),
    ("ix_reports_scan_id_created", "reports", '("scan_id", "created_at")'),
    ("ix_ai_analyses_scan_id_kind", "ai_analyses", '("scan_id", "kind")'),
    ("ix_test_credentials_owner_id", "test_credentials", '("owner_id")'),
    ("ix_test_credentials_target_id", "test_credentials", '("target_id")'),
    ("ix_users_role", "users", '("role")'),
)


def _ensure_indexes(engine) -> None:
    tables = set(inspect(engine).get_table_names())
    with engine.begin() as connection:
        for name, table, columns in _INDEXES:
            if table not in tables:
                continue
            connection.execute(
                text(f'CREATE INDEX IF NOT EXISTS "{name}" ON "{table}" {columns}')
            )


def get_db() -> Iterator[Session]:
    session = session_factory()()
    try:
        yield session
    finally:
        session.close()


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite drops tzinfo; treat stored values as UTC."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value

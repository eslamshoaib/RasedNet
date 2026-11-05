"""Migrations must produce exactly the schema the ORM models describe, and be reversible."""

from __future__ import annotations

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from rased.migrations_util import downgrade_to_base, upgrade_to_head
from rased.models import Base


def test_migrated_schema_matches_models(database_url):
    engine = create_engine(database_url)
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        diff = compare_metadata(ctx, Base.metadata)
    engine.dispose()
    assert diff == [], diff


def test_downgrade_and_reupgrade(database_url):
    downgrade_to_base(database_url)
    engine = create_engine(database_url)
    remaining = set(inspect(engine).get_table_names()) - {"alembic_version"}
    engine.dispose()
    assert remaining == set()
    upgrade_to_head(database_url)
    engine = create_engine(database_url)
    assert "assets" in inspect(engine).get_table_names()
    engine.dispose()


def test_upgrade_0001_to_head_with_existing_jobs(database_url):
    """Real-world path: an installed 0.1.0 database that already holds scans must upgrade."""
    from alembic import command
    from sqlalchemy import text

    from rased.migrations_util import alembic_config

    downgrade_to_base(database_url)
    command.upgrade(alembic_config(database_url), "0001")
    engine = create_engine(database_url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO roles (name, name_ar, description_ar) VALUES ('r', 'r', '')"))
        conn.execute(text(
            "INSERT INTO scan_profiles (code, name_ar, description_ar, discovery_ports, tcp_ports, use_icmp, use_arp, resolve_dns,"
            " grab_banners, max_concurrency, per_host_concurrency, rate_per_second, connect_timeout_ms, retries, is_intrusive, is_builtin)"
            " VALUES ('p', 'p', '', '[]', '[]', true, true, true, false, 1, 1, 1, 1000, 0, false, false)"))
        conn.execute(text(
            "INSERT INTO scan_scopes (name, cidr, description, excluded_hosts, excluded_ports, is_sensitive, is_approved, is_active,"
            " created_at, updated_at) VALUES ('s', '10.0.0.0/24', '', '[]', '[]', false, true, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
        conn.execute(text(
            "INSERT INTO scan_jobs (scope_id, profile_id, trigger, status, cancel_requested, scope_snapshot, profile_snapshot,"
            " total_hosts, processed_hosts, alive_hosts, open_services, created_at)"
            " VALUES (1, 1, 'manual', 'interrupted', false, '{}', '{}', 254, 128, 3, 2, CURRENT_TIMESTAMP)"))
    engine.dispose()
    upgrade_to_head(database_url)
    engine = create_engine(database_url)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT resume_offset, processed_hosts FROM scan_jobs")).one() == (0, 128)
        assert conn.execute(text("SELECT schedule_interval_minutes FROM scan_scopes")).scalar() is None
    engine.dispose()

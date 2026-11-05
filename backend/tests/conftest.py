"""Shared fixtures.

Every test gets a freshly migrated database:
* default: a SQLite file copied from a template built once with ``alembic upgrade head``;
* if ``RASED_TEST_DATABASE_URL`` is set (PostgreSQL), the public schema is dropped and
  re-migrated for every test.
"""

from __future__ import annotations

import os
import shutil
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from rased.app import create_app
from rased.config import Settings
from rased.db import Database
from rased.discovery.arp import Neighbor
from rased.discovery.engine import EngineConfig, ScanEngine
from rased.discovery.icmp import PingResult
from rased.migrations_util import upgrade_to_head
from rased.models import Role, User, utcnow
from rased.security.passwords import hash_password
from rased.seed import seed_reference_data

PG_URL = os.environ.get("RASED_TEST_DATABASE_URL")
STRONG_PASSWORD = "Str0ng!Passw0rd#2026"


@pytest.fixture(scope="session")
def sqlite_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("template") / "template.db"
    upgrade_to_head(f"sqlite:///{path.as_posix()}")
    return path


def _reset_postgres(url: str) -> None:
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()


@pytest.fixture
def database_url(tmp_path: Path, sqlite_template: Path) -> str:
    if PG_URL:
        _reset_postgres(PG_URL)
        upgrade_to_head(PG_URL)
        return PG_URL
    target = tmp_path / "rased.db"
    shutil.copyfile(sqlite_template, target)
    return f"sqlite:///{target.as_posix()}"


@pytest.fixture
def settings(database_url: str, tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=database_url,
        cookie_secure=False,
        login_rate_per_minute=1000,
        api_rate_per_minute=100000,
        frontend_dist=tmp_path / "no-frontend",
        log_level="WARNING",
    )


@pytest.fixture
def db(settings: Settings) -> Iterator[Database]:
    database = Database(settings.database_url)
    with database.session() as session:
        seed_reference_data(session)
    yield database
    database.dispose()


def make_user(db: Database, username: str, role: str, password: str = STRONG_PASSWORD) -> int:
    with db.session() as session:
        role_obj = session.query(Role).filter_by(name=role).one()
        user = User(
            username=username, display_name=username, password_hash=hash_password(password),
            role=role_obj, is_active=True, failed_login_count=0,
            password_changed_at=utcnow(), created_at=utcnow(),
        )
        session.add(user)
        session.flush()
        return user.id


def login(client: TestClient, username: str, password: str = STRONG_PASSWORD) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


# --- offline-safe engine doubles -------------------------------------------------------------


async def fake_ping_alive(ip: str, timeout_ms: int) -> PingResult:
    return PingResult(alive=True, ttl=128)


async def fake_ping_dead(ip: str, timeout_ms: int) -> PingResult:
    return PingResult(alive=False, ttl=None)


async def fake_resolver(ip: str) -> str | None:
    return None


def make_engine_factory(
    *,
    pinger=fake_ping_alive,  # type: ignore[no-untyped-def]
    neighbors: dict[str, Neighbor] | None = None,
    gate: threading.Event | None = None,
) -> Callable[[EngineConfig, threading.Event], ScanEngine]:
    """Real ScanEngine (real TCP probes), with ICMP/ARP/DNS replaced for determinism.

    ``gate``: when given, every ping waits until the gate is opened (keeps a job running).
    """

    async def gated_ping(ip: str, timeout_ms: int) -> PingResult:
        import asyncio

        while gate is not None and not gate.is_set():
            await asyncio.sleep(0.05)
        return await pinger(ip, timeout_ms)

    def factory(cfg: EngineConfig, cancel: threading.Event) -> ScanEngine:
        return ScanEngine(
            cfg, cancel, pinger=gated_ping, resolver=fake_resolver,
            neighbor_reader=lambda: dict(neighbors or {}), netbios_query=None, ssdp_discover=None,
        )

    return factory


@pytest.fixture
def make_client(settings: Settings, db: Database) -> Iterator[Callable[..., TestClient]]:
    clients: list[TestClient] = []

    def _make(engine_factory=None, settings_override: Settings | None = None) -> TestClient:  # type: ignore[no-untyped-def]
        app = create_app(settings_override or settings, engine_factory=engine_factory or make_engine_factory())
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield _make
    for c in clients:
        c.__exit__(None, None, None)

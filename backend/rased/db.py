"""Database engine / session management."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


class Database:
    """Owns the SQLAlchemy engine and session factory.

    PostgreSQL is the supported production database. SQLite is accepted only for
    development and the automated test-suite.
    """

    def __init__(self, url: str, pool_size: int = 10, max_overflow: int = 5) -> None:
        self.url = url
        if _is_sqlite(url):
            self.engine: Engine = create_engine(
                url, connect_args={"check_same_thread": False, "timeout": 30}
            )

            @event.listens_for(self.engine, "connect")
            def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA busy_timeout=30000")
                cur.close()
        else:
            self.engine = create_engine(
                url,
                pool_size=pool_size,
                max_overflow=max_overflow,
                pool_pre_ping=True,
                pool_recycle=1800,
            )
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

    @property
    def is_sqlite(self) -> bool:
        return _is_sqlite(self.url)

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Transactional scope: commits on success, rolls back on any exception."""
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:
        self.engine.dispose()

"""SQLAlchemy engine/session for the metadata database (PostgreSQL 16 in production)."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

_connect_args = {}
if settings.database_url.startswith("sqlite"):
    # Needed so FastAPI's threadpool and the workers can share a dev SQLite file.
    _connect_args["check_same_thread"] = False

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    connect_args=_connect_args or {},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency: one session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables. In production prefer Alembic migrations; create_all keeps first start easy."""
    from . import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(engine)

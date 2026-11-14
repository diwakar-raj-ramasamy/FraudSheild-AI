import time
from contextlib import contextmanager
from sqlalchemy import create_engine, text, event
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

connect_args = {}
engine_kwargs = {
    "echo": False,
    "pool_pre_ping": True  # Tests connections before using them; prevents dropped connection errors
}

if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 30  # 30 second busy timeout for concurrent threads
    engine_kwargs["connect_args"] = connect_args
elif settings.DATABASE_URL.startswith("postgresql"):
    # Production-ready PostgreSQL connection pooling
    engine_kwargs.update({
        "pool_size": 20,
        "max_overflow": 10,
        "pool_timeout": 30,
        "pool_recycle": 1800,
    })

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)

if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        """Enforces relational foreign keys, WAL concurrency, and fast normal synchrony on SQLite connections."""
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """FastAPI dependency for request-scoped database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@contextmanager
def transaction_scope():
    """
    Transactional context manager ensuring atomic multi-operation persistence
    with automatic rollback on failure and guaranteed session cleanup.
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

def check_database_health() -> dict:
    """
    Executes a lightweight query (SELECT 1) and PRAGMA integrity checks
    to verify database responsiveness, integrity, and schema safety.
    Returns latency and health status for /health/ready endpoint.
    """
    start = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            integrity_status = "ok"
            if engine.dialect.name == "sqlite":
                res = conn.execute(text("PRAGMA integrity_check")).fetchone()
                if res and res[0] != "ok":
                    integrity_status = res[0]
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "status": "healthy" if integrity_status == "ok" else "degraded",
            "latency_ms": latency_ms,
            "dialect": engine.dialect.name,
            "integrity": integrity_status
        }
    except Exception as ex:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "status": "unhealthy",
            "latency_ms": latency_ms,
            "error": str(ex)
        }

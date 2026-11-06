import time
from contextlib import contextmanager
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

connect_args = {}
engine_kwargs = {
    "echo": False,
    "pool_pre_ping": True  # Tests connections before using them; prevents dropped connection errors
}

if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
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
    Executes a lightweight query (SELECT 1) to verify database responsiveness.
    Returns latency and health status for /health/ready endpoint.
    """
    start = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "status": "healthy",
            "latency_ms": latency_ms,
            "dialect": engine.dialect.name
        }
    except Exception as ex:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "status": "unhealthy",
            "latency_ms": latency_ms,
            "error": str(ex)
        }

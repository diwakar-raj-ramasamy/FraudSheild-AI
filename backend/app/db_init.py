"""
FraudShield AI - Database Schema and Core Accounts Initializer
Initializes database tables, administrative accounts, and baseline metadata.
Contains ZERO synthetic/mock/dummy data.
"""

import sys
from pathlib import Path

# Add backend directory to sys.path if not present
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from sqlalchemy.orm import Session
from app.core.database import engine, Base, SessionLocal
from app.core.security import get_password_hash
from app.models import User, BlocklistMeta

def init_db():
    print("Creating all database tables...")
    Base.metadata.create_all(bind=engine)

    db: Session = SessionLocal()
    try:
        # 1. Ensure Default Admin User exists
        admin_email = "admin@fraudshield.ai"
        existing_admin = db.query(User).filter(User.email == admin_email).first()
        if not existing_admin:
            admin_user = User(
                email=admin_email,
                hashed_password=get_password_hash("Admin@FraudShield2026!"),
                full_name="Chief Security Officer (FraudShield Admin)",
                role="admin",
                is_active=True
            )
            db.add(admin_user)
            print(f"Created default admin account: {admin_email}")
        else:
            print(f"Verified admin account exists: {admin_email}")

        # 2. Ensure Security Analyst User exists
        analyst_email = "analyst@fraudshield.ai"
        existing_analyst = db.query(User).filter(User.email == analyst_email).first()
        if not existing_analyst:
            analyst_user = User(
                email=analyst_email,
                hashed_password=get_password_hash("Analyst@FraudShield2026!"),
                full_name="Security Operations Analyst",
                role="analyst",
                is_active=True
            )
            db.add(analyst_user)
            print(f"Created default analyst account: {analyst_email}")
        else:
            print(f"Verified analyst account exists: {analyst_email}")

        # 3. Initialize Blocklist Metadata (Version 1)
        meta = db.query(BlocklistMeta).first()
        if not meta:
            meta = BlocklistMeta(current_version=1)
            db.add(meta)
            print("Initialized Blocklist metadata to version 1.")
        else:
            print(f"Verified Blocklist metadata at version {meta.current_version}.")

        db.commit()
        print("Database schema and core administrative accounts initialized successfully (Zero Mock Data).")
    except Exception as e:
        db.rollback()
        print(f"Database initialization error: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    init_db()

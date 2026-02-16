from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from pathlib import Path

# Main database for login events and user baselines
DB_PATH = Path(__file__).resolve().parent / "rba.db"

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Separate database for audit logs
AUDIT_DB_PATH = Path(__file__).resolve().parent / "audit.db"

audit_engine = create_engine(f"sqlite:///{AUDIT_DB_PATH}", connect_args={"check_same_thread": False})
AuditSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=audit_engine)
AuditBase = declarative_base()
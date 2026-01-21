import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from risk_engine.db.cookie_model import Base

@pytest.fixture()
def engine():
    eng = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        future=True,
    )
    Base.metadata.create_all(eng)
    return eng

@pytest.fixture()
def db_session(engine):
    SessionLocal = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
        future=True
    )
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



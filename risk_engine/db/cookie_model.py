from sqlalchemy import Column, String, Integer, DateTime, UniqueConstraint
from risk_engine.db.db_setup import Base



class DeviceToken(Base):
    __tablename__ = "device_cookie"

    id = Column(Integer, primary_key=True)

    token_hash = Column(String, nullable=False, unique=True, index=True)

    bound_user_id = Column(String, nullable=False, index=True)
    bound_device_id = Column(String, nullable=False, index=True)

    issued_at_utc = Column(DateTime(timezone=True), nullable=False)
    expires_at_utc = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint("bound_user_id", "bound_device_id", "revoked", name="uq_user_device_active"),
    )

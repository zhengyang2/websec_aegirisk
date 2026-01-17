from sqlalchemy import Column, String, Integer, DateTime
from .db_setup import Base


class DeviceToken(Base):
    __tablename__ = "device_cookie"

    token_hash = Column(String, primary_key=True, index=True)
    bound_device_id = Column(String, index=True, nullable=True)
    bound_user_id = Column(String, index=True, nullable=True)
    issued_at_utc = Column(DateTime(timezone=True), nullable=False)
    expires_at_utc = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Integer, default=0, nullable=False)



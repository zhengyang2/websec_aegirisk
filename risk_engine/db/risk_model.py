from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime

from risk_engine.db.db_setup import Base

class LoginEvent(Base):
    __tablename__ = "login_events"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String, index=True, nullable=False)
    event_time_utc = Column(DateTime, nullable=False, default=datetime.utcnow)

    ip = Column(String, nullable=True)
    ip_prefix = Column(String, index=True, nullable=True)      # e.g., "1.2.3"
    user_agent = Column(Text, nullable=True)
    device_token = Column(String, index=True, nullable=True)   # from web app

    decision = Column(String, nullable=False)                  # allow/challenge/block
    score = Column(Integer, nullable=False, default=0)
    reasons = Column(Text, nullable=True)                      # JSON string or comma list


class UserBaseline(Base):
    __tablename__ = "user_baseline"

    username = Column(String, primary_key=True, index=True)

    known_device_tokens = Column(Text, nullable=True)  # JSON string: ["tok1","tok2"]
    known_ip_prefixes = Column(Text, nullable=True)    # JSON string: ["1.2.3","5.6.7"]

    # optional simple baseline: typical hours as JSON list
    typical_login_hours = Column(Text, nullable=True)  # e.g. "[8,9,10,20]"

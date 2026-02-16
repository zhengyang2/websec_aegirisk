"""Audit logging model for tracking admin actions."""
from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime

from risk_engine.db.db_setup import AuditBase


class AuditLog(AuditBase):
    """Track all admin activity for security auditing."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    
    # When
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # What action
    action = Column(String, nullable=False, index=True)  # login, logout, config_update, etc.
    resource = Column(String, nullable=True)  # What was affected (e.g., "risk_config", "session")
    
    # Status
    status = Column(String, nullable=False)  # success, failure, error
    
    # Details
    details = Column(Text, nullable=True)  # JSON string with additional context
    error_message = Column(Text, nullable=True)  # If status is failure/error

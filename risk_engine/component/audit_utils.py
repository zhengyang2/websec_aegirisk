"""Audit logging utilities for tracking admin actions."""
from sqlalchemy.orm import Session
from fastapi import Request
from datetime import datetime
import json
from typing import Optional, Dict, Any

from risk_engine.db.audit_model import AuditLog
from risk_engine.db.db_setup import AuditSessionLocal


def log_audit_event(
    action: str,
    request: Request,
    status: str = "success",
    resource: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    error_message: Optional[str] = None
) -> None:
    """
    Log an audit event to the database.
    
    Args:
        action: The action performed (e.g., 'login', 'logout', 'config_update')
        request: The FastAPI request object
        status: 'success', 'failure', or 'error'
        resource: What was affected (e.g., 'risk_config', 'session')
        details: Additional context as a dictionary (will be JSON serialized)
        error_message: Error description if status is failure/error
    """
    db = AuditSessionLocal()
    try:
        audit_entry = AuditLog(
            timestamp=datetime.utcnow(),
            action=action,
            resource=resource,
            status=status,
            details=json.dumps(details) if details else None,
            error_message=error_message
        )
        
        db.add(audit_entry)
        db.commit()
    except Exception as e:
        # Don't let audit logging failures break the application
        # But we should at least try to rollback
        try:
            db.rollback()
        except:
            pass
        # In production, you might want to log this to a file or monitoring system
        print(f"Failed to write audit log: {e}")
    finally:
        db.close()


def log_login_attempt(request: Request, success: bool, reason: Optional[str] = None) -> None:
    """Log an admin login attempt."""
    log_audit_event(
        action="admin_login",
        request=request,
        status="success" if success else "failure",
        resource="admin_session",
        details={"success": success},
        error_message=reason if not success else None
    )


def log_logout(request: Request) -> None:
    """Log an admin logout."""
    log_audit_event(
        action="admin_logout",
        request=request,
        status="success",
        resource="admin_session"
    )


def log_config_change(
    request: Request,
    old_config: Dict[str, Any],
    new_config: Dict[str, Any],
    success: bool = True,
    error_message: Optional[str] = None
) -> None:
    """Log a risk configuration change."""
    # Calculate what changed
    changes = {}
    for key in new_config:
        if key in old_config and old_config[key] != new_config[key]:
            changes[key] = {
                "old": old_config[key],
                "new": new_config[key]
            }
    
    log_audit_event(
        action="config_update",
        request=request,
        status="success" if success else "failure",
        resource="risk_config",
        details={"changes": changes},
        error_message=error_message
    )

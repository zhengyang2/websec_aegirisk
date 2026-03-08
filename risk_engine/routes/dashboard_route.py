from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, Any
import json
import os
import time
from datetime import datetime

import hmac
from risk_engine.db.risk_model import LoginEvent
from risk_engine.dependancy import get_db, get_audit_db, require_admin, _is_api_key_valid, is_admin_session_active
from risk_engine.component.risk_utils import load_risk_config, reload_risk_config
from risk_engine.component.csrf_utils import get_csrf_token, verify_csrf_token
from risk_engine.component.audit_utils import log_login_attempt, log_logout, log_config_change
from risk_engine.component.validation_utils import (
    validate_api_key,
    validate_risk_score,
    validate_threshold,
    validate_speed,
    validate_distance,
    validate_time_window,
    validate_percentage,
    validate_positive_integer,
    validate_hour,
    validate_hour_list
)
from risk_engine import config

dashboard_router = APIRouter(
    prefix="/admin",
    tags=["dashboard"],
)

templates = Jinja2Templates(directory="risk_engine/templates")

ADMIN_LOGIN_MAX_ATTEMPTS = int(os.getenv("RISK_ENGINE_ADMIN_LOGIN_MAX_ATTEMPTS", "5"))
ADMIN_LOGIN_WINDOW_SEC = int(os.getenv("RISK_ENGINE_ADMIN_LOGIN_WINDOW_SEC", "300"))
ADMIN_LOGIN_LOCKOUT_SEC = int(os.getenv("RISK_ENGINE_ADMIN_LOGIN_LOCKOUT_SEC", "300"))

_LOGIN_ATTEMPTS: dict[str, dict[str, int]] = {}


def _client_key(request: Request) -> str:
    host = request.client.host if request.client else "unknown"
    return host


def _lockout_remaining(key: str) -> int:
    record = _LOGIN_ATTEMPTS.get(key)
    if not record:
        return 0
    lock_until = record.get("lock_until", 0)
    now = int(time.time())
    if lock_until and lock_until > now:
        return lock_until - now
    return 0


def _record_login_failure(key: str) -> None:
    now = int(time.time())
    record = _LOGIN_ATTEMPTS.get(key)
    if not record:
        record = {"failures": 0, "first_ts": now, "lock_until": 0}

    if now - record["first_ts"] > ADMIN_LOGIN_WINDOW_SEC:
        record = {"failures": 0, "first_ts": now, "lock_until": 0}

    record["failures"] += 1
    if record["failures"] >= ADMIN_LOGIN_MAX_ATTEMPTS:
        record["lock_until"] = now + ADMIN_LOGIN_LOCKOUT_SEC

    _LOGIN_ATTEMPTS[key] = record


def _clear_login_failures(key: str) -> None:
    _LOGIN_ATTEMPTS.pop(key, None)


def _has_admin_access(request: Request) -> bool:
    if is_admin_session_active(request):
        return True
    if not config.ENFORCE_API_KEY:
        return True
    try:
        return _is_api_key_valid(
            request.headers.get("x-api-key"),
            request.headers.get("authorization"),
        )
    except HTTPException:
        return False


@dashboard_router.get("")
def admin_root():
    return RedirectResponse(url="/admin/login", status_code=302)

@dashboard_router.get("/login")
def admin_login_form(request: Request):
    key = _client_key(request)
    remaining = _lockout_remaining(key)
    csrf_token = get_csrf_token(request)
    if remaining > 0:
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": f"Too many attempts. Try again in {remaining} seconds.", "csrf_token": csrf_token},
            status_code=429,
        )
    return templates.TemplateResponse(
        "admin_login.html",
        {"request": request, "error": None, "csrf_token": csrf_token},
    )


@dashboard_router.post("/login")
def admin_login(request: Request, api_key: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    key = _client_key(request)
    
    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        log_login_attempt(request, success=False, reason="Invalid CSRF token")
        error_message = "Invalid security token. Please try again."
        if "missing from session" in str(e.detail).lower():
            error_message = "Security session expired. Please refresh and try again."
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": error_message, "csrf_token": get_csrf_token(request)},
            status_code=403,
        )

    csrf_session_token = request.session.get("csrf_token") or get_csrf_token(request)
    
    remaining = _lockout_remaining(key)
    if remaining > 0:
        log_login_attempt(request, success=False, reason=f"Rate limited ({remaining}s remaining)")
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": f"Too many attempts. Try again in {remaining} seconds.", "csrf_token": csrf_session_token},
            status_code=429,
        )

    # Validate API key format
    try:
        validate_api_key(api_key)
    except HTTPException:
        _record_login_failure(key)
        log_login_attempt(request, success=False, reason="Invalid API key format")
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": "Invalid credentials.", "csrf_token": csrf_session_token},
            status_code=401,
        )

    # use engine key, not risk config
    from risk_engine import config
    expected_key = config.get_engine_api_key()

    if not expected_key or not hmac.compare_digest(api_key.strip(), expected_key):
        _record_login_failure(key)
        log_login_attempt(request, success=False, reason="Invalid credentials")
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": "Invalid credentials.", "csrf_token": csrf_session_token},
            status_code=401,
        )

    # Regenerate session to prevent session fixation attacks
    old_csrf = request.session.get("csrf_token")
    request.session.clear()
    if old_csrf:
        request.session["csrf_token"] = old_csrf  # Preserve CSRF token
    
    request.session["admin_auth"] = True
    request.session["admin_last_seen"] = int(time.time())
    _clear_login_failures(key)
    log_login_attempt(request, success=True)
    return RedirectResponse(url="/admin/dashboard", status_code=303)


@dashboard_router.post("/logout")
def admin_logout(request: Request, csrf_token: str = Form(...)):
    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    
    log_logout(request)
    request.session.pop("admin_auth", None)
    request.session.pop("admin_last_seen", None)
    return RedirectResponse(url="/admin/login", status_code=303)


@dashboard_router.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)):
    if not _has_admin_access(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    raw_events = (
    db.query(LoginEvent)
    .order_by(LoginEvent.event_time_utc.desc())
    .limit(500)
    .all()
    )

    events = [
        {
            "username": e.username,
            "event_time_utc": e.event_time_utc.isoformat(),
            "ip": e.ip,
            "ip_prefix": e.ip_prefix,
            "user_agent": e.user_agent,
            "device_token": e.device_token,
            "decision": e.decision,
            "score": e.score,
            "reasons": e.reasons,
        }
        for e in raw_events
    ]
    
    # Check if viewing old data (before last config change)
    show_config_warning = False
    config_change_date = None
    try:
        state_path = os.path.join(os.path.dirname(__file__), '..', 'engine_state.json')
        if os.path.exists(state_path):
            with open(state_path, 'r') as f:
                state = json.load(f)
                last_config_change = state.get('last_config_change')
                if last_config_change and raw_events:
                    config_change_dt = datetime.fromisoformat(last_config_change)
                    oldest_event = raw_events[-1]
                    if oldest_event.event_time_utc < config_change_dt:
                        show_config_warning = True
                        config_change_date = config_change_dt.strftime('%Y-%m-%d %H:%M UTC')
    except Exception:
        pass

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "events": events,
            "show_config_warning": show_config_warning,
            "config_change_date": config_change_date,
            "csrf_token": get_csrf_token(request)
        }
    )


@dashboard_router.get("/config-page")
def config_page(request: Request, db: Session = Depends(get_db)):
    """Render the risk configuration editor page."""
    if not _has_admin_access(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    return templates.TemplateResponse(
        "config.html",
        {
            "request": request,
            "csrf_token": get_csrf_token(request)
        }
    )


class RiskConfigUpdate(BaseModel):
    risk_scores: Dict[str, int]
    decision_thresholds: Dict[str, int]
    rate_limit: Dict[str, Any]
    baseline: Dict[str, Any]


@dashboard_router.get("/config")
def get_risk_config_redirect(request: Request, db: Session = Depends(get_db)):
    if not is_admin_session_active(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    config = load_risk_config()
    return JSONResponse(content=config)


@dashboard_router.post("/config/read")
def get_risk_config(request: Request, db: Session = Depends(get_db), _=Depends(require_admin)):
    """Get current risk scoring configuration (session-required)."""
    # Verify CSRF token from header
    csrf_token = request.headers.get("X-CSRF-Token")
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    
    config = load_risk_config()
    return JSONResponse(content=config)


@dashboard_router.post("/config/reload")
def reload_config(request: Request, _=Depends(require_admin)):
    """Reload risk configuration from JSON file (clears cache)."""
    # Verify CSRF token from header
    csrf_token = request.headers.get("X-CSRF-Token")
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    
    reload_risk_config()
    config = load_risk_config()
    
    return JSONResponse(content={
        "status": "success",
        "message": "Configuration reloaded from risk_config.json",
        "config": config
    })


@dashboard_router.post("/config")
def update_risk_config(request: Request, config_update: RiskConfigUpdate, db: Session = Depends(get_db), _=Depends(require_admin)):
    """Update risk scoring configuration."""
    # Verify CSRF token from header
    csrf_token = request.headers.get("X-CSRF-Token")
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    
    try:
        # Validate all config values
        for key, value in config_update.risk_scores.items():
            validate_risk_score(value, f"risk_scores.{key}")
        
        for key, value in config_update.decision_thresholds.items():
            validate_threshold(value, f"decision_thresholds.{key}")
        
        # Validate rate_limit config
        if "window_seconds" in config_update.rate_limit:
            validate_positive_integer(
                config_update.rate_limit["window_seconds"],
                "rate_limit.window_seconds",
                min_val=1,
                max_val=3600
            )
        if "thresholds" in config_update.rate_limit:
            thresholds = config_update.rate_limit["thresholds"]
            if not isinstance(thresholds, list):
                raise HTTPException(
                    status_code=400,
                    detail="rate_limit.thresholds must be a list"
                )
            for idx, threshold in enumerate(thresholds):
                if not isinstance(threshold, dict):
                    raise HTTPException(
                        status_code=400,
                        detail=f"rate_limit.thresholds[{idx}] must be an object"
                    )
                if "attempts" in threshold:
                    validate_positive_integer(
                        threshold["attempts"],
                        f"rate_limit.thresholds[{idx}].attempts",
                        min_val=1,
                        max_val=1000
                    )
                if "score" in threshold:
                    validate_risk_score(
                        threshold["score"],
                        f"rate_limit.thresholds[{idx}].score"
                    )
        
        # Validate baseline config
        if "typical_hours_minimum_events" in config_update.baseline:
            validate_positive_integer(
                config_update.baseline["typical_hours_minimum_events"],
                "baseline.typical_hours_minimum_events",
                min_val=1,
                max_val=1000
            )
        if "typical_hours_percentage_threshold" in config_update.baseline:
            validate_percentage(
                config_update.baseline["typical_hours_percentage_threshold"],
                "baseline.typical_hours_percentage_threshold"
            )
        if "typical_hours_default" in config_update.baseline:
            validate_hour_list(
                config_update.baseline["typical_hours_default"],
                "baseline.typical_hours_default"
            )
        if "recalculation_frequency" in config_update.baseline:
            validate_positive_integer(
                config_update.baseline["recalculation_frequency"],
                "baseline.recalculation_frequency",
                min_val=1,
                max_val=1000
            )
        if "event_limit" in config_update.baseline:
            validate_positive_integer(
                config_update.baseline["event_limit"],
                "baseline.event_limit",
                min_val=10,
                max_val=10000
            )
        if "typical_hours_start" in config_update.baseline:
            validate_hour(
                config_update.baseline["typical_hours_start"],
                "baseline.typical_hours_start"
            )
        if "typical_hours_end" in config_update.baseline:
            validate_hour(
                config_update.baseline["typical_hours_end"],
                "baseline.typical_hours_end"
            )
            # Validate that end hour can be >= start hour (handles wraparound case like 22-6)
            if "typical_hours_start" in config_update.baseline:
                start = config_update.baseline["typical_hours_start"]
                end = config_update.baseline["typical_hours_end"]
                if start == end:
                    raise HTTPException(
                        status_code=400,
                        detail="Typical hours start and end cannot be the same (would match no hours)"
                    )
        
        config_path = os.path.join(os.path.dirname(__file__), '..', 'risk_config.json')
        
        # Load old config for audit trail
        old_config = load_risk_config()
        
        # Convert Pydantic model to dict
        new_config = config_update.model_dump()
        
        # Preserve impossible_travel settings from old config (not exposed in UI)
        if "impossible_travel" in old_config:
            new_config["impossible_travel"] = old_config["impossible_travel"]
        
        # Preserve legacy baseline fields if they exist (not exposed in UI)
        if "baseline" in old_config:
            if "typical_hours_percentage_threshold" in old_config["baseline"]:
                new_config["baseline"]["typical_hours_percentage_threshold"] = old_config["baseline"]["typical_hours_percentage_threshold"]
            if "typical_hours_default" in old_config["baseline"]:
                new_config["baseline"]["typical_hours_default"] = old_config["baseline"]["typical_hours_default"]
        
        # Write to file
        with open(config_path, 'w') as f:
            json.dump(new_config, f, indent=2)
        
        # Record config change timestamp
        state_path = os.path.join(os.path.dirname(__file__), '..', 'engine_state.json')
        if os.path.exists(state_path):
            with open(state_path, 'r') as f:
                state = json.load(f)
            state['last_config_change'] = datetime.utcnow().isoformat()
            with open(state_path, 'w') as f:
                json.dump(state, f, indent=2)
        
        # Reload config cache
        reload_risk_config()
        
        # Log the config change
        log_config_change(request, old_config, new_config, success=True)
        
        return JSONResponse(content={
            "status": "success",
            "message": "Risk configuration updated successfully",
            "config": new_config
        })
    except Exception as e:
        # Log the failure
        try:
            old_config = load_risk_config()
            new_config = config_update.model_dump()
            log_config_change(request, old_config, new_config, success=False, error_message=str(e))
        except:
            pass  # Don't let audit logging break error handling
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {str(e)}")


@dashboard_router.get("/audit-logs")
def audit_logs_page(request: Request, audit_db: Session = Depends(get_audit_db)):
    """View audit logs."""
    if not _has_admin_access(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    
    from risk_engine.db.audit_model import AuditLog
    
    # Get recent audit logs
    logs = (
        audit_db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(500)
        .all()
    )
    
    log_entries = [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "action": log.action,
            "resource": log.resource,
            "status": log.status,
            "details": log.details,
            "error_message": log.error_message
        }
        for log in logs
    ]
    
    return templates.TemplateResponse(
        "audit_logs.html",
        {
            "request": request,
            "logs": log_entries,
            "csrf_token": get_csrf_token(request)
        }
    )

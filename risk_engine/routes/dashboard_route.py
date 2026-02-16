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

from risk_engine.db.risk_model import LoginEvent
from risk_engine.dependancy import get_db, require_admin, _is_api_key_valid, is_admin_session_active
from risk_engine.component.risk_utils import load_risk_config, reload_risk_config
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
    if remaining > 0:
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": f"Too many attempts. Try again in {remaining} seconds."},
            status_code=429,
        )
    return templates.TemplateResponse(
        "admin_login.html",
        {"request": request, "error": None},
    )


@dashboard_router.post("/login")
def admin_login(request: Request, api_key: str = Form(...)):
    key = _client_key(request)
    remaining = _lockout_remaining(key)
    if remaining > 0:
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": f"Too many attempts. Try again in {remaining} seconds."},
            status_code=429,
        )

    # use engine key, not risk config
    from risk_engine import config
    expected_key = config.get_engine_api_key()

    if not expected_key or api_key != expected_key:
        _record_login_failure(key)
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": "Invalid API key."},
            status_code=401,
        )

    request.session["admin_auth"] = True
    request.session["admin_last_seen"] = int(time.time())
    _clear_login_failures(key)
    return RedirectResponse(url="/admin/dashboard", status_code=303)


@dashboard_router.post("/logout")
def admin_logout(request: Request):
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
            "config_change_date": config_change_date
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
        }
    )


class RiskConfigUpdate(BaseModel):
    risk_scores: Dict[str, int]
    decision_thresholds: Dict[str, int]
    impossible_travel: Dict[str, float]
    baseline: Dict[str, Any]


@dashboard_router.get("/config")
def get_risk_config_redirect(request: Request, db: Session = Depends(get_db)):
    if not is_admin_session_active(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    config = load_risk_config()
    return JSONResponse(content=config)


@dashboard_router.post("/config/read")
def get_risk_config(db: Session = Depends(get_db), _=Depends(require_admin)):
    """Get current risk scoring configuration (session-required)."""
    config = load_risk_config()
    return JSONResponse(content=config)


@dashboard_router.post("/config")
def update_risk_config(config_update: RiskConfigUpdate, db: Session = Depends(get_db), _=Depends(require_admin)):
    """Update risk scoring configuration."""
    try:
        config_path = os.path.join(os.path.dirname(__file__), '..', 'risk_config.json')
        
        # Convert Pydantic model to dict
        new_config = config_update.model_dump()
        
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
        
        return JSONResponse(content={
            "status": "success",
            "message": "Risk configuration updated successfully",
            "config": new_config
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {str(e)}")

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
import secrets
import os
from pathlib import Path

# db import
from risk_engine.db.db_setup import Base, engine, AuditBase, audit_engine

# ensure models are registered with Base before create_all
from risk_engine.db import cookie_model
from risk_engine.db import risk_model
from risk_engine.db import audit_model

#routes imports
from risk_engine.routes.cookie_route import cookie_router
from risk_engine.routes.risk_route import risk_router
from risk_engine.routes.dashboard_route import dashboard_router

from risk_engine.config import ENV_PATH
#component import
from risk_engine import config
from risk_engine.component.risk_utils import reload_risk_config, load_risk_config
from risk_engine.dependancy import require_api_key


app = FastAPI(title="RBA Risk Engine")

app.add_middleware(
    SessionMiddleware,
    secret_key="aegirisk-demo-session-key-2026",
    https_only=os.getenv("RISK_ENGINE_HTTPS_ONLY", "false").lower() == "true",
    max_age=int(os.getenv("RISK_ENGINE_ADMIN_SESSION_TIMEOUT_SEC", "900")),
    same_site="strict",  # CSRF protection via cookie policy
    session_cookie="risk_engine_admin_session",
)

# Mount static files for dashboard CSS/JS
app.mount("/static", StaticFiles(directory="risk_engine/static"), name="static")

app.include_router(cookie_router)
app.include_router(risk_router)
app.include_router(dashboard_router)



@app.on_event("startup")
def init_db():
    Base.metadata.create_all(bind=engine)
    AuditBase.metadata.create_all(bind=audit_engine)

@app.get("/")
def read_root():
    return RedirectResponse(url="/admin/login", status_code=302)



@app.post("/setup")
def setup():
    try:
        if config.is_sealed():
            raise HTTPException(status_code=410, detail="Already initialized")
    except RuntimeError:
        # State exists but is corrupt: fail closed
        raise HTTPException(status_code=500, detail="Engine misconfigured")

    api_key = secrets.token_urlsafe(32)

    try:
        config.write_engine_state_atomically(api_key)
    except FileExistsError:
        # If you implement locking via O_EXCL and it already exists
        raise HTTPException(status_code=410, detail="Already initialized")
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to initialize")

    return {"api_key": api_key}

@app.post("/config/reload")
def reload_config_endpoint(_=Depends(require_api_key)):
    """Reload risk configuration from JSON file. Requires API key."""
    reload_risk_config()
    current_config = load_risk_config()
    return {
        "status": "success",
        "message": "Configuration reloaded from risk_config.json",
        "config": current_config
    }

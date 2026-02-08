from fastapi import FastAPI, HTTPException
import secrets
import os
from pathlib import Path

# db import
from risk_engine.db.db_setup import Base, engine

# ensure models are registered with Base before create_all
from risk_engine.db import cookie_model
from risk_engine.db import risk_model

#routes imports
from risk_engine.routes.cookie_route import cookie_router
from risk_engine.routes.risk_route import risk_router
from risk_engine.routes.dashboard_route import dashboard_router

from risk_engine.config import ENV_PATH
#component import
from risk_engine import config


app = FastAPI(title="RBA Risk Engine")
app.include_router(cookie_router)
app.include_router(risk_router)
app.include_router(dashboard_router)



@app.on_event("startup")
def init_db():
    Base.metadata.create_all(bind=engine)

@app.get("/")
def read_root():

    return {"Hello": "World"}



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
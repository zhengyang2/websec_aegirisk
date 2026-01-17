from fastapi import FastAPI, Response, Header, HTTPException
import httpx
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta, timezone




RISK_ENGINE = FastAPI(title="RBA Risk Engine")

# use to check when web app call that it is secure
ENGINE_API_KEY = "change-me"


DB_PATH = "db/rba.db"
COOKIE_NAME = "__Host_rba_dt"
TOKEN_TTL_DAYS = 180

# used to secure RBA API. verify when API called is it the web app
#
def require_api_key(x_api_key: str | None):
    if ENGINE_API_KEY and x_api_key != ENGINE_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")


@RISK_ENGINE.get("/")
def read_root():
    return {"Hello": "World"}

@RISK_ENGINE.post("/device/generate")
def generate():
    return {"generate"}
    pass


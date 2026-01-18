from fastapi import FastAPI, Response, Header, HTTPException, Depends
import httpx
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

# db import
from db.db_setup import Base, engine, SessionLocal
from db.cookie_model import DeviceToken

#component import
from device_cookie import generate_device_token
from json_schema import GenerateCookieRequestJSON


RISK_ENGINE = FastAPI(title="RBA Risk Engine")

# use to check when web app call that it is secure
ENFORCE_API_KEY_FLAG = 0
ENGINE_API_KEY = "change-me"



DB_PATH = "db/rba.db"

@RISK_ENGINE.on_event("startup")
def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# used to secure RBA API. verify when API called is it the web app
def require_api_key(x_api_key: str | None):
    if ENFORCE_API_KEY_FLAG == 1:
        if ENGINE_API_KEY and x_api_key != ENGINE_API_KEY:
            raise HTTPException(status_code=401, detail="Unauthorized")


@RISK_ENGINE.get("/")
def read_root():
    require_api_key("replace")
    return {"Hello": "World"}




# cookies API
@RISK_ENGINE.post("/device/generate")
def generate(request: GenerateCookieRequestJSON, db: Session = Depends(get_db)):
    require_api_key("replace")

    raw_token, exp_date, cookie_name = generate_device_token(db, request.user_id, request.device_id)

    return {
        "cookie_name": cookie_name,
        "cookie_value": raw_token,
        "expires_at_utc": exp_date.isoformat()
        }


#TODO: make rotate cookie api

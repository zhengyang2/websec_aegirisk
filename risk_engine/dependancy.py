from risk_engine.db.db_setup import SessionLocal
from fastapi import Header, HTTPException

from risk_engine.config import ENFORCE_API_KEY_FLAG, ENGINE_API_KEY
# use to check when web app call that it is secure




def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()




# used to secure RBA API. verify when API called is it the web app

def require_api_key(x_api_key: str | None  = Header(default=None)):
    if ENFORCE_API_KEY_FLAG == 1:
        if ENGINE_API_KEY and x_api_key != ENGINE_API_KEY:
            raise HTTPException(status_code=401, detail="Unauthorized / Missing API Key")

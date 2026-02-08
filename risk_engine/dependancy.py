from risk_engine.db.db_setup import SessionLocal
from fastapi import Header, HTTPException, status
import hmac
from risk_engine import config
# use to check when web app call that it is secure




def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()




# used to secure RBA API. verify when API called is it the web app

def require_api_key(x_api_key: str | None  = Header(default=None)):

    if config.ENFORCE_API_KEY:


        expected = config.get_engine_api_key()

        if not expected:
            # Engine is misconfigured or not initialized
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="API key not configured",
            )

        if not x_api_key or not hmac.compare_digest(x_api_key, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized / Missing API Key",
            )


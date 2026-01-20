from fastapi import Depends, APIRouter
from sqlalchemy.orm import Session

from risk_engine.dependancy import get_db, require_api_key
from risk_engine.device_cookie import generate_device_token
from risk_engine.json_schema import GenerateCookieRequestJSON


cookie_router = APIRouter( prefix="/cookie",
                        tags=["cookie"],
                        dependencies=[Depends(require_api_key)])




# cookies API
@cookie_router.post("/generate")
def generate(request: GenerateCookieRequestJSON, db: Session = Depends(get_db)):

    raw_token, exp_date, cookie_name = generate_device_token(db, request.user_id, request.device_id)

    return {
        "cookie_name": cookie_name,
        "cookie_value": raw_token,
        "expires_at_utc": exp_date.isoformat()
        }


#TODO: make rotate cookie api


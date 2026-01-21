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

    result = generate_device_token(db,
                                   user = request.user_id,
                                   device = request.device_id,
                                   force_rotate = request.force_rotate)

    return result

#TODO: make rotate cookie api


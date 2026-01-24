import json
from datetime import datetime
from fastapi import Depends, APIRouter
from sqlalchemy.orm import Session

from risk_engine.dependancy import get_db, require_api_key
from risk_engine.json_schema import RiskEvaluateRequestJSON, RiskEvaluateResponseJSON
from risk_engine.db.risk_model import LoginEvent
from risk_engine.component.risk_utils import score_login, update_baseline_on_success

risk_router = APIRouter(
    prefix="/risk",
    tags=["risk"],
    dependencies=[Depends(require_api_key)]
)

@risk_router.post("/evaluate", response_model=RiskEvaluateResponseJSON)
def evaluate(request: RiskEvaluateRequestJSON, db: Session = Depends(get_db)):
    # parse event_time_utc if given, else use now
    try:
        event_time = datetime.fromisoformat(request.event_time_utc.replace("Z", "+00:00")) if request.event_time_utc else datetime.utcnow()
    except Exception:
        event_time = datetime.utcnow()

    score, reasons, decision, ip_prefix = score_login(
        db=db,
        username=request.username,
        ip=request.ip,
        user_agent=request.user_agent,
        device_token=request.device_token
    )

    # store the event (always)
    evt = LoginEvent(
        username=request.username,
        event_time_utc=event_time,
        ip=request.ip,
        ip_prefix=ip_prefix,
        user_agent=request.user_agent,
        device_token=request.device_token,
        decision=decision,
        score=score,
        reasons=json.dumps(reasons)
    )
    db.add(evt)
    db.commit()

    # for MVP baseline: if decision isn't block, treat as "successful enough" to learn
    # (later: only learn after web confirms password_ok / otp_ok)
    if decision != "block":
        update_baseline_on_success(db, request.username, request.device_token, ip_prefix)

    return {"decision": decision, "score": score, "reasons": reasons}

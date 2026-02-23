import json
from datetime import datetime, timedelta
from fastapi import Depends, APIRouter, HTTPException
from sqlalchemy.orm import Session

from risk_engine.dependancy import get_db, require_api_key
from risk_engine.json_schema import RiskEvaluateRequestJSON, RiskEvaluateResponseJSON, RiskAuthResultResponseJSON, \
    RiskAuthResultRequestJSON
from risk_engine.db.risk_model import LoginEvent
from risk_engine.component.risk_utils import score_login, update_baseline_on_success

from risk_engine.config import EVENT_TTL_SECONDS

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
        reasons=json.dumps(reasons),
        status="pending"
    )
    db.add(evt)
    db.commit()
    db.refresh(evt)

    # # for MVP baseline: if decision isn't block, treat as "successful enough" to learn
    # # (later: only learn after web confirms password_ok / otp_ok)
    # if decision != "block":
    #     update_baseline_on_success(db, request.username, request.device_token, ip_prefix)

    return {"event_id": evt.id, "decision": decision, "score": score, "reasons": reasons}



@risk_router.post("/auth-result", response_model=RiskAuthResultResponseJSON)
def authResult(request: RiskAuthResultRequestJSON, db: Session = Depends(get_db)):


    # 1) Load event
    evt = db.query(LoginEvent).filter(LoginEvent.id == request.event_id).first()
    if not evt:
        raise HTTPException(status_code=404, detail="event_id not found")

    # 2) check if login event expired
    event_time = evt.event_time_utc
    now = datetime.now()
    expired = now >= (event_time + timedelta(seconds=EVENT_TTL_SECONDS))

    # convert pending to expired status when past TTL
    if evt.status == "pending" and expired:
        evt.status = "expired"
        db.commit()
        return {
            "event_id": evt.id,
            "status": evt.status,
            "baseline_updated": False,
            "expired": True
        }

    # Already expired
    if evt.status == "expired":
        return {
            "event_id": evt.id,
            "status": evt.status,
            "baseline_updated": False,
            "expired": True
        }

    # Prevent double finalize
    if evt.status in ("confirmed_success", "confirmed_failure"):
        already = "success" if evt.status == "confirmed_success" else "failure"
        if already == request.outcome:
            return {
                "event_id": evt.id,
                "status": evt.status,
                "baseline_updated": False,
                "expired": False
            }
        raise HTTPException(status_code=409, detail="event already finalized")

    # Must be pending
    if evt.status != "pending":
        raise HTTPException(status_code=409, detail="invalid event state")

    baseline_updated = False

    if request.outcome == "success":
        evt.status = "confirmed_success"
        db.commit()

        update_baseline_on_success(
            db=db,
            username=evt.username,
            device_token=evt.device_token,
            ip_prefix=evt.ip_prefix
        )
        db.commit()
        baseline_updated = True

    elif request.outcome == "failure":
        evt.status = "confirmed_failure"
        db.commit()

    else:
        raise HTTPException(status_code=400, detail="invalid outcome")

    return {
        "event_id": evt.id,
        "status": evt.status,
        "baseline_updated": baseline_updated,
        "expired": False
    }

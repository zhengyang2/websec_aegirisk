from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from risk_engine.db.risk_model import LoginEvent
from risk_engine.dependancy import get_db, require_api_key

dashboard_router = APIRouter(
    prefix="/admin",
    tags=["dashboard"],
    dependencies=[Depends(require_api_key)]
)

templates = Jinja2Templates(directory="risk_engine/templates")

@dashboard_router.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)):
    raw_events = (
    db.query(LoginEvent)
    .order_by(LoginEvent.event_time_utc.desc())
    .limit(500)
    .all()
    )

    events = [
        {
            "username": e.username,
            "event_time_utc": e.event_time_utc.isoformat(),
            "ip": e.ip,
            "ip_prefix": e.ip_prefix,
            "user_agent": e.user_agent,
            "device_token": e.device_token,
            "decision": e.decision,
            "score": e.score,
            "reasons": e.reasons,
        }
        for e in raw_events
    ]


    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "events": events
        }
    )

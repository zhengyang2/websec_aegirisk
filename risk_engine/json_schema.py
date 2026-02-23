from pydantic import BaseModel
from typing import TypedDict, Literal, Optional, List


# cookie JSON parameter definition

class GenerateCookieRequestJSON(BaseModel):
    user_id: str
    device_id: str
    force_rotate: bool = False

class DeviceTokenResult(TypedDict):
    case: Literal["first_issue", "risk_rotate", "periodic_rotate", "no_rotate"]
    rotate: bool
    raw_token: Optional[str]
    expires_at_utc: Optional[str]
    cookie_name: str

class RiskEvaluateRequestJSON(BaseModel):
    username: str
    event_time_utc: Optional[str] = None   # ISO string (web already generates this)
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    device_token: Optional[str] = None

class RiskEvaluateResponseJSON(BaseModel):
    event_id: int
    decision: Literal["allow", "challenge", "block"]
    score: int
    reasons: List[str]

class RiskAuthResultRequestJSON(BaseModel):
    event_id: int
    outcome: Literal["success", "failure"]

class RiskAuthResultResponseJSON(BaseModel):
    event_id: int
    status: Literal["expired","confirmed_success","confirmed_failure"]
    baseline_updated: bool
    expired: bool
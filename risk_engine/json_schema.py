from pydantic import BaseModel
from typing import TypedDict, Literal, Optional


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



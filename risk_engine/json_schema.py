from pydantic import BaseModel
from typing import Optional


class GenerateCookieRequestJSON(BaseModel):
    user_id: str
    device_id: str





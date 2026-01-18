import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from db.cookie_model import DeviceToken


COOKIE_NAME = "__Host_rba_dt"
TOKEN_TTL_DAYS = 90


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def generate_device_token(db: Session, user, device) -> tuple[str, datetime, str]:
    """
    Returns (raw_token, expires_at). Stores only hash in DB.
    """

    # gen random token string and hash
    raw_token = secrets.token_urlsafe(32)
    token_hash = sha256_hex(raw_token)

    now = utcnow()
    exp = now + timedelta(days=TOKEN_TTL_DAYS)

    db.add(DeviceToken(
        token_hash=token_hash,
        bound_device_id=device,
        bound_user_id=user,
        issued_at_utc=now,
        expires_at_utc=exp,
        revoked=0
    ))
    db.commit()

    return raw_token, exp , COOKIE_NAME

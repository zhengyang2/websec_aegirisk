import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from sqlalchemy.exc import IntegrityError

from risk_engine.db.cookie_model import DeviceToken


COOKIE_NAME = "__Host_rba_dt"
TOKEN_TTL_DAYS = 90
ROTATE_IF_EXPIRES_WITHIN_DAYS = 7

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def generate_device_token(db: Session, user, device) -> tuple[str, datetime, str]:
    """
    Returns (raw_token, expires_at). Stores only hash in DB.

    case 1st issue

    case periodic rotate near expiry

    case possible risk event rotation

    """

    # check for active token

    active = (
        db.query(DeviceToken)
        .filter(
            DeviceToken.bound_user_id == user,
            DeviceToken.bound_device_id == device,
            DeviceToken.revoked == 0
        )
        .one_or_none()
    )
    print(active)

    # gen random token string and hash
    raw_token = secrets.token_urlsafe(32)
    token_hash = sha256_hex(raw_token)

    now = utcnow()
    exp = now + timedelta(days=TOKEN_TTL_DAYS)
    try:
        # revoke existing active token
        db.query(DeviceToken).filter(
            DeviceToken.bound_user_id == user,
            DeviceToken.bound_device_id == device,
            DeviceToken.revoked == 0
        ).update({"revoked": 1}, synchronize_session=False)

        #
        db.add(DeviceToken(
            token_hash=token_hash,
            bound_device_id=device,
            bound_user_id=user,
            issued_at_utc=now,
            expires_at_utc=exp,
            revoked=0
        ))
        db.commit()

    except IntegrityError:
        db.rollback()

    return raw_token, exp, COOKIE_NAME

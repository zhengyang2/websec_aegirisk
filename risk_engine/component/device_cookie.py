import secrets
import hashlib
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, MultipleResultsFound
from fastapi import HTTPException


from risk_engine.db.cookie_model import DeviceToken
from risk_engine.json_schema import DeviceTokenResult

from risk_engine.config import COOKIE_NAME, TOKEN_TTL_DAYS, EXPIRES_WITHIN_DAYS


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def generate_device_token(db: Session,
                          user: str,
                          device: str,
                          force_rotate: bool = False) -> DeviceTokenResult:
    """
    Returns DeviceTokenResult
    """

    try:
        with db.begin():
            # define result
            result: DeviceTokenResult = {
                "case": "no_rotate",
                "rotate": False,
                "raw_token": None,
                "expires_at_utc": None,
                "cookie_name": COOKIE_NAME,
            }

            now = datetime.utcnow()

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




            # Case 1: First issue (no active token)
            if active is None:
                case = "first_issue"
                should_rotate = True

            # Case 2: Risk-triggered rotation
            elif force_rotate:
                case = "risk_rotate"
                should_rotate = True

            # Case 3: Periodic rotation (near expiry)
            elif (active.expires_at_utc - now) <= timedelta(days=EXPIRES_WITHIN_DAYS):
                case = "periodic_rotate"
                should_rotate = True

            # Case 4: No rotation needed
            else:
                case = "no_rotate"
                should_rotate = False


            if not should_rotate:
                # only edit field that change
                result["case"] = case
                result["expires_at_utc"] = active.expires_at_utc.isoformat()

                return result

            # gen random token string and hash
            raw_token = secrets.token_urlsafe(32)
            token_hash = sha256_hex(raw_token)
            exp = now + timedelta(days=TOKEN_TTL_DAYS)


            # Re-check active
            if active is not None:
                active.revoked = 1


            # insert new row
            db.add(DeviceToken(
                token_hash=token_hash,
                bound_device_id=device,
                bound_user_id=user,
                issued_at_utc=now,
                expires_at_utc=exp,
                revoked=0
            ))

            result["case"] = case
            result["rotate"] = True
            result["raw_token"] = raw_token
            result["expires_at_utc"] = exp.isoformat()

            return result

    except MultipleResultsFound:
        # invariant violation: more than one active token
        print("Invariant violation: multiple active device tokens for user/device")
        raise HTTPException(
            status_code=500,
            detail="Invariant violation: multiple active tokens"
        )

    except HTTPException:
        raise

    except IntegrityError as e:
        print(e)
        raise HTTPException(
            status_code=409,
            detail="Active device token already exists"
        )

    except Exception as e:
        # Absolute last-resort catch-all
        print("Unexpected error in device_cookie.py generate_device_token")
        print(e)
        raise HTTPException(
            status_code=500,
            detail="Internal server error")




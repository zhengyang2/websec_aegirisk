from base64 import b64decode
from binascii import Error as BinasciiError
import hmac
import os
import time

from fastapi import Header, HTTPException, Request, status
from risk_engine.db.db_setup import SessionLocal, AuditSessionLocal
from risk_engine import config
# use to check when web app call that it is secure




def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_audit_db():
    """Get audit database session."""
    db = AuditSessionLocal()
    try:
        yield db
    finally:
        db.close()




# used to secure RBA API. verify when API called is it the web app

def _basic_password(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "basic" or not value:
        return None
    try:
        decoded = b64decode(value).decode("utf-8")
    except (BinasciiError, UnicodeDecodeError):
        return None
    _, _, password = decoded.partition(":")
    return password or None


def _is_api_key_valid(x_api_key: str | None, authorization: str | None) -> bool:
    expected = config.get_engine_api_key()

    if not expected:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key not configured",
        )

    basic_password = _basic_password(authorization)

    if x_api_key and hmac.compare_digest(x_api_key, expected):
        return True

    if basic_password and hmac.compare_digest(basic_password, expected):
        return True

    return False


ADMIN_SESSION_TIMEOUT_SEC = int(os.getenv("RISK_ENGINE_ADMIN_SESSION_TIMEOUT_SEC", "900"))


def is_admin_session_active(request: Request) -> bool:
    if request.session.get("admin_auth") is not True:
        return False

    now = int(time.time())
    last_seen = request.session.get("admin_last_seen")

    if last_seen is None:
        request.session["admin_last_seen"] = now
        return True

    try:
        last_seen_int = int(last_seen)
    except (TypeError, ValueError):
        request.session.pop("admin_auth", None)
        request.session.pop("admin_last_seen", None)
        return False

    if now - last_seen_int > ADMIN_SESSION_TIMEOUT_SEC:
        request.session.pop("admin_auth", None)
        request.session.pop("admin_last_seen", None)
        return False

    request.session["admin_last_seen"] = now
    return True


def require_api_key(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):

    if config.ENFORCE_API_KEY:


        expected = config.get_engine_api_key()

        if not expected:
            # Engine is misconfigured or not initialized
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="API key not configured",
            )

        if _is_api_key_valid(x_api_key, authorization):
            return

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized / Missing API Key",
            headers={"WWW-Authenticate": 'Basic realm="RBA Admin"'},
        )


def require_admin(
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    if is_admin_session_active(request):
        return

    if not config.ENFORCE_API_KEY:
        return

    if _is_api_key_valid(x_api_key, authorization):
        return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized / Missing API Key",
        headers={"WWW-Authenticate": 'Basic realm="RBA Admin"'},
    )


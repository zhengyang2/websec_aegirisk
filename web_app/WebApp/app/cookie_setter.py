
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Literal

import secrets
import string

from fastapi import Response


class CookieProfile(str, Enum):
    APP_DEVICE_ID = "app_device_id"          # web-app issued continuity cookie
    RISK_ENGINE_TOKEN = "risk_engine_token"  # engine-issued trusted device token

@dataclass(frozen=True)
class CookiePolicy:
    httponly: bool
    secure: bool
    samesite: Literal["lax", "strict", "none"]     # "lax" | "strict" | "none"
    path: str = "/"
    max_age: Optional[int] = None  # seconds
    domain: Optional[str] = None   # usually None for host-only cookies


def _policy_for(profile: CookieProfile, *, is_prod: bool) -> CookiePolicy:
    """
    Central place where you lock down cookie settings.
    - DEVICE_CONTINUITY: Secure only in prod (so local http:// works)
    - TRUSTED_DEVICE_TOKEN: Secure ALWAYS
    """
    if profile == CookieProfile.APP_DEVICE_ID:
        return CookiePolicy(
            httponly=True,
            secure=is_prod,
            samesite="lax",
            path="/",
            max_age=60 * 60 * 24 * 365,  # 1 year
            domain=None,
        )

    if profile == CookieProfile.RISK_ENGINE_TOKEN:
        return CookiePolicy(
            httponly=True,
            secure=is_prod,
            samesite="lax",
            path="/",
            max_age=60 * 60 * 24 * 90,   # set to 90 days align with engine
            domain=None,
        )


def generate_device_id(length: int = 32) -> str:
    """
    Generate a cryptographically secure, opaque device identifier.

    - Default length: 32 chars (~190 bits entropy)
    - URL- and cookie-safe
    - No embedded meaning (not fingerprinting)
    """
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))



def set_cookie(
    response: Response,
    *,
    name: str,
    value: str,
    kind: CookieProfile,
    is_prod: bool,
    max_age: Optional[int] = None,
    expires: Optional[int] = None,
) -> None:
    """
    Set a cookie using standardized security rules.

    - Does NOT generate values
    - Does NOT read requests
    - Centralizes cookie hardening
    """
    policy = _policy_for(kind, is_prod=is_prod)

    response.set_cookie(
        key=name,
        value=value,
        httponly=policy.httponly,
        secure=policy.secure,
        samesite=policy.samesite,
        path=policy.path,
        domain=policy.domain,
        max_age=max_age if max_age is not None else policy.max_age,
        expires=expires,
    )


def delete_cookie(
    response: Response,
    *,
    name: str,
    kind: CookieProfile,
    is_prod: bool,
) -> None:
    """
    Delete a cookie using the same scope it was set with.
    """
    policy = _policy_for(kind, is_prod=is_prod)
    response.delete_cookie(
        key=name,
        path=policy.path,
        domain=policy.domain,
    )

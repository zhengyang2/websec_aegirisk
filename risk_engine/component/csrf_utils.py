"""CSRF protection utilities for admin forms."""
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import HTTPException, Request


# Use the same secret as session middleware for consistency
CSRF_SECRET = "aegirisk-demo-session-key-2026"
CSRF_TOKEN_MAX_AGE = 3600  # 1 hour


def generate_csrf_token() -> str:
    """Generate a new CSRF token."""
    serializer = URLSafeTimedSerializer(CSRF_SECRET, salt="csrf-token")
    # Use a simple payload - we just need a signed token
    return serializer.dumps("csrf-protection")


def validate_csrf_token(token: str) -> bool:
    """Validate a CSRF token."""
    if not token:
        return False
    
    serializer = URLSafeTimedSerializer(CSRF_SECRET, salt="csrf-token")
    try:
        serializer.loads(token, max_age=CSRF_TOKEN_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False


def get_csrf_token(request: Request) -> str:
    """Get or create CSRF token from session."""
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = generate_csrf_token()
    return request.session["csrf_token"]


def verify_csrf_token(request: Request, token: str) -> None:
    """Verify CSRF token, raise HTTPException if invalid."""
    session_token = request.session.get("csrf_token")
    
    if not session_token:
        raise HTTPException(status_code=403, detail="CSRF token missing from session")
    
    if not token:
        raise HTTPException(status_code=403, detail="CSRF token missing from request")
    
    if not validate_csrf_token(token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    
    if token != session_token:
        raise HTTPException(status_code=403, detail="CSRF token mismatch")

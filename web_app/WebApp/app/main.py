import os
import io
import base64
import httpx
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

import pyotp
import qrcode
from datetime import datetime, timezone

from .db import init_db, get_conn
from .auth import (
    create_user,
    get_user_by_username,
    get_user_by_id,
    verify_password,
    get_2fa_info,
    set_2fa_for_user,
    disable_2fa_for_user,
    verify_totp,
)

from .context_extract import request_context_extract
from .cookie_setter import generate_device_id, set_cookie, delete_cookie, CookieProfile


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="Mock WebApp (Register/Login + Adaptive 2FA)")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

app.add_middleware(SessionMiddleware, secret_key="dev-secret-change-me", https_only=False)

@app.on_event("startup")
def on_startup():
    init_db()
    print("ROUTES:", [(r.path, getattr(r, "methods", None)) for r in app.routes], flush=True)

def current_user(request: Request) -> str | None:
    return request.session.get("username")

def make_qr_data_uri(text: str) -> str:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"

RISK_ENGINE_URL = os.getenv("RISK_ENGINE_URL", "http://127.0.0.1:8003")
RISK_ENGINE_API_KEY = os.getenv("RISK_ENGINE_API_KEY", "")

if not RISK_ENGINE_API_KEY:
    print("[risk] warning: RISK_ENGINE_API_KEY is not set; risk engine calls may return 401", flush=True)

def call_risk_engine(context_features: dict) -> dict:
    """
    Calls risk engine /risk/evaluate and returns:
      {"decision": "...", "score": int, "reasons": [...]}
    If the risk engine is down, fail open (allow) for MVP.
    """
    headers = {}
    if RISK_ENGINE_API_KEY:
        headers["X-API-Key"] = RISK_ENGINE_API_KEY  # matches your require_api_key dependency style

    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.post(f"{RISK_ENGINE_URL}/risk/evaluate", json=context_features, headers=headers)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        print(f"[risk] engine call failed, fail-open allow. err={e}", flush=True)
        return {"decision": "allow", "score": 0, "reasons": ["risk_engine_unavailable"]}

def check_cookie_action(request, user):
    # If not logged in, do nothing (no engine token issuance)
    if user is None:
        return None, None

    device_token = request.cookies.get("__Host_rba_dt")
    device_id = request.cookies.get("app_device_id")

    new_device_id = None
    new_risk_token = None

    # 1) Ensure app_device_id exists (only set if missing)
    if device_id is None:
        new_device_id = generate_device_id()
        device_id = new_device_id  # use it for the engine call



    # 3) Call risk engine to mint trusted device token
    payload = {
        "user_id": user,
        "device_id": device_id,
        "force_rotate": False,
    }

    headers = {}
    if RISK_ENGINE_API_KEY:
        headers["X-API-Key"] = RISK_ENGINE_API_KEY

    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.post(f"{RISK_ENGINE_URL}/cookie/generate", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()


    except Exception as e:
        print(f"[risk_cookie] engine call failed err={e}", flush=True)
        # still allow setting new_device_id if we generated it
        return new_device_id, None

    return new_device_id, data

def parse_utc_expires(ts: str) -> datetime:
    """
    Parse ISO 8601 UTC timestamp from risk engine.
    """
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@app.get("/", response_class=HTMLResponse)
def home(request: Request):

    device_id, token_data = check_cookie_action(request, current_user(request))
    response = templates.TemplateResponse(
        "home.html",
        {"request": request, "username": current_user(request)},
    )

    if device_id:
        set_cookie(
            response,
            name="app_device_id",
            value=device_id,
            kind=CookieProfile.APP_DEVICE_ID,
            is_prod=False,
        )
        print("device id cookie set:", device_id)

    if token_data and token_data.get("case") != "no_rotate":
        expires_at = token_data.get("expires_at_utc")
        expires_dt = parse_utc_expires(expires_at)

        set_cookie(
            response,
            name=token_data.get("cookie_name"),
            value=token_data.get("raw_token"),
            kind=CookieProfile.RISK_ENGINE_TOKEN,
            is_prod=False,
            expires=expires_dt,
            max_age=None,
        )
        print("device token cookie set:", token_data.get("raw_token"))


    return response

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})

@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    ok, msg = create_user(username, password)
    if not ok:
        return templates.TemplateResponse("register.html", {"request": request, "error": msg})

    return RedirectResponse(url="/login", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    # request context extraction
    context_features = request_context_extract(request, username)
    print(context_features)

    # Call risk engine BEFORE password verification (for proper rate limiting)
    risk = call_risk_engine(context_features)
    decision = risk.get("decision", "allow")
    print(f"[risk] decision={decision} score={risk.get('score')} reasons={risk.get('reasons')}", flush=True)

    # Check for BLOCK decision immediately
    if decision == "block":
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Login blocked due to suspicious activity. Try again later."}
        )

    # Now verify credentials
    user = get_user_by_username(username)
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid username or password."}
        )

    enabled, secret = get_2fa_info(user.id)

    # If risk says challenge, send them through 2FA step (force setup if not enabled)
    if decision == "challenge":
        if enabled and secret:
            request.session["pending_2fa_user_id"] = user.id
            return RedirectResponse(url="/2fa", status_code=303)
        else:
            # Force 2FA setup for challenge decisions
            request.session["pending_2fa_user_id"] = user.id
            return RedirectResponse(url="/2fa/setup/required", status_code=303)

    # Otherwise: login completes immediately (ALLOW)
    request.session["username"] = user.username
    return RedirectResponse(url="/", status_code=303)

@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)

# -------------------------
# 2FA Challenge Step
# -------------------------

@app.get("/2fa", response_class=HTMLResponse)
def twofa_prompt(request: Request):
    if not request.session.get("pending_2fa_user_id"):
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse("twofa.html", {"request": request, "error": None})

@app.post("/2fa", response_class=HTMLResponse)
def twofa_verify(request: Request, code: str = Form(...)):
    user_id = request.session.get("pending_2fa_user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=303)

    enabled, secret = get_2fa_info(user_id)
    if not enabled or not secret:
        request.session.pop("pending_2fa_user_id", None)
        return RedirectResponse(url="/login", status_code=303)

    if not verify_totp(secret, code):
        return templates.TemplateResponse("twofa.html", {"request": request, "error": "Invalid code."})

    # Success → finalize login
    with get_conn() as conn:
        row = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()

    request.session.pop("pending_2fa_user_id", None)
    request.session["username"] = row["username"]
    return RedirectResponse(url="/", status_code=303)

# -------------------------
# 2FA Setup (Enable/Disable)
# -------------------------

@app.get("/2fa/setup/required", response_class=HTMLResponse)
def twofa_setup_required(request: Request):
    """Force 2FA setup for users who don't have it when challenge decision occurs"""
    user_id = request.session.get("pending_2fa_user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=303)

    user = get_user_by_id(user_id)
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    # Generate a temporary secret for setup
    temp_secret = pyotp.random_base32()
    issuer = "MockWebApp"
    otp_uri = pyotp.TOTP(temp_secret).provisioning_uri(name=user.username, issuer_name=issuer)
    qr_uri = make_qr_data_uri(otp_uri)

    request.session["twofa_temp_secret"] = temp_secret

    return templates.TemplateResponse(
        "twofa_setup.html",
        {
            "request": request,
            "already_enabled": False,
            "qr_uri": qr_uri,
            "secret": temp_secret,
            "error": None,
            "required": True,  # Indicate this is mandatory
        },
    )

@app.post("/2fa/setup/required", response_class=HTMLResponse)
def twofa_setup_required_confirm(request: Request, code: str = Form(...)):
    """Confirm forced 2FA setup"""
    user_id = request.session.get("pending_2fa_user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=303)

    user = get_user_by_id(user_id)
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    temp_secret = request.session.get("twofa_temp_secret")
    if not temp_secret:
        return RedirectResponse(url="/2fa/setup/required", status_code=303)

    if not verify_totp(temp_secret, code):
        issuer = "MockWebApp"
        otp_uri = pyotp.TOTP(temp_secret).provisioning_uri(name=user.username, issuer_name=issuer)
        qr_uri = make_qr_data_uri(otp_uri)
        return templates.TemplateResponse(
            "twofa_setup.html",
            {
                "request": request,
                "already_enabled": False,
                "qr_uri": qr_uri,
                "secret": temp_secret,
                "error": "Invalid code. Try again.",
                "required": True,
            },
        )

    # Save the secret for this user
    set_2fa_for_user(user.id, temp_secret)
    request.session.pop("twofa_temp_secret", None)

    # Now redirect to 2FA verification
    return RedirectResponse(url="/2fa", status_code=303)

@app.get("/2fa/setup", response_class=HTMLResponse)
def twofa_setup(request: Request):
    username = current_user(request)
    if not username:
        return RedirectResponse(url="/login", status_code=303)

    user = get_user_by_username(username)
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    enabled, secret = get_2fa_info(user.id)
    if enabled and secret:
        return templates.TemplateResponse(
            "twofa_setup.html",
            {"request": request, "already_enabled": True, "qr_uri": None, "secret": None, "error": None},
        )

    # Generate a temporary secret for setup (only saved on confirm)
    temp_secret = pyotp.random_base32()
    issuer = "MockWebApp"
    otp_uri = pyotp.TOTP(temp_secret).provisioning_uri(name=user.username, issuer_name=issuer)
    qr_uri = make_qr_data_uri(otp_uri)

    request.session["twofa_temp_secret"] = temp_secret

    return templates.TemplateResponse(
        "twofa_setup.html",
        {"request": request, "already_enabled": False, "qr_uri": qr_uri, "secret": temp_secret, "error": None},
    )

@app.post("/2fa/setup", response_class=HTMLResponse)
def twofa_setup_confirm(request: Request, code: str = Form(...)):
    username = current_user(request)
    if not username:
        return RedirectResponse(url="/login", status_code=303)

    user = get_user_by_username(username)
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    temp_secret = request.session.get("twofa_temp_secret")
    if not temp_secret:
        return RedirectResponse(url="/2fa/setup", status_code=303)

    if not verify_totp(temp_secret, code):
        issuer = "MockWebApp"
        otp_uri = pyotp.TOTP(temp_secret).provisioning_uri(name=user.username, issuer_name=issuer)
        qr_uri = make_qr_data_uri(otp_uri)
        return templates.TemplateResponse(
            "twofa_setup.html",
            {
                "request": request,
                "already_enabled": False,
                "qr_uri": qr_uri,
                "secret": temp_secret,
                "error": "Invalid code. Try again.",
            },
        )

    # Persist 2FA
    set_2fa_for_user(user.id, temp_secret)
    request.session.pop("twofa_temp_secret", None)
    return RedirectResponse(url="/", status_code=303)

@app.post("/2fa/disable")
def twofa_disable(request: Request):
    username = current_user(request)
    if not username:
        return RedirectResponse(url="/login", status_code=303)

    user = get_user_by_username(username)
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    disable_2fa_for_user(user.id)
    return RedirectResponse(url="/", status_code=303)

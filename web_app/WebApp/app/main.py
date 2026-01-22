import os
import io
import base64

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

import pyotp
import qrcode

from .db import init_db, get_conn
from .auth import (
    create_user,
    get_user_by_username,
    verify_password,
    get_2fa_info,
    set_2fa_for_user,
    disable_2fa_for_user,
    verify_totp,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="Mock WebApp (Register/Login + Adaptive 2FA)")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

app.add_middleware(SessionMiddleware, secret_key="dev-secret-change-me", https_only=False)

@app.on_event("startup")
def on_startup():
    init_db()

def current_user(request: Request) -> str | None:
    return request.session.get("username")

def make_qr_data_uri(text: str) -> str:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"

def should_challenge(request: Request, user_id: int) -> bool:
    """
    Temporary "risk decision" placeholder.
    Later replace this with middleware/risk-engine decision:
      allow / challenge / block
    """
    # Easiest manual testing: /login?force_2fa=1
    return request.query_params.get("force_2fa") == "1"

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        "home.html",
        {"request": request, "username": current_user(request)},
    )

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
    user = get_user_by_username(username)
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid username or password."}
        )

    enabled, secret = get_2fa_info(user.id)

    # If 2FA is enabled AND policy says challenge → go to 2FA step
    if enabled and secret and should_challenge(request, user.id):
        request.session["pending_2fa_user_id"] = user.id
        return RedirectResponse(url="/2fa", status_code=303)

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

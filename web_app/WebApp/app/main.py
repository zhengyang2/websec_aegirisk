import os
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .db import init_db
from .auth import create_user, get_user_by_username, verify_password

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="Mock WebApp (Register/Login)")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Change this secret in real apps; for mock local dev it's fine.
app.add_middleware(SessionMiddleware, secret_key="dev-secret-change-me", https_only=False)

@app.on_event("startup")
def on_startup():
    init_db()

def current_user(request: Request) -> str | None:
    return request.session.get("username")

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        "home.html",
        {"request": request, "username": current_user(request)},
    )

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "error": None},
    )

@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    ok, msg = create_user(username, password)
    if not ok:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": msg},
        )
    # after registration, redirect to login
    return RedirectResponse(url="/login", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": None},
    )

@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user = get_user_by_username(username)
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password."},
        )

    # Logged in: set session
    request.session["username"] = user.username
    return RedirectResponse(url="/", status_code=303)

@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)

from passlib.context import CryptContext
from sqlite3 import IntegrityError
from .db import get_conn
from .models import User
import pyotp

# Windows-safe, no native deps (bcrypt causes issues on Windows)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

def create_user(username: str, password: str) -> tuple[bool, str]:
    username = (username or "").strip()
    password = password or ""

    if not username or not password:
        return False, "Username and password are required."
    if len(password.encode("utf-8")) < 8:
        return False, "Password must be at least 8 characters."

    pw_hash = hash_password(password)

    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash),
            )
            conn.commit()
        return True, "User created."
    except IntegrityError:
        return False, "Username already exists."

def get_user_by_username(username: str) -> User | None:
    username = (username or "").strip()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not row:
        return None

    return User(id=row["id"], username=row["username"], password_hash=row["password_hash"])

# -------------------------
# 2FA / TOTP helpers
# -------------------------

def get_2fa_info(user_id: int) -> tuple[bool, str | None]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT is_2fa_enabled, totp_secret FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    if not row:
        return False, None

    enabled = (row["is_2fa_enabled"] == 1)
    secret = row["totp_secret"]
    return enabled, secret

def set_2fa_for_user(user_id: int, secret: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = ?, is_2fa_enabled = 1 WHERE id = ?",
            (secret, user_id),
        )
        conn.commit()

def disable_2fa_for_user(user_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = NULL, is_2fa_enabled = 0 WHERE id = ?",
            (user_id,),
        )
        conn.commit()

def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False

    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

from passlib.context import CryptContext
from sqlite3 import IntegrityError
from .db import get_conn
from .models import User

# Use PBKDF2 instead of bcrypt (Windows-safe, no length limit)
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

def create_user(username: str, password: str) -> tuple[bool, str]:
    username = (username or "").strip()
    password = password or ""

    if not username or not password:
        return False, "Username and password are required."

    pw_bytes = password.encode("utf-8")
    if len(pw_bytes) < 8:
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

    return User(
        id=row["id"],
        username=row["username"],
        password_hash=row["password_hash"],
    )

from pathlib import Path
import os
import json

from dotenv import load_dotenv


ENV_PATH = Path("risk_engine/.env")


BASE_DIR = Path(__file__).resolve().parent
ENGINE_STATE_PATH = BASE_DIR / "engine_state.json"

load_dotenv(dotenv_path=ENV_PATH)

def load_state() -> dict | None:
    if not ENGINE_STATE_PATH.exists():
        return None
    data = json.loads(ENGINE_STATE_PATH.read_text(encoding="utf-8"))
    # Validate minimally, fail closed
    if data.get("sealed") is not True:
        raise RuntimeError("Engine state corrupt: sealed flag not true")
    api_key = (data.get("api_key") or "").strip()
    if not api_key:
        raise RuntimeError("Engine state corrupt: api_key missing")
    return data


def write_engine_state_atomically(api_key: str) -> None:
    payload = {
        "version": 1,
        "sealed": True,
        "api_key": api_key,
    }

    tmp_path = ENGINE_STATE_PATH.with_suffix(".json.tmp")

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f)
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp_path, ENGINE_STATE_PATH)


def is_sealed() -> bool:
    return load_state() is not None

def get_engine_api_key() -> str | None:
    state = load_state()
    return state["api_key"] if state else None

# API settings
ENFORCE_API_KEY = os.getenv("RISK_ENGINE_ENFORCE_API_KEY", "1") == "1"

#cookie settings

COOKIE_NAME = "__Host_rba_dt"
TOKEN_TTL_DAYS = 90
EXPIRES_WITHIN_DAYS = 7


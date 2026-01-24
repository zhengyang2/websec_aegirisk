import json
from typing import List, Tuple, Optional
from sqlalchemy.orm import Session

from risk_engine.db.risk_model import LoginEvent, UserBaseline

def ip_to_prefix(ip: Optional[str]) -> Optional[str]:
    # simple IPv4 /24 prefix: "1.2.3.4" -> "1.2.3"
    if not ip:
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return ".".join(parts[:3])

def _loads_list(s: Optional[str]) -> List[str]:
    if not s:
        return []
    try:
        v = json.loads(s)
        return v if isinstance(v, list) else []
    except Exception:
        return []

def _dumps_list(lst: List[str]) -> str:
    return json.dumps(lst)

def get_or_build_baseline(db: Session, username: str) -> UserBaseline:
    baseline = db.query(UserBaseline).filter(UserBaseline.username == username).one_or_none()
    if baseline:
        return baseline

    # build minimal baseline from existing login events (if any)
    events = (
        db.query(LoginEvent)
        .filter(LoginEvent.username == username, LoginEvent.decision != "block")
        .order_by(LoginEvent.event_time_utc.desc())
        .limit(50)
        .all()
    )

    known_devices = []
    known_prefixes = []

    for e in events:
        if e.device_token and e.device_token not in known_devices:
            known_devices.append(e.device_token)
        if e.ip_prefix and e.ip_prefix not in known_prefixes:
            known_prefixes.append(e.ip_prefix)

    baseline = UserBaseline(
        username=username,
        known_device_tokens=_dumps_list(known_devices),
        known_ip_prefixes=_dumps_list(known_prefixes),
        typical_login_hours=None,
    )
    db.add(baseline)
    db.commit()
    db.refresh(baseline)
    return baseline

def score_login(db: Session, username: str, ip: Optional[str], user_agent: Optional[str], device_token: Optional[str]) -> Tuple[int, List[str], str, Optional[str]]:
    baseline = get_or_build_baseline(db, username)

    reasons: List[str] = []
    score = 0

    ip_prefix = ip_to_prefix(ip)
    known_devices = _loads_list(baseline.known_device_tokens)
    known_prefixes = _loads_list(baseline.known_ip_prefixes)

    if device_token and device_token not in known_devices:
        score += 30
        reasons.append("new_device")

    if ip_prefix and ip_prefix not in known_prefixes:
        score += 20
        reasons.append("new_ip_prefix")

    # (optional) small bump if user_agent missing or empty
    if not user_agent:
        score += 5
        reasons.append("missing_user_agent")

    # decision thresholds
    if score >= 60:
        decision = "block"
    elif score >= 30:
        decision = "challenge"
    else:
        decision = "allow"

    return score, reasons, decision, ip_prefix

def update_baseline_on_success(db: Session, username: str, device_token: Optional[str], ip_prefix: Optional[str]) -> None:
    baseline = get_or_build_baseline(db, username)

    known_devices = _loads_list(baseline.known_device_tokens)
    known_prefixes = _loads_list(baseline.known_ip_prefixes)

    changed = False
    if device_token and device_token not in known_devices:
        known_devices.append(device_token)
        baseline.known_device_tokens = _dumps_list(known_devices)
        changed = True

    if ip_prefix and ip_prefix not in known_prefixes:
        known_prefixes.append(ip_prefix)
        baseline.known_ip_prefixes = _dumps_list(known_prefixes)
        changed = True

    if changed:
        db.commit()

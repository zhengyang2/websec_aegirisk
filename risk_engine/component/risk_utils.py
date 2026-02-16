import json
import math
import os
from typing import List, Tuple, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

from risk_engine.db.risk_model import LoginEvent, UserBaseline

# Cache for config to avoid repeated file reads
_config_cache: Optional[Dict[str, Any]] = None
_config_path = os.path.join(os.path.dirname(__file__), '..', 'risk_config.json')

def load_risk_config() -> Dict[str, Any]:
    """Load risk configuration from JSON file with caching."""
    global _config_cache
    
    if _config_cache is not None:
        return _config_cache
    
    default_config = {
        "risk_scores": {
            "new_device": 30,
            "new_ip_prefix": 20,
            "impossible_travel": 30,
            "unusual_login_time": 20,
            "missing_user_agent": 5
        },
        "decision_thresholds": {
            "block": 60,
            "challenge": 30
        },
        "impossible_travel": {
            "time_window_hours": 6,
            "minimum_distance_km": 100,
            "speed_threshold_kmh": 900
        },
        "rate_limit": {
            "window_seconds": 30,
            "thresholds": [
                {"attempts": 5, "score": 15},
                {"attempts": 10, "score": 30},
                {"attempts": 20, "score": 60}
            ]
        },
        "baseline": {
            "typical_hours_minimum_events": 10,
            "typical_hours_percentage_threshold": 0.1,
            "typical_hours_default": list(range(9, 19)),
            "recalculation_frequency": 10,
            "event_limit": 50
        }
    }
    
    try:
        with open(_config_path, 'r') as f:
            _config_cache = json.load(f)
            return _config_cache
    except (FileNotFoundError, json.JSONDecodeError):
        _config_cache = default_config
        return _config_cache

def reload_risk_config() -> None:
    """Force reload of risk configuration from file."""
    global _config_cache
    _config_cache = None
    load_risk_config()

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

def _haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance between two coordinates in kilometers using Haversine formula."""
    R = 6371  # Earth's radius in kilometers
    
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)
    
    a = math.sin(delta_lat / 2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    return R * c

def _get_location_from_ip(ip: Optional[str]) -> Optional[Tuple[float, float]]:
    """Get coordinates (latitude, longitude) from IP address.
    
    Uses GeoIP2 database for lookup. Does NOT store results.
    Returns None if geolocation is unavailable or fails.
    """
    if not ip or not GEOIP_AVAILABLE:
        return None
    
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(ip)
        
        lat = response.location.latitude
        lon = response.location.longitude
        reader.close()
        
        if lat is not None and lon is not None:
            return (lat, lon)
        return None
    except (geoip2.errors.AddressNotFoundError, FileNotFoundError, Exception):
        return None

def _calculate_typical_hours(events: List[LoginEvent]) -> List[int]:
    """Calculate typical login hours from historical events.
    
    Requires at least minimum events to establish a pattern. This prevents
    false positives for new accounts with limited history.
    """
    config = load_risk_config()
    min_events = config["baseline"]["typical_hours_minimum_events"]
    threshold_percentage = config["baseline"]["typical_hours_percentage_threshold"]
    
    if not events or len(events) < min_events:
        return []
    
    hour_counts = {}
    for event in events:
        if event.event_time_utc:
            hour = event.event_time_utc.hour
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
    
    if not hour_counts:
        return []
    
    # Consider hours with at least threshold percentage of total logins as "typical"
    total = sum(hour_counts.values())
    threshold = max(1, total * threshold_percentage)
    typical_hours = [hour for hour, count in hour_counts.items() if count >= threshold]
    
    return sorted(typical_hours)

def get_or_build_baseline(db: Session, username: str) -> UserBaseline:
    baseline = db.query(UserBaseline).filter(UserBaseline.username == username).one_or_none()
    if baseline:
        return baseline

    # build minimal baseline from existing login events (if any)
    config = load_risk_config()
    event_limit = config["baseline"]["event_limit"]
    
    events = (
        db.query(LoginEvent)
        .filter(LoginEvent.username == username, LoginEvent.decision != "block")
        .order_by(LoginEvent.event_time_utc.desc())
        .limit(event_limit)
        .all()
    )

    known_devices = []
    known_prefixes = []

    for e in events:
        if e.device_token and e.device_token not in known_devices:
            known_devices.append(e.device_token)
        if e.ip_prefix and e.ip_prefix not in known_prefixes:
            known_prefixes.append(e.ip_prefix)

    # Calculate typical login hours from historical data; fall back to configured default
    default_hours = config["baseline"].get("typical_hours_default", list(range(9, 19)))
    typical_hours = _calculate_typical_hours(events) or default_hours
    typical_hours_json = _dumps_list(typical_hours)

    baseline = UserBaseline(
        username=username,
        known_device_tokens=_dumps_list(known_devices),
        known_ip_prefixes=_dumps_list(known_prefixes),
        typical_login_hours=typical_hours_json,
    )
    db.add(baseline)
    db.commit()
    db.refresh(baseline)
    return baseline

def score_login(db: Session, username: str, ip: Optional[str], user_agent: Optional[str], device_token: Optional[str]) -> Tuple[int, List[str], str, Optional[str]]:
    baseline = get_or_build_baseline(db, username)
    config = load_risk_config()

    reasons: List[str] = []
    score = 0

    ip_prefix = ip_to_prefix(ip)
    known_devices = _loads_list(baseline.known_device_tokens)
    known_prefixes = _loads_list(baseline.known_ip_prefixes)

    if device_token and device_token not in known_devices:
        score += config["risk_scores"]["new_device"]
        reasons.append("new_device")

    if ip_prefix and ip_prefix not in known_prefixes:
        score += config["risk_scores"]["new_ip_prefix"]
        reasons.append("new_ip_prefix")

    # Check for impossible travel (geo-velocity)
    if ip:
        current_location = _get_location_from_ip(ip)
        
        if current_location:
            current_time = datetime.utcnow()
            time_window = timedelta(hours=config["impossible_travel"]["time_window_hours"])
            
            # Look for recent login with different location
            recent_event = (
                db.query(LoginEvent)
                .filter(
                    LoginEvent.username == username,
                    LoginEvent.event_time_utc >= current_time - time_window,
                    LoginEvent.ip != None,
                    LoginEvent.ip != ip,  # Different IP
                    LoginEvent.decision != "block"
                )
                .order_by(LoginEvent.event_time_utc.desc())
                .first()
            )
            
            if recent_event and recent_event.ip:
                # Lookup previous location on-demand
                previous_location = _get_location_from_ip(recent_event.ip)
                
                if previous_location:
                    # Calculate distance
                    distance_km = _haversine_distance(
                        previous_location[0], previous_location[1],
                        current_location[0], current_location[1]
                    )
                    
                    time_diff_hours = (current_time - recent_event.event_time_utc).total_seconds() / 3600
                    
                    # Only flag if meaningful movement and time elapsed
                    min_distance = config["impossible_travel"]["minimum_distance_km"]
                    speed_threshold = config["impossible_travel"]["speed_threshold_kmh"]
                    
                    if distance_km > min_distance and time_diff_hours > 0:
                        speed_kmh = distance_km / time_diff_hours
                        
                        # Flag if travel speed exceeds threshold
                        if speed_kmh > speed_threshold:
                            score += config["risk_scores"]["impossible_travel"]
                            reasons.append("impossible_travel")

    # Check for rate limit within a short window
    rate_cfg = config.get("rate_limit") or {}
    rate_window = int(rate_cfg.get("window_seconds", 0) or 0)
    thresholds = rate_cfg.get("thresholds", []) or []

    if rate_window > 0 and thresholds:
        window_start = datetime.utcnow() - timedelta(seconds=rate_window)
        attempt_count = (
            db.query(LoginEvent)
            .filter(
                LoginEvent.username == username,
                LoginEvent.event_time_utc >= window_start,
            )
            .count()
        )

        matched = None
        for rule in sorted(thresholds, key=lambda r: r.get("attempts", 0)):
            if attempt_count >= int(rule.get("attempts", 0) or 0):
                matched = rule

        if matched:
            score += int(matched.get("score", 0) or 0)
            reasons.append(f"rate_limit_ge_{matched.get('attempts', 0)}")

    # Check for unusual login time
    current_hour = datetime.utcnow().hour
    
    try:
        default_hours = config["baseline"].get("typical_hours_default", list(range(9, 19)))
        typical_hours = json.loads(baseline.typical_login_hours) if baseline.typical_login_hours else default_hours
        if typical_hours and current_hour not in typical_hours:
            score += config["risk_scores"]["unusual_login_time"]
            reasons.append("unusual_login_time")
    except Exception:
        pass  # Ignore if parsing fails

    # (optional) small bump if user_agent missing or empty
    if not user_agent:
        score += config["risk_scores"]["missing_user_agent"]
        reasons.append("missing_user_agent")

    # decision thresholds
    block_threshold = config["decision_thresholds"]["block"]
    challenge_threshold = config["decision_thresholds"]["challenge"]
    
    if score >= block_threshold:
        decision = "block"
    elif score >= challenge_threshold:
        decision = "challenge"
    else:
        decision = "allow"

    return score, reasons, decision, ip_prefix

def update_baseline_on_success(db: Session, username: str, device_token: Optional[str], ip_prefix: Optional[str]) -> None:
    baseline = get_or_build_baseline(db, username)
    config = load_risk_config()

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

    # Periodically update typical login hours based on recent successful logins
    # Recalculate based on configured frequency to adapt to user behavior changes
    recalc_frequency = config["baseline"]["recalculation_frequency"]
    event_limit = config["baseline"]["event_limit"]
    
    successful_count = (
        db.query(LoginEvent)
        .filter(LoginEvent.username == username, LoginEvent.decision == "allow")
        .count()
    )
    
    if successful_count % recalc_frequency == 0 and successful_count > 0:
        recent_events = (
            db.query(LoginEvent)
            .filter(LoginEvent.username == username, LoginEvent.decision == "allow")
            .order_by(LoginEvent.event_time_utc.desc())
            .limit(event_limit)
            .all()
        )
        
        typical_hours = _calculate_typical_hours(recent_events)
        new_typical_hours_json = _dumps_list(typical_hours) if typical_hours else None
        
        if baseline.typical_login_hours != new_typical_hours_json:
            baseline.typical_login_hours = new_typical_hours_json
            changed = True

    if changed:
        db.commit()

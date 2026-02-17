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
            "block": 80,
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
                {"attempts": 5, "score": 20},
                {"attempts": 10, "score": 80}
            ]
        },
        "baseline": {
            "typical_hours_minimum_events": 10,
            "recalculation_frequency": 10,
            "event_limit": 50,
            "typical_hours_start": 9,
            "typical_hours_end": 19
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
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city(ip)
            lat = response.location.latitude
            lon = response.location.longitude
            
            if lat is not None and lon is not None:
                return (lat, lon)
        return None
    except (geoip2.errors.AddressNotFoundError, FileNotFoundError, Exception):
        return None

def _calculate_hour_frequencies(events: List[LoginEvent]) -> Dict[int, float]:
    """Calculate login hour frequency percentages from historical events.
    
    Returns a dict mapping hour (0-23) to frequency percentage (0.0-1.0).
    Requires minimum events to establish a pattern.
    """
    config = load_risk_config()
    min_events = config["baseline"]["typical_hours_minimum_events"]
    
    if not events or len(events) < min_events:
        return {}
    
    hour_counts = {}
    for event in events:
        if event.event_time_utc:
            hour = event.event_time_utc.hour
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
    
    if not hour_counts:
        return {}
    
    # Calculate frequency percentage for each hour
    total = sum(hour_counts.values())
    hour_frequencies = {hour: count / total for hour, count in hour_counts.items()}
    
    return hour_frequencies

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

    # Calculate hour frequency percentages from historical data
    hour_frequencies = _calculate_hour_frequencies(events)
    hour_freq_json = json.dumps(hour_frequencies) if hour_frequencies else None

    baseline = UserBaseline(
        username=username,
        known_device_tokens=_dumps_list(known_devices),
        known_ip_prefixes=_dumps_list(known_prefixes),
        typical_login_hours=hour_freq_json,
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
        ) + 1  # Include current attempt

        matched = None
        for rule in sorted(thresholds, key=lambda r: r.get("attempts", 0)):
            if attempt_count >= int(rule.get("attempts", 0) or 0):
                matched = rule

        if matched:
            score += int(matched.get("score", 0) or 0)
            # Semantic reason labels for rate limiting
            attempts = matched.get('attempts', 0)
            if attempts >= 10:
                reasons.append("excessive_login_attempts")
            elif attempts >= 5:
                reasons.append("rapid_login_attempts")
            else:
                reasons.append(f"rate_limit_ge_{attempts}")

    # Check for unusual login time (probability-based scoring)
    current_hour = datetime.utcnow().hour
    
    try:
        if baseline.typical_login_hours:
            hour_frequencies = json.loads(baseline.typical_login_hours)
            
            # Check if it's a dict (new format) or list (old format for backward compatibility)
            if isinstance(hour_frequencies, dict):
                # New probability-based scoring
                freq = hour_frequencies.get(str(current_hour), 0.0)
                
                # Score based on rarity:
                # 50%+ → 0 points (very common)
                # 10-50% → 5 points (somewhat common)
                # 1-10% → 10 points (uncommon)
                # 0.1-1% → 15 points (rare)
                # <0.1% or never → 20 points (very rare/never)
                if freq >= 0.5:
                    time_score = 0
                elif freq >= 0.1:
                    time_score = 5
                elif freq >= 0.01:
                    time_score = 10
                elif freq >= 0.001:
                    time_score = 15
                else:
                    time_score = config["risk_scores"]["unusual_login_time"]
                
                if time_score > 0:
                    score += time_score
                    reasons.append(f"unusual_login_time_{time_score}pts")
            else:
                # Old format: list of typical hours (backward compatibility)
                if current_hour not in hour_frequencies:
                    score += config["risk_scores"]["unusual_login_time"]
                    reasons.append("unusual_login_time")
        else:
            # No baseline data: check against default hours range
            start_hour = config["baseline"].get("typical_hours_start", 9)
            end_hour = config["baseline"].get("typical_hours_end", 19)
            
            # Handle overnight ranges (e.g., 22:00-06:00)
            if start_hour < end_hour:
                # Normal range (e.g., 9-19)
                is_typical = start_hour <= current_hour < end_hour
            else:
                # Overnight range (e.g., 22-6 means 22:00-23:59 OR 00:00-05:59)
                is_typical = current_hour >= start_hour or current_hour < end_hour
            
            if not is_typical:
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
        
        hour_frequencies = _calculate_hour_frequencies(recent_events)
        new_hour_freq_json = json.dumps(hour_frequencies) if hour_frequencies else None
        
        if baseline.typical_login_hours != new_hour_freq_json:
            baseline.typical_login_hours = new_hour_freq_json
            changed = True

    if changed:
        db.commit()

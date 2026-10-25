from collections import Counter, defaultdict
from datetime import datetime, timezone

# Detection thresholds. Tweak these to make rules more or less sensitive.
FAILED_LOGIN_THRESHOLD = 5      # failures for one user from one IP
SPRAY_USER_THRESHOLD = 3        # distinct users targeted by one IP
DISTRIBUTED_IP_THRESHOLD = 3    # distinct IPs failing against one user
BRUTE_FORCE_SUCCESS_MIN = 3     # failures before a success from same user/IP
OFF_HOURS = range(0, 5)         # logins between 00:00 and 04:59

FAILED_TYPES = {"failed_login", "login_failed", "login_failure"}
SUCCESS_TYPES = {"login_success", "successful_login", "login"}

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _parse_time(value):
    """Return a datetime from an ISO timestamp, or None if it can't be read."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None

    # Convert timezone-aware times to naive UTC so mixed formats can be compared.
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)

    return parsed


def _event_type(event):
    return (event.get("event_type") or "").strip().lower()


def detect_repeated_failures(events):
    """Many failed logins for one user from one IP (classic brute force)."""
    failed_logins = Counter()

    for event in events:
        if _event_type(event) in FAILED_TYPES:
            key = (event.get("username"), event.get("ip_address"))
            failed_logins[key] += 1

    threats = []
    for (username, ip_address), count in failed_logins.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            threats.append({
                "type": "Repeated failed logins",
                "username": username,
                "ip_address": ip_address,
                "attempts": count,
                "severity": "High",
                "description": (
                    f"{count} failed login attempts "
                    f"were recorded for {username} "
                    f"from {ip_address}."
                ),
            })

    return threats


def detect_password_spraying(events):
    """One IP failing logins against many different accounts."""
    users_by_ip = defaultdict(set)
    attempts_by_ip = Counter()

    for event in events:
        if _event_type(event) in FAILED_TYPES:
            ip_address = event.get("ip_address")
            users_by_ip[ip_address].add(event.get("username"))
            attempts_by_ip[ip_address] += 1

    threats = []
    for ip_address, users in users_by_ip.items():
        if len(users) >= SPRAY_USER_THRESHOLD:
            threats.append({
                "type": "Password spraying",
                "username": f"multiple ({len(users)})",
                "ip_address": ip_address,
                "attempts": attempts_by_ip[ip_address],
                "severity": "High",
                "description": (
                    f"{ip_address} failed to log in to {len(users)} "
                    f"different accounts: {', '.join(sorted(map(str, users)))}."
                ),
            })

    return threats


def detect_distributed_attack(events):
    """One account failing logins from many different IPs."""
    ips_by_user = defaultdict(set)
    attempts_by_user = Counter()

    for event in events:
        if _event_type(event) in FAILED_TYPES:
            username = event.get("username")
            ips_by_user[username].add(event.get("ip_address"))
            attempts_by_user[username] += 1

    threats = []
    for username, ips in ips_by_user.items():
        if len(ips) >= DISTRIBUTED_IP_THRESHOLD:
            threats.append({
                "type": "Distributed login attack",
                "username": username,
                "ip_address": f"multiple ({len(ips)})",
                "attempts": attempts_by_user[username],
                "severity": "Medium",
                "description": (
                    f"{username} had failed logins from {len(ips)} "
                    f"different IPs: {', '.join(sorted(map(str, ips)))}."
                ),
            })

    return threats


def detect_brute_force_success(events):
    """Several failed logins followed by a successful one from the same source."""
    # Sort by timestamp if every event has a readable one; otherwise keep file order.
    ordered = events
    if events and all(_parse_time(e.get("timestamp")) for e in events):
        ordered = sorted(events, key=lambda e: _parse_time(e.get("timestamp")))

    failures = Counter()
    flagged = set()
    threats = []

    for event in ordered:
        key = (event.get("username"), event.get("ip_address"))
        event_type = _event_type(event)

        if event_type in FAILED_TYPES:
            failures[key] += 1
        elif event_type in SUCCESS_TYPES:
            if failures[key] >= BRUTE_FORCE_SUCCESS_MIN and key not in flagged:
                username, ip_address = key
                threats.append({
                    "type": "Successful login after failures",
                    "username": username,
                    "ip_address": ip_address,
                    "attempts": failures[key],
                    "severity": "High",
                    "description": (
                        f"{username} logged in successfully from {ip_address} "
                        f"after {failures[key]} failed attempts. "
                        f"The account may be compromised."
                    ),
                })
                flagged.add(key)
            failures[key] = 0

    return threats


def detect_off_hours_logins(events):
    """Successful logins during unusual hours."""
    logins = defaultdict(list)

    for event in events:
        if _event_type(event) not in SUCCESS_TYPES:
            continue
        timestamp = _parse_time(event.get("timestamp"))
        if timestamp and timestamp.hour in OFF_HOURS:
            key = (event.get("username"), event.get("ip_address"))
            logins[key].append(timestamp)

    threats = []
    for (username, ip_address), times in logins.items():
        shown = ", ".join(t.strftime("%Y-%m-%d %H:%M") for t in times[:3])
        threats.append({
            "type": "Off-hours login",
            "username": username,
            "ip_address": ip_address,
            "attempts": len(times),
            "severity": "Low",
            "description": (
                f"{username} logged in from {ip_address} outside normal "
                f"hours ({shown})."
            ),
        })

    return threats


RULES = [
    detect_repeated_failures,
    detect_password_spraying,
    detect_distributed_attack,
    detect_brute_force_success,
    detect_off_hours_logins,
]


def detect_threat(events):
    threats = []

    for rule in RULES:
        threats.extend(rule(events))

    # Most severe first so they get the AI reports.
    threats.sort(key=lambda t: SEVERITY_ORDER.get(t["severity"], 99))

    return threats


from detector import detect_threat

def make_events(attempts):
    return [
        {
            "event_type": "failed_login",
            "username": "admin",
            "ip_address": "192.0.2.10",
        }
        for _ in range(attempts)
    ]


def event(event_type, username, ip_address, timestamp=""):
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "username": username,
        "ip_address": ip_address,
    }


def types_of(threats):
    return {t["type"] for t in threats}


# Test 1: Four failed logins should not trigger an alert.
result = detect_threat(make_events(4))
assert len(result) == 0, "Failed: four attempts triggered an alert"

# Test 2: Five failed logins should trigger an alert.
result = detect_threat(make_events(5))
assert len(result) == 1, "Failed: five attempts did not trigger an alert"
assert result[0]["severity"] == "High"
assert result[0]["attempts"] == 5

# Test 3: One IP failing against three accounts is password spraying.
result = detect_threat([
    event("failed_login", user, "198.51.100.7")
    for user in ["alice", "bob", "carol"]
])
assert types_of(result) == {"Password spraying"}, result

# Test 4: One account failing from three IPs is a distributed attack.
result = detect_threat([
    event("failed_login", "admin", ip)
    for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
])
assert types_of(result) == {"Distributed login attack"}, result

# Test 5: Three failures then a success from the same source.
result = detect_threat(
    [event("failed_login", "j_doe", "203.0.113.42")] * 3
    + [event("login_success", "j_doe", "203.0.113.42")]
)
assert types_of(result) == {"Successful login after failures"}, result

# Test 6: A success *before* the failures should not count.
result = detect_threat(
    [event("login_success", "j_doe", "203.0.113.42")]
    + [event("failed_login", "j_doe", "203.0.113.42")] * 3
)
assert "Successful login after failures" not in types_of(result), result

# Test 7: A 3 a.m. login is flagged, a 2 p.m. login is not.
result = detect_threat([
    event("login_success", "night_owl", "192.0.2.50", "2026-10-19T03:15:00"),
    event("login_success", "day_user", "192.0.2.51", "2026-10-19T14:00:00"),
])
assert [t["username"] for t in result] == ["night_owl"], result
assert result[0]["severity"] == "Low"

# Test 8: Results are sorted High -> Medium -> Low.
result = detect_threat(
    [event("login_success", "night_owl", "192.0.2.50", "2026-10-19T03:15:00")]
    + [event("failed_login", "admin", ip) for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]]
    + make_events(5)
)
assert [t["severity"] for t in result] == ["High", "Medium", "Low"], result

# Test 9: Mixing timezone-aware and naive timestamps must not crash.
result = detect_threat(
    [event("failed_login", "j_doe", "203.0.113.42", "2026-10-19T10:00:00Z")] * 3
    + [event("login_success", "j_doe", "203.0.113.42", "2026-10-19T10:05:00")]
)
assert "Successful login after failures" in types_of(result), result

print("PASS: Four attempts produce no alert.")
print("PASS: Five attempts produce one high-severity alert.")
print("PASS: Password spraying detected.")
print("PASS: Distributed login attack detected.")
print("PASS: Successful login after failures detected.")
print("PASS: Off-hours login detected.")
print("PASS: Threats sorted by severity.")
print("All detector tests passed!")

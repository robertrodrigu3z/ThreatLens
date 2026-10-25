from ai_analyst import analyse_threat

threat = {
    "type": "Repeated failed logins",
    "username": "admin",
    "ip_address": "192.0.2.10",
    "attempts": 5,
    "severity": "High",
}

result = analyse_threat(threat)

print("Gemini analysis:")
print(result)

assert isinstance(result, str) and len(result.strip()) > 0, (
    "AI test failed: no analysis returned"
)

print("\nPASS: Gemini returned an analysis.")
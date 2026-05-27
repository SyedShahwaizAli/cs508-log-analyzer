from collections import Counter
import re

SUSPICIOUS_EVENTS = [
    "ConsoleLogin",
    "CreateUser",
    "DeleteUser",
    "AuthorizeSecurityGroup",
    "StartInstances",
    "StopInstances",
    "RevokeSecurityGroup",
    "LoginFailure",
    "failed",
    "unauthorized",
    "access denied",
]

KNOWN_CLOUD_SERVICES = {
    "aws": ["cloudtrail", "ec2", "iam", "s3"],
    "azure": ["activitylog", "microsoft", "azure"],
    "gcp": ["audit", "gcp", "googleapis"],
}


def analyze_log_entries(entries):
    summary = {
        "total_events": len(entries),
        "cloud_types": Counter(),
        "top_users": Counter(),
        "top_ips": Counter(),
        "suspicious_events": [],
        "risk_score": 0,
        "detected_alerts": [],
        "timeline": [],
    }

    for entry in entries:
        source = str(entry.get("source", "unknown")).lower()
        event = str(entry.get("event", "")).lower()
        user = extract_user(entry.get("user"))
        ip = entry.get("ip") or "unknown"

        cloud = detect_provider(source, event)
        summary["cloud_types"][cloud] += 1
        summary["top_users"][user] += 1
        summary["top_ips"][ip] += 1

        alert = evaluate_event(source, event, user, ip)
        if alert:
            summary["suspicious_events"].append(alert)

        summary["timeline"].append({
            "timestamp": entry.get("timestamp") or "unknown",
            "event": entry.get("event"),
            "source": source,
            "user": user,
            "ip": ip,
            "alert": bool(alert),
        })

    summary["suspicious_events"] = trimmed_alerts(summary["suspicious_events"])
    summary["risk_score"] = compute_risk_score(summary)
    summary["cloud_types"] = summary["cloud_types"].most_common(5)
    summary["top_users"] = summary["top_users"].most_common(5)
    summary["top_ips"] = summary["top_ips"].most_common(5)
    return summary


def extract_user(value):
    if isinstance(value, dict):
        return value.get("userName") or value.get("principalId") or value.get("name") or "unknown"
    if isinstance(value, str):
        return value
    return "unknown"


def detect_provider(source, event):
    key = f"{source} {event}".lower()
    for provider, patterns in KNOWN_CLOUD_SERVICES.items():
        for pattern in patterns:
            if pattern in key:
                return provider
    return "other"


def evaluate_event(source, event, user, ip):
    raw_text = f"{source} {event} {user} {ip}".lower()
    score = 0
    reasons = []

    for pattern in SUSPICIOUS_EVENTS:
        if pattern.lower() in raw_text:
            score += 2
            reasons.append(f"Suspicious keyword: {pattern}")

    if ip and ip != "unknown" and ip.startswith("192.") is False and ip.startswith("10.") is False and ip.startswith("172.") is False:
        if event and any(word in event for word in ["failed", "unauthorized", "forbidden", "denied"]):
            score += 3
            reasons.append("Possible external attack or misconfiguration")

    if user and user.lower() in ["anonymous", "unknown", "root", "admin"]:
        score += 1
        reasons.append(f"High-risk user identity: {user}")

    if score > 0:
        return {
            "source": source,
            "event": event,
            "user": user,
            "ip": ip,
            "score": score,
            "reasons": reasons,
        }
    return None


def trimmed_alerts(alerts):
    unique = []
    seen = set()
    for alert in alerts:
        signature = (alert["source"], alert["event"], alert["user"], alert["ip"])
        if signature not in seen:
            seen.add(signature)
            unique.append(alert)
    return unique[:10]


def compute_risk_score(summary):
    base = len(summary["suspicious_events"]) * 8
    cloud_types = summary["cloud_types"]
    if hasattr(cloud_types, "items"):
        provider_counts = cloud_types.items()
    else:
        provider_counts = cloud_types
    cloud_factors = sum(count for provider, count in provider_counts if provider != "other")
    return min(100, base + cloud_factors)

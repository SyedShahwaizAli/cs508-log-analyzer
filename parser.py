import json
import csv
from datetime import datetime

CLOUD_PATTERNS = ["cloudtrail", "audit", "activity"]


def parse_uploaded_log(file_path):
    lower_path = file_path.lower()
    try:
        if lower_path.endswith(".json"):
            with open(file_path, "r", encoding="utf-8") as handler:
                raw = json.load(handler)
            return normalize_json_log(raw), "json"

        if lower_path.endswith(".csv"):
            with open(file_path, "r", encoding="utf-8") as handler:
                rows = list(csv.DictReader(handler))
            return normalize_records(rows), "csv"

        if lower_path.endswith(('.log', '.txt')):
            with open(file_path, "r", encoding="utf-8") as handler:
                lines = [line.strip() for line in handler if line.strip()]
            return normalize_text_log(lines), "text"
    except Exception:
        return None, None

    return None, None


def normalize_json_log(raw):
    if isinstance(raw, dict):
        if "Records" in raw and isinstance(raw["Records"], list):
            return normalize_records(raw["Records"])
        if "events" in raw and isinstance(raw["events"], list):
            return normalize_records(raw["events"])
        return normalize_records([raw])

    if isinstance(raw, list):
        return normalize_records(raw)

    return []


def normalize_records(items):
    normalized = []
    for item in items:
        entry = {
            "timestamp": first_nonempty(item, ["eventTime", "timestamp", "time", "datetime"]),
            "source": first_nonempty(item, ["eventSource", "source", "service", "cloud_provider"]),
            "event": first_nonempty(item, ["eventName", "action", "operation", "event"]),
            "user": first_nonempty(item, ["userIdentity", "user", "principal", "actor"]),
            "ip": first_nonempty(item, ["sourceIPAddress", "ipAddress", "clientIp", "remote_addr"]),
            "status": first_nonempty(item, ["errorCode", "response", "status", "result"]),
            "raw": item,
        }
        entry["timestamp"] = parse_timestamp(entry["timestamp"])
        normalized.append(entry)
    return normalized


def normalize_text_log(lines):
    entries = []
    for line in lines:
        parts = line.split()
        timestamp = None
        if len(parts) >= 3:
            timestamp = " ".join(parts[:2])
        entries.append({
            "timestamp": parse_timestamp(timestamp),
            "source": "text",
            "event": line,
            "user": "unknown",
            "ip": find_ip_in_text(line),
            "status": "parsed",
            "raw": {"line": line},
        })
    return entries


def first_nonempty(item, keys):
    if isinstance(item, dict):
        for key in keys:
            if key in item and item[key] not in (None, "", []):
                return item[key]
    return None


def find_ip_in_text(text):
    tokens = text.split()
    for token in tokens:
        if token.count('.') == 3 and all(part.isdigit() and 0 <= int(part) < 256 for part in token.split('.')):
            return token
    return None


def parse_timestamp(value):
    if not value:
        return None
    if isinstance(value, int):
        try:
            return datetime.utcfromtimestamp(value).isoformat() + "Z"
        except Exception:
            return str(value)

    if isinstance(value, str):
        for fmt in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S", "%Y-%m-%d"]:
            try:
                return datetime.strptime(value, fmt).isoformat() + "Z"
            except ValueError:
                continue
        return value

    return str(value)

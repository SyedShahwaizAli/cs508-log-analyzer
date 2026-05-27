"""
Pure Python MapReduce Engine
Implements the full pipeline: Split -> Map -> Shuffle -> Reduce
Uses concurrent.futures for parallel chunk processing.
"""

import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─────────────────────────────────────────────
# STEP 1: SPLIT
# Divide the list of log entries into N equal chunks
# ─────────────────────────────────────────────

def split_chunks(entries, num_chunks=4):
    """Split log entries into independent sub-chunks for parallel processing."""
    if not entries:
        return []
    chunk_size = max(1, len(entries) // num_chunks)
    chunks = []
    for i in range(0, len(entries), chunk_size):
        chunks.append(entries[i: i + chunk_size])
    return chunks


# ─────────────────────────────────────────────
# STEP 2: MAP
# Each chunk is processed independently, emitting (key, value) pairs
# ─────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "consolefailed", "loginfailure", "failed", "unauthorized",
    "access denied", "createuser", "deleteuser", "authorizesecuritygroup",
    "consolelogin", "root",
]

HTTP_ERROR_PATTERN = re.compile(r'\b(4\d\d|5\d\d)\b')


def map_chunk(chunk):
    """
    Map phase: process a single chunk of log entries.
    Emits (key, 1) pairs for:
        - HTTP error codes  → ("http_error:404", 1)
        - Hourly traffic    → ("hour:14", 1)
        - Suspicious events → ("suspicious:ConsoleLogin", 1)
        - Cloud providers   → ("provider:aws", 1)
    """
    pairs = []

    for entry in chunk:
        event = str(entry.get("event") or "").lower()
        source = str(entry.get("source") or "").lower()
        timestamp = entry.get("timestamp") or ""
        ip = str(entry.get("ip") or "unknown")
        user = str(entry.get("user") or "unknown")
        if isinstance(user, dict):
            user = user.get("userName") or user.get("name") or "unknown"

        # ── HTTP error codes ──────────────────
        combined_text = f"{event} {source}"
        for match in HTTP_ERROR_PATTERN.finditer(combined_text):
            code = match.group()
            pairs.append((f"http_error:{code}", 1))

        # ── Hourly traffic ────────────────────
        hour = None
        if timestamp and "T" in str(timestamp):
            try:
                hour = str(timestamp).split("T")[1][:2]
            except Exception:
                pass
        if hour and hour.isdigit():
            pairs.append((f"hour:{hour}", 1))

        # ── Suspicious event flags ────────────
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in event or keyword in source:
                pairs.append((f"suspicious:{keyword}", 1))

        # ── Cloud provider detection ──────────
        if any(p in source for p in ["cloudtrail", "ec2", "iam", "s3"]):
            pairs.append(("provider:aws", 1))
        elif any(p in source for p in ["azure", "microsoft", "activitylog"]):
            pairs.append(("provider:azure", 1))
        elif any(p in source for p in ["gcp", "audit", "googleapis"]):
            pairs.append(("provider:gcp", 1))
        else:
            pairs.append(("provider:other", 1))

    return pairs


def map_phase(chunks):
    """Run map_chunk on all chunks concurrently using threads."""
    all_pairs = []
    with ThreadPoolExecutor(max_workers=len(chunks) or 1) as executor:
        futures = {executor.submit(map_chunk, chunk): i for i, chunk in enumerate(chunks)}
        for future in as_completed(futures):
            all_pairs.extend(future.result())
    return all_pairs


# ─────────────────────────────────────────────
# STEP 3: SHUFFLE & SORT
# Group all values by key
# ─────────────────────────────────────────────

def shuffle_phase(pairs):
    """Shuffle: group all values sharing the same key together."""
    grouped = defaultdict(list)
    for key, value in pairs:
        grouped[key].append(value)
    # Sort keys for deterministic output
    return dict(sorted(grouped.items()))


# ─────────────────────────────────────────────
# STEP 4: REDUCE
# Aggregate the grouped values into final counts
# ─────────────────────────────────────────────

def reduce_phase(grouped):
    """Reduce: sum all values for each key → final counts."""
    result = {}
    for key, values in grouped.items():
        result[key] = sum(values)
    return result


# ─────────────────────────────────────────────
# ORCHESTRATOR
# Runs the full pipeline and returns structured output
# ─────────────────────────────────────────────

def run_mapreduce(entries, num_chunks=4):
    """
    Full MapReduce pipeline.

    Returns a dict with:
        http_errors   – {error_code: count}
        traffic_hours – {hour: count}
        suspicious    – {keyword: count}
        providers     – {cloud_provider: count}
        chunk_count   – how many chunks were used
        total_entries – total log lines processed
    """
    # SPLIT
    chunks = split_chunks(entries, num_chunks=num_chunks)

    # MAP (parallel)
    pairs = map_phase(chunks)

    # SHUFFLE
    grouped = shuffle_phase(pairs)

    # REDUCE
    reduced = reduce_phase(grouped)

    # ── Structure output ──────────────────────
    http_errors = {}
    traffic_hours = {}
    suspicious = {}
    providers = {}

    for key, count in reduced.items():
        prefix, _, name = key.partition(":")
        if prefix == "http_error":
            http_errors[name] = count
        elif prefix == "hour":
            traffic_hours[name] = count
        elif prefix == "suspicious":
            suspicious[name] = count
        elif prefix == "provider":
            providers[name] = count

    # Sort traffic hours numerically for display
    traffic_hours = dict(sorted(traffic_hours.items(), key=lambda x: int(x[0])))

    # Top 5 busiest hours
    busiest_hours = sorted(traffic_hours.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "http_errors": dict(sorted(http_errors.items(), key=lambda x: x[1], reverse=True)),
        "traffic_hours": traffic_hours,
        "busiest_hours": busiest_hours,
        "suspicious": dict(sorted(suspicious.items(), key=lambda x: x[1], reverse=True)),
        "providers": providers,
        "chunk_count": len(chunks),
        "total_entries": len(entries),
    }

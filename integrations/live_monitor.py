
import sys
import json
import re
import ipaddress
from notifier import notify_alert
from auto_response import record_auto_response
from incident_store import save_alert
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

THRESHOLD = 3
WINDOW = timedelta(minutes=5)
COOLDOWN = timedelta(minutes=5)

PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ "
    r"from (?P<ip>\S+) port \d+",
    re.IGNORECASE,
)

failures = defaultdict(deque)
last_alert = {}

output = Path("alerts/live_ssh_alerts.jsonl")
output.parent.mkdir(parents=True, exist_ok=True)

print("SOC Real-Time SSH Monitor Started", flush=True)
print("Waiting for SSH events...", flush=True)

for line in sys.stdin:
    try:
        event = json.loads(line)
        message = event.get("MESSAGE", "")

        if isinstance(message, str) and (
            "Accepted password" in message
            or "Failed password" in message
):
            print("[SSH EVENT]", message, flush=True)

        if not isinstance(message, str):
            continue

        match = PATTERN.search(message)
        if not match:
            continue

        ip = str(ipaddress.ip_address(match.group("ip")))

        if "__REALTIME_TIMESTAMP" in event:
            timestamp = datetime.fromtimestamp(
                int(event["__REALTIME_TIMESTAMP"]) / 1_000_000,
                tz=timezone.utc,
            )
        else:
            timestamp = datetime.fromisoformat(
                event["ts"].replace("Z", "+00:00")
            ).astimezone(timezone.utc)

        recent = failures[ip]
        recent.append(timestamp)

        while recent and timestamp - recent[0] > WINDOW:
            recent.popleft()

        if len(recent) < THRESHOLD:
            continue

        if (
            ip in last_alert
            and timestamp - last_alert[ip] < COOLDOWN
        ):
            continue

        alert = {
            "rule_id": "SOC-SSH-001",
            "severity": "medium",
            "source_ip": ip,
            "failed_attempts": len(recent),
            "detected_at": timestamp.isoformat(),
            "description": "Repeated SSH login failures",
        }
        if not save_alert(alert):
            continue
        with output.open("a", encoding="utf-8") as file:
            file.write(json.dumps(alert) + "\n")

        last_alert[ip] = timestamp
        record_auto_response(alert)
        notify_alert(alert)

        print(
            f"[LIVE ALERT] {ip} | "
            f"{len(recent)} failed SSH attempts",
            flush=True,
        )

    except (ValueError, KeyError, TypeError, OverflowError):
        continue

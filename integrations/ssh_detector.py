
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# Detect failed SSH password attempts
PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)

THRESHOLD = 3
WINDOW = timedelta(minutes=5)


def detect_ssh_attacks(log_file):
    failures = defaultdict(list)

    with open(log_file, encoding="utf-8") as file:
        for line in file:
            match = PATTERN.search(line)

            if not match:
                continue

            timestamp = datetime.fromisoformat(
                line.split()[0].replace("Z", "+00:00")
            )

            failures[match.group("ip")].append(timestamp)

    alerts = []

    for ip, timestamps in failures.items():
        timestamps.sort()

        for index in range(len(timestamps) - THRESHOLD + 1):
            first = timestamps[index]
            last = timestamps[index + THRESHOLD - 1]

            if last - first <= WINDOW:
                alerts.append({
                    "rule_id": "SOC-SSH-001",
                    "severity": "medium",
                    "attack_type": "Repeated SSH Login Failures",
                    "source_ip": ip,
                    "failed_attempts": THRESHOLD,
                    "first_seen": first.isoformat(),
                    "last_seen": last.isoformat(),
                })
                break

    return alerts


if __name__ == "__main__":
    log_file = sys.argv[1]

    alerts = detect_ssh_attacks(log_file)

    Path("alerts").mkdir(exist_ok=True)

    Path("alerts/ssh_alerts.json").write_text(
        json.dumps(alerts, indent=4),
        encoding="utf-8"
    )

    print(f"SOC Scan Complete: {len(alerts)} alert(s)")

    for alert in alerts:
        print(
            f"[SECURITY ALERT] {alert['source_ip']} | "
            f"{alert['failed_attempts']} failed SSH attempts"
        )


import ipaddress
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "incidents.db"
ACTION_LOG = ROOT / "data" / "response_actions.jsonl"

# Reserved test networks are allowed for dry-run demonstrations
DEMO_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def record_auto_response(alert):
    ip = ipaddress.ip_address(alert["source_ip"])

    with sqlite3.connect(DB_PATH) as db:
        incident = db.execute(
            """
            SELECT id, status
            FROM incidents
            WHERE rule_id = ?
              AND source_ip = ?
              AND detected_at = ?
            LIMIT 1
            """,
            (
                alert["rule_id"],
                alert["source_ip"],
                alert["detected_at"],
            ),
        ).fetchone()

    if incident is None:
        raise ValueError("Incident not found in database")

    incident_id, status = incident

    is_demo = any(ip in net for net in DEMO_NETWORKS)

    protected = (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )

    if status == "resolved":
        decision = "SKIPPED_RESOLVED"
    elif protected and not is_demo:
        decision = "SKIPPED_PROTECTED_IP"
    elif int(alert["failed_attempts"]) < 3:
        decision = "SKIPPED_LOW_CONFIDENCE"
    else:
        decision = "SIMULATED_BLOCK"

    action = {
        "incident_id": incident_id,
        "source_ip": str(ip),
        "decision": decision,
        "dry_run": True,
        "trigger": "automatic",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    ACTION_LOG.parent.mkdir(parents=True, exist_ok=True)

    with ACTION_LOG.open("a", encoding="utf-8") as file:
        file.write(json.dumps(action) + "\n")

    print(
        f"[AUTO RESPONSE] {ip} | {decision}",
        flush=True,
    )

    return action

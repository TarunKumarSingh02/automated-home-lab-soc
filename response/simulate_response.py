
import argparse
import ipaddress
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "incidents.db"
ACTION_LOG = ROOT / "data" / "response_actions.jsonl"

# Networks that must never be automatically blocked
PROTECTED = [
    ipaddress.ip_network(network)
    for network in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def simulate_response(incident_id):
    if not DB_PATH.exists():
        raise FileNotFoundError("Initialize incident database first.")

    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        incident = db.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()

    if incident is None:
        print("Incident not found.")
        return

    ip = ipaddress.ip_address(incident["source_ip"])
    status = incident["status"]

    if status == "resolved":
        decision = "SKIPPED_RESOLVED"
    elif any(ip in network for network in PROTECTED):
        decision = "SKIPPED_PROTECTED_IP"
    else:
        decision = "SIMULATED_BLOCK"

    action = {
        "incident_id": incident_id,
        "source_ip": str(ip),
        "decision": decision,
        "dry_run": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    ACTION_LOG.parent.mkdir(parents=True, exist_ok=True)

    with ACTION_LOG.open("a", encoding="utf-8") as file:
        file.write(json.dumps(action) + "\n")

    print("=" * 45)
    print("AUTOMATED SOC RESPONSE ENGINE")
    print("=" * 45)
    print("Incident:", incident_id)
    print("Source IP:", ip)
    print("Incident Status:", status)
    print("Decision:", decision)
    print("Firewall Changes: NONE (simulation mode)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("incident_id", type=int)
    args = parser.parse_args()

    simulate_response(args.incident_id)

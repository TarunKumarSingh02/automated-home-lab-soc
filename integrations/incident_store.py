
import argparse
import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "incidents.db"
)


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")

    db.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT UNIQUE NOT NULL,
            rule_id TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            attempts INTEGER NOT NULL,
            severity TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open'
                CHECK(status IN (
                    'open', 'investigating', 'resolved'
                ))
        )
    """)
    db.commit()
    return db


def save_alert(alert):
    identity = (
        f"{alert['rule_id']}|"
        f"{alert['source_ip']}|"
        f"{alert['detected_at']}"
    )
    event_key = hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()

    with closing(connect()) as db:
        result = db.execute("""
            INSERT OR IGNORE INTO incidents
            (event_key, rule_id, source_ip,
             attempts, severity, detected_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            event_key,
            alert["rule_id"],
            alert["source_ip"],
            int(alert["failed_attempts"]),
            alert.get("severity", "medium"),
            alert["detected_at"],
        ))
        db.commit()
        return result.rowcount == 1


def list_incidents():
    with closing(connect()) as db:
        return db.execute("""
            SELECT id, source_ip, attempts,
                   severity, status, detected_at
            FROM incidents
            ORDER BY id DESC
            LIMIT 25
        """).fetchall()


def update_status(incident_id, status):
    with closing(connect()) as db:
        result = db.execute(
            "UPDATE incidents SET status=? WHERE id=?",
            (status, incident_id),
        )
        db.commit()
        return result.rowcount > 0


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(
        dest="command", required=True
    )

    commands.add_parser("init")
    commands.add_parser("list")

    change = commands.add_parser("set-status")
    change.add_argument("id", type=int)
    change.add_argument(
        "status",
        choices=["open", "investigating", "resolved"],
    )

    args = parser.parse_args()

    if args.command == "init":
        with closing(connect()):
            pass
        print("SOC incident database initialized.")

    elif args.command == "list":
        rows = list_incidents()
        print(f"Stored incidents: {len(rows)}")
        for row in rows:
            print(
                f"#{row['id']} | {row['source_ip']} | "
                f"{row['attempts']} attempts | "
                f"{row['severity']} | {row['status']}"
            )

    elif args.command == "set-status":
        changed = update_status(args.id, args.status)
        print(
            "Incident updated."
            if changed else "Incident ID not found."
        )


if __name__ == "__main__":
    main()

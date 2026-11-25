import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ROOT = Path(__file__).resolve().parent.parent
NOTIFICATION_FILE = ROOT / "data" / "notifications.jsonl"
TELEGRAM_CONFIG = Path.home() / ".config" / "automated-soc" / "telegram.env"


def load_telegram_credentials():
    """Read Telegram credentials without displaying them."""
    credentials = {}

    try:
        for line in TELEGRAM_CONFIG.read_text(encoding="utf-8").splitlines():
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            credentials[key.strip()] = value.strip().strip("'\"")

    except OSError:
        return None, None

    return (
        credentials.get("TELEGRAM_BOT_TOKEN"),
        credentials.get("TELEGRAM_CHAT_ID"),
    )


def send_telegram_message(message):
    """Send a Telegram message. Failures never stop local notifications."""
    token, chat_id = load_telegram_credentials()

    if not token or not chat_id:
        print("[TELEGRAM] Credentials unavailable.", flush=True)
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    payload = json.dumps({
        "chat_id": chat_id,
        "text": message
    }).encode("utf-8")

    request = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urlopen(request, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("ok"):
            print("[TELEGRAM] Alert sent successfully.", flush=True)
            return True

        print("[TELEGRAM] API rejected the message.", flush=True)
        return False

    except (URLError, HTTPError, TimeoutError, OSError, ValueError) as error:
        print(f"[TELEGRAM] Sending failed: {type(error).__name__}", flush=True)
        return False


def notify_alert(alert):
    notification = {
        "type": "SECURITY_ALERT",
        "rule_id": alert["rule_id"],
        "source_ip": alert["source_ip"],
        "severity": alert["severity"],
        "failed_attempts": alert["failed_attempts"],
        "message": "Suspicious SSH login activity detected",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # Preserve local JSON notification storage.
    NOTIFICATION_FILE.parent.mkdir(
        parents=True, exist_ok=True
    )

    with NOTIFICATION_FILE.open(
        "a", encoding="utf-8"
    ) as file:
        file.write(json.dumps(notification) + "\n")

    print(
        f"[NOTIFICATION] Security alert from {alert['source_ip']}",
        flush=True,
    )

    # Also send the alert to Telegram.
    telegram_message = (
        "🚨 SOC SECURITY ALERT\n\n"
        f"Source IP: {notification['source_ip']}\n"
        f"Severity: {notification['severity']}\n"
        f"Rule ID: {notification['rule_id']}\n"
        f"Failed attempts: {notification['failed_attempts']}\n"
        f"Time: {notification['created_at']}\n\n"
        "Suspicious SSH login activity detected."
    )

    send_telegram_message(telegram_message)

    return notification

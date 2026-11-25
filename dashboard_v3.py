
import json
from collections import deque
from hmac import compare_digest
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from secrets import token_urlsafe
from urllib.parse import parse_qs

from integrations.incident_store import list_incidents, update_status
from response.simulate_response import simulate_response

ROOT = Path(__file__).resolve().parent
ACTION_LOG = ROOT / "data" / "response_actions.jsonl"

STATUSES = ("open", "investigating", "resolved")
CSRF_TOKEN = token_urlsafe(32)


def get_action_history():
    if not ACTION_LOG.exists():
        return []

    recent = deque(maxlen=20)

    with ACTION_LOG.open(encoding="utf-8") as file:
        for line in file:
            try:
                action = json.loads(line)
                if isinstance(action, dict):
                    recent.append(action)
            except json.JSONDecodeError:
                continue

    return list(reversed(recent))


class SOCDashboard(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return

        incidents = list_incidents()
        rows = []

        for incident in incidents:
            incident_id = int(incident["id"])
            current = str(incident["status"])

            status_buttons = ""

            for status in STATUSES:
                disabled = "disabled" if status == current else ""

                status_buttons += f"""
                <form method="POST" action="/status">
                  <input type="hidden" name="csrf"
                         value="{CSRF_TOKEN}">
                  <input type="hidden" name="id"
                         value="{incident_id}">
                  <input type="hidden" name="status"
                         value="{status}">
                  <button {disabled}>{status.title()}</button>
                </form>
                """

            response_button = f"""
            <form method="POST" action="/simulate">
              <input type="hidden" name="csrf"
                     value="{CSRF_TOKEN}">
              <input type="hidden" name="id"
                     value="{incident_id}">
              <button class="response">Simulate Response</button>
            </form>
            """

            rows.append(f"""
            <tr>
              <td>#{incident_id}</td>
              <td>{escape(str(incident["source_ip"]))}</td>
              <td>{int(incident["attempts"])}</td>
              <td>{escape(str(incident["severity"]))}</td>
              <td>{escape(current.title())}</td>
              <td>
                <div class="actions">
                  {status_buttons}
                  {response_button}
                </div>
              </td>
            </tr>
            """)

        incident_rows = "".join(rows) or (
            "<tr><td colspan='6'>No incidents yet</td></tr>"
        )

        history_rows = []

        for action in get_action_history():
            history_rows.append(f"""
            <tr>
              <td>{escape(str(action.get("incident_id", "")))}</td>
              <td>{escape(str(action.get("source_ip", "")))}</td>
              <td>{escape(str(action.get("decision", "")))}</td>
              <td>{escape(str(action.get("timestamp", "")))}</td>
            </tr>
            """)

        action_rows = "".join(history_rows) or (
            "<tr><td colspan='4'>No response actions yet</td></tr>"
        )

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width">
<meta http-equiv="refresh" content="10">
<title>Automated SOC Dashboard V3</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #0b1220;
    color: #e2e8f0;
    padding: 24px;
}}
h1 {{ color: #60a5fa; }}
.card {{
    background: #172338;
    padding: 24px;
    margin: 20px 0;
    border-radius: 12px;
    overflow-x: auto;
}}
.count {{
    color: #fb7185;
    font-size: 36px;
    font-weight: bold;
}}
table {{
    width: 100%;
    border-collapse: collapse;
}}
th, td {{
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #334155;
}}
th {{ color: #93c5fd; }}
.actions {{
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}}
button {{
    border: none;
    border-radius: 6px;
    padding: 9px;
    color: white;
    background: #2563eb;
    cursor: pointer;
}}
button.response {{ background: #0d9488; }}
button:disabled {{
    background: #475569;
    cursor: default;
}}
.note {{ color: #94a3b8; }}
</style>
</head>
<body>
<h1>Automated SOC Dashboard V3</h1>
<p>Local Security Operations Center</p>

<div class="card">
  <h2>Recent Security Incidents</h2>
  <div class="count">{len(incidents)}</div>
  <p>Showing up to 25 recent incidents</p>
</div>

<div class="card">
  <h2>Incident Management</h2>
  <table>
    <tr>
      <th>ID</th>
      <th>Source IP</th>
      <th>Failed Attempts</th>
      <th>Severity</th>
      <th>Status</th>
      <th>Actions</th>
    </tr>
    {incident_rows}
  </table>
</div>

<div class="card">
  <h2>Response Action History</h2>
  <table>
    <tr>
      <th>Incident ID</th>
      <th>Source IP</th>
      <th>Decision</th>
      <th>Time</th>
    </tr>
    {action_rows}
  </table>
</div>

<p class="note">
  Simulation only. No actual firewall changes.
  Refreshes every 10 seconds.
</p>
</body>
</html>
"""
        body = html.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path not in ("/status", "/simulate"):
            self.send_error(404)
            return

        if self.headers.get("Content-Type", "").split(";")[0] != \
                "application/x-www-form-urlencoded":
            self.send_error(415)
            return

        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 2048:
                self.send_error(413)
                return

            fields = parse_qs(
                self.rfile.read(size).decode("utf-8")
            )

            token = fields.get("csrf", [""])[0]
            incident_id = int(fields.get("id", ["0"])[0])

            if not compare_digest(token, CSRF_TOKEN):
                self.send_error(403)
                return

            if incident_id <= 0:
                self.send_error(400)
                return

            if self.path == "/status":
                status = fields.get("status", [""])[0]

                if status not in STATUSES:
                    self.send_error(400)
                    return

                if not update_status(incident_id, status):
                    self.send_error(404)
                    return

            else:
                simulate_response(incident_id)

        except (ValueError, UnicodeDecodeError, TypeError):
            self.send_error(400)
            return

        except Exception as error:
            print("Dashboard action error:", error, flush=True)
            self.send_error(500, "Response operation failed")
            return

        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


if __name__ == "__main__":
    server = ThreadingHTTPServer(
        ("127.0.0.1", 8766),
        SOCDashboard
    )

    print("SOC Dashboard V3 running on http://127.0.0.1:8766")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

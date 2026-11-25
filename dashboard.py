
import json
from collections import deque
from integrations.incident_store import list_incidents
from html import escape
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = Path(__file__).resolve().parent
ALERT_FILE = BASE / "alerts" / "live_ssh_alerts.jsonl"



def get_alerts():
    incidents = list_incidents()

    return [
        {
            "source_ip": row["source_ip"],
            "failed_attempts": row["attempts"],
            "severity": row["severity"],
            "detected_at": row["detected_at"],
            "status": row["status"],
        }
        for row in incidents
    ]



class Dashboard(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return

        alerts = get_alerts()
        rows = []

        for alert in alerts:
            ip = escape(str(alert.get("source_ip", "Unknown")))
            count = escape(str(alert.get("failed_attempts", 0)))
            severity = escape(str(alert.get("severity", "medium")))
            status = escape(str(alert.get("status", "open")))
            timestamp = escape(str(alert.get("detected_at", "N/A")))
            rows.append(
                f"<tr><td>{ip}</td><td>{count}</td>"
                f"<td>{severity}</td><td>{status}</td>"
                f"<td>{timestamp}</td></tr>"
            )


        table_rows = "".join(rows) or (
            "<tr><td colspan='5'>No alerts yet</td></tr>"
        )

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width">
<title>Automated SOC Dashboard</title>
<style>
body {{
  font-family: Arial, sans-serif;
  background: #0b1220;
  color: #e2e8f0;
  margin: 0;
  padding: 32px;
}}
h1 {{ color: #60a5fa; }}
.panel {{
  background: #172338;
  padding: 24px;
  border-radius: 12px;
  margin: 20px 0;
}}
.number {{
  font-size: 36px;
  font-weight: bold;
  color: #fb7185;
}}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{
  text-align: left;
  padding: 12px;
  border-bottom: 1px solid #334155;
}}
th {{ color: #93c5fd; }}
</style>
</head>
<body>
<h1>🛡 Automated SOC Dashboard</h1>
<p>Local Security Monitoring System</p>
<div class="panel">
  <h2>Recent Security Alerts</h2>
  <div class="number">{len(alerts)}</div>
  <p>Showing up to the latest 100 alerts</p>
</div>
<div class="panel">
  <h2>SSH Threat Detection</h2>
  <table>
    <tr>
      <th>Source IP</th>
      <th>Failed Attempts</th>
      <th>Severity</th>
      <th>Status</th>
      <th>Timestamp</th>
    </tr>
    {table_rows}
  </table>
</div>
<p>Refreshes automatically every 5 seconds.</p>
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


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Dashboard)
    print("SOC Dashboard running on http://127.0.0.1:8765")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

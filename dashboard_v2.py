
from html import escape
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from secrets import token_urlsafe
from urllib.parse import parse_qs

from integrations.incident_store import (
    list_incidents,
    update_status,
)

STATUSES = ("open", "investigating", "resolved")
CSRF_TOKEN = token_urlsafe(32)


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

            buttons = ""

            for status in STATUSES:
                disabled = "disabled" if status == current else ""

                buttons += f"""
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

            rows.append(f"""
            <tr>
                <td>#{incident_id}</td>
                <td>{escape(str(incident["source_ip"]))}</td>
                <td>{int(incident["attempts"])}</td>
                <td>{escape(str(incident["severity"]))}</td>
                <td>{escape(current.title())}</td>
                <td><div class="actions">{buttons}</div></td>
            </tr>
            """)

        table = "".join(rows) or (
            "<tr><td colspan='6'>No incidents yet</td></tr>"
        )

        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="10">
        <title>Automated SOC Dashboard</title>
        <style>
            body {{
                background: #0b1220;
                color: #e2e8f0;
                font-family: Arial, sans-serif;
                padding: 30px;
            }}
            h1 {{ color: #60a5fa; }}
            .card {{
                background: #172338;
                padding: 24px;
                border-radius: 12px;
                margin: 20px 0;
                overflow-x: auto;
            }}
            .count {{
                font-size: 36px;
                color: #fb7185;
                font-weight: bold;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                padding: 14px;
                text-align: left;
                border-bottom: 1px solid #334155;
            }}
            th {{ color: #93c5fd; }}
            .actions {{
                display: flex;
                gap: 6px;
            }}
            button {{
                background: #2563eb;
                color: white;
                border: none;
                padding: 9px;
                border-radius: 6px;
                cursor: pointer;
            }}
            button:disabled {{
                background: #475569;
                cursor: default;
            }}
        </style>
        </head>
        <body>
            <h1>Automated SOC Dashboard</h1>
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
                    {table}
                </table>
            </div>
            <p>Refreshes every 10 seconds.</p>
        </body>
        </html>
        """

        data = html.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/status":
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
            status = fields.get("status", [""])[0]

            if not compare_digest(token, CSRF_TOKEN):
                self.send_error(403)
                return

            if incident_id <= 0 or status not in STATUSES:
                self.send_error(400)
                return

            if not update_status(incident_id, status):
                self.send_error(404)
                return

        except (ValueError, UnicodeDecodeError):
            self.send_error(400)
            return

        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


if __name__ == "__main__":
    server = ThreadingHTTPServer(
        ("127.0.0.1", 8765),
        SOCDashboard
    )
    print("SOC Dashboard V2 running on port 8765")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from database import initialize_database
from database import get_connection
import json

PORT = 8099

class GuestAccessHandler(BaseHTTPRequestHandler):
    def do_GET(self):

        if self.path == "/health":
            try:
                with get_connection() as connection:
                    rows = connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' ORDER BY name"
                    ).fetchall()

                tables = [row["name"] for row in rows]
                required = {
                    "reservations",
                    "reservation_doors",
                    "access_events"
                }

                result = {
                    "database": "OK" if required.issubset(tables) else "INCOMPLETE",
                    "tables": tables
                }
                status = 200 if required.issubset(tables) else 503

            except Exception:
                result = {"database": "ERROR"}
                status = 503

            data = json.dumps(result).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Guest Access Manager</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
        </head>
        <body>
            <h1>Guest Access Manager</h1>
            <h2>System Setup Successful</h2>
            <p>Reservation database: Not configured</p>
            <p>Schlage lock connection: Not configured</p>
            <p>Guest PIN automation: Not configured</p>
            <p>A101 pilot: Existing Home Assistant scripts unchanged</p>
        </body>
        </html>
        """
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

if __name__ == "__main__":
    initialize_database()
    server = HTTPServer(("0.0.0.0", PORT), GuestAccessHandler)
    print(f"Guest Access Manager listening on port {PORT}", flush=True)
    server.serve_forever()

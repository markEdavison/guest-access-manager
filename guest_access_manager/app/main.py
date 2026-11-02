
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from database import initialize_database
from database import get_connection
import json
from urllib.parse import parse_qs

PORT = 8099
# Keep the web server restricted to Home Assistant ingress.
# Direct network access remains disabled during development.
HOST = "0.0.0.0"

class GuestAccessHandler(BaseHTTPRequestHandler):
    

    def do_POST(self):
        # Reject oversized or invalid login requests.
        try:
            content_length = int(
                self.headers.get("Content-Length", "0")
            )
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return

        if content_length <= 0 or content_length > 4096:
            self.send_error(413, "Invalid request size")
            return
        if self.path != "/login":
            self.send_error(404, "Not Found")
            return

        # Accept only standard HTML form submissions.
        content_type = self.headers.get("Content-Type", "")

        if content_type.split(";", 1)[0].strip().lower() != \
                "application/x-www-form-urlencoded":
            self.send_error(415, "Unsupported Media Type")
            return

        try:
            body = self.rfile.read(content_length)
            form = parse_qs(
                body.decode("utf-8"),
                keep_blank_values=True,
                max_num_fields=10
            )
        except (UnicodeDecodeError, ValueError):
            self.send_error(400, "Invalid login form")
            return

        # Login remains disabled until CSRF validation,
        # authentication, and rate limiting are connected.
        self.send_error(403, "Login not enabled yet")

    def do_GET(self):


        if self.path == "/login":
            from auth import create_csrf_token
            from http.cookies import SimpleCookie

            try:
                csrf_token = create_csrf_token()

                with open("/app/login.html", "r", encoding="utf-8") as file:
                    html = file.read()

                html = html.replace(
                    "{{CSRF_TOKEN}}",
                    csrf_token
                )
                data = html.encode("utf-8")

                cookie = SimpleCookie()
                cookie["gam_csrf"] = csrf_token
                cookie["gam_csrf"]["path"] = "/"
                cookie["gam_csrf"]["httponly"] = True
                cookie["gam_csrf"]["samesite"] = "Strict"
                # Secure=True will be required for HTTPS deployment.

                self.send_response(200)
                self.send_header(
                    "Content-Type",
                    "text/html; charset=utf-8"
                )
                self.send_header(
                    "Set-Cookie",
                    cookie["gam_csrf"].OutputString()
                )
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            except OSError:
                self.send_error(500, "Login page unavailable")

            return

        if self.path == "/staff-check":
 
            # Only trust identity headers from Home Assistant Supervisor.
            trusted_proxy = self.client_address[0] == "172.30.32.2"

            if trusted_proxy:
                username = self.headers.get(
                    "X-Remote-User-Name", ""
                )
                user_id = self.headers.get(
                    "X-Remote-User-Id", ""
                )
            else:
                username = ""
                user_id = ""

            result = {
                "authenticated": bool(user_id),
                "front_desk": bool(user_id and username == "frontdesk")
            }

            data = json.dumps(result).encode("utf-8")
            self.send_response(200 if user_id else 403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

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

        # Require a valid staff session for the reservation page.
        from http.cookies import SimpleCookie
        from sessions import get_session_user

        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
            session_cookie = cookies.get("gam_session")
            token = session_cookie.value if session_cookie else None
        except Exception:
            token = None

        user = get_session_user(token)

        if user is None:
            self.send_response(302)
            self.send_header("Location", "login")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
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
            
<h2>New Guest Reservation</h2>

<form>
    <label>Guest Name</label>
    <input type="text" name="guest_name" required>

    <label>Guest Email</label>
    <input type="email" name="guest_email" required>

    <label>Reservation Number</label>
    <input type="text" name="reservation_number" required>

    <label>Check-in Date and Time</label>
    <input type="datetime-local" name="checkin" id="checkin" required>

    <label>Checkout Date and Time</label>
    <input type="datetime-local" name="checkout" required>

    <label>Assigned Room</label>
    <select name="room">
        <option value="A101">A101</option>
    </select>

    <p>Reservation saving is not enabled yet.</p>
</form>

<script>
    const checkin = document.getElementById("checkin");
    const date = new Date();
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
   
checkin.value = `${year}-${month}-${day}T14:30`;

const checkout = document.querySelector('input[name="checkout"]');
const nextDay = new Date(date);
nextDay.setDate(nextDay.getDate() + 1);

const checkoutYear = nextDay.getFullYear();
const checkoutMonth = String(nextDay.getMonth() + 1).padStart(2, "0");
const checkoutDay = String(nextDay.getDate()).padStart(2, "0");

checkout.value = `${checkoutYear}-${checkoutMonth}-${checkoutDay}T11:30`;

</script>

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
    server = HTTPServer((HOST, PORT), GuestAccessHandler)
    print(f"Guest Access Manager listening on port {PORT}", flush=True)
    server.serve_forever()


from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import json
def get_admin_settings():
    """Read initial administrator settings from Home Assistant."""
    with open("/data/options.json", "r", encoding="utf-8") as file:
        options = json.load(file)

    return (
        options.get("admin_username", ""),
        options.get("admin_password", "")
    )
from database import initialize_database
from database import get_connection
from database import save_reservation

from urllib.parse import parse_qs

PORT = 8099
# Keep the web server restricted to Home Assistant ingress.
# Direct network access remains disabled during development.
HOST = "0.0.0.0"

class GuestAccessHandler(BaseHTTPRequestHandler):
    

    def do_POST(self):
        from sessions import get_session_user
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

        if self.path == "/save-reservation":
            from http.cookies import SimpleCookie

            cookies = SimpleCookie()
            try:
                cookies.load(self.headers.get("Cookie", ""))
                session = cookies.get("gam_session")
                token = session.value if session else None
            except Exception:
                token = None

            user = get_session_user(token)

            if user is None:
                self.send_error(403, "Staff login required")
                return
            from auth import verify_csrf_token

            csrf_cookie = cookies.get("gam_csrf")
            expected_token = (
                csrf_cookie.value if csrf_cookie else None
            )

            if not expected_token:
                self.send_error(403, "Missing security token")
                return

            try:
                body = self.rfile.read(content_length)
                form = parse_qs(
                    body.decode("utf-8"),
                    keep_blank_values=True,
                    max_num_fields=10
                )
                submitted_tokens = form.get("csrf_token", [])
            except (UnicodeDecodeError, ValueError):
                self.send_error(400, "Invalid reservation form")
                return

            if (
                len(submitted_tokens) != 1
                or not verify_csrf_token(
                    submitted_tokens[0], expected_token
                )
            ):
                self.send_error(403, "Invalid security token")
                return
            fields = (
                "reservation_number",
                "guest_name",
                "guest_email",
                "checkin",
                "checkout",
                "room"
            )

            if any(
                len(form.get(field, [])) != 1
                or not form[field][0].strip()
                for field in fields
            ):
                self.send_error(400, "Missing or invalid reservation fields")
                return

            reservation = {
                field: form[field][0].strip()
                for field in fields
            }

            if reservation["checkout"] <= reservation["checkin"]:
                self.send_error(400, "Checkout must be after check-in")
                return
            from datetime import datetime

            try:
                checkin_dt = datetime.fromisoformat(
                    reservation["checkin"]
                )
                checkout_dt = datetime.fromisoformat(
                    reservation["checkout"]
                )
            except ValueError:
                self.send_error(400, "Invalid reservation dates")
                return

            if checkout_dt <= checkin_dt:
                self.send_error(400, "Checkout must be after check-in")
                return

            import sqlite3

            try:
                reservation_id = save_reservation(
                    reservation["reservation_number"],
                    reservation["guest_name"],
                    reservation["guest_email"],
                    reservation["checkin"],
                    reservation["checkout"],
                    reservation["room"]
                )
            except sqlite3.IntegrityError:
                self.send_error(409, "Reservation number already exists")
                return
            except sqlite3.Error:
                self.send_error(500, "Unable to save reservation")
                return

            self.send_response(303)
            self.send_header("Location", "./")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
            from email.utils import parseaddr

            email = reservation["guest_email"]

            if (
                len(email) > 254
                or any(char.isspace() for char in email)
                or parseaddr(email)[1] != email
                or email.count("@") != 1
                or "." not in email.split("@")[1]
            ):
                self.send_error(400, "Invalid guest email")
                return            
        if self.path == "/logout":
            from http.cookies import SimpleCookie
            from sessions import delete_session

            cookies = SimpleCookie()

            try:
                cookies.load(self.headers.get("Cookie", ""))
                session = cookies.get("gam_session")
                token = session.value if session else None
            except Exception:
                token = None

            # Keep logout disabled until CSRF and
            # request-origin checks are implemented.

            from auth import verify_csrf_token

            csrf_cookie = cookies.get("gam_csrf")
            expected_token = (
                csrf_cookie.value if csrf_cookie else None
            )

            if not token or not expected_token:
                self.send_error(403, "Invalid logout request")
                return


            # Verify the submitted logout security token.
            try:
                body = self.rfile.read(content_length)
                form = parse_qs(
                    body.decode("utf-8"),
                    keep_blank_values=True,
                    max_num_fields=10
                )
                submitted_tokens = form.get("csrf_token", [])
            except (UnicodeDecodeError, ValueError):
                self.send_error(400, "Invalid logout form")
                return

            if (
                len(submitted_tokens) != 1
                or not verify_csrf_token(
                    submitted_tokens[0], expected_token
                )
            ):
                self.send_error(403, "Invalid security token")
                return


            # Invalidate the session in SQLite.
            delete_session(token)

            # Clear the browser's session cookie.
            expired_cookie = SimpleCookie()
            expired_cookie["gam_session"] = ""
            expired_cookie["gam_session"]["path"] = "/"
            expired_cookie["gam_session"]["httponly"] = True
            expired_cookie["gam_session"]["samesite"] = "Strict"
            expired_cookie["gam_session"]["max-age"] = 0

            self.send_response(303)
            self.send_header(
                "Set-Cookie",
                expired_cookie["gam_session"].OutputString()
            )
            self.send_header("Location", "login")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
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

        from http.cookies import SimpleCookie
        from auth import verify_csrf_token

        cookies = SimpleCookie()

        try:
            cookies.load(self.headers.get("Cookie", ""))
            csrf_cookie = cookies.get("gam_csrf")
            expected_token = (
                csrf_cookie.value if csrf_cookie else None
            )
        except Exception:
            expected_token = None

        submitted_tokens = form.get("csrf_token", [])

        if len(submitted_tokens) != 1 or not verify_csrf_token(
            submitted_tokens[0], expected_token
        ):
            self.send_error(403, "Invalid security token")
            return

        usernames = form.get("username", [])
        passwords = form.get("password", [])

        if len(usernames) != 1 or len(passwords) != 1:
            self.send_error(400, "Invalid login fields")
            return

        username = usernames[0].strip()
        password = passwords[0]

        if (
            not username
            or not password
            or len(username) > 100
            or len(password) > 1024
        ):
            self.send_error(400, "Invalid login fields")
            return

        from auth import login_is_rate_limited, ip_is_rate_limited

        # Use the direct connection address for now.
        # Proxy-aware client identification must be
        # configured before LAN deployment.
        source_ip = self.client_address[0]

        if (
            login_is_rate_limited(username, source_ip)
            or ip_is_rate_limited(source_ip)
        ):
            self.send_error(429, "Too many login attempts")
            return

        # Login remains disabled until CSRF validation,
        # authentication, and rate limiting are connected.
        
        from auth import authenticate_staff_user

        # Verify credentials without enabling login yet.
        staff_user = authenticate_staff_user(
            username,
            password
        )

        if staff_user is None:
            from auth import record_login_attempt

            record_login_attempt(
                username,
                source_ip,
                False
            )
            self.send_error(401, "Invalid username or password")
            return

        # Record successful credential verification.
        # A login session is not created yet.
        from auth import record_login_attempt

        record_login_attempt(
            username,
            source_ip,
            True
        )

        from sessions import save_session

        # Create a session token after successful
        # credential verification.
        session_token = save_session(staff_user["id"])

        # Prepare the authenticated session cookie.
        session_cookie = SimpleCookie()
        session_cookie["gam_session"] = session_token
        session_cookie["gam_session"]["path"] = "/"
        session_cookie["gam_session"]["httponly"] = True
        session_cookie["gam_session"]["samesite"] = "Strict"
        session_cookie["gam_session"]["max-age"] = 28800

        # The cookie is not sent until login is enabled.
        # HTTPS deployment will require the Secure flag.

    
        # Send the authenticated session cookie.
        self.send_response(303)
        self.send_header(
            "Set-Cookie",
            session_cookie["gam_session"].OutputString()
        )
        self.send_header("Location", "./")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()
        return

    def do_GET(self):

        if self.path == "/logout":
            # Logout will be implemented as a protected
            # POST request to prevent unwanted logouts.
            self.send_error(405, "Use POST to log out")
            return

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
        if self.path == "/a101-codes":
            from urllib.request import Request, urlopen

            token = os.environ.get("SUPERVISOR_TOKEN", "")

            request = Request(
                "http://supervisor/core/api/services/schlage/get_codes?return_response",
                data=json.dumps({
                    "entity_id": "lock.a101_main"
                }).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                method="POST"
            )

            try:
                with urlopen(request, timeout=15) as response:
                    result = json.load(response)

                # Return code names and IDs only. Never expose PINs.
                service_data = result.get("service_response", {})

                codes = []

                if isinstance(service_data, dict):
                    lock_data = service_data.get("lock.a101_main", {})

                    if isinstance(lock_data, dict):
                        for code_id, details in lock_data.items():
                            if isinstance(details, dict):
                                codes.append({
                                    "id": str(code_id),
                                    "name": details.get("name", "")
                                })
                                
                output = json.dumps({
                    "success": True,
                    "response_received": bool(service_data),
                    "codes": codes
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(output)))
                self.end_headers()
                self.wfile.write(output)

            except Exception as error:
                print(
                    "A101 code retrieval failed:",
                    type(error).__name__,
                    flush=True
                )
                self.send_error(502, "Unable to retrieve A101 codes")
            return
        if self.path == "/a101-status":
            from urllib.request import Request, urlopen

            token = os.environ.get("SUPERVISOR_TOKEN", "")
            request = Request(
                "http://supervisor/core/api/states/lock.a101_main",
                headers={"Authorization": f"Bearer {token}"}
            )

            try:
                with urlopen(request, timeout=10) as response:
                    result = json.load(response)

                data = json.dumps({
                    "entity_id": result.get("entity_id"),
                    "state": result.get("state")
                }).encode("utf-8")

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as error:
                print("A101 status check failed:", type(error).__name__, flush=True)
                self.send_error(502, "Unable to read A101 status")
            return

        if self.path == "/check-test-reservation":
            from http.cookies import SimpleCookie
            from sessions import get_session_user

            cookies = SimpleCookie()
            try:
                cookies.load(self.headers.get("Cookie", ""))
                session = cookies.get("gam_session")
                token = session.value if session else None
            except Exception:
                token = None

            if get_session_user(token) is None:
                self.send_error(403, "Staff login required")
                return

            with get_connection() as connection:
                row = connection.execute(
                    "SELECT id FROM reservations WHERE reservation_number = ?",
                    ("TEST001",)
                ).fetchone()

            data = json.dumps({
                "reservation_found": row is not None
            }).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/api-test":
            from urllib.request import Request, urlopen

            token = os.environ.get("SUPERVISOR_TOKEN", "")

            print("SUPERVISOR_TOKEN present:", bool(token), flush=True)

            print(
                "Supervisor-related environment variables:",
                [
                    name for name in os.environ
                    if "SUPERVISOR" in name or "HASSIO" in name
                ],
                flush=True
            )            
            if not token:
                self.send_error(503, "API token unavailable")
                return

            request = Request(
                "http://supervisor/core/api/",
                headers={"Authorization": f"Bearer {token}"}
            )

            try:
                with urlopen(request, timeout=10) as response:
                    result = response.read()
                    status = response.status
            except Exception:
                self.send_error(502, "Home Assistant API unavailable")
                return

            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)
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
                    "": "OK" if required.issubset(tables) else "INCOMPLETE",
                    "tables": tables
                }
                status = 200 if required.issubset(tables) else 503

            except Exception:
                result = {"": "ERROR"}
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
            
<form method="POST" action="logout">
    <input
        type="hidden"
        name="csrf_token"
        value="{{CSRF_TOKEN}}"
    >
    <button type="submit">Log Out</button>
</form>

            <h2>System Setup Successful</h2>
            
<h2>New Guest Reservation</h2>

<form method="POST" action="save-reservation">
    <input
    type="hidden"
    name="csrf_token"
    value="{{CSRF_TOKEN}}"
    >
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

    <button type="submit">Save Reservation</button>
    <p id="reservation-message">Enter reservation details and click Save Reservation.</p>
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

            <p>Reservation : Not configured</p>
<p>Schlage lock connection: Connected to Home Assistant</p>
<p>A101 lock status: <span id="a101-state">Checking...</span></p>
<h3>A101 Programmed Codes</h3>
<ul id="a101-codes-list">
  <li>Loading...</li>
</ul>

<script>
fetch("a101-codes")
  .then(response => {
    if (!response.ok) throw new Error("Request failed");
    return response.json();
  })
  .then(data => {
    const list = document.getElementById("a101-codes-list");
    list.replaceChildren();

    if (!data.codes || data.codes.length === 0) {
      const item = document.createElement("li");
      item.textContent = "No codes found";
      list.appendChild(item);
      return;
    }

    data.codes.forEach(code => {
      const item = document.createElement("li");
      item.textContent = `${code.name || "Unnamed"} (${code.id})`;
      list.appendChild(item);
    });
  })
  .catch(() => {
    const list = document.getElementById("a101-codes-list");
    list.textContent = "Unable to load codes";
  });
</script>
<script>
fetch("a101-status")
  .then(response => response.json())
  .then(data => {
    document.getElementById("a101-state").textContent = data.state || "Unknown";
  })
  .catch(() => {
    document.getElementById("a101-state").textContent = "Unavailable";
  });
</script>            <p>Guest PIN automation: Not configured</p>
            <p>A101 pilot: Existing Home Assistant scripts unchanged</p>
        </body>
        </html>
        """
        
        from auth import create_csrf_token
        from http.cookies import SimpleCookie

        logout_csrf_token = create_csrf_token()

        html = html.replace(
            "{{CSRF_TOKEN}}",
            logout_csrf_token
        )

        logout_cookie = SimpleCookie()
        logout_cookie["gam_csrf"] = logout_csrf_token
        logout_cookie["gam_csrf"]["path"] = "/"
        logout_cookie["gam_csrf"]["httponly"] = True
        logout_cookie["gam_csrf"]["samesite"] = "Strict"

        data = html.encode("utf-8")
        self.send_response(200)
        
        self.send_header(
            "Set-Cookie",
            logout_cookie["gam_csrf"].OutputString()
        )
        self.send_header("Cache-Control", "no-store")

        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    initialize_database()

    from auth import create_staff_user

    try:
        admin_username, admin_password = get_admin_settings()
    except (OSError, ValueError):
        admin_username, admin_password = "", ""

    if admin_username and admin_password:
        with get_connection() as connection:
            existing = connection.execute(
                "SELECT id FROM staff_users WHERE username = ?",
                (admin_username,)
            ).fetchone()

        if existing is None:
            create_staff_user(
                admin_username,
                admin_password,
                role="admin"
            )
            print("Initial administrator account created.", flush=True)

    server = HTTPServer((HOST, PORT), GuestAccessHandler)
    print(f"Guest Access Manager listening on port {PORT}", flush=True)
    server.serve_forever()

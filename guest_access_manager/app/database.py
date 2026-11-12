
import os
import sqlite3

DB_PATH = os.environ.get(
    "GUEST_ACCESS_DB",
    "/data/guest_access.db"
)

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS reservations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reservation_number TEXT NOT NULL UNIQUE,
                guest_name TEXT NOT NULL,
                guest_email TEXT NOT NULL,
                checkin TEXT NOT NULL,
                checkout TEXT NOT NULL,
                room TEXT,
                pin TEXT,
                status TEXT NOT NULL DEFAULT 'Pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS reservation_doors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reservation_id INTEGER NOT NULL,
                door_id TEXT NOT NULL,
                programming_status TEXT NOT NULL DEFAULT 'Pending',
                UNIQUE(reservation_id, door_id),
                FOREIGN KEY(reservation_id)
                    REFERENCES reservations(id)
                    ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS access_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reservation_id INTEGER,
                door_id TEXT,
                event_type TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(reservation_id)
                    REFERENCES reservations(id)
            )
        """)
        
        connection.execute("""
            CREATE TABLE IF NOT EXISTS staff_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'frontdesk',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS staff_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id)
                    REFERENCES staff_users(id)
                    ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                attempted_at INTEGER NOT NULL,
                successful INTEGER NOT NULL DEFAULT 0
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
                idx_login_attempts_lookup
            ON login_attempts
                (username, source_ip, attempted_at)
        """)


from datetime import datetime

def save_reservation(
    reservation_number,
    guest_name,
    guest_email,
    checkin,
    checkout,
    doors
):
    reservation_number = reservation_number.strip()
    guest_name = guest_name.strip()
    guest_email = guest_email.strip()

    if not reservation_number or not guest_name or not guest_email:
        raise ValueError("Reservation number, guest name, and email are required.")

    if (
        "@" not in guest_email
        or guest_email.startswith("@")
        or guest_email.endswith("@")
    ):
        raise ValueError("Enter a valid guest email address.")

    try:
        start = datetime.fromisoformat(checkin)
        end = datetime.fromisoformat(checkout)
    except (ValueError, TypeError):
        raise ValueError("Invalid check-in or checkout date.")

    if end <= start:
        raise ValueError("Checkout must be after check-in.")

    doors = list(dict.fromkeys(doors))

    if not doors:
        raise ValueError("Select at least one room.")

    # Only A101 is configured during the pilot.
    allowed_doors = {"A101"}

    if any(door not in allowed_doors for door in doors):
        raise ValueError("An assigned room is not configured.")

    with get_connection() as connection:
        existing = connection.execute(
            "SELECT id FROM reservations WHERE reservation_number = ?",
            (reservation_number,)
        ).fetchone()

        if existing:
            raise ValueError("This reservation number already exists.")

        cursor = connection.execute(
            """
            INSERT INTO reservations
            (reservation_number, guest_name, guest_email,
             checkin, checkout, status)
            VALUES (?, ?, ?, ?, ?, 'Pending')
            """,
            (
                reservation_number,
                guest_name,
                guest_email,
                checkin,
                checkout
            )
        )

        reservation_id = cursor.lastrowid

        for door in doors:
            connection.execute(
                """
                INSERT INTO reservation_doors
                (reservation_id, door_id)
                VALUES (?, ?)
                """,
                (reservation_id, door)
            )

    return reservation_id

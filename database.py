# database.py
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta

DB_PATH = "shepherd.db"

TIER_LIMITS = {
    "free":       1,
    "starter":   10,
    "pro":       999999,  # unlimited
    "enterprise": 999999,
}

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Creates tables if they don't exist. Safe to call every startup."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            tier        TEXT DEFAULT 'free',
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            api_key     TEXT UNIQUE NOT NULL,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_usage (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            scanned_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            target_url  TEXT,
            score       REAL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized.")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_user(email: str, password: str, tier: str = "free"):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        hashed = hash_password(password)
        cursor.execute(
            "INSERT INTO users (email, password, tier) VALUES (?, ?, ?)",
            (email, hashed, tier)
        )
        user_id = cursor.lastrowid

        # Auto-generate API key for the new user
        api_key = f"shep-{tier[:3]}-{secrets.token_hex(16)}"
        cursor.execute(
            "INSERT INTO api_keys (user_id, api_key) VALUES (?, ?)",
            (user_id, api_key)
        )
        conn.commit()
        return {"user_id": user_id, "api_key": api_key, "tier": tier}
    except sqlite3.IntegrityError:
        return None  # email already exists
    finally:
        conn.close()

def get_user_by_email(email: str, password: str):
    conn = get_connection()
    cursor = conn.cursor()
    hashed = hash_password(password)
    cursor.execute(
        "SELECT * FROM users WHERE email = ? AND password = ?",
        (email, hashed)
    )
    user = cursor.fetchone()
    if not user:
        conn.close()
        return None
    cursor.execute(
        "SELECT api_key FROM api_keys WHERE user_id = ?",
        (user["id"],)
    )
    key_row = cursor.fetchone()
    conn.close()
    return {
        "user_id": user["id"],
        "email": user["email"],
        "tier": user["tier"],
        "api_key": key_row["api_key"] if key_row else None
    }

def get_user_by_api_key(api_key: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT users.id, users.email, users.tier, api_keys.api_key
        FROM api_keys
        JOIN users ON api_keys.user_id = users.id
        WHERE api_keys.api_key = ?
    """, (api_key,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def count_scans_this_month(user_id: int) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    start_of_month = datetime.now().replace(day=1, hour=0, minute=0, second=0).isoformat()
    cursor.execute("""
        SELECT COUNT(*) as total FROM scan_usage
        WHERE user_id = ? AND scanned_at >= ?
    """, (user_id, start_of_month))
    row = cursor.fetchone()
    conn.close()
    return row["total"] if row else 0

def log_scan(user_id: int, target_url: str, score: float):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_usage (user_id, target_url, score) VALUES (?, ?, ?)",
        (user_id, target_url, score)
    )
    conn.commit()
    conn.close()

def check_scan_limit(user_id: int, tier: str) -> dict:
    used = count_scans_this_month(user_id)
    limit = TIER_LIMITS.get(tier, 1)
    return {
        "used": used,
        "limit": limit,
        "allowed": used < limit
    }
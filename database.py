import sqlite3
import secrets
import hashlib
from datetime import datetime

DB_PATH = "shepherd.db"

TIER_LIMITS = {
    "free":       10,
    "starter":    75,      # FIX 1: was 50, settings.html advertises 75
    "pro":        200,     # FIX 1: was 999999, settings.html advertises 200
    "enterprise": 999999,  # unlimited
}

# ─────────────────────────────────────────────
#  Connection
# ─────────────────────────────────────────────
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ─────────────────────────────────────────────
#  Init DB
# ─────────────────────────────────────────────
def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            email           TEXT UNIQUE NOT NULL,
            password        TEXT NOT NULL,
            tier            TEXT DEFAULT 'free',
            email_alerts    INTEGER DEFAULT 0,
            alert_email     TEXT,
            slack_webhook   TEXT,
            slack_alerts    INTEGER DEFAULT 0,
            company_name    TEXT DEFAULT 'Shepherd AI',
            logo_url        TEXT,
            custom_keywords TEXT DEFAULT '',
            created_at      TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_token TEXT UNIQUE NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
""")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_usage (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
            target_url TEXT,
            score      REAL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized.")

# ─────────────────────────────────────────────
#  Password
# ─────────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ─────────────────────────────────────────────
#  Auth
# ─────────────────────────────────────────────
def create_user(email: str, password: str, tier: str = "free"):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        hashed = hash_password(password)
        cursor.execute(
            "INSERT INTO users (email, password, tier, alert_email) VALUES (?, ?, ?, ?)",
            (email, hashed, tier, email)
        )
        user_id = cursor.lastrowid
        api_key = f"shep-{tier[:3]}-{secrets.token_hex(16)}"
        cursor.execute(
            "INSERT INTO api_keys (user_id, api_key) VALUES (?, ?)",
            (user_id, api_key)
        )
        conn.commit()
        return {"user_id": user_id, "api_key": api_key, "tier": tier}
    except sqlite3.IntegrityError:
        return None
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
    cursor.execute("SELECT api_key FROM api_keys WHERE user_id = ?", (user["id"],))
    key_row = cursor.fetchone()
    conn.close()
    return {
        "id":      user["id"],
        "email":   user["email"],
        "tier":    user["tier"],
        "api_key": key_row["api_key"] if key_row else None,
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

# ─────────────────────────────────────────────
#  Tier Upgrade  (called by Paystack webhook)
# ─────────────────────────────────────────────
def update_user_tier(user_id: int, new_tier: str):
    """Upgrades a user's tier after successful Paystack payment."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET tier = ? WHERE id = ?",
        (new_tier, user_id)
    )
    conn.commit()
    conn.close()
    print(f"✅ User {user_id} upgraded to {new_tier}")

# ─────────────────────────────────────────────
#  Scan Limits & Logging
# ─────────────────────────────────────────────
def count_scans_this_month(user_id: int) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    start_of_month = datetime.now().replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    ).isoformat()
    cursor.execute(
        "SELECT COUNT(*) as total FROM scan_usage WHERE user_id = ? AND scanned_at >= ?",
        (user_id, start_of_month)
    )
    row = cursor.fetchone()
    conn.close()
    return row["total"] if row else 0

def check_scan_limit(user_id: int, tier: str) -> dict:
    used  = count_scans_this_month(user_id)
    limit = TIER_LIMITS.get(tier, 10)
    return {
        "used":    used,
        "limit":   limit,
        "allowed": used < limit,
    }

def log_scan(user_id: int, target_url: str, score: float):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_usage (user_id, target_url, score) VALUES (?, ?, ?)",
        (user_id, target_url, score)
    )
    conn.commit()
    conn.close()

def get_scan_history(user_id: int, limit: int = 20) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT target_url, score, scanned_at
        FROM scan_usage
        WHERE user_id = ?
        ORDER BY scanned_at DESC
        LIMIT ?
    """, (user_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ─────────────────────────────────────────────
#  Email Alert Settings
# ─────────────────────────────────────────────
def get_alert_settings(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT email_alerts, alert_email FROM users WHERE id = ?",
        (user_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "email_alerts": bool(row["email_alerts"]),
            "alert_email":  row["alert_email"],
        }
    return None

def save_alert_settings(user_id: int, email_alerts: bool, alert_email: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET email_alerts = ?, alert_email = ? WHERE id = ?",
        (1 if email_alerts else 0, alert_email, user_id)
    )
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
#  Slack Settings
# ─────────────────────────────────────────────
def save_slack_settings(user_id: int, webhook_url: str, slack_alerts: bool):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET slack_webhook = ?, slack_alerts = ? WHERE id = ?",
        (webhook_url, 1 if slack_alerts else 0, user_id)
    )
    conn.commit()
    conn.close()

def get_slack_settings(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT slack_webhook, slack_alerts FROM users WHERE id = ?",
        (user_id,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

# ─────────────────────────────────────────────
#  Enterprise Settings
# ─────────────────────────────────────────────
def save_enterprise_settings(
    user_id: int,
    company_name: str,
    logo_url: str,
    custom_keywords: str,
):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET company_name = ?, logo_url = ?, custom_keywords = ?
        WHERE id = ?
    """, (company_name, logo_url, custom_keywords, user_id))
    conn.commit()
    conn.close()

def get_enterprise_settings(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT company_name, logo_url, custom_keywords FROM users WHERE id = ?",
        (user_id,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}  # FIX 2: dead code removed — nothing after this return

# ─────────────────────────────────────────────
#  Bridge helpers (kept for compatibility)
# ─────────────────────────────────────────────
def get_slack_settings_by_key(api_key: str):
    user = get_user_by_api_key(api_key)
    if not user:
        return None
    return get_slack_settings(user["id"])

def get_enterprise_settings_by_key(api_key: str):
    user = get_user_by_api_key(api_key)
    if not user:
def create_session(user_id: int, session_token: str, expires_at: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO sessions (user_id, session_token, expires_at)
        VALUES (?, ?, ?)
        """,
        (user_id, session_token, expires_at)
    )

    conn.commit()
    conn.close()
def get_session(session_token: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM sessions WHERE session_token = ?",
        (session_token,)
    )

    row = cursor.fetchone()
    conn.close()

    return dict(row) if row else None
        return {}
    return get_enterprise_settings(user["id"])

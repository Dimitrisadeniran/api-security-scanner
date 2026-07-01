"""
database.py
Production database layer for Shepherd AI

Features
---------
• SQLite
• FastAPI compatible
• bcrypt password hashing
• API Keys
• Session Management
• Two-Factor Authentication
• Scan History
• Alert Settings
• Enterprise Settings

Author:
OpenAI (Customized for Shepherd AI)
"""

from __future__ import annotations

import sqlite3
import secrets
import hashlib
import bcrypt
import pyotp

from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List

###############################################################################
# Configuration
###############################################################################

BASE_DIR = Path(__file__).resolve().parent

DATABASE_PATH = BASE_DIR / "shepherd.db"

SESSION_DURATION_DAYS = 30

###############################################################################
# Database Connection
###############################################################################

def dict_factory(cursor, row):
    """
    Return sqlite rows as dictionaries.
    """
    return {
        cursor.description[idx][0]: value
        for idx, value in enumerate(row)
    }


@contextmanager
def get_connection():
    """
    Opens a SQLite connection.

    Automatically commits on success.

    Automatically rolls back on failure.
    """

    conn = sqlite3.connect(DATABASE_PATH)

    conn.row_factory = dict_factory

    conn.execute("PRAGMA foreign_keys = ON")

    try:

        yield conn

        conn.commit()

    except Exception:

        conn.rollback()

        raise

    finally:

        conn.close()
###############################################################################
# Password Helpers
###############################################################################

def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    ).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(
        password.encode(),
        hashed.encode()
    )
    ###############################################################################
# API Keys
###############################################################################

def generate_api_key() -> str:
    return secrets.token_hex(32)
###############################################################################
# Session Tokens
###############################################################################

def generate_session_token() -> str:
    return secrets.token_urlsafe(48)
###############################################################################
# User IDs
###############################################################################

def generate_user_id() -> str:
    return secrets.token_hex(16)
###############################################################################
# Time
###############################################################################

def now():
    return datetime.now().isoformat()
###############################################################################
# Database Schema
###############################################################################

def init_db():
    """
    Creates every table required by Shepherd AI.

    Safe to run multiple times.
    """

    with get_connection() as conn:

        cursor = conn.cursor()

        #######################################################################
        # USERS
        #######################################################################

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(

            id TEXT PRIMARY KEY,

            email TEXT UNIQUE NOT NULL,

            password TEXT NOT NULL,

            tier TEXT NOT NULL DEFAULT 'free',

            created_at TEXT NOT NULL,

            otp_secret TEXT,

            is_2fa_enabled INTEGER DEFAULT 0

        )
        """)

        #######################################################################
        # API KEYS
        #######################################################################

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys(

            api_key TEXT PRIMARY KEY,

            user_id TEXT UNIQUE NOT NULL,

            created_at TEXT,

            FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE

        )
        """)

        #######################################################################
        # SESSIONS
        #######################################################################

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions(

            session_token TEXT PRIMARY KEY,

            user_id TEXT NOT NULL,

            expires_at TEXT NOT NULL,

            created_at TEXT NOT NULL,

            FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE

        )
        """)

        #######################################################################
        # ALERT SETTINGS
        #######################################################################

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_settings(

            user_id TEXT PRIMARY KEY,

            email_alerts INTEGER DEFAULT 1,

            alert_email TEXT,

            FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE

        )
        """)

        #######################################################################
        # SLACK SETTINGS
        #######################################################################

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS slack_settings(

            user_id TEXT PRIMARY KEY,

            slack_webhook TEXT,

            slack_alerts INTEGER DEFAULT 0,

            FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE

        )
        """)

        #######################################################################
        # ENTERPRISE SETTINGS
        #######################################################################

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS enterprise_settings(

            user_id TEXT PRIMARY KEY,

            company_name TEXT DEFAULT '',

            logo_url TEXT DEFAULT '',

            custom_keywords TEXT DEFAULT '',

            FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE

        )
        """)

        #######################################################################
        # SCAN HISTORY
        #######################################################################

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history(

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id TEXT NOT NULL,

            target_url TEXT NOT NULL,

            score REAL NOT NULL,

            scanned_at TEXT NOT NULL,

            FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE

        )
        """)

        #######################################################################
        # INDEXES
        #######################################################################

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_user_email
        ON users(email)
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_api_key
        ON api_keys(api_key)
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_user
        ON scan_history(user_id)
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_session_user
        ON sessions(user_id)
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_session_token
        ON sessions(session_token)
        """)

        conn.commit()

        print("✓ Shepherd database initialized.")
        ###############################################################################
# User Management & Authentication
###############################################################################

def create_user(email: str, password: str, tier: str = "free"):
    """
    Creates a new Shepherd AI user.

    Returns:
        {
            "id": ...,
            "email": ...,
            "tier": ...,
            "api_key": ...
        }

    Returns None if email already exists.
    """

    email = email.strip().lower()

    with get_connection() as conn:

        cursor = conn.cursor()

        # Check existing email
        cursor.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        )

        if cursor.fetchone():
            return None

        user_id = generate_user_id()

        api_key = generate_api_key()

        hashed_password = hash_password(password)

        created = now()

        # Create user
        cursor.execute("""
            INSERT INTO users(

                id,
                email,
                password,
                tier,
                created_at,
                otp_secret,
                is_2fa_enabled

            )

            VALUES(?,?,?,?,?,?,?)
        """, (

            user_id,
            email,
            hashed_password,
            tier,
            created,
            None,
            0

        ))

        # Create API key
        cursor.execute("""

            INSERT INTO api_keys(

                api_key,
                user_id,
                created_at

            )

            VALUES(?,?,?)

        """, (

            api_key,
            user_id,
            created

        ))

        # Default alert settings
        cursor.execute("""

            INSERT INTO alert_settings(

                user_id,
                email_alerts,
                alert_email

            )

            VALUES(?,?,?)

        """, (

            user_id,
            1,
            email

        ))

        # Default Slack settings
        cursor.execute("""

            INSERT INTO slack_settings(

                user_id,
                slack_webhook,
                slack_alerts

            )

            VALUES(?,?,?)

        """, (

            user_id,
            "",
            0

        ))

        # Default enterprise settings
        cursor.execute("""

            INSERT INTO enterprise_settings(

                user_id,
                company_name,
                logo_url,
                custom_keywords

            )

            VALUES(?,?,?,?)

        """, (

            user_id,
            "Shepherd AI",
            "",
            ""

        ))

        conn.commit()

        return {

            "id": user_id,

            "email": email,

            "tier": tier,

            "api_key": api_key

        }


###############################################################################
# Lookup by Email
###############################################################################

def get_user_by_email(email: str, password: str):
    """
    Login helper.

    Returns None if credentials are invalid.
    """

    email = email.strip().lower()

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute("""

            SELECT

                users.*,

                api_keys.api_key

            FROM users

            LEFT JOIN api_keys

            ON users.id = api_keys.user_id

            WHERE users.email = ?

        """, (email,))

        user = cursor.fetchone()

        if not user:
            return None

        if not verify_password(password, user["password"]):
            return None

        return user


###############################################################################
# Lookup by API Key
###############################################################################

def get_user_by_api_key(api_key: str):
    """
    Used by verify_api_key()
    """

    if not api_key:
        return None

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute("""

            SELECT

                users.*,

                api_keys.api_key

            FROM users

            INNER JOIN api_keys

            ON users.id = api_keys.user_id

            WHERE api_keys.api_key = ?

        """, (

            api_key,

        ))

        return cursor.fetchone()


###############################################################################
# Lookup User by ID
###############################################################################

def get_user_by_id(user_id: str):

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute("""

            SELECT

                users.*,

                api_keys.api_key

            FROM users

            LEFT JOIN api_keys

            ON users.id = api_keys.user_id

            WHERE users.id = ?

        """, (

            user_id,

        ))

        return cursor.fetchone()


###############################################################################
# Upgrade User Tier
###############################################################################

def update_user_tier(user_id: str, new_tier: str):

    with get_connection() as conn:

        conn.execute("""

            UPDATE users

            SET tier = ?

            WHERE id = ?

        """, (

            new_tier,

            user_id

        ))

        conn.commit()

        return True
###############################################################################
# Session Management
###############################################################################

def create_session(user_id, session_token, expires_at):

    with get_connection() as conn:

        conn.execute("""
            INSERT INTO sessions(
                session_token,
                user_id,
                expires_at,
                created_at
            )
            VALUES(?,?,?,?)
        """, (
            session_token,
            user_id,
            expires_at,
            now()
        ))

        conn.commit()

    return True

###############################################################################

def get_session(session_token: str):

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute("""

            SELECT *

            FROM sessions

            WHERE session_token = ?

        """, (

            session_token,

        ))

        return cursor.fetchone()


###############################################################################

def delete_session(session_token: str):

    with get_connection() as conn:

        conn.execute("""

            DELETE FROM sessions

            WHERE session_token = ?

        """, (

            session_token,

        ))

        conn.commit()

        return True


###############################################################################

def get_session_user(session_token: str):
    """
    Returns the logged-in user for the given session token.
    """

    session = get_session(session_token)

    if not session:
        return None

    try:
        expires = datetime.fromisoformat(session["expires_at"])
    except Exception:
        return None

    if expires < datetime.now():
        delete_session(session_token)
        return None

    return get_user_by_id(session["user_id"])

###############################################################################
# Two-Factor Authentication
###############################################################################

def generate_otp_secret():
    """
    Creates a new TOTP secret.
    """

    return pyotp.random_base32()


###############################################################################

def get_otp_uri(
    email: str,
    secret: str,
    issuer: str = "Shepherd AI"
):
    """
    Returns provisioning URI for QR code.
    """

    return pyotp.TOTP(secret).provisioning_uri(

        name=email,

        issuer_name=issuer

    )


###############################################################################

def verify_otp(
    secret: str,
    otp_code: str
):
    """
    Verifies a 6-digit OTP.
    """

    if not secret:

        return False

    try:

        totp = pyotp.TOTP(secret)

        return totp.verify(

            otp_code,

            valid_window=1

        )

    except Exception:

        return False


###############################################################################

def store_otp_secret_temp(
    user_id: str,
    secret: str
):
    """
    Saves generated secret before user verifies.
    """

    with get_connection() as conn:

        conn.execute("""

            UPDATE users

            SET otp_secret = ?

            WHERE id = ?

        """, (

            secret,

            user_id

        ))

        conn.commit()

        return True


###############################################################################

def enable_2fa_for_user(
    user_id: str,
    secret: str
):
    """
    Enables 2FA after OTP verification.
    """

    with get_connection() as conn:

        conn.execute("""

            UPDATE users

            SET

                otp_secret = ?,

                is_2fa_enabled = 1

            WHERE id = ?

        """, (

            secret,

            user_id

        ))

        conn.commit()

        return True


###############################################################################

def disable_2fa_for_user(
    user_id: str
):
    """
    Removes user's 2FA.
    """

    with get_connection() as conn:

        conn.execute("""

            UPDATE users

            SET

                otp_secret = NULL,

                is_2fa_enabled = 0

            WHERE id = ?

        """, (

            user_id,

        ))

        conn.commit()

        return True


###############################################################################

def get_user_2fa_status(
    user_id: str
):
    """
    Returns:

    {
        "enabled": True/False
    }
    """

    user = get_user_by_id(user_id)

    if not user:

        return {

            "enabled": False

        }

    return {

        "enabled": bool(
            user["is_2fa_enabled"]
        )

    } 
###############################################################################
# Alert Settings
###############################################################################

def save_alert_settings(
    user_id: str,
    email_alerts: bool,
    alert_email: str
):
    with get_connection() as conn:

        conn.execute("""

            INSERT INTO alert_settings(

                user_id,
                email_alerts,
                alert_email

            )

            VALUES(?,?,?)

            ON CONFLICT(user_id)

            DO UPDATE SET

                email_alerts=excluded.email_alerts,
                alert_email=excluded.alert_email

        """, (

            user_id,
            int(email_alerts),
            alert_email

        ))

        conn.commit()

        return True


###############################################################################

def get_alert_settings(user_id: str):

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute("""

            SELECT *

            FROM alert_settings

            WHERE user_id=?

        """, (

            user_id,

        ))

        row = cursor.fetchone()

        if not row:
            return None

        row["email_alerts"] = bool(row["email_alerts"])

        return row


###############################################################################
# Slack Settings
###############################################################################

def save_slack_settings(
    user_id: str,
    webhook_url: str,
    slack_alerts: bool
):

    with get_connection() as conn:

        conn.execute("""

            INSERT INTO slack_settings(

                user_id,
                slack_webhook,
                slack_alerts

            )

            VALUES(?,?,?)

            ON CONFLICT(user_id)

            DO UPDATE SET

                slack_webhook=excluded.slack_webhook,
                slack_alerts=excluded.slack_alerts

        """, (

            user_id,
            webhook_url,
            int(slack_alerts)

        ))

        conn.commit()

        return True


###############################################################################

def get_slack_settings(user_id: str):

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute("""

            SELECT *

            FROM slack_settings

            WHERE user_id=?

        """, (

            user_id,

        ))

        row = cursor.fetchone()

        if not row:
            return None

        row["slack_alerts"] = bool(row["slack_alerts"])

        return row


###############################################################################
# Enterprise Settings
###############################################################################

def save_enterprise_settings(
    user_id: str,
    company_name: str,
    logo_url: str,
    custom_keywords: str
):

    with get_connection() as conn:

        conn.execute("""

            INSERT INTO enterprise_settings(

                user_id,
                company_name,
                logo_url,
                custom_keywords

            )

            VALUES(?,?,?,?)

            ON CONFLICT(user_id)

            DO UPDATE SET

                company_name=excluded.company_name,
                logo_url=excluded.logo_url,
                custom_keywords=excluded.custom_keywords

        """, (

            user_id,
            company_name,
            logo_url,
            custom_keywords

        ))

        conn.commit()

        return True


###############################################################################

def get_enterprise_settings(user_id: str):

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute("""

            SELECT *

            FROM enterprise_settings

            WHERE user_id=?

        """, (

            user_id,

        ))

        row = cursor.fetchone()

        if not row:

            return {

                "company_name": "Shepherd AI",

                "logo_url": "",

                "custom_keywords": ""

            }

        return row


###############################################################################
# Scan History
###############################################################################

def log_scan(
    user_id: str,
    target_url: str,
    score: float
):

    with get_connection() as conn:

        conn.execute("""

            INSERT INTO scan_history(

                user_id,
                target_url,
                score,
                scanned_at

            )

            VALUES(?,?,?,?)

        """, (

            user_id,
            target_url,
            score,
            now()

        ))

        conn.commit()

        return True


###############################################################################

def get_scan_history(user_id: str):

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute("""

            SELECT *

            FROM scan_history

            WHERE user_id=?

            ORDER BY scanned_at DESC

        """, (

            user_id,

        ))

        return cursor.fetchall()


###############################################################################
# Usage Limits
###############################################################################

SCAN_LIMITS = {

    "free": 10,

    "starter": 100,

    "pro": 1000,

    "enterprise": 999999

}


###############################################################################

def check_scan_limit(
    user_id: str,
    tier: str
):
    """
    Returns

    {
        allowed,
        used,
        limit
    }
    """

    limit = SCAN_LIMITS.get(
        tier,
        10
    )

    month = datetime.now(timezone.utc).strftime("%Y-%m")

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute("""

            SELECT COUNT(*) AS total

            FROM scan_history

            WHERE

                user_id=?

            AND

                substr(scanned_at,1,7)=?

        """, (

            user_id,
            month

        ))

        total = cursor.fetchone()["total"]

    return {

        "allowed": total < limit,

        "used": total,

        "limit": limit

    }
    ###############################################################################
# Database Maintenance Utilities
###############################################################################

def rotate_api_key(user_id: str):
    """
    Generate a brand-new API key for a user.
    """

    new_key = generate_api_key()

    with get_connection() as conn:

        conn.execute("""

            UPDATE api_keys

            SET api_key = ?,
                created_at = ?

            WHERE user_id = ?

        """, (

            new_key,
            now(),
            user_id

        ))

        conn.commit()

    return new_key


###############################################################################

def delete_user(user_id: str):
    """
    Permanently delete a user.
    Foreign keys automatically delete related records.
    """

    with get_connection() as conn:

        conn.execute(

            "DELETE FROM users WHERE id=?",

            (user_id,)

        )

        conn.commit()

        return True


###############################################################################

def cleanup_expired_sessions():
    """
    Remove expired login sessions.
    """

    with get_connection() as conn:

        conn.execute("""
            DELETE FROM sessions
            WHERE expires_at < ?
        """, (
            datetime.now(timezone.utc).isoformat(),
        ))

        conn.commit()


###############################################################################

def count_users():

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute(

            "SELECT COUNT(*) AS total FROM users"

        )

        return cursor.fetchone()["total"]


###############################################################################

def count_scans():

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute(

            "SELECT COUNT(*) AS total FROM scan_history"

        )

        return cursor.fetchone()["total"]


###############################################################################

def get_database_stats():
    """
    Useful for an admin dashboard.
    """

    return {

        "users": count_users(),

        "scans": count_scans()

    }


###############################################################################

def database_health():
    """
    Quick health check.
    """

    try:

        with get_connection() as conn:

            conn.execute("SELECT 1")

        return True

    except Exception:

        return False


###############################################################################

def reset_scan_history(user_id: str):
    """
    Delete all scans belonging to a user.
    """

    with get_connection() as conn:

        conn.execute(

            "DELETE FROM scan_history WHERE user_id=?",

            (user_id,)

        )

        conn.commit()

        return True


###############################################################################

def regenerate_api_key(user_id: str):
    """
    Alias used if main.py later changes naming.
    """

    return rotate_api_key(user_id)


###############################################################################

def get_user_count():
    return count_users()


###############################################################################

def get_scan_count():
    return count_scans()


###############################################################################

def close():
    """
    Compatibility function.
    SQLite connections are managed automatically.
    """
    return True


###############################################################################
# End of database.py
###############################################################################

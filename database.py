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
    return datetime.utcnow().isoformat()

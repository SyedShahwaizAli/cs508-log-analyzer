"""
Database layer — Neon DB (serverless PostgreSQL)
Credentials are NEVER hardcoded; they are loaded from environment variables.
"""

import os
import json
from datetime import datetime

# ── Try to import psycopg2; gracefully degrade if not installed ──
try:
    import psycopg2
    import psycopg2.extras
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False


def _get_connection():
    """
    Build a connection from the DATABASE_URL environment variable.
    This is set in Railway's dashboard (or a local .env file that is
    excluded from version control via .gitignore).
    """
    database_url = os.environ.get("DATABASE_URL")
    if not database_url or not DB_AVAILABLE:
        return None
    try:
        conn = psycopg2.connect(database_url, sslmode="require")
        return conn
    except Exception:
        return None


def init_db():
    """
    Create tables if they don't already exist.
    Called once on application startup.
    """
    conn = _get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                # Users / admin accounts
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id          SERIAL PRIMARY KEY,
                        username    VARCHAR(80) UNIQUE NOT NULL,
                        password    VARCHAR(200) NOT NULL,
                        created_at  TIMESTAMP DEFAULT NOW()
                    );
                """)
                # Analysis results persist here
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS analysis_results (
                        id           SERIAL PRIMARY KEY,
                        filename     TEXT,
                        total_events INTEGER,
                        http_errors  TEXT,
                        busiest_hour TEXT,
                        risk_score   INTEGER,
                        created_at   TIMESTAMP DEFAULT NOW()
                    );
                """)
                # Audit trail
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id         SERIAL PRIMARY KEY,
                        action     TEXT,
                        username   TEXT,
                        ip_address TEXT,
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                """)
                # Default admin (password is hashed by auth.py)
                cur.execute("""
                    INSERT INTO users (username, password)
                    VALUES ('admin', 'pbkdf2:sha256:600000$defaulthash$placeholder')
                    ON CONFLICT (username) DO NOTHING;
                """)
        return True
    except Exception:
        return False
    finally:
        conn.close()


def save_analysis(filename, total_events, http_errors, busiest_hour, risk_score):
    """Persist an analysis result to the cloud database."""
    conn = _get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO analysis_results
                        (filename, total_events, http_errors, busiest_hour, risk_score)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    filename,
                    total_events,
                    json.dumps(http_errors),
                    str(busiest_hour),
                    risk_score,
                ))
        return True
    except Exception:
        return False
    finally:
        conn.close()


def log_audit(action, username, ip_address):
    """Record an administrative action in the audit trail."""
    conn = _get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO audit_log (action, username, ip_address)
                    VALUES (%s, %s, %s)
                """, (action, username, ip_address))
        return True
    except Exception:
        return False
    finally:
        conn.close()


def get_analysis_history(limit=20):
    """Retrieve the most recent analysis records."""
    conn = _get_connection()
    if not conn:
        return []
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("""
                SELECT filename, total_events, http_errors, busiest_hour,
                       risk_score, created_at
                FROM analysis_results
                ORDER BY created_at DESC
                LIMIT %s
            """, (limit,))
            return [dict(row) for row in cur.fetchall()]
    except Exception:
        return []
    finally:
        conn.close()


def get_user(username):
    """Look up a user by username."""
    conn = _get_connection()
    if not conn:
        return None
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            return dict(row) if row else None
    except Exception:
        return None
    finally:
        conn.close()

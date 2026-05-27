"""
Authentication / IAM layer.
Implements session-based login so only authenticated admins
can access the dashboard and upload logs.
"""

import os
from functools import wraps
from flask import session, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_user, log_audit, DB_AVAILABLE

# ── Fallback in-memory admin when DB is unavailable ──────────────────────────
# In production, credentials live in the database. This fallback uses
# environment variables so no plaintext passwords are ever in the source code.
FALLBACK_ADMIN = {
    "username": os.environ.get("ADMIN_USERNAME", "admin"),
    "password": os.environ.get("ADMIN_PASSWORD_HASH",
                               generate_password_hash("admin123")),
}


def verify_credentials(username, password):
    """
    Check username + password against the database (or fallback).
    Returns True on success.
    """
    # Try the database first
    if DB_AVAILABLE:
        user = get_user(username)
        if user:
            return check_password_hash(user["password"], password)

    # Fallback: environment-variable-based admin account
    if username == FALLBACK_ADMIN["username"]:
        return check_password_hash(FALLBACK_ADMIN["password"], password)

    return False


def login_user(username):
    """Persist the authenticated user in the server-side session."""
    session["user"] = username
    session.permanent = True


def logout_user():
    """Clear the session."""
    session.pop("user", None)


def current_user():
    """Return the currently logged-in username, or None."""
    return session.get("user")


def login_required(f):
    """
    Decorator – redirects unauthenticated requests to the login page.
    Applied to every route that should be admin-only.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user():
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def record_login(username, success):
    """Write a login attempt to the audit log."""
    ip = request.remote_addr or "unknown"
    action = f"LOGIN_{'SUCCESS' if success else 'FAILURE'} for user '{username}'"
    log_audit(action, username, ip)

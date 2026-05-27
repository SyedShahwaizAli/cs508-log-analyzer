"""
Secure Cloud Log Analyzer — Main Flask Application
CS-508 Cloud Computing Project
"""

import os
from flask import (Flask, render_template, request, redirect,
                   url_for, flash, session)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# ── Load .env BEFORE anything else ──────────────────────────────────────────
load_dotenv()

from parser import parse_uploaded_log
from analyzer import analyze_log_entries
from mapreduce import run_mapreduce
from utils import allowed_file
from database import init_db, save_analysis, log_audit, get_analysis_history
from auth import login_required, verify_credentials, login_user, logout_user, current_user, record_login

# ── App Configuration ────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"json", "csv", "log", "txt"}

app = Flask(__name__)

# Secret key is loaded from environment — NEVER hardcoded
app.secret_key = os.environ.get("SECRET_KEY", "fallback-dev-only-key-change-in-prod")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── Initialize DB on startup ─────────────────────────────────────────────────
with app.app_context():
    init_db()


# ── Context processor: inject current user into all templates ─────────────────
@app.context_processor
def inject_user():
    return {"current_user": current_user()}


# ════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if verify_credentials(username, password):
            login_user(username)
            record_login(username, success=True)
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("index"))
        else:
            record_login(username, success=False)
            flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    username = current_user()
    logout_user()
    if username:
        log_audit(f"LOGOUT for user '{username}'", username,
                  request.remote_addr or "unknown")
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ════════════════════════════════════════════════════════════════════════════
# MAIN DASHBOARD — requires login
# ════════════════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        uploaded_file = request.files.get("logfile")
        if not uploaded_file or uploaded_file.filename == "":
            flash("Please select a log file before submitting.", "warning")
            return redirect(request.url)

        filename = secure_filename(uploaded_file.filename)
        if not allowed_file(filename, ALLOWED_EXTENSIONS):
            flash("Unsupported file format. Use JSON, CSV, TXT, or LOG.", "danger")
            return redirect(request.url)

        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        uploaded_file.save(file_path)

        # ── Parse ──────────────────────────────────────────────────────────
        entries, source_info = parse_uploaded_log(file_path)
        if entries is None:
            flash("Failed to parse the log file. Check the sample formats.", "danger")
            return redirect(request.url)

        # ── MapReduce (parallel analysis) ──────────────────────────────────
        mr_result = run_mapreduce(entries, num_chunks=4)

        # ── Sequential analysis (risk scoring, top users, etc.) ───────────
        analysis = analyze_log_entries(entries)
        analysis["mapreduce"] = mr_result  # merge MR output into dashboard data

        # ── Persist to Neon DB ─────────────────────────────────────────────
        busiest = mr_result["busiest_hours"][0][0] if mr_result["busiest_hours"] else "N/A"
        save_analysis(
            filename=filename,
            total_events=mr_result["total_entries"],
            http_errors=mr_result["http_errors"],
            busiest_hour=busiest,
            risk_score=analysis["risk_score"],
        )
        log_audit(f"LOG_UPLOAD: {filename}", current_user(),
                  request.remote_addr or "unknown")

        return render_template(
            "results.html",
            analysis=analysis,
            source_info=source_info,
            filename=filename,
            mr=mr_result,
        )

    # GET — show upload form + recent history from DB
    history = get_analysis_history(limit=5)
    return render_template("index.html", history=history)


@app.route("/about")
def about():
    return render_template("about.html")


# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0",
            port=int(os.environ.get("PORT", 5000)))

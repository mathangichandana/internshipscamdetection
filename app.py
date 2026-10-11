import os
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    flash,
)
from werkzeug.security import generate_password_hash, check_password_hash
from scam_checker import check as rule_check
from risk_assessor import assess_posting
from ml_model import get_model_metrics, load_or_train_model

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "intern-guard-secret-key-2026-btech")
DB_NAME = os.path.join(os.path.dirname(__file__), "history.db")


# Helper decorator to require user login for protected routes.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in or create an account to view your history.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# Returns an active SQLite connection configured with Row factory.
def get_db():
    con = sqlite3.connect(DB_NAME)
    con.row_factory = sqlite3.Row
    return con


# Initializes database tables and safely migrates missing columns in existing databases.
def init_db():
    with get_db() as con:
        # 1. Create users table for authentication
        con.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )

        # 2. Create checks table if not existing
        con.execute(
            """CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                time TEXT,
                snippet TEXT,
                score INTEGER,
                level TEXT,
                rule_score INTEGER,
                ml_prob REAL,
                reasons TEXT,
                url_warnings TEXT,
                full_text TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )"""
        )

        # 3. Migrate existing checks table columns if migrating from legacy version
        cursor = con.execute("PRAGMA table_info(checks)")
        existing_cols = {row["name"] for row in cursor.fetchall()}

        needed_cols = {
            "user_id": "INTEGER",
            "rule_score": "INTEGER",
            "ml_prob": "REAL",
            "reasons": "TEXT",
            "url_warnings": "TEXT",
            "full_text": "TEXT",
        }

        for col, col_type in needed_cols.items():
            if col not in existing_cols:
                try:
                    con.execute(f"ALTER TABLE checks ADD COLUMN {col} {col_type}")
                except Exception:
                    pass


# Saves an individual scan result into the SQLite history database.
def save_check(user_id, text, result):
    snippet = text.strip()[:60] if text else "Empty posting"
    time_str = datetime.now().strftime("%d-%m-%Y %H:%M")
    reasons_str = "; ".join(result.get("warning_reasons", []))
    url_warnings_str = "; ".join(result.get("url_findings", []))

    with get_db() as con:
        con.execute(
            """INSERT INTO checks 
               (user_id, time, snippet, score, level, rule_score, ml_prob, reasons, url_warnings, full_text) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                time_str,
                snippet,
                result["final_score"],
                result["final_level"],
                result["rule_score"],
                result["ml_probability"] / 100.0,
                reasons_str,
                url_warnings_str,
                text,
            ),
        )


# Home route: handles internship scanning, assessment, and result presentation.
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    posting_text = ""

    if request.method == "POST":
        posting_text = request.form.get("posting", "")
        if posting_text.strip():
            result = assess_posting(posting_text)
            user_id = session.get("user_id")
            save_check(user_id, posting_text, result)
        else:
            flash("Please paste or type an internship posting text to analyze.", "error")

    return render_template("index.html", result=result, posting_text=posting_text, title="Scanner | InternGuard")


# User registration route: validates inputs and hashes passwords with Werkzeug.
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(username) < 3:
            flash("Username must be at least 3 characters long.", "error")
            return render_template("register.html", title="Register | InternGuard")

        if len(password) < 4:
            flash("Password must be at least 4 characters long.", "error")
            return render_template("register.html", title="Register | InternGuard")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html", title="Register | InternGuard")

        password_hash = generate_password_hash(password)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            with get_db() as con:
                cursor = con.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, password_hash, created_at),
                )
                user_id = cursor.lastrowid

            session["user_id"] = user_id
            session["username"] = username
            flash(f"Welcome, {username}! Your account has been registered successfully.", "success")
            return redirect(url_for("home"))
        except sqlite3.IntegrityError:
            flash("Username is already taken. Please choose another.", "error")

    return render_template("register.html", title="Register | InternGuard")


# User login route: validates credentials and establishes user session.
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as con:
            user = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html", title="Login | InternGuard")


# User logout route: clears active session.
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


# Report history route: shows per-user previous checks with delete option.
@app.route("/history")
@login_required
def history():
    user_id = session.get("user_id")
    with get_db() as con:
        rows = con.execute(
            """SELECT id, time, snippet, score, level, rule_score, ml_prob, reasons 
               FROM checks 
               WHERE user_id = ? 
               ORDER BY id DESC""",
            (user_id,),
        ).fetchall()

    return render_template("history.html", checks=rows, title="Report History | InternGuard")


# Deletes an individual check entry belonging to the authenticated user.
@app.route("/history/delete/<int:check_id>", methods=["POST"])
@login_required
def delete_check(check_id):
    user_id = session.get("user_id")
    with get_db() as con:
        con.execute("DELETE FROM checks WHERE id = ? AND user_id = ?", (check_id, user_id))
    flash("History record removed.", "info")
    return redirect(url_for("history"))


# Clears all check history belonging to the authenticated user.
@app.route("/history/clear", methods=["POST"])
@login_required
def clear_history():
    user_id = session.get("user_id")
    with get_db() as con:
        con.execute("DELETE FROM checks WHERE user_id = ?", (user_id,))
    flash("All your check records have been cleared.", "info")
    return redirect(url_for("history"))


# Analytics dashboard route: calculates risk distributions, displays bar chart and ML metrics.
@app.route("/dashboard")
def dashboard():
    with get_db() as con:
        rows = con.execute("SELECT score, level FROM checks").fetchall()

    total_checks = len(rows)
    low_count = sum(1 for r in rows if r["level"] == "Low Risk")
    mod_count = sum(1 for r in rows if r["level"] == "Moderate Risk")
    single_high_count = sum(1 for r in rows if r["level"] == "High Risk")
    vhigh_count = sum(1 for r in rows if r["level"] == "Very High Risk")
    high_count = single_high_count + vhigh_count

    # Calculate proportions for chart bars
    max_count = max(total_checks, 1)
    low_pct = round((low_count / max_count) * 100, 1) if total_checks else 0
    mod_pct = round((mod_count / max_count) * 100, 1) if total_checks else 0
    high_pct = round((high_count / max_count) * 100, 1) if total_checks else 0

    # Scale relative bar heights (max out at 95%)
    highest_bucket = max(low_count, mod_count, single_high_count, vhigh_count, 1)
    low_bar_height = round((low_count / highest_bucket) * 90) if total_checks else 10
    mod_bar_height = round((mod_count / highest_bucket) * 90) if total_checks else 10
    single_high_bar_height = round((single_high_count / highest_bucket) * 90) if total_checks else 10
    vhigh_bar_height = round((vhigh_count / highest_bucket) * 90) if total_checks else 10

    metrics = get_model_metrics()

    return render_template(
        "dashboard.html",
        total_checks=total_checks,
        low_count=low_count,
        mod_count=mod_count,
        high_count=high_count,
        single_high_count=single_high_count,
        vhigh_count=vhigh_count,
        low_pct=low_pct,
        mod_pct=mod_pct,
        high_pct=high_pct,
        low_bar_height=low_bar_height,
        mod_bar_height=mod_bar_height,
        single_high_bar_height=single_high_bar_height,
        vhigh_bar_height=vhigh_bar_height,
        metrics=metrics,
        max=max,
        title="Dashboard | InternGuard",
    )


# App initialization on startup (ensures DB and model are ready for both direct run and WSGI servers like Gunicorn)
init_db()
load_or_train_model()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"InternGuard Server running at http://127.0.0.1:{port}")
    app.run(debug=True, host="0.0.0.0", port=port)
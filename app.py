from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
is_production = os.environ.get("ENVIRONMENT") == "production"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=is_production,  # True in production (HTTPS)
)


def get_db():
    return sqlite3.connect("database.db")


def init_db():
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            completed INTEGER DEFAULT 0
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            subject TEXT,
            status TEXT
        )
        """
    )
    # Add date column to attendance if missing
    cursor.execute("PRAGMA table_info(attendance)")
    cols = [row[1] for row in cursor.fetchall()]
    if "date" not in cols:
        cursor.execute("ALTER TABLE attendance ADD COLUMN date TEXT")

    # Indexes for faster lookups
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_att_user ON attendance(user_id)")
    db.commit()
    db.close()


init_db()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/")
        return view(*args, **kwargs)
    return wrapped_view


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["_csrf_token"] = token
    return token


def validate_csrf():
    form_token = request.form.get("csrf_token")
    session_token = session.get("_csrf_token")
    return session_token and form_token and secrets.compare_digest(form_token, session_token)


@app.context_processor
def inject_csrf():
    return {"csrf_token": get_csrf_token()}


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not validate_csrf():
            flash("Invalid CSRF token", "danger")
            return render_template("login.html")
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (request.form["username"].strip(),))
        user = cursor.fetchone()
        if user and check_password_hash(user[2], request.form["password"]):
            session["user_id"] = user[0]
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not validate_csrf():
            flash("Invalid CSRF token", "danger")
            return render_template("register.html")
        db = get_db()
        cursor = db.cursor()
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            return render_template("register.html", error="Username and password are required")

        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return render_template("register.html", error="Username already taken")

        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )
        db.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor()

    if request.method == "POST":
        if not validate_csrf():
            flash("Invalid CSRF token", "danger")
        else:
            title = request.form.get("task", "").strip()
            if title and len(title) <= 200:
                cursor.execute(
                    "INSERT INTO tasks (user_id, title) VALUES (?, ?)",
                    (session["user_id"], title)
                )
                db.commit()
                flash("Task added", "success")
            else:
                flash("Task must be 1-200 characters", "warning")

    # Pagination helpers
    def page_param(name):
        try:
            val = int(request.args.get(name, 1))
            return val if val > 0 else 1
        except (TypeError, ValueError):
            return 1

    def page_size_param(name):
        try:
            val = int(request.args.get(name, 10))
            return val if val in (10, 20, 50) else 10
        except (TypeError, ValueError):
            return 10

    page_size_tasks = page_size_param("task_size")
    page_size_att = page_size_param("att_size")
    task_page = page_param("task_page")
    att_page = page_param("att_page")

    # Tasks paginated
    cursor.execute("SELECT COUNT(*) FROM tasks WHERE user_id = ?", (session["user_id"],))
    task_total = cursor.fetchone()[0]
    task_offset = (task_page - 1) * page_size_tasks
    cursor.execute(
        "SELECT * FROM tasks WHERE user_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
        (session["user_id"], page_size_tasks, task_offset),
    )
    tasks = cursor.fetchall()

    # Attendance paginated
    att_filter = request.args.get("att_filter", "all")
    filter_clause = ""
    filter_args = [session["user_id"]]
    if att_filter == "today":
        filter_clause = "AND date = date('now','localtime')"
    elif att_filter == "week":
        filter_clause = "AND date >= date('now','-6 day','localtime')"

    cursor.execute(
        f"SELECT COUNT(*) FROM attendance WHERE user_id = ? {filter_clause}",
        filter_args,
    )
    att_total = cursor.fetchone()[0]
    att_offset = (att_page - 1) * page_size_att
    cursor.execute(
        f"SELECT * FROM attendance WHERE user_id = ? {filter_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        filter_args + [page_size_att, att_offset],
    )
    attendance = cursor.fetchall()

    # Attendance summary by subject
    cursor.execute(
        """
        SELECT subject,
               SUM(CASE WHEN status = 'Present' THEN 1 ELSE 0 END) AS present_count,
               SUM(CASE WHEN status = 'Absent' THEN 1 ELSE 0 END) AS absent_count,
               COUNT(*) AS total
        FROM attendance
        WHERE user_id = ?
        GROUP BY subject
        ORDER BY subject
        """,
        (session["user_id"],),
    )
    attendance_summary = cursor.fetchall()

    return render_template(
        "dashboard.html",
        tasks=tasks,
        attendance=attendance,
        attendance_summary=attendance_summary,
        csrf_token=get_csrf_token(),
        task_page=task_page,
        task_total=task_total,
        att_page=att_page,
        att_total=att_total,
        page_size_tasks=page_size_tasks,
        page_size_att=page_size_att,
        att_filter=att_filter,
    )


@app.route("/complete/<int:task_id>", methods=["POST"])
@login_required
def complete(task_id):
    if not validate_csrf():
        flash("Invalid CSRF token", "danger")
        return redirect(url_for("dashboard"))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE tasks SET completed = 1 WHERE id = ? AND user_id = ?", (task_id, session["user_id"]))
    db.commit()
    flash("Task completed", "success")
    return redirect(url_for("dashboard"))


@app.route("/delete_task/<int:task_id>", methods=["POST"])
@login_required
def delete_task(task_id):
    if not validate_csrf():
        flash("Invalid CSRF token", "danger")
        return redirect(url_for("dashboard"))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, session["user_id"]))
    db.commit()
    flash("Task deleted", "info")
    return redirect(url_for("dashboard"))


@app.route("/attendance", methods=["POST"])
@login_required
def add_attendance():
    db = get_db()
    cursor = db.cursor()
    if not validate_csrf():
        flash("Invalid CSRF token", "danger")
        return redirect(url_for("dashboard"))
    subject = request.form.get("subject", "").strip()
    status = request.form.get("status", "").strip()
    date_val = request.form.get("date") or None
    if not date_val:
        cursor.execute("SELECT date('now','localtime')")
        date_val = cursor.fetchone()[0]
    if subject and len(subject) <= 120 and status in ("Present", "Absent"):
        cursor.execute(
            "INSERT INTO attendance (user_id, subject, status, date) VALUES (?, ?, ?, ?)",
            (session["user_id"], subject, status, date_val)
        )
        db.commit()
        flash("Attendance added", "success")
    else:
        flash("Provide subject (<=120 chars) and status", "warning")
    return redirect(url_for("dashboard"))


@app.route("/delete_attendance/<int:att_id>", methods=["POST"])
@login_required
def delete_attendance(att_id):
    if not validate_csrf():
        flash("Invalid CSRF token", "danger")
        return redirect(url_for("dashboard"))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM attendance WHERE id = ? AND user_id = ?", (att_id, session["user_id"]))
    db.commit()
    flash("Attendance entry deleted", "info")
    return redirect(url_for("dashboard"))


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

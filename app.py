from flask import Flask, render_template, request, redirect, session, flash
import sqlite3, os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from pathlib import Path

# ---------------- APP CONFIG ----------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "scms_render_secret_123"

DB = "./database.db"

# Ensure database file exists
if not os.path.exists(DB):
    Path(DB).touch()

# ---------------- DATABASE ----------------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()

    # ---- FIX OLD USERS TABLE (2 columns issue) ----
    try:
        # Check if role column exists
        db.execute("SELECT role FROM users LIMIT 1")
    except sqlite3.OperationalError:
        # Old schema detected → drop table
        db.execute("DROP TABLE IF EXISTS users")

    # Create users table (CORRECT SCHEMA)
    db.execute("""
    CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password TEXT,
        role TEXT
    )
    """)

    # Create complaints table
    db.execute("""
    CREATE TABLE IF NOT EXISTS complaints(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        title TEXT,
        description TEXT,
        status TEXT,
        created_at TEXT,
        updated_at TEXT
    )
    """)

    db.commit()

# ---------------- DECORATORS ----------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect("/")
        return f(*args, **kwargs)
    return wrapper

# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=?",
            (u,)
        ).fetchone()

        if user and check_password_hash(user["password"], p):
            session["user"] = u
            session["role"] = user["role"]
            return redirect("/admin" if user["role"] == "admin" else "/dashboard")

        flash("Invalid username or password", "danger")

    return render_template("auth_login.html")

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            db = get_db()
            db.execute(
                "INSERT INTO users VALUES (?,?,?)",
                (
                    request.form["username"],
                    generate_password_hash(request.form["password"]),
                    request.form["role"]
                )
            )
            db.commit()
            flash("Account created successfully", "success")
            return redirect("/")
        except sqlite3.IntegrityError:
            flash("Username already exists", "danger")

    return render_template("auth_register.html")

# ---------------- USER DASHBOARD ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    complaints = db.execute(
        "SELECT * FROM complaints WHERE user=? ORDER BY id DESC",
        (session["user"],)
    ).fetchall()

    stats = {
        "total": len(complaints),
        "pending": len([c for c in complaints if c["status"] == "Pending"]),
        "resolved": len([c for c in complaints if c["status"] == "Resolved"])
    }

    return render_template(
        "user_dashboard.html",
        complaints=complaints,
        stats=stats
    )

# ---------------- ADD COMPLAINT ----------------
@app.route("/add", methods=["GET", "POST"])
@login_required
def add_complaint():
    if request.method == "POST":
        db = get_db()
        db.execute("""
        INSERT INTO complaints(
            user, title, description, status, created_at, updated_at
        ) VALUES (?,?,?,?,?,?)
        """, (
            session["user"],
            request.form["title"],
            request.form["description"],
            "Pending",
            datetime.now().strftime("%d-%m-%Y %H:%M"),
            "-"
        ))
        db.commit()
        return redirect("/dashboard")

    return render_template("add_complaint.html")

# ---------------- TRACK COMPLAINT ----------------
@app.route("/track", methods=["GET", "POST"])
@login_required
def track():
    complaint = None
    if request.method == "POST":
        cid = request.form["cid"]
        db = get_db()
        complaint = db.execute(
            "SELECT * FROM complaints WHERE id=? AND user=?",
            (cid, session["user"])
        ).fetchone()

    return render_template(
        "track_complaint.html",
        complaint=complaint
    )

# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    complaints = db.execute(
        "SELECT * FROM complaints ORDER BY id DESC"
    ).fetchall()

    stats = {
        "total": len(complaints),
        "pending": len([c for c in complaints if c["status"] == "Pending"]),
        "resolved": len([c for c in complaints if c["status"] == "Resolved"])
    }

    return render_template(
        "admin_dashboard.html",
        complaints=complaints,
        stats=stats
    )

# ---------------- RESOLVE COMPLAINT ----------------
@app.route("/resolve/<int:id>")
@admin_required
def resolve(id):
    db = get_db()
    db.execute("""
    UPDATE complaints
    SET status='Resolved', updated_at=?
    WHERE id=?
    """, (
        datetime.now().strftime("%d-%m-%Y %H:%M"),
        id
    ))
    db.commit()
    return redirect("/admin")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- INIT DB FOR GUNICORN ----------------
init_db()

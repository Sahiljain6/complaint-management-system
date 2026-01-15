from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = "scms_pro_secret"

DB = "database.db"

# ---------------- DB ----------------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.execute("""
    CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password TEXT,
        role TEXT
    )""")

    db.execute("""
    CREATE TABLE IF NOT EXISTS complaints(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        title TEXT,
        description TEXT,
        status TEXT,
        created_at TEXT,
        updated_at TEXT
    )""")
    db.commit()

# ---------------- DECORATORS ----------------
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user" not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect("/")
        return f(*args, **kwargs)
    return wrap

# ---------------- AUTH ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form["username"], request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()

        if user and check_password_hash(user["password"], p):
            session["user"] = u
            session["role"] = user["role"]
            return redirect("/admin" if user["role"] == "admin" else "/dashboard")
        flash("Invalid Login", "danger")
    return render_template("auth_login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        db = get_db()
        db.execute("INSERT INTO users VALUES (?,?,?)", (
            request.form["username"],
            generate_password_hash(request.form["password"]),
            request.form["role"]
        ))
        db.commit()
        flash("Account Created", "success")
        return redirect("/")
    return render_template("auth_register.html")

# ---------------- USER ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    data = db.execute(
        "SELECT * FROM complaints WHERE user=? ORDER BY id DESC",
        (session["user"],)
    ).fetchall()

    stats = {
        "total": len(data),
        "pending": len([d for d in data if d["status"] == "Pending"]),
        "resolved": len([d for d in data if d["status"] == "Resolved"])
    }
    return render_template("user_dashboard.html", complaints=data, stats=stats)

@app.route("/add", methods=["GET", "POST"])
@login_required
def add_complaint():
    if request.method == "POST":
        db = get_db()
        db.execute("""
        INSERT INTO complaints(user,title,description,status,created_at,updated_at)
        VALUES (?,?,?,?,?,?)
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
    return render_template("track_complaint.html", complaint=complaint)

# ---------------- ADMIN ----------------
@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    data = db.execute("SELECT * FROM complaints").fetchall()

    stats = {
        "total": len(data),
        "pending": len([d for d in data if d["status"] == "Pending"]),
        "resolved": len([d for d in data if d["status"] == "Resolved"])
    }
    return render_template("admin_dashboard.html", complaints=data, stats=stats)

@app.route("/resolve/<int:id>")
@admin_required
def resolve(id):
    db = get_db()
    db.execute("""
    UPDATE complaints 
    SET status='Resolved', updated_at=?
    WHERE id=?
    """, (datetime.now().strftime("%d-%m-%Y %H:%M"), id))
    db.commit()
    return redirect("/admin")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    init_db()
    app.run(debug=True)

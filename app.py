from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import mysql.connector

app = Flask(__name__)
app.secret_key = "scms_xampp_secret"

# ---------------- DATABASE CONNECTION ----------------
def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",          # XAMPP default
        database="scms_db"
    )

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
        db = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username=%s", (request.form["username"],))
        user = cur.fetchone()

        if user and check_password_hash(user["password"], request.form["password"]):
            session["user"] = user["username"]
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
            cur = db.cursor()
            cur.execute(
                "INSERT INTO users VALUES (%s,%s,%s)",
                (
                    request.form["username"],
                    generate_password_hash(request.form["password"]),
                    request.form["role"]
                )
            )
            db.commit()
            flash("Account created successfully", "success")
            return redirect("/")
        except mysql.connector.IntegrityError:
            flash("Username already exists", "danger")

    return render_template("auth_register.html")

# ---------------- USER DASHBOARD ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM complaints WHERE user=%s ORDER BY id DESC", (session["user"],))
    complaints = cur.fetchall()

    stats = {
        "total": len(complaints),
        "pending": len([c for c in complaints if c["status"] == "Pending"]),
        "resolved": len([c for c in complaints if c["status"] == "Resolved"])
    }

    return render_template("user_dashboard.html", complaints=complaints, stats=stats)

# ---------------- ADD COMPLAINT ----------------
@app.route("/add", methods=["GET", "POST"])
@login_required
def add_complaint():
    if request.method == "POST":
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """INSERT INTO complaints
               (user,title,description,status,created_at,updated_at)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (
                session["user"],
                request.form["title"],
                request.form["description"],
                "Pending",
                datetime.now().strftime("%d-%m-%Y %H:%M"),
                "-"
            )
        )
        db.commit()
        return redirect("/dashboard")

    return render_template("add_complaint.html")

# ---------------- TRACK COMPLAINT ----------------
@app.route("/track", methods=["GET", "POST"])
@login_required
def track():
    complaint = None
    if request.method == "POST":
        db = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT * FROM complaints WHERE id=%s AND user=%s",
            (request.form["cid"], session["user"])
        )
        complaint = cur.fetchone()

    return render_template("track_complaint.html", complaint=complaint)

# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM complaints ORDER BY id DESC")
    complaints = cur.fetchall()

    stats = {
        "total": len(complaints),
        "pending": len([c for c in complaints if c["status"] == "Pending"]),
        "resolved": len([c for c in complaints if c["status"] == "Resolved"])
    }

    return render_template("admin_dashboard.html", complaints=complaints, stats=stats)

# ---------------- RESOLVE COMPLAINT ----------------
@app.route("/resolve/<int:id>")
@admin_required
def resolve(id):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "UPDATE complaints SET status=%s, updated_at=%s WHERE id=%s",
        ("Resolved", datetime.now().strftime("%d-%m-%Y %H:%M"), id)
    )
    db.commit()
    return redirect("/admin")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)

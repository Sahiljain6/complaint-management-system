from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "complaint_secret_key"

DB_NAME = "database.db"

# ---------- DATABASE CONNECTION ----------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# ---------- HOME / LOGIN ----------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        )
        user = cur.fetchone()

        if user:
            session["user"] = username
            return redirect(url_for("dashboard"))

    return render_template("login.html")

# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password)
        )
        db.commit()

        return redirect(url_for("login"))

    return render_template("register.html")

# ---------- DASHBOARD ----------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT * FROM complaints WHERE user=?",
        (session["user"],)
    )
    complaints = cur.fetchall()

    return render_template("dashboard.html", complaints=complaints)

# ---------- ADD COMPLAINT ----------
@app.route("/add", methods=["GET", "POST"])
def add_complaint():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO complaints (user, title, description) VALUES (?, ?, ?)",
            (session["user"], title, description)
        )
        db.commit()

        return redirect(url_for("dashboard"))

    return render_template("add_complaint.html")

# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- CREATE TABLES ----------
def init_db():
    db = get_db()
    cur = db.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            title TEXT,
            description TEXT
        )
    """)

    db.commit()

# ---------- RUN APP ----------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)

from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3

app = Flask(__name__)
app.secret_key = "secret_key_123"

DB = "database.db"

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    cur = db.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password TEXT,
        role TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS complaints(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        title TEXT,
        description TEXT,
        status TEXT DEFAULT 'Pending'
    )
    """)
    db.commit()

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (u, p))
        user = cur.fetchone()

        if user:
            session["user"] = u
            session["role"] = user["role"]
            if user["role"] == "admin":
                return redirect("/admin")
            return redirect("/dashboard")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        role = request.form["role"]

        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO users VALUES (?,?,?)", (u, p, role))
        db.commit()
        return redirect("/")
    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM complaints WHERE user=?", (session["user"],))
    complaints = cur.fetchall()
    return render_template("dashboard.html", complaints=complaints)

@app.route("/admin")
def admin_dashboard():
    if session.get("role") != "admin":
        return redirect("/")
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM complaints")
    complaints = cur.fetchall()
    return render_template("admin_dashboard.html", complaints=complaints)

@app.route("/add", methods=["GET", "POST"])
def add_complaint():
    if request.method == "POST":
        t = request.form["title"]
        d = request.form["description"]

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO complaints(user,title,description,status) VALUES (?,?,?,?)",
            (session["user"], t, d, "Pending")
        )
        db.commit()
        return redirect("/dashboard")
    return render_template("add_complaint.html")

@app.route("/resolve/<int:id>")
def resolve(id):
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE complaints SET status='Resolved' WHERE id=?", (id,))
    db.commit()
    return redirect("/admin")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)

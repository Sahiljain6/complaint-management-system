from flask import Flask, render_template, request, redirect, session
import sqlite3

app = Flask(__name__)
app.secret_key = "complaint123"

def db():
    return sqlite3.connect("database.db")

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        con = db()
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (u, p))
        user = cur.fetchone()

        if user:
            session["user"] = u
            return redirect("/dashboard")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        con = db()
        cur = con.cursor()
        cur.execute("INSERT INTO users VALUES (?,?)", (u, p))
        con.commit()
        return redirect("/")
    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM complaints WHERE user=?", (session["user"],))
    data = cur.fetchall()
    return render_template("dashboard.html", complaints=data)

@app.route("/add", methods=["GET", "POST"])
def add():
    if request.method == "POST":
        t = request.form["title"]
        d = request.form["desc"]

        con = db()
        cur = con.cursor()
        cur.execute("INSERT INTO complaints VALUES (?,?,?)",
                    (session["user"], t, d))
        con.commit()
        return redirect("/dashboard")
    return render_template("add_complaint.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    con = db()
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users(username TEXT, password TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS complaints(user TEXT, title TEXT, description TEXT)")
    con.commit()
    app.run(debug=True)
    if __name__ == "__main__":
    app.run(debug=True)


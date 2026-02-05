import os
from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime

# ---------------- APP CONFIG ----------------
app = Flask(__name__)
app.secret_key = "scms_render_secret"

# DATABASE CONFIG (Render PostgreSQL)
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---------------- DATABASE MODELS ----------------
class User(db.Model):
    username = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(50), nullable=False)
    title = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="Pending")
    created_at = db.Column(db.String(50))
    updated_at = db.Column(db.String(50))

# Create tables ONCE (safe, persistent)
with app.app_context():
    db.create_all()

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

# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and check_password_hash(user.password, request.form["password"]):
            session["user"] = user.username
            session["role"] = user.role
            return redirect("/admin" if user.role == "admin" else "/dashboard")

        flash("Invalid credentials", "danger")
    return render_template("auth_login.html")

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if User.query.filter_by(username=request.form["username"]).first():
            flash("Username already exists", "danger")
        else:
            user = User(
                username=request.form["username"],
                password=generate_password_hash(request.form["password"]),
                role=request.form["role"]
            )
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully", "success")
            return redirect("/")
    return render_template("auth_register.html")

# ---------------- USER DASHBOARD ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    complaints = Complaint.query.filter_by(user=session["user"]).order_by(Complaint.id.desc()).all()

    stats = {
        "total": len(complaints),
        "pending": len([c for c in complaints if c.status == "Pending"]),
        "resolved": len([c for c in complaints if c.status == "Resolved"])
    }
    return render_template("user_dashboard.html", complaints=complaints, stats=stats)

# ---------------- ADD COMPLAINT ----------------
@app.route("/add", methods=["GET", "POST"])
@login_required
def add_complaint():
    if request.method == "POST":
        c = Complaint(
            user=session["user"],
            title=request.form["title"],
            description=request.form["description"],
            status="Pending",
            created_at=datetime.now().strftime("%d-%m-%Y %H:%M"),
            updated_at="-"
        )
        db.session.add(c)
        db.session.commit()
        return redirect("/dashboard")
    return render_template("add_complaint.html")

# ---------------- TRACK ----------------
@app.route("/track", methods=["GET", "POST"])
@login_required
def track():
    complaint = None
    if request.method == "POST":
        complaint = Complaint.query.filter_by(
            id=request.form["cid"],
            user=session["user"]
        ).first()
    return render_template("track_complaint.html", complaint=complaint)

# ---------------- ADMIN ----------------
@app.route("/admin")
@admin_required
def admin():
    complaints = Complaint.query.order_by(Complaint.id.desc()).all()
    stats = {
        "total": len(complaints),
        "pending": len([c for c in complaints if c.status == "Pending"]),
        "resolved": len([c for c in complaints if c.status == "Resolved"])
    }
    return render_template("admin_dashboard.html", complaints=complaints, stats=stats)

# ---------------- RESOLVE ----------------
@app.route("/resolve/<int:id>")
@admin_required
def resolve(id):
    c = Complaint.query.get(id)
    c.status = "Resolved"
    c.updated_at = datetime.now().strftime("%d-%m-%Y %H:%M")
    db.session.commit()
    return redirect("/admin")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


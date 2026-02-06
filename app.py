import os
import smtplib
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime

# =================================================
# APP CONFIG
# =================================================
app = Flask(__name__)
app.secret_key = "scms_secret_key"

# =================================================
# DATABASE CONFIG (RENDER POSTGRESQL)
# =================================================
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

# Fix Render postgres:// issue
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# =================================================
# DATABASE MODELS
# =================================================
class User(db.Model):
    __tablename__ = "users"
    username = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Complaint(db.Model):
    __tablename__ = "complaints"
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(50), nullable=False)
    title = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(30), nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default="Pending")
    created_at = db.Column(db.String(50))
    updated_at = db.Column(db.String(50))

# =================================================
# CREATE TABLES (SAFE FOR FLASK 3)
# =================================================
with app.app_context():
    db.create_all()

# =================================================
# AUTH DECORATORS
# =================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

# =================================================
# ROOT ROUTE (FIXES RENDER 404)
# =================================================
@app.route("/", methods=["GET", "HEAD"])
def home():
    return redirect("/login")

# =================================================
# AUTO PRIORITY LOGIC
# =================================================
def auto_set_priority(text):
    text = text.lower()

    high_keywords = [
        "urgent", "emergency", "not working",
        "broken", "failure", "crash", "immediately"
    ]
    low_keywords = [
        "suggestion", "feedback", "improve", "enhancement"
    ]

    for word in high_keywords:
        if word in text:
            return "High"

    for word in low_keywords:
        if word in text:
            return "Low"

    return "Medium"

# =================================================
# EMAIL FUNCTION (OPTIONAL)
# =================================================
def send_email(subject, body):
    email_user = os.environ.get("EMAIL_USER")
    email_pass = os.environ.get("EMAIL_PASS")

    if not email_user or not email_pass:
        return

    msg = EmailMessage()
    msg["From"] = email_user
    msg["To"] = email_user
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(email_user, email_pass)
        smtp.send_message(msg)

# =================================================
# LOGIN
# =================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(
            username=request.form.get("username")
        ).first()

        if user and check_password_hash(
            user.password,
            request.form.get("password", "")
        ):
            session["user"] = user.username
            session["role"] = user.role
            return redirect("/admin" if user.role == "admin" else "/dashboard")

        flash("Invalid username or password", "danger")

    return render_template("auth_login.html")

# =================================================
# REGISTER
# =================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role", "user")

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
        else:
            user = User(
                username=username,
                password=generate_password_hash(password),
                role=role
            )
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully", "success")
            return redirect("/login")

    return render_template("auth_register.html")

# =================================================
# USER DASHBOARD
# =================================================
@app.route("/dashboard")
@login_required
def dashboard():
    complaints = Complaint.query.filter_by(
        user=session["user"]
    ).order_by(Complaint.id.desc()).all()

    stats = {
        "total": len(complaints),
        "pending": sum(1 for c in complaints if c.status == "Pending"),
        "resolved": sum(1 for c in complaints if c.status == "Resolved")
    }

    return render_template(
        "user_dashboard.html",
        complaints=complaints,
        stats=stats
    )

# =================================================
# ADD COMPLAINT (SAFE – NO 400 ERROR)
# =================================================
@app.route("/add", methods=["GET", "POST"])
@login_required
def add_complaint():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "Other")

        if not title or not description:
            flash("Title and description are required", "danger")
            return redirect("/add")

        priority = auto_set_priority(title + " " + description)

        complaint = Complaint(
            user=session["user"],
            title=title,
            description=description,
            category=category,
            priority=priority,
            status="Pending",
            created_at=datetime.now().strftime("%d-%m-%Y %H:%M"),
            updated_at="-"
        )

        db.session.add(complaint)
        db.session.commit()

        flash("Complaint submitted successfully", "success")
        return redirect("/dashboard")

    return render_template("add_complaint.html")

# =================================================
# ADMIN DASHBOARD
# =================================================
@app.route("/admin")
@admin_required
def admin():
    complaints = Complaint.query.all()

    status_count = {"Pending": 0, "Resolved": 0}
    priority_count = {"Low": 0, "Medium": 0, "High": 0}
    category_count = {}

    for c in complaints:
        status_count[c.status] += 1
        priority_count[c.priority] += 1
        category_count[c.category] = category_count.get(c.category, 0) + 1

    return render_template(
        "admin_dashboard.html",
        complaints=complaints,
        status_count=status_count,
        priority_count=priority_count,
        category_count=category_count
    )

# =================================================
# RESOLVE COMPLAINT
# =================================================
@app.route("/resolve/<int:id>")
@admin_required
def resolve(id):
    complaint = Complaint.query.get(id)
    if complaint:
        complaint.status = "Resolved"
        complaint.updated_at = datetime.now().strftime("%d-%m-%Y %H:%M")
        db.session.commit()

    return redirect("/admin")

# =================================================
# LOGOUT
# =================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

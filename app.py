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
            return redirect("/")
        return f(*args, **kwargs)
    return

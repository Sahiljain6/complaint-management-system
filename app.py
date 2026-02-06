import os
import uuid
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# =================================================
# APP CONFIG
# =================================================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "scms_secret_key")

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
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}
STATUS_OPTIONS = ["Pending", "Assigned", "In Progress", "Resolved", "Rejected"]
PRIORITY_OPTIONS = ["Low", "Medium", "High", "Critical"]

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)

# =================================================
# DATABASE MODELS
# =================================================
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    complaints = db.relationship("Complaint", back_populates="user")

class Complaint(db.Model):
    __tablename__ = "complaints"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(30), nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default="Pending", nullable=False)
    attachment_filename = db.Column(db.String(255), nullable=False)
    assigned_to = db.Column(db.String(120))
    admin_remarks = db.Column(db.Text)
    resolution_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    user = db.relationship("User", back_populates="complaints")
    history = db.relationship(
        "ComplaintStatusHistory",
        back_populates="complaint",
        order_by="ComplaintStatusHistory.changed_at",
        cascade="all, delete-orphan",
    )


class ComplaintStatusHistory(db.Model):
    __tablename__ = "complaint_status_history"
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey("complaints.id"), nullable=False)
    old_status = db.Column(db.String(20), nullable=False)
    new_status = db.Column(db.String(20), nullable=False)
    changed_by = db.Column(db.String(120), nullable=False)
    remark = db.Column(db.Text)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    complaint = db.relationship("Complaint", back_populates="history")

# =================================================
# CREATE TABLES (SAFE FOR FLASK 3)
# =================================================
with app.app_context():
    db.create_all()
    # Optionally seed an admin account from environment variables for production.
    if os.environ.get("ADMIN_USERNAME") and os.environ.get("ADMIN_PASSWORD"):
        existing_admin = User.query.filter_by(
            username=os.environ["ADMIN_USERNAME"]
        ).first()
        if not existing_admin:
            db.session.add(
                User(
                    username=os.environ["ADMIN_USERNAME"],
                    password_hash=generate_password_hash(
                        os.environ["ADMIN_PASSWORD"]
                    ),
                    role="admin",
                )
            )
            db.session.commit()

# =================================================
# AUTH DECORATORS
# =================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper


def user_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "user":
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# =================================================
# ROOT ROUTE (FIXES RENDER 404)
# =================================================
@app.route("/", methods=["GET", "HEAD"])
def home():
    return redirect(url_for("login"))

# =================================================
# AUTO PRIORITY LOGIC
# =================================================
def auto_set_priority(text):
    text = text.lower()

    critical_keywords = ["broken", "failed", "crash"]
    high_keywords = ["urgent", "emergency", "not working"]
    low_keywords = ["suggestion", "feedback"]

    if any(word in text for word in critical_keywords):
        return "Critical"
    if any(word in text for word in high_keywords):
        return "High"
    if any(word in text for word in low_keywords):
        return "Low"
    return "Medium"


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# =================================================
# LOGIN (USER)
# =================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form.get("username")).first()
        if (
            user
            and user.role == "user"
            and check_password_hash(
                user.password_hash, request.form.get("password", "")
            )
        ):
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            return redirect(url_for("dashboard"))
        flash("Invalid username or password", "danger")

    return render_template("auth_login.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        admin_user = User.query.filter_by(
            username=request.form.get("username"), role="admin"
        ).first()
        if admin_user and check_password_hash(
            admin_user.password_hash, request.form.get("password", "")
        ):
            session["user_id"] = admin_user.id
            session["username"] = admin_user.username
            session["role"] = admin_user.role
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin credentials", "danger")

    return render_template("auth_login.html", admin_login=True)

# =================================================
# REGISTER
# =================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
        else:
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                role="user",
            )
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully", "success")
            return redirect(url_for("login"))

    return render_template("auth_register.html")

# =================================================
# USER DASHBOARD
# =================================================
@app.route("/dashboard")
@login_required
@user_required
def dashboard():
    complaints = Complaint.query.filter_by(
        user_id=session["user_id"]
    ).order_by(Complaint.created_at.desc()).all()

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
@app.route("/complaints/new", methods=["GET", "POST"])
@login_required
@user_required
def add_complaint():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "Other")
        attachment = request.files.get("attachment")

        if not title or not description:
            flash("Title and description are required", "danger")
            return redirect(url_for("add_complaint"))

        if not attachment or attachment.filename == "":
            flash("Attachment is required (image or PDF)", "danger")
            return redirect(url_for("add_complaint"))

        if not allowed_file(attachment.filename):
            flash("Only image or PDF files are allowed", "danger")
            return redirect(url_for("add_complaint"))

        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        safe_name = secure_filename(attachment.filename)
        unique_name = f"{uuid.uuid4().hex}_{safe_name}"
        attachment.save(os.path.join(app.config["UPLOAD_FOLDER"], unique_name))

        priority = auto_set_priority(title + " " + description)

        complaint = Complaint(
            user_id=session["user_id"],
            title=title,
            description=description,
            category=category,
            priority=priority,
            status="Pending",
            attachment_filename=unique_name,
        )

        db.session.add(complaint)
        db.session.flush()
        db.session.add(
            ComplaintStatusHistory(
                complaint_id=complaint.id,
                old_status="Pending",
                new_status="Pending",
                changed_by=session["username"],
                remark="Complaint submitted",
            )
        )
        db.session.commit()

        flash("Complaint submitted successfully", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_complaint.html")


@app.route("/add")
def add_redirect():
    return redirect(url_for("add_complaint"))

# =================================================
# ADMIN DASHBOARD
# =================================================
@app.route("/admin")
@admin_required
def admin_dashboard():
    complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()

    status_count = {status: 0 for status in STATUS_OPTIONS}
    priority_count = {priority: 0 for priority in PRIORITY_OPTIONS}
    category_count = {}

    for complaint in complaints:
        status_count[complaint.status] += 1
        priority_count[complaint.priority] += 1
        category_count[complaint.category] = category_count.get(
            complaint.category, 0
        ) + 1

    return render_template(
        "admin_dashboard.html",
        complaints=complaints,
        status_count=status_count,
        priority_count=priority_count,
        category_count=category_count,
        status_options=STATUS_OPTIONS,
    )

# =================================================
# RESOLVE COMPLAINT
# =================================================
@app.route("/admin/complaints/<int:complaint_id>/update", methods=["POST"])
@admin_required
def update_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    new_status = request.form.get("status", complaint.status)
    assigned_to = request.form.get("assigned_to", "").strip()
    admin_remarks = request.form.get("admin_remarks", "").strip()
    resolution_date = request.form.get("resolution_date", "").strip()

    if new_status not in STATUS_OPTIONS:
        flash("Invalid status selected", "danger")
        return redirect(url_for("admin_dashboard"))

    if resolution_date:
        complaint.resolution_date = datetime.strptime(resolution_date, "%Y-%m-%d")
    else:
        complaint.resolution_date = None

    complaint.assigned_to = assigned_to or None
    complaint.admin_remarks = admin_remarks or None

    if new_status != complaint.status:
        db.session.add(
            ComplaintStatusHistory(
                complaint_id=complaint.id,
                old_status=complaint.status,
                new_status=new_status,
                changed_by=session["username"],
                remark=admin_remarks or "Status updated",
            )
        )
        complaint.status = new_status

    db.session.commit()
    flash("Complaint updated", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/attachments/<filename>")
@login_required
def download_attachment(filename):
    complaint = Complaint.query.filter_by(attachment_filename=filename).first()
    if not complaint:
        abort(404)
    if session.get("role") != "admin" and complaint.user_id != session.get("user_id"):
        abort(403)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

# =================================================
# LOGOUT
# =================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

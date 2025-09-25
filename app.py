import os
import random
from datetime import datetime, timedelta
from flask import Flask, request, session, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev_secret")
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///site.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ---------------------------------------------------------------------------
# Database Models
# ---------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp_hash = db.Column(db.String(200), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------------------------------------------------------------------
# Initialize Database
# ---------------------------------------------------------------------------
with app.app_context():
    db.create_all()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def generate_otp():
    return str(random.randint(100000, 999999))

def store_otp(email, otp):
    """Store OTP hash in DB with expiration."""
    otp_hash = generate_password_hash(otp)
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    pr = PasswordReset(email=email, otp_hash=otp_hash, expires_at=expires_at)
    db.session.add(pr)
    db.session.commit()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("hompagenew.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/project_details")
def project_details():
    return render_template("project_details.html")

# ---------------- Register ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password")
        password2 = request.form.get("password2")

        if not all([username, name, email, password, password2]):
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if password != password2:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "warning")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return redirect(url_for("register"))

        user = User(
            username=username,
            name=name,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ---------------- Login ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            session["username"] = user.username
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

# ---------------- Logout ----------------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

# ---------------- Forgot Password ----------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email not registered.", "danger")
            return redirect(url_for("forgot"))

        otp = generate_otp()
        store_otp(email, otp)
        session["reset_email_pending"] = email

        # Ideally send OTP via email here
        print(f"OTP for {email}: {otp}")  # For testing only

        flash("OTP sent to your email. Check console for OTP (for testing).", "success")
        return redirect(url_for("verify_otp"))

    return render_template("forgot.html")

# ---------------- Verify OTP ----------------
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = session.get("reset_email_pending")
    if not email:
        flash("Please provide your email first.", "warning")
        return redirect(url_for("forgot"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        now = datetime.utcnow()

        pr = PasswordReset.query.filter_by(email=email, used=False)\
            .order_by(PasswordReset.created_at.desc()).first()

        if not pr or pr.expires_at < now:
            flash("No valid OTP found or OTP expired — request again.", "danger")
            return redirect(url_for("forgot"))

        if check_password_hash(pr.otp_hash, otp):
            pr.used = True
            db.session.commit()
            session.pop("reset_email_pending", None)
            session["reset_email"] = email
            flash("OTP verified — set your new password now.", "success")
            return redirect(url_for("reset_password"))
        else:
            flash("Invalid OTP — try again.", "danger")
            return redirect(url_for("verify_otp"))

    return render_template("otp.html", email=email)

# ---------------- Reset Password ----------------
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    email = session.get("reset_email")
    if not email:
        flash("OTP verification required.", "warning")
        return redirect(url_for("forgot"))

    if request.method == "POST":
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if not password or password != password2:
            flash("Passwords empty or do not match.", "danger")
            return redirect(url_for("reset_password"))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("register"))

        user.password_hash = generate_password_hash(password)
        db.session.commit()

        session.pop("reset_email", None)
        flash("Password updated. You may now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)

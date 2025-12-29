import os
import hmac
import hashlib
import subprocess

from flask import Flask, render_template, request, abort, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Config ---
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///local.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# --- Model ---
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_member = db.Column(db.Boolean, default=True, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --------------------
# Pages
# --------------------
@app.get("/")
def home():
    return render_template("index.html")

@app.get("/login")
def login():
    return render_template("login.html")

@app.post("/login")
def login_post():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    user = User.query.filter_by(email=email).first()
    if not user or not user.is_member or not check_password_hash(user.password_hash, password):
        flash("Invalid login.")
        return redirect(url_for("login"))

    login_user(user)
    return redirect(url_for("members"))

@app.get("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.get("/members")
@login_required
def members():
    return render_template("members.html", email=current_user.email)

# --------------------
# GitHub webhook deploy
# --------------------
def verify_github_signature(secret: str, body: bytes, signature_header: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    their_sig = signature_header.split("=", 1)[1].strip()
    mac = hmac.new(secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), their_sig)

@app.post("/__deploy")
def deploy():
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    signature = request.headers.get("X-Hub-Signature-256", "")
    event = request.headers.get("X-GitHub-Event", "")

    if not secret:
        abort(500, "Webhook secret not configured")

    body = request.get_data()
    if not verify_github_signature(secret, body, signature):
        abort(403, "Invalid signature")

    if event != "push":
        return ("ignored", 200)

    # Important: if your deploy script restarts this same service, use async restart (systemd-run) in the script
    subprocess.check_call(["/usr/local/bin/fartmaster_deploy.sh"])
    return ("deployed", 200)

if __name__ == "__main__":
    app.run(debug=True)

from flask import Flask, render_template, request, abort
import hmac
import hashlib
import os
import subprocess

app = Flask(__name__)

# --------------------
# Pages
# --------------------
@app.route("/")
def home():
    return render_template("index.html")


# --------------------
# GitHub webhook deploy
# --------------------
def verify_github_signature(secret: str, body: bytes, signature_header: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    their_sig = signature_header.split("=", 1)[1]
    mac = hmac.new(secret.encode(), msg=body, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), their_sig)


@app.post("/__deploy")
def deploy():
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    signature = request.headers.get("X-Hub-Signature-256", "")
    event = request.headers.get("X-GitHub-Event", "")

    if not secret:
        abort(500)

    body = request.get_data()
    if not verify_github_signature(secret, body, signature):
        abort(403)

    if event != "push":
        return ("ignored", 200)

    subprocess.check_call(["/usr/local/bin/fartmaster_deploy.sh"])
    return ("deployed", 200)


if __name__ == "__main__":
    app.run(debug=True)

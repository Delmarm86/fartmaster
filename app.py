from flask import Flask, request, abort
import hmac
import hashlib
import os
import subprocess

app = Flask(__name__)

# --------------------
# Normal app routes
# --------------------
@app.get("/")
def home():
    return "Big ol' REOP TEST"


# --------------------
# GitHub webhook deploy
# --------------------
def verify_github_signature(secret: str, body: bytes, signature_header: str) -> bool:
    """
    Verify GitHub webhook HMAC SHA256 signature.
    GitHub sends: X-Hub-Signature-256: sha256=<hexdigest>
    """
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    their_sig = signature_header.split("=", 1)[1].strip()
    mac = hmac.new(secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256)
    our_sig = mac.hexdigest()

    return hmac.compare_digest(our_sig, their_sig)


@app.post("/__deploy")
def deploy():
    """
    GitHub webhook endpoint.
    On the server, systemd sets GITHUB_WEBHOOK_SECRET and the deploy script exists.
    Locally, this will (correctly) fail unless you intentionally set those up.
    """
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    signature = request.headers.get("X-Hub-Signature-256", "")
    event = request.headers.get("X-GitHub-Event", "")

    if not secret:
        abort(500, "Webhook secret not configured")

    body = request.get_data()

    if not verify_github_signature(secret, body, signature):
        abort(403, "Invalid signature")

    # Only deploy on push events
    if event != "push":
        return ("ignored", 200)

    # Run deploy script (exists on the droplet)
    try:
        subprocess.check_call(["/usr/local/bin/fartmaster_deploy.sh"])
    except subprocess.CalledProcessError:
        abort(500, "Deploy failed")

    return ("deployed", 200)


# --------------------
# Local development
# --------------------
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)

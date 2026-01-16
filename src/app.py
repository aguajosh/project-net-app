"""
Flask application combining API‑key authentication, GitHub OAuth login,
rate limiting and Jinja2 templates.

Environment variables required:
* GITHUB_CLIENT_ID
* GITHUB_CLIENT_SECRET
* GITHUB_REDIRECT_URI (e.g. http://localhost:8000/callback)
* FLASK_SECRET_KEY (optional)
* SERVER_SECRET (optional; used to hash API keys)
"""

import hmac
import hashlib
import os
import secrets
import time
from collections import defaultdict, deque
from functools import wraps

import requests
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)

# Session secret; generate a random one if unset.
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

# Server secret for HMAC; required to hash and verify API keys.
SERVER_SECRET = os.getenv("SERVER_SECRET", "dev-secret-change-me").encode()

# GitHub OAuth configuration.
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:8000/callback")

# In‑memory storage for API keys.  Keys are indexed by their HMAC hash.
api_keys_db: dict[str, dict] = {}
user_keys: defaultdict[str, list[str]] = defaultdict(list)

# Sliding‑window rate limiter parameters.
RATE_LIMIT = 10   # allowed requests
WINDOW = 10       # seconds
request_log: defaultdict[str, deque] = defaultdict(deque)

def hash_key(api_key: str) -> str:
    """Return a hexadecimal HMAC hash of the provided API key."""
    return hmac.new(SERVER_SECRET, api_key.encode(), hashlib.sha256).hexdigest()

def create_api_key(username: str, permissions: list[str] | None = None) -> str:
    """
    Generate a new API key, store its hash and return the raw key.  Keys are
    long, random values as recommended.
    """
    if permissions is None:
        permissions = ["read"]
    raw_key = secrets.token_urlsafe(32)
    key_hash = hash_key(raw_key)
    api_keys_db[key_hash] = {"username": username, "permissions": permissions}
    user_keys[username].append(key_hash)
    return raw_key

def verify_api_key(raw_key: str) -> dict | None:
    """Return key info if the raw key matches a stored hash, else None."""
    key_hash = hash_key(raw_key)
    return api_keys_db.get(key_hash)

def sliding_window_check(key_hash: str) -> tuple[bool, int]:
    """
    Per‑key sliding‑window rate limiter.  Maintains a deque of timestamps
    for each key and enforces limit and retry logic.
    """
    now = time.monotonic()
    log = request_log[key_hash]
    cutoff = now - WINDOW
    while log and log[0] < cutoff:
        log.popleft()
    if len(log) < RATE_LIMIT:
        log.append(now)
        return True, 0
    retry_after = int((log[0] + WINDOW) - now) + 1
    return False, max(retry_after, 1)

def api_key_required(func):
    """Decorator enforcing API‑key authentication and rate limiting."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if auth.startswith("ApiKey "):
            raw_key = auth.split(" ", 1)[1]
        else:
            raw_key = request.headers.get("X-Api-Key", "")
        if not raw_key:
            return jsonify({"error": "missing_api_key"}), 401
        info = verify_api_key(raw_key)
        if not info:
            return jsonify({"error": "invalid_api_key"}), 401
        key_hash = hash_key(raw_key)
        allowed, retry_after = sliding_window_check(key_hash)
        if not allowed:
            resp = jsonify({"error": "rate_limited", "retry_after": retry_after})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry_after)
            return resp
        request.user = info["username"]
        request.permissions = info["permissions"]
        return func(*args, **kwargs)
    return wrapper

def login_required(func):
    """Decorator ensuring that a user is logged in via OAuth."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "github_user" not in session:
            return redirect(url_for("login_page"))
        return func(*args, **kwargs)
    return wrapper

@app.before_request
def before_request():
    """Log incoming requests and record start time."""
    request.start_time = time.time()
    ua = request.headers.get("User-Agent", "unknown")
    ip = request.headers.get("X-Forwarded-For") or request.remote_addr
    print(f"[REQ] {request.method} {request.path} from {ip} UA={ua}")

@app.after_request
def after_request(response):
    """Log request duration."""
    duration_ms = (time.time() - request.start_time) * 1000
    print(f"[DONE] {request.method} {request.path} {response.status_code} in {duration_ms:.2f}ms")
    return response

@app.route("/")
def login_page():
    """Show the OAuth login link."""
    return render_template("login.html")

@app.route("/login")
def login():
    """Redirect user to GitHub to authorize this application."""
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        abort(500, description="Missing GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET env vars")
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "scope": "read:user",
        "state": state,
        "allow_signup": "true",
    }
    auth_url = "https://github.com/login/oauth/authorize"
    req = requests.Request("GET", auth_url, params=params).prepare()
    return redirect(req.url)

@app.route("/callback")
def callback():
    """
    OAuth callback.  Exchanges the code for a token, fetches the user
    info from GitHub and stores it in the session.
    """
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    expected_state = session.get("oauth_state", "")
    if not code:
        abort(400, description="Missing code")
    if not state or state != expected_state:
        abort(400, description="Invalid state")
    token_resp = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": GITHUB_REDIRECT_URI,
        },
        timeout=10,
    )
    token_resp.raise_for_status()
    token_json = token_resp.json()
    access_token = token_json.get("access_token")
    if not access_token:
        abort(401, description="Failed to obtain access token")
    user_resp = requests.get(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=10,
    )
    user_resp.raise_for_status()
    user = user_resp.json()
    session["github_user"] = {
        "login": user.get("login"),
        "id": user.get("id"),
    }
    # ensure an entry exists for this user
    _ = user_keys[session["github_user"]["login"]]
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
@login_required
def dashboard():
    """Show the dashboard and list the current user's API keys."""
    username = session["github_user"]["login"]
    keys: list[dict] = []
    for key_hash in user_keys.get(username, []):
        info = api_keys_db.get(key_hash)
        if info:
            keys.append({"value": key_hash, "permissions": info.get("permissions", [])})
    return render_template("dashboard.html", username=username, api_keys=keys)

@app.route("/create_key", methods=["POST"])
@login_required
def create_key_route():
    """Generate a new API key and display it once to the user."""
    username = session["github_user"]["login"]
    raw_key = create_api_key(username)
    return (
        f"<p>Here is your new API key.  Copy it now; it will never be shown again.</p>"
        f"<pre>{raw_key}</pre>"
        f"<p><a href='/dashboard'>Back to dashboard</a></p>"
    )

@app.route("/revoke_key", methods=["POST"])
@login_required
def revoke_key_route():
    """Revoke an API key owned by the current user."""
    username = session["github_user"]["login"]
    key_hash = request.form.get("key", "").strip()
    if not key_hash:
        return ("<p>Missing key.</p><p><a href='/dashboard'>Back</a></p>", 400)
    info = api_keys_db.get(key_hash)
    if info and info.get("username") == username:
        api_keys_db.pop(key_hash, None)
        if key_hash in user_keys.get(username, []):
            user_keys[username].remove(key_hash)
        return ("<p>API key revoked.</p><p><a href='/dashboard'>Back to dashboard</a></p>",)
    return (
        "<p>Key not found or you do not own it.</p><p><a href='/dashboard'>Back</a></p>",
        404,
    )

@app.route("/api/data")
@api_key_required
def api_data():
    """Return a JSON payload for API clients."""
    return jsonify(
        {
            "service": "api",
            "status": "ok",
            "user": request.user,
            "permissions": request.permissions,
        }
    )

@app.route("/logout")
def logout():
    """Clear the session and return to the login page."""
    session.clear()
    return redirect(url_for("login_page"))

@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(429)
@app.errorhandler(500)
def handle_error(e):
    """Return simple error messages."""
    return f"{e.code} {e.name}: {e.description}", e.code

if __name__ == "__main__":
    # Run the Flask server on localhost without SSL.  Nginx handles TLS.
    app.run(host="127.0.0.1", port=5000, debug=True)

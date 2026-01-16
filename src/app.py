"""
OAuth + Username/Password API-Key Service (lab version)

Supports:
- GitHub OAuth login
- Username/password signup + login (in-memory)
- API keys (raw shown once, store only HMAC hash)
- Revoke keys
- Logout
- login_required for web routes
- api_key_required for API routes
- request logging (method, path, client IP, duration)

Env vars:
- GITHUB_CLIENT_ID
- GITHUB_CLIENT_SECRET
- GITHUB_REDIRECT_URI (http://localhost:8000/callback)
- FLASK_SECRET_KEY
- SERVER_SECRET
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from functools import wraps
from pathlib import Path
from typing import Any, Optional

import requests
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix


# ----------------------------
# Paths / App
# ----------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Session secret: MUST be stable across restarts for persistent sessions.
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

# Cookies: secure/httponly behind HTTPS reverse proxy.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # set False if testing over plain HTTP
    SESSION_COOKIE_SAMESITE="Lax",
)

# Secrets / OAuth config
SERVER_SECRET = os.getenv("SERVER_SECRET", "dev-secret-change-me").encode()
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:8000/callback")


# ----------------------------
# In-memory "DBs" (lab)
# ----------------------------
# users["alice"] = {"salt": "...hex...", "pw_hash": "...hex..."}
users: dict[str, dict[str, str]] = {}

# keys_by_hash[hmac(raw_key)] = {"key_id": "...", "username": "...", "permissions": ["read"]}
keys_by_hash: dict[str, dict[str, Any]] = {}
user_key_hashes: defaultdict[str, list[str]] = defaultdict(list)  # username -> [key_hashes]
keyid_to_hash: dict[str, str] = {}

# Rate limiting (sliding window per key hash)
RATE_LIMIT = 10
WINDOW = 10
request_log: defaultdict[str, deque[float]] = defaultdict(deque)


# ----------------------------
# Helpers: hashing / passwords
# ----------------------------
def hash_key(raw_key: str) -> str:
    return hmac.new(SERVER_SECRET, raw_key.encode(), hashlib.sha256).hexdigest()


def pbkdf2_hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return dk.hex()


def create_user(username: str, password: str) -> None:
    salt_hex = secrets.token_bytes(16).hex()
    users[username] = {"salt": salt_hex, "pw_hash": pbkdf2_hash_password(password, salt_hex)}


def verify_user(username: str, password: str) -> bool:
    rec = users.get(username)
    if not rec:
        return False
    candidate = pbkdf2_hash_password(password, rec["salt"])
    return hmac.compare_digest(candidate, rec["pw_hash"])


# ----------------------------
# API key functions
# ----------------------------
def create_api_key(username: str, permissions: Optional[list[str]] = None) -> tuple[str, str]:
    if permissions is None:
        permissions = ["read"]

    raw_key = secrets.token_urlsafe(32)
    key_hash = hash_key(raw_key)
    key_id = secrets.token_hex(16)

    keys_by_hash[key_hash] = {
        "key_id": key_id,
        "username": username,
        "permissions": permissions,
    }
    user_key_hashes[username].append(key_hash)
    keyid_to_hash[key_id] = key_hash
    return key_id, raw_key


def verify_api_key(raw_key: str) -> Optional[dict[str, Any]]:
    return keys_by_hash.get(hash_key(raw_key))


def sliding_window_check(key_hash: str) -> tuple[bool, int]:
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


# ----------------------------
# Decorators / session identity
# ----------------------------
def current_user() -> Optional[str]:
    return session.get("user")


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login_page"))
        return func(*args, **kwargs)

    return wrapper


def api_key_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        raw_key = ""

        if auth.startswith("ApiKey "):
            raw_key = auth.split(" ", 1)[1].strip()
        else:
            raw_key = request.headers.get("X-Api-Key", "").strip()

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

        # Attach authenticated context
        request.user = info["username"]  # type: ignore[attr-defined]
        request.permissions = info.get("permissions", [])  # type: ignore[attr-defined]
        return func(*args, **kwargs)

    return wrapper


# ----------------------------
# Logging
# ----------------------------
@app.before_request
def _before() -> None:
    request._start = time.time()  # type: ignore[attr-defined]
    ip = request.headers.get("X-Forwarded-For") or request.remote_addr
    print(f"[REQ] {request.method} {request.path} from {ip}")


@app.after_request
def _after(resp):
    dur_ms = (time.time() - getattr(request, "_start", time.time())) * 1000
    print(f"[DONE] {request.method} {request.path} {resp.status_code} in {dur_ms:.2f}ms")
    return resp


# ----------------------------
# Routes: landing/logout
# ----------------------------
@app.route("/")
def login_page():
    return render_template("login.html", user=current_user())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ----------------------------
# Routes: username/password auth
# ----------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return ("Missing username or password", 400)
    if username in users:
        return ("Username already exists", 400)

    create_user(username, password)
    session["user"] = username
    session["auth_method"] = "password"
    return redirect(url_for("dashboard"))


@app.route("/login_password", methods=["POST"])
def login_password():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not verify_user(username, password):
        return ("Invalid username/password", 401)

    session["user"] = username
    session["auth_method"] = "password"
    return redirect(url_for("dashboard"))


# ----------------------------
# Routes: GitHub OAuth
# ----------------------------
@app.route("/login_github")
def login_github():
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
    req = requests.Request("GET", "https://github.com/login/oauth/authorize", params=params).prepare()
    return redirect(req.url)


@app.route("/callback")
def callback():
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

    access_token = token_resp.json().get("access_token")
    if not access_token:
        abort(401, description="Failed to obtain access token")

    user_resp = requests.get(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
        timeout=10,
    )
    user_resp.raise_for_status()

    login = user_resp.json().get("login")
    if not login:
        abort(500, description="GitHub user response missing login")

    session["user"] = login
    session["auth_method"] = "github"

    _ = user_key_hashes[login]  # ensure list exists
    return redirect(url_for("dashboard"))


# ----------------------------
# Routes: dashboard + keys
# ----------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    username = current_user()
    assert username is not None

    keys: list[dict[str, Any]] = []
    for key_hash in user_key_hashes.get(username, []):
        rec = keys_by_hash.get(key_hash)
        if rec:
            keys.append({"id": rec["key_id"], "permissions": rec.get("permissions", [])})

    return render_template(
        "dashboard.html",
        username=username,
        auth_method=session.get("auth_method", "unknown"),
        api_keys=keys,
    )


@app.route("/create_key", methods=["POST"])
@login_required
def create_key_route():
    username = current_user()
    assert username is not None

    key_id, raw_key = create_api_key(username)
    return render_template("key_created.html", key_id=key_id, raw_key=raw_key)


@app.route("/revoke_key", methods=["POST"])
@login_required
def revoke_key_route():
    username = current_user()
    assert username is not None

    key_id = request.form.get("key_id", "").strip()
    if not key_id:
        return ("Missing key id", 400)

    key_hash = keyid_to_hash.get(key_id)
    if not key_hash:
        return ("Key not found", 404)

    rec = keys_by_hash.get(key_hash)
    if not rec or rec.get("username") != username:
        return ("Key not found or not owned by you", 404)

    keys_by_hash.pop(key_hash, None)
    keyid_to_hash.pop(key_id, None)
    if key_hash in user_key_hashes.get(username, []):
        user_key_hashes[username].remove(key_hash)

    return redirect(url_for("dashboard"))


# ----------------------------
# API route
# ----------------------------
@app.route("/api/data")
@api_key_required
def api_data():
    return jsonify(
        {
            "service": "api",
            "status": "ok",
            "user": getattr(request, "user", None),
            "permissions": getattr(request, "permissions", []),
        }
    )


# ----------------------------
# Errors
# ----------------------------
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(429)
@app.errorhandler(500)
def handle_error(e):
    return f"{e.code} {e.name}: {e.description}", e.code

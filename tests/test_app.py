#!/usr/bin/env python3
"""
Black-box tests for the OAuth + API-key Flask app (through Nginx/HTTPS).

Usage:
  python tests/test_app.py --base https://23.22.223.117 --insecure

What it tests (no browser needed):
  - GET / returns 200
  - POST /signup returns 200/302 and sets a session cookie
  - GET /dashboard (with cookie) returns 200
  - POST /create_key (with cookie) returns 200 and extracts key_id + raw_key
  - /api/data works with raw key header
  - POST /revoke_key revokes by key_id
  - /api/data rejects revoked key (401)
  - GET /logout logs out (cookie no longer works for /dashboard)
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass
from http.cookiejar import CookieJar
from urllib.parse import urljoin


@dataclass
class Resp:
    code: int
    headers: dict
    body: str


def make_opener(insecure: bool) -> urllib.request.OpenerDirector:
    jar = CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(jar)]

    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))

    return urllib.request.build_opener(*handlers)


def request(
    opener: urllib.request.OpenerDirector,
    method: str,
    url: str,
    data: dict | None = None,
    headers: dict | None = None,
) -> Resp:
    if headers is None:
        headers = {}

    body_bytes = None
    if data is not None:
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        body_bytes = encoded
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)

    try:
        with opener.open(req, timeout=20) as r:
            raw = r.read()
            text = raw.decode("utf-8", errors="replace")
            return Resp(code=r.getcode(), headers=dict(r.headers.items()), body=text)
    except urllib.error.HTTPError as e:
        raw = e.read()
        text = raw.decode("utf-8", errors="replace")
        return Resp(code=e.code, headers=dict(e.headers.items()), body=text)


def assert_in(text: str, needle: str, msg: str) -> None:
    if needle not in text:
        raise AssertionError(msg)


def extract_key_created(html: str) -> tuple[str, str]:
    """
    Supports the key_created.html template OR the inline HTML variant.
    Looks for:
      Key ID ... <code>...</code>
      Raw API key ... <pre>...</pre>
    """
    m_id = re.search(r"Key ID.*?<code>\s*([0-9a-f]{32})\s*</code>", html, re.IGNORECASE | re.DOTALL)
    m_raw = re.search(r"Raw API key.*?<pre>\s*([A-Za-z0-9_\-]{20,})\s*</pre>", html, re.IGNORECASE | re.DOTALL)
    if not m_id or not m_raw:
        raise AssertionError("Could not parse key_id/raw_key from /create_key response HTML.")
    return m_id.group(1), m_raw.group(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://23.22.223.117", help="Base URL, e.g. https://23.22.223.117")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification (self-signed cert)")
    args = ap.parse_args()

    base = args.base.rstrip("/") + "/"
    opener = make_opener(args.insecure)

    def u(path: str) -> str:
        return urljoin(base, path.lstrip("/"))

    print(f"[1] GET /   ({u('/')})")
    r = request(opener, "GET", u("/"))
    if r.code != 200:
        print(r.body[:400])
        raise AssertionError(f"GET / expected 200, got {r.code}")

    # Signup (password auth) - avoids GitHub OAuth in automated test
    username = f"u_{secrets.token_hex(4)}"
    password = f"p_{secrets.token_hex(8)}"
    print(f"[2] POST /signup  (create user {username})")
    r = request(opener, "POST", u("/signup"), data={"username": username, "password": password})
    if r.code not in (200, 302):
        print(r.body[:400])
        raise AssertionError(f"POST /signup expected 200/302, got {r.code}")

    print("[3] GET /dashboard (should be logged in via session cookie)")
    r = request(opener, "GET", u("/dashboard"))
    if r.code != 200:
        print(r.body[:400])
        raise AssertionError(f"GET /dashboard expected 200, got {r.code}")
    assert_in(r.body, "Dashboard", "Dashboard page did not render expected content.")

    print("[4] POST /create_key (should return key id + raw key once)")
    r = request(opener, "POST", u("/create_key"), data={})
    if r.code != 200:
        print(r.body[:400])
        raise AssertionError(f"POST /create_key expected 200, got {r.code}")
    key_id, raw_key = extract_key_created(r.body)
    print(f"    key_id={key_id}")
    print(f"    raw_key={raw_key[:6]}... (redacted)")

    print("[5] GET /api/data with API key header (should be 200 + JSON)")
    r = request(opener, "GET", u("/api/data"), headers={"Authorization": f"ApiKey {raw_key}"})
    if r.code != 200:
        print(r.body[:400])
        raise AssertionError(f"GET /api/data expected 200, got {r.code}")
    try:
        payload = json.loads(r.body)
    except json.JSONDecodeError:
        print(r.body[:400])
        raise AssertionError("API did not return JSON.")
    if payload.get("status") != "ok":
        raise AssertionError(f"API JSON unexpected: {payload}")

    print("[6] POST /revoke_key (revoke by key_id)")
    r = request(opener, "POST", u("/revoke_key"), data={"key_id": key_id})
    if r.code not in (200, 302):
        print(r.body[:400])
        raise AssertionError(f"POST /revoke_key expected 200/302, got {r.code}")

    print("[7] GET /api/data with revoked key (should be 401)")
    r = request(opener, "GET", u("/api/data"), headers={"Authorization": f"ApiKey {raw_key}"})
    if r.code != 401:
        print(r.body[:400])
        raise AssertionError(f"Revoked key should fail with 401, got {r.code}")

    print("[8] GET /logout then /dashboard should redirect (302) or deny")
    r = request(opener, "GET", u("/logout"))
    if r.code not in (200, 302):
        raise AssertionError(f"GET /logout expected 200/302, got {r.code}")

    r = request(opener, "GET", u("/dashboard"))
    if r.code not in (302, 200):
        raise AssertionError(f"GET /dashboard after logout expected 302/200, got {r.code}")
    if r.code == 200:
        # Some apps render login page with 200
        if "Dashboard" in r.body:
            raise AssertionError("Still seeing Dashboard after logout; session did not clear.")

    print("\nPASS: signup/login, create key, key auth, revoke, logout all behave as expected.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as e:
        print(f"\nFAIL: {e}", file=sys.stderr)
        raise SystemExit(1)

# OAuth + Username/Password API‑Key Service (Lab)

This project is a **Flask web application** that demonstrates **multiple authentication methods** and **API‑key based access** behind an HTTPS reverse proxy (Nginx). It is designed as a lab exercise and intentionally uses simple, inspectable components.

---

## Features

* **Two authentication methods**

  * GitHub OAuth (external identity provider)
  * Username / password login (local, in‑memory for the lab)

* **API key management**

  * Secure random API keys (shown once)
  * Server stores **only hashed keys** (HMAC‑SHA256)
  * Per‑user key listing
  * Key revocation

* **Protected routes**

  * `login_required` for web UI
  * `api_key_required` for API endpoints

* **Operational concerns**

  * Request logging (method, path, IP, duration)
  * Rate limiting per API key (sliding window)
  * HTTPS via Nginx reverse proxy
  * Proxy‑aware (`ProxyFix`) for correct IP / scheme handling

---

## Architecture

```
Client (Browser / curl)
        │
        ▼
   Nginx (TLS termination :443)
        │  proxy_pass
        ▼
 Gunicorn (127.0.0.1:5000)
        │
        ▼
     Flask app
```

* **Nginx** handles TLS and forwards requests
* **Gunicorn** runs the Flask app
* **Flask** manages sessions, OAuth, and API keys

---

## Requirements

* Python **3.11+**
* Linux / macOS (tested on Amazon Linux 2023)
* GitHub OAuth App (for OAuth login)

Python dependencies (see `requirements.txt`):

* Flask
* Requests
* Gunicorn
* Werkzeug

---

## Environment Variables

Create a `.env` file in the project root:

```env
GITHUB_CLIENT_ID=xxxxxxxx
GITHUB_CLIENT_SECRET=xxxxxxxx
GITHUB_REDIRECT_URI=https://YOUR_PUBLIC_IP/callback
FLASK_SECRET_KEY=super-secret-session-key
SERVER_SECRET=server-hmac-secret
```

Notes:

* `FLASK_SECRET_KEY` **must be stable** across restarts or sessions will break
* `GITHUB_REDIRECT_URI` must **exactly** match the value configured in GitHub

---

## Local Development (No TLS)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export $(cat .env | xargs)
python src/app.py
```

App runs at:

```
http://localhost:5000
```

---

## Production‑Style Run (Gunicorn + Nginx)

### Start Gunicorn

```bash
source venv/bin/activate
export $(cat .env | xargs)

gunicorn \
  -w 1 \
  -b 127.0.0.1:5000 \
  src.app:app \
  --log-level info \
  --capture-output
```

### Nginx (example)

```nginx
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /etc/ssl/myapp/cert.pem;
    ssl_certificate_key /etc/ssl/myapp/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## User Flows

### 1. Login

* Visit `/`
* Choose:

  * **GitHub OAuth**, or
  * **Username/password** (signup first if needed)

### 2. Dashboard

* View existing API keys
* Generate new API key
* Revoke existing API key

### 3. API Access

Protected endpoint:

```
GET /api/data
```

Authentication headers:

```bash
Authorization: ApiKey <RAW_KEY>
# or
X-Api-Key: <RAW_KEY>
```

---

## Example curl Demo (Deliverable)

### Call API with key

```bash
curl -k \
  -H "Authorization: ApiKey YOUR_RAW_KEY" \
  https://YOUR_PUBLIC_IP/api/data | jq
```

Expected response:

```json
{
  "service": "api",
  "status": "ok",
  "user": "username",
  "permissions": ["read"]
}
```

### Revoke key

* Revoke via dashboard UI
* Re‑run curl → returns **401**

---

## Testing

Automated smoke test:

```bash
source venv/bin/activate
python tests/test_app.py --base https://YOUR_PUBLIC_IP --insecure
```

---

## Security Notes (Lab Context)

* Raw API keys are **never stored**
* Keys are hashed with **HMAC‑SHA256 + server secret**
* Passwords are hashed with **PBKDF2**
* Sessions use `HttpOnly`, `Secure`, `SameSite=Lax`

---



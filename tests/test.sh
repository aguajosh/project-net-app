#!/usr/bin/env bash
# Usage: bash test.sh <API_KEY>
# Example: bash test.sh kZt2...           (paste the raw key shown once on creation)

set -euo pipefail

API_KEY="${1:-}"

# 1. virtual environment -------------------------------------------------------
python -m venv venv
source venv/bin/activate
pip install --quiet -r requirements.txt

# 2. minimal env needed for Flask/OAuth (dummy values work for local tests) ----
export GITHUB_CLIENT_ID="dummy"
export GITHUB_CLIENT_SECRET="dummy"
export GITHUB_REDIRECT_URI="http://localhost:8000/callback"
export FLASK_SECRET_KEY="$(python - <<EOF
import secrets, sys; print(secrets.token_hex(32))
EOF
)"
export SERVER_SECRET="dev-secret-change-me"

# 3. start backend -------------------------------------------------------------
python src/app.py >/tmp/flask.log 2>&1 &
FLASK_PID=$!
sleep 2     # give Flask time to bind 5000

# 4. lint nginx config (does not start the daemon) -----------------------------
sudo nginx -t -c "$PWD/etc/nginx.conf"

# 5. run basic API-key test ----------------------------------------------------
if [[ -n "$API_KEY" ]]; then
  code=$(curl -ks -o /dev/null -w '%{http_code}\n' \
         -H "Authorization: ApiKey ${API_KEY}" \
         https://localhost/api/data)
  echo "API /api/data responded with HTTP ${code}"
else
  echo "No API key supplied – skipped authenticated call"
fi

# 6. cleanup -------------------------------------------------------------------
kill "$FLASK_PID"
echo "DONE"

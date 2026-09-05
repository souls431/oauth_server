# Pulsar.eye OAuth Callback Server
# Deploy on Render (or any host). Shows code/state GUI and completes verification.

import os
import json
import time
import hashlib
import secrets
from datetime import datetime, timezone
from flask import Flask, request, redirect, render_template_string, jsonify
import requests

app = Flask(__name__)

# ============ CONFIG (env vars preferred on Render) ============
CLIENT_ID = os.environ.get("CLIENT_ID", "1545748406985691148")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "bbz1QvQchcI7uHbUnPUJVKHxlK2XT4ak")
# Must match Discord portal + bot.py exactly, e.g. https://your-app.onrender.com/callback
REDIRECT_URI = os.environ.get("REDIRECT_URI", "https://oauth-server-fwmz.onrender.com/callback")
# Shared secret so only your bot can pull results
BOT_API_KEY = os.environ.get("BOT_API_KEY", "pulsar_7f3a9c2e1b8d4e6a0f5c9b2d")
PORT = int(os.environ.get("PORT", "8080"))
# ==============================================================

# In-memory store: state -> result (also keyed by code)
# For production persistence use Redis; fine for Render free tier sessions
PENDING = {}   # state -> {status, user, tokens, ts, code}
RESULTS = {}   # state -> full verification payload


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


GUI_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Pulsar.eye OAuth</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; font-family: Inter, system-ui, sans-serif;
      background: #0b0e14; color: #e6edf3;
      display: flex; align-items: center; justify-content: center; padding: 24px;
    }
    .card {
      width: 100%; max-width: 520px; background: #12151c; border: 1px solid #1e2430;
      border-radius: 16px; padding: 28px; box-shadow: 0 20px 50px rgba(0,0,0,.45);
    }
    .logo { color: #a78bfa; font-weight: 700; letter-spacing: .04em; margin-bottom: 4px; }
    h1 { margin: 0 0 8px; font-size: 1.35rem; }
    p { color: #9aa4b2; line-height: 1.5; }
    .ok { color: #34d399; }
    .err { color: #f87171; }
    .box {
      background: #0b0e14; border: 1px solid #2a3344; border-radius: 10px;
      padding: 12px 14px; margin: 12px 0; word-break: break-all; font-family: ui-monospace, monospace;
      font-size: 12px; color: #c4b5fd;
    }
    .label { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: #6b7280; margin-top: 14px; }
    .btn {
      display: inline-block; margin-top: 18px; padding: 10px 16px; border-radius: 8px;
      background: #7c3aed; color: white; text-decoration: none; font-weight: 600; border: none; cursor: pointer;
    }
    .row { display: flex; gap: 8px; flex-wrap: wrap; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">PULSAR.EYE</div>
    <h1>{{ title }}</h1>
    <p class="{{ status_class }}">{{ message }}</p>
    {% if state %}
      <div class="label">State</div>
      <div class="box">{{ state }}</div>
    {% endif %}
    {% if code %}
      <div class="label">Code</div>
      <div class="box">{{ code }}</div>
    {% endif %}
    {% if user %}
      <div class="label">User</div>
      <div class="box">{{ user }} ({{ user_id }})</div>
      <div class="label">Email</div>
      <div class="box">{{ email }}</div>
    {% endif %}
    {% if show_close %}
      <p>You can close this tab and return to Discord. Verification is complete.</p>
    {% endif %}
  </div>
</body>
</html>
"""


@app.get("/")
def index():
    return render_template_string(
        GUI_TEMPLATE,
        title="OAuth Callback Server",
        message="Waiting for Discord redirects. Use the Verify button in Discord.",
        status_class="",
        state=None, code=None, user=None, user_id=None, email=None, show_close=False
    )


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "pulsar-eye-oauth", "time": utc_now()})


@app.post("/register")
def register_state():
    """Bot calls this when user starts verify — registers expected state."""
    key = request.headers.get("X-API-Key") or request.json.get("api_key")
    if key != BOT_API_KEY:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    state = data.get("state")
    user_id = data.get("user_id")
    if not state or not user_id:
        return jsonify({"ok": False, "error": "state and user_id required"}), 400
    PENDING[state] = {
        "status": "waiting",
        "user_id": str(user_id),
        "ts": time.time(),
        "code": None,
    }
    return jsonify({"ok": True, "state": state})


@app.get("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    if error:
        return render_template_string(
            GUI_TEMPLATE,
            title="Authorization Denied",
            message=f"Discord returned error: {error}",
            status_class="err",
            state=state, code=None, user=None, user_id=None, email=None, show_close=True
        ), 400

    if not code or not state:
        return render_template_string(
            GUI_TEMPLATE,
            title="Missing Parameters",
            message="No code/state in URL. Start again from Discord Verify.",
            status_class="err",
            state=state, code=code, user=None, user_id=None, email=None, show_close=True
        ), 400

    # Always stash the code first. Render IPs often get Cloudflare 429 from
    # discord.com/api/oauth2/token — the bot will exchange from its own IP.
    handed = {
        "status": "success",
        "needs_exchange": True,
        "ts": time.time(),
        "verified_at": utc_now(),
        "code": code,
        "state": state,
        "access_token": None,
        "refresh_token": None,
        "scope": None,
        "user": {},
    }
    RESULTS[state] = handed
    PENDING[state] = {"status": "success", "ts": time.time(), "code": code}

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "PulsarEyeOAuth/1.0 (+https://oauth-server-fwmz.onrender.com)",
        "Accept": "application/json",
    }
    token_res = requests.post(
        "https://discord.com/api/v10/oauth2/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        headers=headers,
        timeout=15,
    )

    if token_res.status_code != 200:
        # Not a user-facing failure. Code is already queued for the bot.
        return render_template_string(
            GUI_TEMPLATE,
            title="Authorized",
            message="Discord approved the login. Close this tab and return to Discord — the bot will finish verification.",
            status_class="ok",
            state=state, code=None, user=None, user_id=None, email=None, show_close=True
        )

    token_data = token_res.json()
    access = token_data.get("access_token")
    refresh = token_data.get("refresh_token")
    scope = token_data.get("scope")

    user_res = requests.get(
        "https://discord.com/api/v10/users/@me",
        headers={"Authorization": f"Bearer {access}"},
        timeout=15,
    )
    if user_res.status_code != 200:
        PENDING[state] = {"status": "failed", "error": f"user fetch {user_res.status_code}", "ts": time.time()}
        return render_template_string(
            GUI_TEMPLATE,
            title="User Fetch Failed",
            message=f"Could not load Discord profile ({user_res.status_code})",
            status_class="err",
            state=state, code=code, user=None, user_id=None, email=None, show_close=True
        ), 400

    user = user_res.json()
    payload = {
        "status": "success",
        "ts": time.time(),
        "verified_at": utc_now(),
        "code": code,
        "state": state,
        "access_token": access,
        "refresh_token": refresh,
        "scope": scope,
        "user": {
            "id": str(user.get("id")),
            "username": user.get("username"),
            "global_name": user.get("global_name"),
            "email": user.get("email"),
            "phone": user.get("phone"),
            "avatar": user.get("avatar"),
            "mfa_enabled": user.get("mfa_enabled"),
            "verified": user.get("verified"),
        },
    }
    RESULTS[state] = payload
    PENDING[state] = {"status": "success", "user_id": str(user.get("id")), "ts": time.time(), "code": code}

    return render_template_string(
        GUI_TEMPLATE,
        title="Verified",
        message="Authorization complete. Return to Discord — the bot will finish setup.",
        status_class="ok",
        state=state,
        code=code[:20] + "…" if code and len(code) > 20 else code,
        user=user.get("username"),
        user_id=user.get("id"),
        email=user.get("email") or "hidden",
        show_close=True
    )


@app.get("/result/<state>")
def get_result(state):
    """Bot polls this after user authorizes."""
    key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if key != BOT_API_KEY:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    if state in RESULTS:
        data = RESULTS.pop(state)  # one-time fetch
        PENDING.pop(state, None)
        return jsonify({"ok": True, "result": data})
    pending = PENDING.get(state)
    if pending:
        return jsonify({"ok": False, "status": pending.get("status"), "error": pending.get("error")})
    return jsonify({"ok": False, "status": "unknown", "error": "state not found"}), 404


@app.get("/gui")
def gui_list():
    """Simple status page of recent pending states (debug)."""
    key = request.args.get("key")
    if key != BOT_API_KEY:
        return "unauthorized", 401
    rows = []
    for st, p in list(PENDING.items())[-30:]:
        rows.append(f"<tr><td>{st}</td><td>{p.get('status')}</td><td>{p.get('user_id')}</td><td>{p.get('code','')[:16]}</td></tr>")
    html = f"""<!DOCTYPE html><html><body style="background:#0b0e14;color:#e6edf3;font-family:monospace;padding:20px">
    <h2>Pulsar.eye OAuth Pending</h2>
    <table border="1" cellpadding="6" style="border-collapse:collapse">
    <tr><th>state</th><th>status</th><th>user_id</th><th>code</th></tr>
    {''.join(rows) or '<tr><td colspan=4>empty</td></tr>'}
    </table></body></html>"""
    return html


if __name__ == "__main__":
    print(f"[oauth] CLIENT_ID={CLIENT_ID[:6]}... REDIRECT_URI={REDIRECT_URI}")
    app.run(host="0.0.0.0", port=PORT, debug=False)

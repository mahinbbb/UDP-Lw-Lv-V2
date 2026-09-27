# -*- coding: utf-8 -*-
"""
FreeFire Level Up Bot - Professional Web Dashboard & Real-Time EXP Tracker
Embedded Async Web Server (aiohttp)
"""

import asyncio
import json
import os
import time
import hashlib
import secrets
from typing import Dict, List, Any, Optional
from aiohttp import web

# Global bot state shared between Main.py and Web Dashboard
class BotState:
    def __init__(self):
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.logs: List[Dict[str, Any]] = []
        self.max_logs = 200
        self.total_matches = 0
        self.total_gained_exp = 0
        self.start_time = time.time()
        self.account_workers: Dict[str, asyncio.Task] = {}
        self.refresh_callbacks: Dict[str, Any] = {}
        self.account_credentials: Dict[str, Dict[str, Any]] = {}

    def log(self, message: str, level: str = "info", uid: Optional[str] = None):
        entry = {
            "time": time.strftime("%H:%M:%S"),
            "level": level,
            "message": message,
            "uid": uid
        }
        self.logs.append(entry)
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    def register_account(self, uid: str, nickname: str, region: str, level: int, exp: int, likes: int = 0):
        uid_str = str(uid)
        if uid_str not in self.accounts:
            self.accounts[uid_str] = {
                "uid": uid_str,
                "nickname": nickname or f"Player_{uid_str[:6]}",
                "region": region or "BD",
                "level": level or 1,
                "initial_exp": exp,
                "current_exp": exp,
                "gained_exp": 0,
                "likes": likes or 0,
                "status": "ONLINE",
                "matches_played": 0,
                "active_matches": 0,
                "last_match_time": None,
                "last_updated": time.strftime("%H:%M:%S")
            }
        else:
            acc = self.accounts[uid_str]
            if nickname:
                acc["nickname"] = nickname
            if region:
                acc["region"] = region
            if level:
                acc["level"] = level
            acc["current_exp"] = exp
            acc["gained_exp"] = max(0, exp - acc["initial_exp"])
            acc["likes"] = likes
            acc["status"] = "ONLINE"
            acc["last_updated"] = time.strftime("%H:%M:%S")
        self.recalc_totals()

    def update_exp(self, uid: str, current_exp: int, level: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            acc = self.accounts[uid_str]
            old_exp = acc["current_exp"]
            acc["current_exp"] = current_exp
            if level is not None and level > 0:
                acc["level"] = level
            acc["gained_exp"] = max(0, current_exp - acc["initial_exp"])
            acc["last_updated"] = time.strftime("%H:%M:%S")
            diff = current_exp - old_exp
            if diff > 0:
                self.log(f"Account {acc['nickname']} ({uid_str}) gained +{diff} EXP! Total Gained: +{acc['gained_exp']}", "success", uid_str)
            self.recalc_totals()

    def update_status(self, uid: str, status: str, active_matches: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            self.accounts[uid_str]["status"] = status
            if active_matches is not None:
                self.accounts[uid_str]["active_matches"] = active_matches
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")

    def increment_match(self, uid: str):
        uid_str = str(uid)
        self.total_matches += 1
        if uid_str in self.accounts:
            self.accounts[uid_str]["matches_played"] += 1
            self.accounts[uid_str]["last_match_time"] = time.strftime("%H:%M:%S")
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")
            self.log(f"Account {self.accounts[uid_str]['nickname']} finished Match #{self.accounts[uid_str]['matches_played']}", "info", uid_str)

    def recalc_totals(self):
        self.total_gained_exp = sum(acc.get("gained_exp", 0) for acc in self.accounts.values())


bot_state = BotState()


# ==================== DASHBOARD AUTHENTICATION ====================
AUTH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_auth.json")
SESSION_COOKIE = "mahin_dashboard_session"
SESSIONS: Dict[str, float] = {}
SESSION_TTL = 24 * 60 * 60

def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000).hex()

def _ensure_auth_file():
    if os.path.exists(AUTH_FILE):
        return
    # Initial credentials can be changed with environment variables before first start.
    username = os.getenv("DASHBOARD_USERNAME", "MAHIN")
    password = os.getenv("DASHBOARD_PASSWORD", "MAHIN999")
    salt = secrets.token_bytes(16)
    data = {
        "username": username,
        "salt": salt.hex(),
        "password_hash": _hash_password(password, salt)
    }
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print("[AUTH] Created dashboard_auth.json. Change the default password after first login.")

def _check_credentials(username: str, password: str) -> bool:
    try:
        _ensure_auth_file()
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if username != data.get("username"):
            return False
        salt = bytes.fromhex(data["salt"])
        supplied = _hash_password(password, salt)
        return secrets.compare_digest(supplied, data.get("password_hash", ""))
    except Exception:
        return False

def _is_authenticated(request: web.Request) -> bool:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return False
    expires = SESSIONS.get(token)
    if not expires:
        return False
    if expires < time.time():
        SESSIONS.pop(token, None)
        return False
    SESSIONS[token] = time.time() + SESSION_TTL
    return True

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#0b63f6">
<title>MAHIN MODZ | Secure Login</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root{--blue:#0b63f6;--blue2:#38a3ff;--navy:#071426;--muted:#6b7890;--line:#dfe8f5;--soft:#f5f9ff;--danger:#e5484d}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:Inter,Arial,sans-serif}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;overflow:hidden;color:var(--navy);background:linear-gradient(145deg,#f8fbff 0%,#edf5ff 52%,#e8f2ff 100%);position:relative}
body:before,body:after{content:"";position:absolute;border-radius:50%;filter:blur(3px);pointer-events:none}.body:before{display:none}
body:before{width:430px;height:430px;left:-180px;top:-170px;background:radial-gradient(circle,rgba(56,163,255,.22),transparent 68%)}
body:after{width:500px;height:500px;right:-220px;bottom:-250px;background:radial-gradient(circle,rgba(11,99,246,.18),transparent 68%)}
.shell{width:min(440px,100%);position:relative;z-index:1}
.card{background:rgba(255,255,255,.92);border:1px solid rgba(255,255,255,.95);border-radius:28px;padding:34px;box-shadow:0 25px 70px rgba(24,76,140,.16),0 4px 18px rgba(24,76,140,.07);backdrop-filter:blur(18px)}
.brand{text-align:center;margin-bottom:27px}.logo{width:72px;height:72px;margin:0 auto 17px;border-radius:21px;background:linear-gradient(145deg,#0b63f6,#39a5ff);display:flex;align-items:center;justify-content:center;color:white;font-size:25px;font-weight:900;letter-spacing:-1px;box-shadow:0 14px 30px rgba(11,99,246,.28);position:relative}.logo:after{content:"";position:absolute;inset:5px;border:1px solid rgba(255,255,255,.35);border-radius:17px}.brand-name{font-size:24px;font-weight:900;letter-spacing:-.8px;color:#0a2344}.brand-name span{color:var(--blue)}.tag{display:inline-flex;margin-top:9px;padding:6px 11px;border-radius:999px;background:#eef6ff;color:#2472d8;font-size:10px;font-weight:800;letter-spacing:1.3px;text-transform:uppercase}
h1{font-size:27px;line-height:1.15;text-align:center;margin:0;color:#0a1d36;letter-spacing:-.7px}.sub{text-align:center;color:var(--muted);font-size:13px;line-height:1.6;margin:9px 0 27px}
.field{margin-bottom:17px}.field label{display:flex;align-items:center;gap:7px;font-size:12px;font-weight:700;color:#35455d;margin:0 0 8px}.field-icon{color:#6c86a5;font-size:13px}
.input-wrap{position:relative}.input-wrap input{width:100%;height:52px;padding:0 46px 0 15px;border:1px solid var(--line);border-radius:14px;background:#fbfdff;color:#0b1e36;font:500 14px Inter,Arial,sans-serif;outline:none;transition:.2s;box-shadow:inset 0 1px 2px rgba(16,61,110,.025)}.input-wrap input::placeholder{color:#a0adbf}.input-wrap input:focus{border-color:#54a4ff;background:#fff;box-shadow:0 0 0 4px rgba(11,99,246,.09)}
.toggle{position:absolute;right:13px;top:50%;transform:translateY(-50%);border:0;background:none;color:#7c8da5;cursor:pointer;padding:7px;font-size:14px}.toggle:hover{color:var(--blue)}
.error{min-height:0;display:none;margin:2px 0 14px;padding:11px 12px;border-radius:11px;background:#fff1f2;border:1px solid #ffd6d9;color:var(--danger);font-size:12px;line-height:1.45;font-weight:600}.error.show{display:block}
.btn{width:100%;height:52px;border:0;border-radius:14px;background:linear-gradient(135deg,#0759e9,#1687ff);color:#fff;font:800 13px Inter,Arial,sans-serif;letter-spacing:.8px;cursor:pointer;box-shadow:0 10px 24px rgba(11,99,246,.24);transition:.2s;position:relative}.btn:hover{transform:translateY(-1px);box-shadow:0 13px 28px rgba(11,99,246,.3)}.btn:active{transform:translateY(0)}.btn:disabled{opacity:.72;cursor:not-allowed;transform:none}.spinner{display:inline-block;width:16px;height:16px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;vertical-align:-3px;margin-right:7px;animation:spin .7s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.secure{text-align:center;margin-top:20px;color:#8a98aa;font-size:10px;font-weight:600;letter-spacing:.3px}.secure strong{color:#54708f}.footer{text-align:center;margin-top:17px;color:#8190a4;font-size:10px}.footer b{color:#3c6ea7}
@media(max-width:480px){body{padding:15px}.card{padding:28px 21px;border-radius:23px}.logo{width:66px;height:66px}.brand-name{font-size:22px}h1{font-size:24px}.sub{margin-bottom:23px}.input-wrap input,.btn{height:50px}}
@media(max-height:700px){body{align-items:flex-start;padding-top:18px;overflow:auto}.card{padding-top:24px;padding-bottom:24px}.logo{width:58px;height:58px;margin-bottom:11px}.brand{margin-bottom:19px}}
</style>
</head>
<body>
<main class="shell">
<section class="card" aria-label="MAHIN MODZ login">
<div class="brand">
<div class="logo">MM</div>
<div class="brand-name">MAHIN <span>MODZ</span></div>
<div class="tag">Secure Control Panel</div>
</div>
<h1>Welcome Back</h1>
<div class="sub">Sign in to continue to your dashboard.</div>
<form id="loginForm" autocomplete="on">
<div class="field"><label for="username"><span class="field-icon">●</span> Username</label><div class="input-wrap"><input id="username" name="username" type="text" autocomplete="username" placeholder="Enter your username" required></div></div>
<div class="field"><label for="password"><span class="field-icon">●</span> Password</label><div class="input-wrap"><input id="password" name="password" type="password" autocomplete="current-password" placeholder="Enter your password" required><button class="toggle" id="togglePassword" type="button" aria-label="Show password">Show</button></div></div>
<div id="error" class="error" role="alert"></div>
<button class="btn" id="loginBtn" type="submit">SIGN IN TO DASHBOARD</button>
</form>
<div class="secure">🔒 <strong>Protected session</strong> · Your connection is secured</div>
</section>
<div class="footer">© <span id="year"></span> <b>MAHIN MODZ</b> · Dashboard Access</div>
</main>
<script>
const form=document.getElementById('loginForm'),btn=document.getElementById('loginBtn'),err=document.getElementById('error'),pass=document.getElementById('password'),toggle=document.getElementById('togglePassword');
document.getElementById('year').textContent=new Date().getFullYear();
toggle.addEventListener('click',()=>{const show=pass.type==='password';pass.type=show?'text':'password';toggle.textContent=show?'Hide':'Show';toggle.setAttribute('aria-label',show?'Hide password':'Show password');});
form.addEventListener('submit',async e=>{e.preventDefault();err.classList.remove('show');err.textContent='';btn.disabled=true;btn.innerHTML='<span class="spinner"></span> SIGNING IN...';try{const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({username:document.getElementById('username').value.trim(),password:pass.value})});let d={};try{d=await r.json()}catch(_){d={}}if(r.ok&&d.status==='ok'){btn.innerHTML='✓ ACCESS GRANTED';setTimeout(()=>location.href='/',180)}else{err.textContent=d.error||'Invalid username or password. Please try again.';err.classList.add('show');btn.disabled=false;btn.textContent='SIGN IN TO DASHBOARD';}}catch(_){err.textContent='Unable to connect to the server. Please try again.';err.classList.add('show');btn.disabled=false;btn.textContent='SIGN IN TO DASHBOARD';}});
</script>
</body></html>"""



# ==================== HTTP HANDLERS ====================

TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "index.html")

async def handle_login(request: web.Request) -> web.Response:
    if request.method == "GET":
        if _is_authenticated(request):
            raise web.HTTPFound("/")
        return web.Response(text=LOGIN_HTML, content_type="text/html", charset="utf-8")
    try:
        data = await request.json()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        if not _check_credentials(username, password):
            return web.json_response({"status": "error", "error": "Invalid username or password"}, status=401)
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = time.time() + SESSION_TTL
        response = web.json_response({"status": "ok"})
        response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="Lax", path="/")
        return response
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid login request"}, status=400)


async def handle_logout(request: web.Request) -> web.Response:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        SESSIONS.pop(token, None)
    response = web.HTTPFound("/login")
    response.del_cookie(SESSION_COOKIE, path="/")
    raise response


def _require_auth(request: web.Request):
    if not _is_authenticated(request):
        raise web.HTTPUnauthorized(text="Authentication required")


async def handle_index(request: web.Request) -> web.Response:
    if not _is_authenticated(request):
        return web.Response(text=LOGIN_HTML, content_type="text/html", charset="utf-8")
    if os.path.exists(TEMPLATE_PATH):
        with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = "<h1>templates/index.html not found!</h1>"
    return web.Response(text=content, content_type="text/html", charset="utf-8")


async def _read_template(name: str, fallback: str = "<h1>Template not found</h1>") -> str:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return fallback


async def handle_monitor(request: web.Request) -> web.Response:
    if not _is_authenticated(request):
        return web.Response(text=LOGIN_HTML, content_type="text/html", charset="utf-8")
    return web.Response(text=await _read_template("monitor.html"), content_type="text/html", charset="utf-8")


async def handle_account_detail(request: web.Request) -> web.Response:
    if not _is_authenticated(request):
        return web.Response(text=LOGIN_HTML, content_type="text/html", charset="utf-8")
    return web.Response(text=await _read_template("account.html"), content_type="text/html", charset="utf-8")


async def handle_get_account(request: web.Request) -> web.Response:
    _require_auth(request)
    uid = str(request.query.get("uid", "")).strip()
    account = bot_state.accounts.get(uid)
    if not account:
        return web.json_response({"status": "error", "error": "Account not found"}, status=404)
    logs = [log for log in bot_state.logs if not log.get("uid") or str(log.get("uid")) == uid][-30:]
    return web.json_response({"status": "ok", "account": account, "logs": logs})


async def handle_get_stats(request: web.Request) -> web.Response:
    _require_auth(request)
    accounts_data = list(bot_state.accounts.values())
    accounts_data.sort(key=lambda x: x.get("gained_exp", 0), reverse=True)
    return web.json_response({
        "total_accounts": len(bot_state.accounts),
        "total_matches": bot_state.total_matches,
        "total_gained_exp": bot_state.total_gained_exp,
        "accounts": accounts_data,
        "logs": bot_state.logs[-60:],
        "uptime": int(time.time() - bot_state.start_time)
    })


async def handle_add_account(request: web.Request) -> web.Response:
    _require_auth(request)
    try:
        data = await request.json()
        accounts_file = "accounts.json"
        existing = []
        if os.path.exists(accounts_file):
            try:
                with open(accounts_file, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        if "uid" in data and "password" in data:
            uid = str(data["uid"]).strip()
            pwd = str(data["password"]).strip()
            if not uid or not pwd:
                return web.json_response({"status": "error", "error": "UID and Password are required"})
            existing = [acc for acc in existing if str(acc.get("uid")) != uid]
            existing.append({"uid": uid, "password": pwd})
        elif "token" in data:
            token = str(data["token"]).strip()
            if not token:
                return web.json_response({"status": "error", "error": "Token is required"})
            existing = [acc for acc in existing if acc.get("token") != token]
            existing.append({"token": token})
        else:
            return web.json_response({"status": "error", "error": "Invalid payload"})

        with open(accounts_file, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

        bot_state.log(f"New account added: {data.get('uid') or 'Token'}", "success")
        
        # Trigger dynamic worker launch
        if "on_account_added" in bot_state.refresh_callbacks:
            asyncio.create_task(bot_state.refresh_callbacks["on_account_added"](data))

        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_delete_account(request: web.Request) -> web.Response:
    _require_auth(request)
    try:
        data = await request.json()
        uid = str(data.get("uid")).strip()
        accounts_file = "accounts.json"
        if os.path.exists(accounts_file):
            with open(accounts_file, "r", encoding="utf-8") as f:
                existing = json.load(f)
            existing = [acc for acc in existing if str(acc.get("uid")) != uid]
            with open(accounts_file, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2)

        if uid in bot_state.accounts:
            del bot_state.accounts[uid]

        if uid in bot_state.account_workers:
            bot_state.account_workers[uid].cancel()
            del bot_state.account_workers[uid]

        bot_state.log(f"Account {uid} removed from rotation.", "warning", uid)
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_refresh_account(request: web.Request) -> web.Response:
    _require_auth(request)
    try:
        data = await request.json()
        uid = str(data.get("uid")).strip()
        if "on_refresh_account" in bot_state.refresh_callbacks:
            asyncio.create_task(bot_state.refresh_callbacks["on_refresh_account"](uid))
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def start_web_dashboard(host: str = "0.0.0.0", port: int = 5000):
    _ensure_auth_file()
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_get("/monitor", handle_monitor)
    app.router.add_get("/account", handle_account_detail)
    app.router.add_get("/login", handle_login)
    app.router.add_post("/login", handle_login)
    app.router.add_get("/logout", handle_logout)
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    if os.path.isdir(static_dir):
        app.router.add_static("/static/", static_dir, show_index=False)
    app.router.add_get("/api/stats", handle_get_stats)
    app.router.add_get("/api/account", handle_get_account)
    app.router.add_post("/api/account/add", handle_add_account)
    app.router.add_post("/api/account/delete", handle_delete_account)
    app.router.add_post("/api/account/refresh", handle_refresh_account)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"\033[92m[+] Web Dashboard running on http://localhost:{port}\033[0m")

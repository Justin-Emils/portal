#!/usr/bin/env python3
"""
蓝旭控制台 —— 统一登录入口 + 服务导航 + 连接信息

路由
  /            门户（未登录显示登录页，已登录显示服务卡片）
  /login       登录提交
  /logout      退出
  /password    修改密码
  /vault       连接信息（需再次验证，10 分钟有效）
  /verify      nginx auth_request 子请求（204/401）

配置文件（同目录）
  services.json    服务卡片
  credentials.json 连接信息
  password.sha256  门户密码哈希
  secret.key       会话签名密钥
"""
import hashlib
import hmac
import html
import json
import os
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
SECRET_FILE = os.path.join(BASE, "secret.key")
SERVICES_FILE = os.path.join(BASE, "services.json")
VAULT_FILE = os.path.join(BASE, "credentials.json")
PASSWORD_FILE = os.path.join(BASE, "password.sha256")

COOKIE = "bx_portal"
REAUTH = "bx_reauth"
DAYS = 30
REAUTH_MINUTES = 10
PORT = int(os.environ.get("PORTAL_PORT", "18090"))

STYLE = """
:root{
  --bg:#0f1216; --bg2:#141922; --card:#171d26; --card-hover:#1d2531;
  --line:rgba(255,255,255,.08); --text:#e8edf5; --dim:#8b97a8; --dim2:#647084;
  --accent:#5b9cff; --accent-soft:rgba(91,156,255,.14); --ok:#3ddc97;
}
@media (prefers-color-scheme:light){
  :root{--bg:#f4f6fa; --bg2:#eaeef6; --card:#ffffff; --card-hover:#ffffff;
        --line:rgba(16,24,40,.09); --text:#121a26; --dim:#5b6678; --dim2:#8692a5;
        --accent:#2563eb; --accent-soft:rgba(37,99,235,.08); --ok:#0fa968;}
}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;padding:0}
body{
  min-height:100vh;background:var(--bg);color:var(--text);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
       "PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  -webkit-font-smoothing:antialiased;
}
a{color:var(--accent);text-decoration:none}
.wrap{max-width:880px;margin:0 auto;padding:40px 22px 64px}

/* 顶部栏 */
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:28px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:11px}
.logo{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,#5b9cff,#7b5bff);
      display:grid;place-items:center;font-size:17px;flex:none}
.title{font-size:19px;font-weight:650;letter-spacing:.2px;margin:0}
.sub{font-size:13px;color:var(--dim);margin:2px 0 0}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}

/* 按钮 */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;
     height:34px;padding:0 14px;border-radius:9px;font-size:13.5px;font-weight:550;
     border:1px solid var(--line);background:var(--card);color:var(--text);
     cursor:pointer;transition:.15s;white-space:nowrap;text-decoration:none}
.btn:hover{background:var(--card-hover);border-color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{filter:brightness(1.08)}
.btn.sm{height:28px;padding:0 11px;font-size:12.5px;border-radius:7px}
.btn.ghost{background:transparent}

/* 服务卡片 */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.card{display:flex;gap:13px;align-items:flex-start;padding:16px;border-radius:13px;
      background:var(--card);border:1px solid var(--line);transition:.16s;color:inherit}
.card:hover{background:var(--card-hover);border-color:var(--accent);transform:translateY(-1px)}
.icon{width:38px;height:38px;border-radius:10px;background:var(--accent-soft);
      display:grid;place-items:center;font-size:18px;flex:none}
.cname{font-weight:620;font-size:14.5px;margin-bottom:2px}
.cdesc{font-size:12.5px;color:var(--dim);line-height:1.5}

/* 登录 / 表单 */
.panel{max-width:400px;margin:8vh auto 0;background:var(--card);border:1px solid var(--line);
       border-radius:16px;padding:30px 26px}
.panel h1{font-size:20px;margin:0 0 6px;font-weight:650}
.panel .sub{margin:0 0 22px}
label{display:block;font-size:12.5px;color:var(--dim);margin:14px 0 6px}
input[type=password],input[type=text]{
  width:100%;height:44px;border-radius:10px;border:1px solid var(--line);
  background:var(--bg2);color:var(--text);padding:0 13px;font-size:15px;outline:none;transition:.15s}
input:focus{border-color:var(--accent)}
.panel .btn{width:100%;height:44px;margin-top:20px;font-size:15px}
.msg{margin-top:14px;font-size:13px;padding:9px 12px;border-radius:8px}
.msg.err{color:#ff8f8f;background:rgba(255,90,90,.1)}
.msg.ok{color:var(--ok);background:rgba(61,220,151,.1)}

/* 连接信息 */
.vgroup{margin:26px 0 10px;font-size:13px;font-weight:600;color:var(--dim);
        letter-spacing:.4px;text-transform:uppercase}
.item{display:grid;grid-template-columns:1.05fr 1.45fr 1.1fr;gap:14px;align-items:center;
      padding:14px 16px;border-radius:12px;background:var(--card);border:1px solid var(--line);
      margin-bottom:8px}
.iname{font-weight:600;font-size:14px}
.inote{font-size:12px;color:var(--dim2);margin-top:2px}
.ihost{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;
       color:var(--dim);word-break:break-all;line-height:1.5}
.icred{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;
       display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.mask{letter-spacing:1.5px;color:var(--dim)}
.empty{padding:40px;text-align:center;color:var(--dim2);font-size:13.5px}
.foot{margin-top:30px;font-size:12px;color:var(--dim2);line-height:1.7}
@media(max-width:660px){
  .wrap{padding:24px 16px 48px}
  .item{grid-template-columns:1fr;gap:6px}
  .icred{justify-content:flex-start}
  .grid{grid-template-columns:1fr}
}
"""


def load_secret() -> bytes:
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "wb") as fh:
            fh.write(os.urandom(32))
        os.chmod(SECRET_FILE, 0o600)
    with open(SECRET_FILE, "rb") as fh:
        return fh.read()


SECRET = load_secret()


def sign(exp: int) -> str:
    return hmac.new(SECRET, str(exp).encode(), hashlib.sha256).hexdigest()[:32]


def make_token(minutes: int) -> str:
    exp = int(time.time()) + minutes * 60
    return f"{exp}.{sign(exp)}"


def token_valid(raw: str) -> bool:
    try:
        exp_s, sig = raw.split(".", 1)
        exp = int(exp_s)
    except (ValueError, AttributeError):
        return False
    return exp >= time.time() and hmac.compare_digest(sig, sign(exp))


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def check_password(given: str) -> bool:
    try:
        with open(PASSWORD_FILE, "r", encoding="utf-8") as fh:
            stored = fh.read().strip()
    except OSError:
        return False
    return hmac.compare_digest(sha(given), stored)


def write_password(new: str) -> None:
    tmp = PASSWORD_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(sha(new))
    os.chmod(tmp, 0o600)
    os.replace(tmp, PASSWORD_FILE)
    sync_vault_portal_password(new)


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def sync_vault_portal_password(new: str) -> None:
    """门户密码变了，连接信息里那条也要跟着变，避免显示旧密码。"""
    data = load_json(VAULT_FILE, [])
    changed = False
    for group in data:
        for item in group.get("items", []):
            if item.get("name") == "门户（本页）":
                item["pass"] = new
                changed = True
    if changed:
        tmp = VAULT_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, VAULT_FILE)


def page(title: str, body: str) -> bytes:
    return f"""<!doctype html><html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0f1216">
<title>{html.escape(title)}</title><style>{STYLE}</style></head>
<body><div class="wrap">{body}</div></body></html>""".encode()


def login_page(next_url: str, error: str = "", whose: str = "") -> bytes:
    action = "vault" if whose == "vault" else "login"
    heading = "连接信息" if whose == "vault" else "蓝旭控制台"
    hint = "此页含明文密码，需再次验证" if whose == "vault" else "登录后可访问全部服务"
    msg = f'<div class="msg err">{html.escape(error)}</div>' if error else ""
    body = f"""
    <div class="panel">
      <h1>{heading}</h1>
      <p class="sub">{hint}</p>
      <form method="post" action="{action}">
        <input type="hidden" name="next" value="{html.escape(next_url)}">
        <label>访问密码</label>
        <input type="password" name="password" autofocus required autocomplete="current-password">
        <button class="btn primary" type="submit">进入</button>
      </form>
      {msg}
    </div>"""
    return page(heading, body)


def dashboard_page() -> bytes:
    services = load_json(SERVICES_FILE, [])
    cards = []
    for s in services:
        if s.get("hide"):
            continue
        cards.append(f"""
      <a class="card" href="{html.escape(s['url'])}" target="_blank" rel="noreferrer">
        <div class="icon">{html.escape(s.get('icon', '•'))}</div>
        <div>
          <div class="cname">{html.escape(s['name'])}</div>
          <div class="cdesc">{html.escape(s.get('desc', ''))}</div>
        </div>
      </a>""")
    body = f"""
    <div class="top">
      <div class="brand">
        <div class="logo">蓝</div>
        <div>
          <h1 class="title">蓝旭控制台</h1>
          <p class="sub">已登录 · 30 天内免登录</p>
        </div>
      </div>
      <div class="actions">
        <a class="btn" href="vault">连接信息</a>
        <a class="btn ghost" href="password">修改密码</a>
        <a class="btn ghost" href="logout">退出</a>
      </div>
    </div>
    <div class="grid">{''.join(cards) or '<div class="empty">还没有配置服务</div>'}</div>
    <div class="foot">所有服务共用这一次登录，点开即用。</div>"""
    return page("蓝旭控制台", body)


def vault_page() -> bytes:
    data = load_json(VAULT_FILE, [])
    rows = []
    for group in data:
        rows.append(f'<div class="vgroup">{html.escape(group["group"])}</div>')
        for it in group.get("items", []):
            pw = it.get("pass", "")
            note = f'<div class="inote">{html.escape(it["note"])}</div>' if it.get("note") else ""
            if pw:
                cred = (f'<span class="mask" data-v="{html.escape(pw)}">••••••••</span>'
                        f'<button class="btn sm" type="button" onclick="toggleOne(this)">显示</button>')
            else:
                cred = '<span style="color:var(--dim2)">—</span>'
            user = html.escape(it.get("user", ""))
            rows.append(f"""
      <div class="item">
        <div><div class="iname">{html.escape(it['name'])}</div>{note}</div>
        <div class="ihost">{html.escape(it.get('host', ''))}</div>
        <div class="icred">{user + ' · ' if user else ''}{cred}</div>
      </div>""")
    body = f"""
    <div class="top">
      <div class="brand">
        <div class="logo">🔑</div>
        <div>
          <h1 class="title">连接信息</h1>
          <p class="sub">验证后 10 分钟内有效</p>
        </div>
      </div>
      <div class="actions">
        <button class="btn" type="button" id="allbtn" onclick="toggleAll()">显示全部</button>
        <a class="btn ghost" href="./">返回</a>
      </div>
    </div>
    {''.join(rows) or '<div class="empty">还没有记录</div>'}
    <div class="foot">这些是明文密码，请勿截图外传。修改门户密码后，第一条会自动同步。</div>
    <script>
      function toggleOne(btn){{
        var span = btn.previousElementSibling;
        var hidden = btn.textContent === '显示';
        span.textContent = hidden ? span.dataset.v : '••••••••';
        btn.textContent = hidden ? '隐藏' : '显示';
      }}
      function toggleAll(){{
        var btn = document.getElementById('allbtn');
        var show = btn.textContent.indexOf('显示') !== -1;
        document.querySelectorAll('.icred button').forEach(function(b){{
          var span = b.previousElementSibling;
          span.textContent = show ? span.dataset.v : '••••••••';
          b.textContent = show ? '隐藏' : '显示';
        }});
        btn.textContent = show ? '隐藏全部' : '显示全部';
      }}
    </script>"""
    return page("连接信息", body)


def password_page(error: str = "") -> bytes:
    msg = f'<div class="msg err">{html.escape(error)}</div>' if error else ""
    body = f"""
    <div class="panel">
      <h1>修改访问密码</h1>
      <p class="sub">改完所有设备需用新密码重新登录</p>
      <form method="post" action="password">
        <label>当前密码</label>
        <input type="password" name="old" required autocomplete="current-password">
        <label>新密码（至少 8 位）</label>
        <input type="password" name="new" required autocomplete="new-password">
        <label>再输一次</label>
        <input type="password" name="confirm" required autocomplete="new-password">
        <button class="btn primary" type="submit">保存</button>
      </form>
      {msg}
      <p class="sub" style="margin-top:18px"><a href="./">← 返回门户</a></p>
    </div>"""
    return page("修改密码", body)


class Handler(BaseHTTPRequestHandler):
    server_version = "bx-portal"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def cookies(self):
        raw = self.headers.get("Cookie", "")
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def authed(self) -> bool:
        return token_valid(self.cookies().get(COOKIE, ""))

    def reauthed(self) -> bool:
        return token_valid(self.cookies().get(REAUTH, ""))

    def send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def form(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(n, 8192)).decode("utf-8", "replace")
        return urllib.parse.parse_qs(raw)

    # ---------- GET ----------
    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        nxt = (qs.get("next") or ["/portal/"])[0]

        if path == "/verify":
            return self.send(204 if self.authed() else 401, b"", "text/plain")
        if path == "/logout":
            return self.send(302, b"", extra={
                "Location": "./",
                "Set-Cookie": f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
            })
        if not self.authed():
            return self.send(200, login_page(nxt))
        if path in ("/", "/portal", "/portal/"):
            return self.send(200, dashboard_page())
        if path in ("/password", "/password/"):
            return self.send(200, password_page())
        if path in ("/vault", "/vault/"):
            if self.reauthed():
                return self.send(200, vault_page())
            return self.send(200, login_page("/vault", "", whose="vault"))
        return self.send(404, b"not found", "text/plain")

    # ---------- POST ----------
    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path in ("/vault", "/vault/"):
            return self.unlock_vault()
        if path in ("/password", "/password/"):
            return self.change_password()
        if path == "/login":
            return self.login()
        return self.send(404, b"not found", "text/plain")

    def login(self):
        f = self.form()
        pwd = (f.get("password") or [""])[0]
        nxt = (f.get("next") or ["/portal/"])[0]
        if not nxt.startswith("/"):
            nxt = "/portal/"
        if not check_password(pwd):
            time.sleep(0.6)
            return self.send(200, login_page(nxt, "密码不对"))
        self.send(302, b"", extra={
            "Location": nxt,
            "Set-Cookie": f"{COOKIE}={make_token(DAYS*1440)}; Path=/; Max-Age={DAYS*86400}; HttpOnly; Secure; SameSite=Lax",
        })

    def unlock_vault(self):
        if not self.authed():
            return self.send(302, b"", extra={"Location": "./"})
        f = self.form()
        if not check_password((f.get("password") or [""])[0]):
            time.sleep(0.6)
            return self.send(200, login_page("/vault", "密码不对", whose="vault"))
        self.send(302, b"", extra={
            "Location": "./vault",
            "Set-Cookie": f"{REAUTH}={make_token(REAUTH_MINUTES)}; Path=/; Max-Age={REAUTH_MINUTES*60}; HttpOnly; Secure; SameSite=Lax",
        })

    def change_password(self):
        if not self.authed():
            return self.send(302, b"", extra={"Location": "./"})
        f = self.form()
        old = (f.get("old") or [""])[0]
        new = (f.get("new") or [""])[0]
        confirm = (f.get("confirm") or [""])[0]
        if not check_password(old):
            return self.send(200, password_page("当前密码不对"))
        if len(new) < 8:
            return self.send(200, password_page("新密码至少 8 位"))
        if new != confirm:
            return self.send(200, password_page("两次输入不一致"))
        write_password(new)
        self.send(302, b"", extra={
            "Location": "login",
            "Set-Cookie": f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
        })


if __name__ == "__main__":
    print(f"portal on 127.0.0.1:{PORT}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

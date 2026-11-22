#!/usr/bin/env python3
"""Sallyport admin site: edits the targets (systems, people, groups and logins) and applies them to Guacamole.

Runs as a container behind Pomerium on its own host name (admin.<domain>) with its own, short allow-list.
It never trusts a plain header: Pomerium signs the user's identity (X-Pomerium-Jwt-Assertion) with a key
only Pomerium holds, and every request is checked against that key's public half. The database account it
uses can write only the tables the targets live in, plus Sallyport's own state and audit tables.

Saved passwords and keys are write-only: they are never sent back to the browser.
"""
import base64
import json
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sallyport_core as core  # noqa: E402

MARK = "__saved__"  # stands in for a secret the browser may not see
MAX_BODY = 2_000_000
EMPTY = {"systems": [], "users": [], "groups": [], "logins": []}


class Problem(Exception):
    def __init__(self, message, code=400):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------------ identity

def b64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def load_public_key(path):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(Path(path).read_bytes())


def verify_assertion(token, public_key, audience, now=None):
    """Check Pomerium's signed identity: signature (ES256), expiry and audience. Returns the email."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    try:
        head, body, sig = token.split(".")
        header = json.loads(b64url(head))
        raw = b64url(sig)
        claims = json.loads(b64url(body))
    except (ValueError, AttributeError):
        raise Problem("not a valid identity assertion", 401)
    if header.get("alg") != "ES256" or len(raw) != 64:
        raise Problem("unexpected assertion format", 401)
    try:
        public_key.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                          f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Problem("identity assertion signature is not valid", 401)
    now = time.time() if now is None else now
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or exp < now - 30:
        raise Problem("identity assertion has expired", 401)
    aud = claims.get("aud")
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise Problem("identity assertion is for a different site", 401)
    email = claims.get("email")
    if not isinstance(email, str) or not email:
        raise Problem("identity assertion has no email", 401)
    return email.lower()


# ------------------------------------------------------------------ document logic

def redact(doc):
    out = json.loads(json.dumps(doc))
    for lg in out.get("logins", []):
        for k in core.SECRET_FIELDS:
            if lg.get(k):
                lg[k] = MARK
    return out


def login_key(lg):
    who = "everyone" if lg.get("everyone") else ("user:" + str(lg.get("user", "")).lower() if "user" in lg else "group:" + str(lg.get("group", "")))
    return f"{lg.get('system')}|{who}"


def merge_secrets(new, old):
    """Put back the stored value wherever the browser sent the placeholder instead of a secret."""
    olds = {login_key(lg): lg for lg in (old or {}).get("logins", [])}
    for lg in new["logins"]:
        for k in core.SECRET_FIELDS:
            if lg.get(k) == MARK:
                prev = olds.get(login_key(lg))
                if not prev or not prev.get(k):
                    raise Problem(f"The saved {k.replace('_', ' ')} for '{lg.get('system')}' cannot be kept because that login "
                                  "changed who or what it is for. Enter the value again.")
                lg[k] = prev[k]
    return new


def compile_document(doc, old):
    """Validate exactly as load-targets does. Returns (clean document, connections, groups)."""
    clean = merge_secrets(core.clean_document(doc), old)
    try:
        targets, groups, _users = core.load_access(clean)
        for t in targets:
            core.target_params(t)
    except SystemExit as e:
        raise Problem(re.sub(r"^error: ", "", str(e.code)))
    return clean, targets, groups


def summarize(old, new):
    """What changed, for the audit log. Names only: never a credential."""
    old, new = old or EMPTY, new
    parts = []

    def diff(label, a, b):
        add, rem = sorted(set(b) - set(a)), sorted(set(a) - set(b))
        if add:
            parts.append(f"{label} added: " + ", ".join(add))
        if rem:
            parts.append(f"{label} removed: " + ", ".join(rem))

    diff("systems", [s["name"] for s in old["systems"]], [s["name"] for s in new["systems"]])
    om = {s["name"]: s for s in old["systems"]}
    ch = [s["name"] for s in new["systems"] if s["name"] in om and om[s["name"]] != s]
    if ch:
        parts.append("systems changed: " + ", ".join(sorted(ch)))
    diff("logins", [login_key(lg) for lg in old["logins"]], [login_key(lg) for lg in new["logins"]])
    ol = {login_key(lg): lg for lg in old["logins"]}
    ch = [login_key(lg) for lg in new["logins"] if login_key(lg) in ol and ol[login_key(lg)] != lg]
    if ch:
        parts.append("logins changed (settings or credentials): " + ", ".join(sorted(ch)))
    diff("groups", [g["name"] for g in old["groups"]], [g["name"] for g in new["groups"]])
    og = {g["name"]: sorted(g["users"]) for g in old["groups"]}
    ch = [g["name"] for g in new["groups"] if g["name"] in og and og[g["name"]] != sorted(g["users"])]
    if ch:
        parts.append("group members changed: " + ", ".join(sorted(ch)))
    diff("people", old["users"], new["users"])
    return ("; ".join(parts) or "no changes")[:3000]


# ------------------------------------------------------------------ database

def txt(value):
    return value.decode("utf-8", "replace") if isinstance(value, (bytes, bytearray)) else value


class Store:
    def __init__(self, env):
        self.env = env

    def connect(self):
        import psycopg
        e = self.env
        return psycopg.connect(host=e.get("DB_HOST", "postgres"), port=int(e.get("DB_PORT", "5432")), dbname=e.get("DB_NAME", "guacamole_db"),
                               user=e.get("DB_USER", core.ADMIN_ROLE), password=e.get("DB_PASSWORD", ""), connect_timeout=5)

    def load(self):
        with self.connect() as conn:
            row = conn.execute("SELECT document, version, updated_at, updated_by FROM sallyport_state WHERE id = 1").fetchone()
        if not row:
            return dict(EMPTY), 0, None, ""
        return row[0], row[1], row[2].isoformat(timespec="seconds"), txt(row[3])

    def audit(self, limit=100):
        with self.connect() as conn:
            rows = conn.execute("SELECT at, actor, action, detail FROM sallyport_audit ORDER BY id DESC LIMIT %s", (limit,)).fetchall()
        return [{"at": r[0].isoformat(timespec="seconds"), "actor": txt(r[1]), "action": txt(r[2]), "detail": txt(r[3])} for r in rows]

    def save(self, doc, base_version, actor):
        with self.connect() as conn:
            with conn.transaction():
                row = conn.execute("SELECT document, version FROM sallyport_state WHERE id = 1 FOR UPDATE").fetchone()
                current, old = (row[1], row[0]) if row else (0, None)
                if base_version != current:
                    raise Problem("The targets were changed by someone else since you loaded them. Reload, then make your change again.", 409)
                clean, targets, groups = compile_document(doc, old)
                detail = summarize(old, clean)
                conn.execute(core.state_sql(clean, actor, "save", detail) + core.build_sql(targets, groups))
                version = conn.execute("SELECT version FROM sallyport_state WHERE id = 1").fetchone()[0]
        return version, detail


# ------------------------------------------------------------------ http

class Handler(BaseHTTPRequestHandler):
    server_version = "SallyportAdmin"
    store = None
    public_key = None
    audience = ""

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                                                    "connect-src 'self'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(data)

    def who(self):
        return verify_assertion(self.headers.get("X-Pomerium-Jwt-Assertion", ""), self.public_key, self.audience)

    def guard(self, post):
        me = self.who()
        if post:
            origin = self.headers.get("Origin", "")
            if origin != "https://" + self.audience:
                raise Problem("bad origin", 403)
            if self.headers.get("X-Sallyport-Admin") != "1" or "application/json" not in self.headers.get("Content-Type", ""):
                raise Problem("bad request", 400)
        return me

    def handle_request(self, post):
        try:
            me = self.guard(post)
            path = self.path.split("?")[0]
            if not post and path == "/":
                return self.send(200, PAGE.replace("__ME__", json.dumps(me)), "text/html")
            if not post and path == "/api/state":
                doc, version, at, by = self.store.load()
                return self.send(200, {"doc": redact(doc), "version": version, "updated_at": at, "updated_by": by, "me": me})
            if not post and path == "/api/audit":
                return self.send(200, {"rows": self.store.audit()})
            if post:
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY:
                    raise Problem("request too large", 413)
                body = json.loads(self.rfile.read(length) or b"{}")
                if path == "/api/validate":
                    doc, _v, _a, _b = self.store.load()
                    clean, targets, groups = compile_document(body.get("doc"), doc)
                    return self.send(200, {"ok": True, "message": f"valid ({len(targets)} login(s), {len(groups)} group(s))"})
                if path == "/api/save":
                    version, detail = self.store.save(body.get("doc"), body.get("version"), me)
                    return self.send(200, {"ok": True, "message": "saved and applied: " + detail, "version": version})
            return self.send(404, {"error": "not found"})
        except Problem as e:
            return self.send(e.code, {"ok": False, "error": str(e), "message": str(e)})
        except (ValueError, KeyError):
            return self.send(400, {"ok": False, "error": "bad request", "message": "bad request"})
        except Exception as e:  # database down, etc.: say so without leaking details
            print("error:", repr(e), file=sys.stderr, flush=True)
            return self.send(503, {"ok": False, "error": "The database is not reachable or not ready (has ./sallyport migrate-db been run?)",
                                   "message": "The database is not reachable or not ready (has ./sallyport migrate-db been run?)"})

    def do_GET(self):
        self.handle_request(False)

    def do_POST(self):
        self.handle_request(True)


def main():
    env = dict(os.environ)
    host = env.get("ADMIN_HOST", "")
    if not host:
        sys.exit("ADMIN_HOST is not set")
    Handler.store = Store(env)
    Handler.public_key = load_public_key(env.get("JWT_PUBLIC_KEY", "/app/jwt.pub"))
    Handler.audience = host
    ThreadingHTTPServer(("0.0.0.0", int(env.get("PORT", "8080"))), Handler).serve_forever()


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sallyport admin</title><style>
:root{color-scheme:light dark;--bd:#8886;--ok:#1a7f37;--bad:#c62828}
body{font:14px/1.45 system-ui,Segoe UI,sans-serif;margin:0 auto;max-width:980px;padding:16px}
h1{font-size:20px;margin:0 0 4px} h2{font-size:15px;margin:22px 0 8px}
.sub{opacity:.7;margin-bottom:12px}
section{border:1px solid var(--bd);border-radius:8px;padding:12px 14px;margin-bottom:14px}
section>h2:first-child{margin-top:0}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:6px 0}
input[type=text]{flex:1;min-width:220px;padding:6px 8px;font:inherit}
button{padding:6px 12px;font:inherit;cursor:pointer}
button.p{font-weight:600}
textarea{width:100%;box-sizing:border-box;height:260px;font:12.5px/1.4 Consolas,monospace;padding:8px;tab-size:2}
pre{background:#0002;border:1px solid var(--bd);border-radius:6px;padding:8px;height:170px;overflow:auto;margin:0;white-space:pre-wrap;font:12.5px/1.4 Consolas,monospace}
.chk{display:grid;grid-template-columns:20px 130px 1fr;gap:2px 8px}
.ok{color:var(--ok)} .bad{color:var(--bad)} .msg.bad{margin-left:6px} .msg.ok{margin-left:6px}
.tabs button.on{font-weight:700;text-decoration:underline}
.grid{display:grid;grid-template-columns:170px 1fr;gap:6px 10px;align-items:center;margin:6px 0}
.grid>label{opacity:.85}.grid input[type=text],.grid input[type=password],.grid select,.grid textarea{width:100%;box-sizing:border-box;padding:6px 8px;font:inherit}
.grid input[type=password]{flex:1}
textarea.small{height:70px;font:12.5px/1.4 Consolas,monospace}
.targets{display:grid;grid-template-columns:230px 1fr;gap:14px}
.tlist{border:1px solid var(--bd);border-radius:6px;min-height:120px;max-height:320px;overflow:auto}
.tlist div{padding:6px 8px;cursor:pointer;border-bottom:1px solid var(--bd)}.tlist div.on{background:#4a90d933;font-weight:600}
.tlist small{opacity:.7;display:block}
.acc{border:1px solid var(--bd);border-radius:6px;padding:8px 10px;margin:8px 0}
.acc.open{border-color:#c62828;background:#c6282814}
.acc .hint,.urow .hint{color:#b26a00;font-size:.9em;margin:2px 0 4px}
.acc .hint.info{color:inherit;opacity:.8}
.urow{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:4px 0;border-bottom:1px solid var(--bd)}
.subtabs{display:flex;gap:4px;margin:8px 0 10px}.subtabs button{border:1px solid var(--bd);background:none;color:inherit;border-radius:14px;padding:4px 14px}
.subtabs button.on{background:#4a90d933;font-weight:700}

.acc .grid{margin:4px 0}
h3{margin:14px 0 4px;font-size:1em}
.hide{display:none!important}
.maintabs{display:flex;gap:2px;border-bottom:2px solid var(--bd);margin:6px 0 14px}
.maintabs button{border:1px solid var(--bd);border-bottom:none;border-radius:6px 6px 0 0;background:none;color:inherit;padding:8px 16px;margin-bottom:-2px}
.maintabs button.on{font-weight:700;background:Canvas;border-bottom:2px solid Canvas}
.banner{border:1px solid var(--bd);border-radius:8px;padding:8px 12px;margin-bottom:12px}
.banner.upd{background:#4a90d922;border-color:#4a90d9}.banner ul{margin:4px 0 6px;padding-left:20px}
.banner.bad{background:#c6282822}
#outpanel{position:sticky;bottom:0;background:Canvas;color:CanvasText;border-top:2px solid var(--bd);padding:2px 0 6px;margin-top:10px}
#outbar{cursor:pointer;margin:2px 0}#jlast{max-width:46%;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--bd);border-top-color:#4a90d9;border-radius:50%;animation:sp .8s linear infinite;vertical-align:-2px}
@keyframes sp{to{transform:rotate(360deg)}}
.card{border:1px solid var(--bd);border-radius:6px;padding:8px 12px;margin:10px 0}.card h3{margin:0 0 4px;font-size:14px}
body{padding-bottom:0}
details summary{cursor:pointer;margin-bottom:8px}
.warn{background:#f9a82522;border:1px solid #f9a82588;border-radius:6px;padding:6px 10px;margin:8px 0}
</style></head><body>
<h1>Sallyport admin</h1>
<div class="sub">Signed in as <b id="me"></b>. <span id="ver"></span> Changes apply to Guacamole as soon as you press Save and apply.</div>
<section><h2>Targets</h2>
<div class="sub" id="tstatus"></div>
<div id="openwarn" class="banner bad hide"></div>
<div id="sharedinfo" class="banner upd hide"></div>
<div class="sub">Four views. <b>Systems</b> are the machines people can connect to. <b>People &amp; groups</b> are the people you give access to, and named groups of them. <b>Logins</b> say who may use which system, and with which credentials (saved, or asked for when they connect). Someone who passes the identity provider but has no login of their own sees only the logins marked Everyone.</div>
<div class="subtabs"><button data-s="systems" class="on">Systems</button><button data-s="people">People &amp; groups</button><button data-s="logins">Logins</button><button data-s="audit">Audit log</button></div>
<div id="st_systems" class="subpanel"><div class="targets">
<div><div id="tlist" class="tlist"></div>
<div class="row"><button id="t_add">Add system</button><button id="t_del">Delete system</button></div></div>
<div id="tform"><div class="grid">
<label for="t_name">Name</label><input type="text" id="t_name">
<label for="t_protocol">Protocol</label><select id="t_protocol"><option>rdp</option><option>ssh</option></select>
<label for="t_host">Host</label><input type="text" id="t_host" placeholder="10.0.0.10 or server.corp">
<label for="t_port">Port</label><input type="text" id="t_port" placeholder="default for the protocol">
<label class="rdp" for="t_security">RDP security</label><select class="rdp" id="t_security"><option>nla</option><option>tls</option><option>rdp</option><option>any</option></select>
<label class="rdp" for="t_ignore_cert">Skip certificate check</label><span class="rdp"><input type="checkbox" id="t_ignore_cert"> <span class="sub">allows interception between guacd and the target</span></span>
<label class="ssh" for="t_host_key">Host key</label><input class="ssh" type="text" id="t_host_key" placeholder="ssh-ed25519 AAAA... (strongly recommended)">
<label for="t_clipboard">Clipboard</label><select id="t_clipboard"><option value="both">both ways</option><option value="none">none</option><option value="paste-only">paste only (you to target)</option><option value="copy-only">copy only (target to you)</option></select>
<label for="t_max_sessions">Max sessions</label><input type="text" id="t_max_sessions" placeholder="1">
</div><div class="sub" id="t_sysinfo"></div></div></div></div>
<div id="st_people" class="subpanel hide">
<h3>People</h3>
<div class="sub">People you give logins to or put in groups. This is not the list of who may log in at all; that is under Settings.</div>
<div id="ulist"></div>
<div class="row"><input type="text" id="u_new" placeholder="person@example.com" list="knownUsers"><button id="u_add">Add person</button><datalist id="knownUsers"></datalist></div>
<h3>Groups</h3>
<div class="sub">A group is a named list of people. Use it to decide who sees a login, for example who sees the firewall.</div>
<div id="glist"></div>
<div class="row"><button id="g_add">Add group</button></div></div>
<div id="st_logins" class="subpanel hide">
<div class="row"><label for="l_filter">Show</label><select id="l_filter"></select><button id="l_add" class="p">Add login</button></div>
<div id="llist"></div></div>
<div id="st_audit" class="subpanel hide"><div class="sub">The last 100 changes: who, when, and what (names only, never credentials).</div><div id="alist"></div></div>
<div class="row"><button id="t_validate">Validate</button><button id="t_save" class="p">Save and apply</button><button id="t_reload">Discard changes and reload</button><span id="tmsg" class="msg"></span></div>
<div class="warn">Saved credentials are stored in plain text in the database, and are never shown here again once saved. Use dedicated, least-privilege accounts, ideally one per person so the target's own logs show who did what. File transfer and printing are always off. Save and apply writes to Guacamole immediately: new logins appear, and removed ones disappear, the next time people load their list. A session that is already open is not ended. Each login becomes a separate connection named like <code>System (person@example.com)</code>, so <b>Max sessions</b> applies to each connection separately.</div></section>

<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
async function api(path,body){
  const o={headers:{"X-Sallyport-Admin":"1"}};
  if(body!==undefined){o.method="POST";o.headers["Content-Type"]="application/json";o.body=JSON.stringify(body)}
  const r=await fetch(path,o); let j={}; try{j=await r.json()}catch(e){}
  if(!r.ok)throw new Error(j.error||j.message||("HTTP "+r.status)); return j;
}
/* ---- targets: systems, people & groups, logins ---- */
const SYS=["name","protocol","host","port","security","host_key","clipboard","max_sessions"];
let systems=[], users=[], groups=[], logins=[], sel=-1, cfgUsers={emails:[],groups:[],domains:[]};
const blankSys=()=>({name:"",protocol:"rdp",host:"",port:"",security:"nla",ignore_cert:false,host_key:"",clipboard:"both",max_sessions:1});
const MARK="__saved__", SECRETS=["password","private_key","passphrase"];
const blankLogin=()=>({who:"user",user:"",grp:null,sys:null,cred:"ask",username:"",password:"",domain:"",private_key:"",passphrase:"",kept:{}});
const CREDK=["username","password","domain","private_key","passphrase"];
const lc=x=>String(x||"").trim().toLowerCase();
function fromFile(d){
  systems=(d.systems||[]).map(e=>Object.assign(blankSys(),e,{port:e.port??"",host_key:e.host_key||"",ignore_cert:!!e.ignore_cert,max_sessions:e.max_sessions??1}));
  users=(d.users||[]).map(lc); groups=(d.groups||[]).map(g=>({name:g.name||"",users:(g.users||[]).map(lc)}));
  logins=(d.logins||[]).map(l=>{const o=blankLogin(); o.sys=systems.find(s=>s.name===l.system)||null;
    if(l.everyone)o.who="all"; else if(l.group!==undefined){o.who="group";o.grp=groups.find(g=>g.name===l.group)||null} else o.user=lc(l.user);
    for(const k of CREDK){if(l[k]===MARK){o[k]="";o.kept[k]=true}else o[k]=l[k]||""}
    o.cred=(o.username||o.password||o.private_key||o.passphrase||Object.values(o.kept).some(Boolean))?"saved":"ask"; return o;});
}
function sysProps(s){
  const o={protocol:s.protocol,host:s.host};
  if(String(s.port).trim()!=="")o.port=s.port;
  if(s.protocol==="rdp"){o.security=s.security;o.ignore_cert=!!s.ignore_cert}
  else if(s.host_key)o.host_key=s.host_key;
  o.clipboard=s.clipboard; if(String(s.max_sessions).trim()!=="")o.max_sessions=s.max_sessions;
  return o;
}
function allUsers(){return [...new Set(users.concat(groups.flatMap(g=>g.users),logins.filter(l=>l.who==="user").map(l=>l.user)).map(lc).filter(Boolean))].sort()}
function toFile(){
  const seen=new Set();
  for(const s of systems){const n=s.name.trim(); if(!n)throw new Error("A system has no name."); if(seen.has(n))throw new Error("Two systems are called '"+n+"'."); seen.add(n)}
  const gseen=new Set();
  for(const g of groups){const n=g.name.trim(); if(!n)throw new Error("A group has no name."); if(gseen.has(n))throw new Error("Two groups are called '"+n+"'."); gseen.add(n)}
  const out=[];
  for(const l of logins){
    if(!l.sys)throw new Error("A login has no system chosen.");
    const o={system:l.sys.name.trim()};
    if(l.who==="all")o.everyone=true;
    else if(l.who==="group"){if(!l.grp)throw new Error("A login for '"+o.system+"' has no group chosen."); o.group=l.grp.name.trim()}
    else{const em=lc(l.user); if(!em)throw new Error("A login for '"+o.system+"' has no person. Enter an email address, or choose a group or Everyone."); o.user=em}
    if(l.cred==="saved"){
      const sec=k=>{if(l[k]!=="")o[k]=l[k]; else if(l.kept[k])o[k]=MARK};
      if(l.username!=="")o.username=l.username; sec("password");
      if(l.sys.protocol==="rdp"){if(l.domain)o.domain=l.domain}
      else{sec("private_key"); sec("passphrase")}
    }
    out.push(o);
  }
  return {systems:systems.map(s=>Object.assign({name:s.name.trim()},sysProps(s))), users:allUsers(),
    groups:groups.map(g=>({name:g.name.trim(),users:g.users.map(lc).filter(Boolean)})), logins:out};
}
const hasSaved=l=>l.cred==="saved"&&!!(l.username||l.password||l.private_key||l.passphrase||Object.values(l.kept).some(Boolean));
const openLogin=l=>l.who==="all"&&hasSaved(l);
const isOpen=s=>logins.some(l=>l.sys===s&&openLogin(l));
const isShared=s=>logins.some(l=>l.sys===s&&l.who==="all"&&!hasSaved(l));
function userHint(em){
  em=lc(em); if(!em||cfgUsers.groups.length||cfgUsers.domains.length||!cfgUsers.emails.length)return "";
  return cfgUsers.emails.includes(em)?"":"⚠ Not in Allowed emails (Settings tab), so this person cannot log in yet.";
}
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e}
function addRow(grid,label,node){grid.appendChild(el("label","",label));grid.appendChild(node);return node}
function objSelect(items,cur,label,onset){const s=el("select");let o=el("option","","— choose —");o.value="-1";s.appendChild(o);
  items.forEach((x,i)=>{o=el("option","",label(x)||"(unnamed)");o.value=String(i);s.appendChild(o)});
  s.value=String(items.indexOf(cur)); if(s.value==="")s.value="-1"; s.onchange=()=>{onset(items[+s.value]||null)}; return s}
function valSelect(l,k,opts,after){const s=el("select");for(const [v,t] of opts){const o=el("option","",t);o.value=v;s.appendChild(o)}s.value=l[k];s.onchange=()=>{l[k]=s.value;after()};return s}
function inp(l,k,type,ph,onflip){const i=el("input");i.type=type||"text";i.autocomplete="off";i.value=l[k];if(ph)i.placeholder=ph;
  i.oninput=()=>{const was=hasSaved(l);l[k]=i.value;if(onflip&&was!==hasSaved(l))onflip()};return i}
function secretField(l,k,flip,multi){
  const wrap=el("span","row"); const i=multi?el("textarea","small"):el("input"); if(!multi){i.type="password";i.autocomplete="new-password"}else i.spellcheck=false;
  const clr=el("button","","Remove saved");
  const sync=()=>{i.placeholder=l.kept[k]?"saved: type to replace":(multi?"-----BEGIN OPENSSH PRIVATE KEY-----":"");clr.style.display=l.kept[k]?"":"none"};
  i.value=l[k]; i.oninput=()=>{const was=hasSaved(l);l[k]=i.value;if(i.value!=="")l.kept[k]=false;sync();if(was!==hasSaved(l))flip()};
  clr.type="button"; clr.onclick=()=>{l.kept[k]=false;l[k]="";i.value="";sync();flip()};
  sync(); wrap.appendChild(i); wrap.appendChild(clr); return wrap;
}
function refreshFlags(){
  const open=[...new Set(systems.filter(isOpen).map(s=>s.name||"(unnamed)"))];
  const shared=[...new Set(systems.filter(s=>isShared(s)&&!isOpen(s)).map(s=>s.name||"(unnamed)"))];
  const gs=[...new Set(logins.filter(l=>l.who==="group"&&hasSaved(l)&&l.sys).map(l=>l.sys.name+" ("+(l.grp?l.grp.name:"?")+")"))];
  const w=$("#openwarn"), lines=[];
  if(open.length)lines.push("⚠ Saved credentials open to everyone who can log in: "+open.join(", ")+". Anyone you add to your identity provider later gets use of these credentials automatically.");
  w.classList.toggle("hide",!lines.length); w.textContent=lines.join(" ");
  const n=$("#sharedinfo"), info=[];
  if(shared.length)info.push("ⓘ Visible to everyone who can log in, but each person supplies their own credentials: "+shared.join(", ")+". Anyone you add later will see these.");
  if(gs.length)info.push("ⓘ Saved credentials shared by every member of a group, so the target's own logs cannot tell them apart: "+gs.join(", ")+".");
  n.classList.toggle("hide",!info.length); n.textContent=info.join(" ");
}
function showSub(n){
  $$(".subtabs button").forEach(b=>b.classList.toggle("on",b.dataset.s===n));
  for(const k of ["systems","people","logins","audit"])$("#st_"+k).classList.toggle("hide",k!==n);
  if(n==="audit")loadAudit(); if(n==="people")renderPeople(); if(n==="logins")renderLogins(); if(n==="systems")tList();
}
$$(".subtabs button").forEach(b=>b.onclick=()=>showSub(b.dataset.s));
function fillKnown(){const dl=$("#knownUsers");dl.textContent="";new Set(allUsers().concat(cfgUsers.emails)).forEach(u=>{const o=el("option");o.value=u;dl.appendChild(o)})}
/* systems */
function tShowFields(){const p=$("#t_protocol").value;
  $$("#tform .rdp").forEach(e=>e.classList.toggle("hide",p!=="rdp")); $$("#tform .ssh").forEach(e=>e.classList.toggle("hide",p!=="ssh"));}
function tFill(){
  const t=systems[sel]; $("#tform").classList.toggle("hide",!t); if(!t)return;
  for(const k of SYS)$("#t_"+k).value=t[k]??""; $("#t_ignore_cert").checked=!!t.ignore_cert; tShowFields();
  const n=logins.filter(l=>l.sys===t).length; $("#t_sysinfo").textContent=n+" login(s) use this system. Add or change them on the Logins tab.";
}
function tWrite(){
  const t=systems[sel]; if(!t)return;
  for(const k of SYS)t[k]=$("#t_"+k).value; t.ignore_cert=$("#t_ignore_cert").checked; tShowFields(); tList();
}
function tList(){
  const box=$("#tlist"); box.textContent="";
  systems.forEach((t,i)=>{const d=el("div",i===sel?"on":"",(isOpen(t)?"⚠ ":isShared(t)?"ⓘ ":"")+(t.name||"(unnamed)"));
    const s=el("small","",t.protocol+" "+(t.host||"")+" · "+logins.filter(l=>l.sys===t).length+" login(s)"); d.appendChild(s);
    d.onclick=()=>{sel=i;tList();tFill()}; box.appendChild(d);});
  refreshFlags();
}
/* people and groups */
function renderPeople(){
  const ul=$("#ulist"); ul.textContent=""; fillKnown();
  const all=allUsers(); if(!all.length)ul.appendChild(el("div","sub","No people yet."));
  all.forEach(u=>{
    const r=el("div","urow"); r.appendChild(el("b","",u));
    const gn=groups.filter(g=>g.users.map(lc).includes(u)).map(g=>g.name||"(unnamed)");
    const n=logins.filter(l=>l.who==="user"&&lc(l.user)===u).length;
    r.appendChild(el("span","sub","groups: "+(gn.join(", ")||"none")+" · "+n+" login(s)"));
    const h=userHint(u); if(h)r.appendChild(el("span","hint",h));
    const add=el("button","","Add login"); add.onclick=()=>{const l=blankLogin();l.user=u;logins.push(l);showSub("logins");$("#l_filter").value="u:"+u;renderLogins()};
    const rm=el("button","","Remove");
    rm.onclick=()=>{if(!confirm("Remove "+u+", their group memberships and their "+n+" login(s)? (Not final until you press Save targets.)"))return;
      users=users.filter(x=>lc(x)!==u); groups.forEach(g=>{g.users=g.users.filter(x=>lc(x)!==u)}); logins=logins.filter(l=>!(l.who==="user"&&lc(l.user)===u)); renderPeople();refreshFlags()};
    r.appendChild(add); r.appendChild(rm); ul.appendChild(r);
  });
  const gl=$("#glist"); gl.textContent=""; if(!groups.length)gl.appendChild(el("div","sub","No groups yet."));
  groups.forEach(g=>{
    const card=el("div","acc"), grid=el("div","grid");
    const nm=el("input");nm.type="text";nm.value=g.name;nm.placeholder="group name";nm.oninput=()=>{g.name=nm.value};
    const ta=el("textarea","small");ta.spellcheck=false;ta.value=g.users.join("\n");ta.placeholder="one email per line";
    ta.oninput=()=>{g.users=ta.value.split(/\n/).map(lc).filter(Boolean)}; ta.onchange=()=>renderPeople();
    addRow(grid,"Group name",nm); addRow(grid,"Members",ta); card.appendChild(grid);
    const n=logins.filter(l=>l.grp===g).length, rm=el("button","","Remove group");
    rm.onclick=()=>{if(!confirm("Remove group "+(g.name||"(unnamed)")+" and its "+n+" login(s)? (Not final until you press Save targets.)"))return;
      groups=groups.filter(x=>x!==g); logins=logins.filter(l=>l.grp!==g); renderPeople();refreshFlags()};
    const r=el("div","row");r.appendChild(rm);card.appendChild(r); gl.appendChild(card);
  });
}
$("#u_add").onclick=()=>{const v=lc($("#u_new").value); if(!v)return; if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)){alert("That is not an email address.");return}
  if(!users.includes(v))users.push(v); $("#u_new").value=""; renderPeople()};
$("#g_add").onclick=()=>{groups.push({name:"",users:[]});renderPeople();const i=$$("#glist input");if(i.length)i[i.length-1].focus()};
/* logins */
function fillFilter(){
  const f=$("#l_filter"), cur=f.value; f.textContent="";
  const add=(v,t)=>{const o=el("option","",t);o.value=v;f.appendChild(o)};
  add("all","All logins"); add("everyone","Everyone logins");
  allUsers().forEach(u=>add("u:"+u,"Person: "+u)); groups.forEach(g=>add("g:"+g.name,"Group: "+(g.name||"(unnamed)"))); systems.forEach(s=>add("s:"+s.name,"System: "+(s.name||"(unnamed)")));
  f.value=cur; if(f.value!==cur)f.value="all";
}
function matches(l,f){
  if(!f||f==="all")return true; if(f==="everyone")return l.who==="all";
  const v=f.slice(2); if(f.startsWith("u:"))return l.who==="user"&&lc(l.user)===v;
  if(f.startsWith("g:"))return l.who==="group"&&!!l.grp&&l.grp.name===v; if(f.startsWith("s:"))return !!l.sys&&l.sys.name===v; return true;
}
function loginCard(l){
  const card=el("div","acc"), g=el("div","grid"), hint=el("div","hint");
  const upd=()=>{const open=openLogin(l); card.className="acc"+(open?" open":"");
    hint.className="hint"+(open?"":" info");
    hint.textContent=l.who==="all"?(hasSaved(l)?"⚠ Everyone who can log in can use these saved credentials, including anyone you add later.":"ⓘ Everyone who can log in sees this system, including anyone you add later. They must enter their own credentials.")
      :l.who==="group"?(hasSaved(l)?"ⓘ Every member of the group shares these saved credentials, so the target's own logs cannot tell them apart.":"")
      :userHint(l.user); hint.style.display=hint.textContent?"":"none";};
  const redo=()=>{renderLogins();refreshFlags()};
  addRow(g,"Who",valSelect(l,"who",[["user","One person"],["group","A group"],["all","Everyone who can log in"]],redo));
  if(l.who==="user"){const em=inp(l,"user","text","person@example.com"); em.setAttribute("list","knownUsers"); const base=em.oninput;
    em.oninput=()=>{base();upd()}; em.onchange=()=>{fillKnown();refreshFlags()}; addRow(g,"Person",em)}
  if(l.who==="group")addRow(g,"Group",objSelect(groups,l.grp,x=>x.name,x=>{l.grp=x;refreshFlags()}));
  addRow(g,"System",objSelect(systems,l.sys,x=>x.name,x=>{l.sys=x;redo()}));
  addRow(g,"Credentials",valSelect(l,"cred",[["ask","Ask them when they connect"],["saved","Use saved credentials"]],redo));
  if(l.cred==="saved"){
    const flip=()=>{upd();refreshFlags();tList()};
    addRow(g,"Username",inp(l,"username","text","",flip)); addRow(g,"Password",secretField(l,"password",flip,false));
    if(!l.sys||l.sys.protocol==="rdp")addRow(g,"Windows domain",inp(l,"domain","text","optional",flip));
    if(l.sys&&l.sys.protocol==="ssh"){addRow(g,"Private key",secretField(l,"private_key",flip,true)); addRow(g,"Key passphrase",secretField(l,"passphrase",flip,false))}
  }
  card.appendChild(g); card.appendChild(hint);
  const rm=el("button","","Remove login"); rm.onclick=()=>{logins=logins.filter(x=>x!==l);redo()}; const r=el("div","row");r.appendChild(rm);card.appendChild(r);
  upd(); return card;
}
function renderLogins(){
  fillFilter(); fillKnown(); const box=$("#llist"); box.textContent=""; const f=$("#l_filter").value;
  const shown=logins.filter(l=>matches(l,f));
  if(!shown.length)box.appendChild(el("div","sub",logins.length?"No logins match this filter.":(systems.length?"No logins yet. Nobody can connect to anything until you add one.":"Add a system first (Systems tab), then give people logins here.")));
  shown.forEach(l=>box.appendChild(loginCard(l)));
}
$("#l_filter").onchange=renderLogins;
$("#l_add").onclick=()=>{const l=blankLogin(), f=$("#l_filter").value;
  if(f==="everyone")l.who="all"; else if(f.startsWith("u:"))l.user=f.slice(2); else if(f.startsWith("g:")){l.who="group";l.grp=groups.find(g=>g.name===f.slice(2))||null}
  else if(f.startsWith("s:"))l.sys=systems.find(s=>s.name===f.slice(2))||null;
  if(!l.sys&&systems.length===1)l.sys=systems[0];
  logins.push(l); renderLogins(); refreshFlags(); tList()};
let stateVersion=0;
async function loadTargets(keep){
  const r=await api("/api/state"); fromFile(r.doc||{}); stateVersion=r.version||0;
  sel=Math.min(keep??0,systems.length-1); $("#me").textContent=r.me;
  $("#ver").textContent=r.updated_at?"Last saved "+r.updated_at.replace("T"," ")+" by "+r.updated_by+".":"Nothing saved yet.";
  tList(); tFill(); if(!$("#st_people").classList.contains("hide"))renderPeople(); if(!$("#st_logins").classList.contains("hide"))renderLogins();
}
async function loadAudit(){
  const r=await api("/api/audit"), box=$("#alist"); box.textContent="";
  if(!r.rows.length)box.appendChild(el("div","sub","Nothing recorded yet."));
  r.rows.forEach(x=>{const d=el("div","urow");d.appendChild(el("b","",x.at.replace("T"," ")));d.appendChild(el("span","",x.actor));d.appendChild(el("span","sub",x.action+": "+x.detail));box.appendChild(d)});
}
async function tAction(kind){
  const m=$("#tmsg"); m.className="msg"; m.textContent="";
  try{const doc=toFile(); const r=await api("/api/"+kind,{doc,version:stateVersion});
    m.className="msg "+(r.ok?"ok":"bad"); m.textContent=(r.ok?"✔ ":"✘ ")+r.message;
    if(kind==="save"&&r.ok)await loadTargets(sel);
  }catch(e){m.className="msg bad";m.textContent="✘ "+e.message}
}
$$("#tform .grid input,#tform .grid select").forEach(e=>{e.oninput=tWrite;e.onchange=tWrite});
$("#st_systems,#st_people,#st_logins");
$("#t_add").onclick=()=>{systems.push(blankSys());sel=systems.length-1;tList();tFill();$("#t_name").focus()};
$("#t_del").onclick=()=>{if(sel<0)return;const s=systems[sel],n=logins.filter(l=>l.sys===s).length;
  if(!confirm("Delete system \""+(s.name||"unnamed")+"\" and its "+n+" login(s)? (Not final until you press Save targets.)"))return;
  logins=logins.filter(l=>l.sys!==s); systems.splice(sel,1); sel=Math.min(sel,systems.length-1); tList(); tFill()};
$("#t_reload").onclick=async()=>{if(confirm("Discard your unsaved changes and reload from the database?"))await loadTargets(sel)};
$("#t_validate").onclick=()=>tAction("validate"); $("#t_save").onclick=()=>tAction("save");

loadTargets(0).catch(e=>{$("#tstatus").textContent="Could not load: "+e.message});
</script></body></html>"""


if __name__ == "__main__":
    main()

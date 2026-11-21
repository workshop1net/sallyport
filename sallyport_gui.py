#!/usr/bin/env python3
"""Sallyport GUI: a small web interface served on 127.0.0.1 only.

Run:  python sallyport_gui.py [--folder PATH] [--port N] [--no-browser]

It checks that Docker and Git are present, clones or updates the Sallyport
repository, edits sallyport.yaml and targets.yaml, and starts, restarts or stops the
stack. All the real work is done by sallyport_core, the same code as the command line.

Security model: the server listens on loopback only, but any web page open in your
browser can send requests to 127.0.0.1, so every request must carry a random token
(given in the URL this program prints), a Host header of exactly 127.0.0.1:<port>,
and, for changes, an Origin of the same address and a JSON body. It exits when the
browser tab is closed.
"""
import argparse
import contextlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

# Isolated mode (-I) does not add this script's directory to the path, so do it explicitly.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sallyport_core as core  # noqa: E402

try:
    import yaml
except ImportError:  # sallyport_core already exits with a message; kept for clarity
    sys.exit("PyYAML is required: pip install pyyaml")

DEFAULT_REPO = "https://github.com/workshop1net/sallyport.git"
EDITABLE = {"sallyport.yaml": "sallyport.example.yaml", "targets.yaml": "targets.example.yaml"}
IDLE_SECONDS = 300  # the page pings every 20 s; a throttled background tab still manages one a minute
MAX_BODY = 256 * 1024
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def settings_path():
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "Sallyport" / "gui.json"


def load_settings():
    try:
        return json.loads(settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_settings(data):
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


class Job:
    """One background operation whose output the page polls."""

    def __init__(self, title):
        self.title = title
        self.lines = []
        self.done = False
        self.ok = None
        self.lock = threading.Lock()

    def add(self, text):
        with self.lock:
            self.lines.extend(text.splitlines() or [""])

    def finish(self, ok):
        with self.lock:
            self.done, self.ok = True, ok

    def snapshot(self, since):
        with self.lock:
            return {"title": self.title, "lines": self.lines[since:], "next": len(self.lines),
                    "done": self.done, "ok": self.ok}


class LineWriter(io.TextIOBase):
    def __init__(self, job):
        self.job, self.buf = job, ""

    def write(self, text):
        self.buf += text
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            self.job.add(line)
        return len(text)

    def flush(self):
        if self.buf:
            self.job.add(self.buf)
            self.buf = ""


class State:
    def __init__(self, folder):
        self.lock = threading.Lock()
        self.job = None
        self.last_seen = time.time()
        self.folder = None
        self.set_folder(folder)

    def set_folder(self, folder):
        self.folder = Path(folder).expanduser().resolve()
        core.set_root(self.folder)

    def touch(self):
        self.last_seen = time.time()


# ---------------------------------------------------------------- environment checks

def run_quiet(cmd, cwd=None, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           cwd=cwd, timeout=timeout, creationflags=NO_WINDOW)
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except (OSError, subprocess.SubprocessError) as e:
        return None, "", str(e)


def check_environment(state):
    out = []
    if not shutil.which("docker"):
        out.append({"name": "Docker", "ok": False, "detail": "not installed (install Docker Desktop)"})
    else:
        rc, so, se = run_quiet(["docker", "version", "--format", "{{.Server.Version}}"])
        if rc == 0 and so:
            out.append({"name": "Docker", "ok": True, "detail": f"engine {so}"})
        else:
            out.append({"name": "Docker", "ok": False, "detail": "installed but not running (start Docker Desktop)"})
        rc, so, se = run_quiet(["docker", "compose", "version", "--short"])
        m = re.search(r"(\d+)\.(\d+)", so or "")
        if rc == 0 and m:
            ok = (int(m.group(1)), int(m.group(2))) >= (2, 24)
            out.append({"name": "Docker Compose", "ok": ok,
                        "detail": so.lstrip("v") + ("" if ok else " (2.24 or later is needed for dev mode)")})
        else:
            out.append({"name": "Docker Compose", "ok": False, "detail": "not available"})
    if shutil.which("git"):
        rc, so, se = run_quiet(["git", "--version"])
        out.append({"name": "Git", "ok": rc == 0, "detail": so or se})
    else:
        out.append({"name": "Git", "ok": False, "detail": "not installed (winget install Git.Git)"})
    folder = state.folder
    has_repo = (folder / ".git").exists()
    has_stack = (folder / "compose.yaml").exists()
    out.append({"name": "Folder", "ok": has_stack,
                "detail": f"{folder} - " + ("Sallyport files present" + (", git checkout" if has_repo else ", not a git checkout")
                                           if has_stack else "no Sallyport files here yet (use Clone / update)")})
    return out


def stack_mode(state):
    try:
        data = yaml.safe_load(core.CONFIG.read_text(encoding="utf-8")) or {}
        return "dev" if data.get("mode") == "dev" else "production"
    except (OSError, yaml.YAMLError, AttributeError):
        return "production"


def compose_cmd(state, *args):
    files = ["-f", "compose.yaml", "-f", "compose.dev.yaml"] if stack_mode(state) == "dev" else []
    return ["docker", "compose", "--progress", "plain", *files, *args]


# ------------------------------------------------------------------------- jobs

def run_process(job, cmd, cwd):
    job.add("$ " + " ".join(cmd))
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace", creationflags=NO_WINDOW)
    except OSError as e:
        job.add(f"error: {e}")
        return False
    for line in proc.stdout:
        job.add(line.rstrip("\r\n"))
    return proc.wait() == 0


def run_core(job, func, *args):
    writer = LineWriter(job)
    try:
        with contextlib.redirect_stdout(writer):
            func(*args)
        writer.flush()
        return True
    except SystemExit as e:
        writer.flush()
        if e.code not in (None, 0):
            job.add(str(e.code))
            return False
        return True
    except Exception as e:  # report instead of killing the server thread
        writer.flush()
        job.add(f"unexpected error: {e!r}")
        return False


def action_clone_or_pull(state, job, body):
    repo = (body.get("repo") or DEFAULT_REPO).strip()
    if not re.match(r"^(https://|git@)[\w.@:/~-]+$", repo):
        job.add("error: repository must be an https:// or git@ URL")
        return False
    folder = state.folder
    if (folder / ".git").exists():
        return run_process(job, ["git", "pull", "--ff-only"], folder)
    if folder.exists() and any(folder.iterdir()):
        job.add(f"error: {folder} is not empty and is not a git checkout; choose an empty or new folder")
        return False
    folder.parent.mkdir(parents=True, exist_ok=True)
    return run_process(job, ["git", "clone", repo, str(folder)], folder.parent)


def need_checkout(state, job):
    if not (state.folder / "compose.yaml").exists():
        job.add("error: no Sallyport files in this folder; clone the repository first")
        return False
    return True


def make_action(name):
    def init(state, job, body):
        return need_checkout(state, job) and run_core(job, core.cmd_init, SimpleNamespace(no_schema=False))

    def up(state, job, body):
        return need_checkout(state, job) and run_process(job, compose_cmd(state, "up", "-d"), state.folder)

    def restart(state, job, body):
        return need_checkout(state, job) and run_process(
            job, compose_cmd(state, "up", "-d", "--force-recreate"), state.folder)

    def down(state, job, body):
        return need_checkout(state, job) and run_process(job, compose_cmd(state, "down"), state.folder)

    def load_targets(state, job, body):
        return need_checkout(state, job) and run_core(job, core.cmd_load_targets, SimpleNamespace(dry_run=False))

    def dry_run(state, job, body):
        return need_checkout(state, job) and run_core(job, core.cmd_load_targets, SimpleNamespace(dry_run=True))

    def check(state, job, body):
        return need_checkout(state, job) and run_core(
            job, core.cmd_check, SimpleNamespace(url=None, insecure=False, skip_ports=False))

    def ps(state, job, body):
        return need_checkout(state, job) and run_process(job, compose_cmd(state, "ps"), state.folder)

    def logs(state, job, body):
        service = body.get("service") or ""
        if service and not re.match(r"^[a-z0-9_-]+$", service):
            job.add("error: bad service name")
            return False
        args = ["logs", "--tail", "200"] + ([service] if service else [])
        return need_checkout(state, job) and run_process(job, compose_cmd(state, *args), state.folder)

    return {"clone": action_clone_or_pull, "init": init, "up": up, "restart": restart, "down": down,
            "load_targets": load_targets, "dry_run": dry_run, "check": check, "ps": ps,
            "logs": logs}.get(name)


TITLES = {"clone": "Clone / update", "init": "Initialise", "up": "Start", "restart": "Restart (recreate)",
          "down": "Stop", "load_targets": "Load targets", "dry_run": "Targets dry run", "check": "Check",
          "ps": "Status", "logs": "Logs"}


def start_job(state, name, body):
    fn = make_action(name)
    if fn is None:
        return None, "unknown action"
    with state.lock:
        if state.job and not state.job.done:
            return None, "another operation is still running"
        job = Job(TITLES[name])
        state.job = job

    def runner():
        try:
            job.finish(bool(fn(state, job, body)))
        except Exception as e:
            job.add(f"unexpected error: {e!r}")
            job.finish(False)

    threading.Thread(target=runner, daemon=True).start()
    return job, None


# ------------------------------------------------------------------------ files

def read_file(state, name):
    path = state.folder / name
    if path.exists():
        return {"exists": True, "text": path.read_text(encoding="utf-8")}
    example = state.folder / EDITABLE[name]
    return {"exists": False, "text": example.read_text(encoding="utf-8") if example.exists() else ""}


def validate_text(name, text):
    """Returns (ok, message). Never writes anything."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return False, f"not valid YAML: {e}"
    if not isinstance(data, dict):
        return False, "must contain a YAML mapping"
    try:
        if name == "sallyport.yaml":
            c = core.validate_config(data)
            return True, f"valid ({c['mode']} mode, domain {c['domain']})"
        targets = core.load_targets(data)
        for t in targets:
            core.target_params(t)
        return True, f"valid ({len(targets)} target(s))"
    except SystemExit as e:
        return False, str(e.code)


# ----------------------------------------------------------------------- server

class Handler(BaseHTTPRequestHandler):
    server_version = "SallyportGUI"
    state = None
    token = ""
    port = 0

    def log_message(self, *a):  # keep the console quiet
        pass

    # -- plumbing
    def reply(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(data)

    def deny(self, code, message):
        self.reply(code, {"error": message})

    def host_ok(self):
        return self.headers.get("Host") == f"127.0.0.1:{self.port}"

    def token_ok(self, supplied):
        return bool(supplied) and secrets.compare_digest(supplied, self.token)

    def do_GET(self):
        if not self.host_ok():
            return self.deny(403, "bad Host header")
        url = urlparse(self.path)
        if url.path == "/":
            t = (parse_qs(url.query).get("t") or [""])[0]
            if not self.token_ok(t):
                return self.reply(403, "Open the full URL printed in the console (it includes the token).", "text/plain")
            return self.reply(200, PAGE, "text/html")
        if not self.token_ok(self.headers.get("X-Sallyport-Token", "")):
            return self.deny(403, "bad token")
        self.state.touch()
        q = parse_qs(url.query)
        if url.path == "/api/ping":
            return self.reply(200, {"ok": True})
        if url.path == "/api/state":
            s = load_settings()
            return self.reply(200, {"folder": str(self.state.folder), "repo": s.get("repo", DEFAULT_REPO),
                                    "checks": check_environment(self.state), "mode": stack_mode(self.state)})
        if url.path == "/api/job":
            job = self.state.job
            since = int((q.get("since") or ["0"])[0] or 0)
            return self.reply(200, job.snapshot(since) if job else {"title": "", "lines": [], "next": 0, "done": True, "ok": None})
        if url.path == "/api/file":
            name = (q.get("name") or [""])[0]
            if name not in EDITABLE:
                return self.deny(400, "unknown file")
            return self.reply(200, read_file(self.state, name))
        self.deny(404, "not found")

    def do_POST(self):
        if not self.host_ok():
            return self.deny(403, "bad Host header")
        if self.headers.get("Origin") != f"http://127.0.0.1:{self.port}":
            return self.deny(403, "bad Origin")
        if not self.token_ok(self.headers.get("X-Sallyport-Token", "")):
            return self.deny(403, "bad token")
        if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
            return self.deny(415, "JSON only")
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self.deny(413, "too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self.deny(400, "bad JSON")
        self.state.touch()
        path = urlparse(self.path).path
        if path == "/api/folder":
            folder = str(body.get("folder") or "").strip()
            if not folder:
                return self.deny(400, "folder required")
            self.state.set_folder(folder)
            s = load_settings()
            s["folder"] = str(self.state.folder)
            if body.get("repo"):
                s["repo"] = str(body["repo"])
            save_settings(s)
            return self.reply(200, {"folder": str(self.state.folder)})
        if path == "/api/run":
            job, err = start_job(self.state, str(body.get("action") or ""), body)
            if err:
                return self.deny(409 if "running" in err else 400, err)
            return self.reply(200, {"started": job.title})
        if path in ("/api/validate", "/api/save"):
            name, text = body.get("name"), body.get("text")
            if name not in EDITABLE or not isinstance(text, str):
                return self.deny(400, "bad request")
            ok, msg = validate_text(name, text)
            if path == "/api/save":
                if not ok and not body.get("force"):
                    return self.reply(200, {"ok": False, "message": msg, "saved": False})
                if not (self.state.folder).exists():
                    return self.deny(400, "folder does not exist yet; clone first or create it")
                core.write_private(self.state.folder / name, text.replace("\r\n", "\n"))
                return self.reply(200, {"ok": ok, "message": ("saved; " + msg) if ok else ("saved anyway; " + msg), "saved": True})
            return self.reply(200, {"ok": ok, "message": msg})
        if path == "/api/quit":
            self.reply(200, {"ok": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        self.deny(404, "not found")


def default_folder():
    saved = load_settings().get("folder")
    if saved:
        return saved
    here = Path(__file__).resolve().parent
    return str(here if (here / "compose.yaml").exists() else Path.home() / "sallyport")


def main():
    ap = argparse.ArgumentParser(description="Sallyport GUI (loopback web interface)")
    ap.add_argument("--folder", help="Sallyport folder (default: the saved one, this checkout, or ~/sallyport)")
    ap.add_argument("--port", type=int, default=0, help="port on 127.0.0.1 (default: any free port)")
    ap.add_argument("--no-browser", action="store_true", help="print the URL instead of opening a browser")
    args = ap.parse_args()

    state = State(args.folder or default_folder())
    Handler.state = state
    Handler.token = secrets.token_urlsafe(24)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    Handler.port = server.server_address[1]
    url = f"http://127.0.0.1:{Handler.port}/?t={Handler.token}"
    print(f"Sallyport GUI: {url}\nClose the browser tab (or press Quit) to stop. Ctrl+C also stops it.")

    def watchdog():
        while True:
            time.sleep(10)
            if time.time() - state.last_seen > IDLE_SECONDS:
                print("no browser activity; shutting down")
                server.shutdown()
                return

    threading.Thread(target=watchdog, daemon=True).start()
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sallyport</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
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
pre{background:#0002;border:1px solid var(--bd);border-radius:6px;padding:8px;height:260px;overflow:auto;margin:0;white-space:pre-wrap;font:12.5px/1.4 Consolas,monospace}
.chk{display:grid;grid-template-columns:20px 130px 1fr;gap:2px 8px}
.ok{color:var(--ok)} .bad{color:var(--bad)} .msg.bad{margin-left:6px} .msg.ok{margin-left:6px}
.tabs button.on{font-weight:700;text-decoration:underline}
.warn{background:#f9a82522;border:1px solid #f9a82588;border-radius:6px;padding:6px 10px;margin:8px 0}
</style></head><body>
<h1>Sallyport</h1><div class="sub">Local control panel &mdash; listening on 127.0.0.1 only. <button id="quit">Quit</button></div>

<section><h2>1. Checks</h2><div id="checks" class="chk">loading&hellip;</div>
<div class="row"><button id="recheck">Check again</button></div></section>

<section><h2>2. Folder and repository</h2>
<div class="row"><label for="folder">Folder</label><input type="text" id="folder"></div>
<div class="row"><label for="repo">Repository</label><input type="text" id="repo"></div>
<div class="row"><button id="clone" class="p">Clone / update</button><span class="sub">clones into the folder if it is empty or new, otherwise runs <code>git pull</code></span></div></section>

<section><h2>3. Configuration</h2>
<div class="tabs row"><button data-f="sallyport.yaml" class="on">sallyport.yaml</button><button data-f="targets.yaml">targets.yaml</button><span id="fstate" class="sub"></span></div>
<textarea id="editor" spellcheck="false"></textarea>
<div class="row"><button id="validate">Validate</button><button id="save" class="p">Save</button><span id="fmsg" class="msg"></span></div>
<div class="warn">These files hold secrets (IdP client secret, target passwords) in plain text. Keep the folder readable only by administrators.</div></section>

<section><h2>4. Run</h2>
<div class="row"><button data-a="init" class="p">Initialise</button><button data-a="up" class="p">Start</button><button data-a="restart">Restart (recreate)</button><button data-a="down">Stop</button><button data-a="load_targets" class="p">Load targets</button><button data-a="dry_run">Targets dry run</button><button data-a="check">Check service</button><button data-a="ps">Status</button><button data-a="logs">Logs</button></div>
<div class="sub">Order for a new install: Clone, edit and save both files, Initialise, Start, Load targets. Re-run Initialise after changing sallyport.yaml, then Restart. Re-run Load targets after changing targets.yaml.</div>
<h2>Output <span id="jtitle" class="sub"></span></h2><pre id="out"></pre></section>

<script>
"use strict";
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let token=new URLSearchParams(location.search).get("t")||"";
history.replaceState(null,"",location.pathname);   // keep the token out of the address bar and history
let cur="sallyport.yaml", since=0, polling=false;
async function api(path,body){
  const o={headers:{"X-Sallyport-Token":token}};
  if(body!==undefined){o.method="POST";o.headers["Content-Type"]="application/json";o.body=JSON.stringify(body);}
  const r=await fetch(path,o); let j={}; try{j=await r.json()}catch(e){}
  if(!r.ok) throw new Error(j.error||("HTTP "+r.status)); return j;
}
function say(t,cls){const o=$("#out");const d=document.createElement("div");d.textContent=t;if(cls)d.className=cls;o.appendChild(d);o.scrollTop=o.scrollHeight}
async function refresh(){
  const s=await api("/api/state");
  if(document.activeElement!==$("#folder"))$("#folder").value=s.folder;
  if(document.activeElement!==$("#repo"))$("#repo").value=s.repo;
  const c=$("#checks");c.textContent="";
  for(const k of s.checks){
    const a=document.createElement("span");a.textContent=k.ok?"✔":"✘";a.className=k.ok?"ok":"bad";
    const b=document.createElement("span");b.textContent=k.name;
    const d=document.createElement("span");d.textContent=k.detail;
    c.append(a,b,d);
  }
}
async function loadFile(){
  const f=await api("/api/file?name="+encodeURIComponent(cur));
  $("#editor").value=f.text;
  $("#fstate").textContent=f.exists?"":"(not created yet: showing the example; Save creates it)";
  $("#fmsg").textContent="";
}
async function folderSet(){
  await api("/api/folder",{folder:$("#folder").value,repo:$("#repo").value});
}
async function run(action,extra){
  try{await folderSet(); $("#out").textContent=""; since=0;
    await api("/api/run",Object.assign({action},extra||{})); poll();
  }catch(e){say("error: "+e.message,"bad")}
}
async function poll(){
  if(polling)return; polling=true;
  try{for(;;){
    const j=await api("/api/job?since="+since);
    $("#jtitle").textContent=j.title?"— "+j.title:"";
    j.lines.forEach(l=>say(l)); since=j.next;
    if(j.done){ if(j.ok===true)say("✔ done","ok"); else if(j.ok===false)say("✘ failed","bad"); break;}
    await new Promise(r=>setTimeout(r,700));
  }}catch(e){say("error: "+e.message,"bad")}
  polling=false; refresh().catch(()=>{}); loadFile().catch(()=>{});
}
$("#clone").onclick=()=>run("clone",{repo:$("#repo").value});
$$("button[data-a]").forEach(b=>b.onclick=()=>run(b.dataset.a));
$("#recheck").onclick=async()=>{try{await folderSet();await refresh();await loadFile()}catch(e){say("error: "+e.message,"bad")}};
$$(".tabs button[data-f]").forEach(b=>b.onclick=async()=>{
  $$(".tabs button[data-f]").forEach(x=>x.classList.toggle("on",x===b)); cur=b.dataset.f;
  try{await folderSet();await loadFile()}catch(e){$("#fmsg").className="msg bad";$("#fmsg").textContent=e.message}});
async function fileAction(kind){
  const m=$("#fmsg");
  try{await folderSet();
    const r=await api("/api/"+kind,{name:cur,text:$("#editor").value});
    m.className="msg "+(r.ok?"ok":"bad"); m.textContent=(r.ok?"✔ ":"✘ ")+r.message;
    if(kind==="save"&&!r.saved&&!r.ok){
      if(confirm("This file is not valid:\n\n"+r.message+"\n\nSave it anyway?")){
        const r2=await api("/api/save",{name:cur,text:$("#editor").value,force:true});
        m.className="msg bad"; m.textContent="✘ "+r2.message;}
    }
    if(kind==="save"){refresh().catch(()=>{});$("#fstate").textContent=""}
  }catch(e){m.className="msg bad";m.textContent=e.message}
}
$("#validate").onclick=()=>fileAction("validate"); $("#save").onclick=()=>fileAction("save");
$("#quit").onclick=async()=>{try{await api("/api/quit",{})}catch(e){} document.body.textContent="Stopped. You can close this tab."};
setInterval(()=>api("/api/ping").catch(()=>{}),20000);
refresh().then(loadFile).catch(e=>{document.body.textContent="Cannot reach the Sallyport GUI: "+e.message+" (was it closed? run it again)"});
</script></body></html>
"""

if __name__ == "__main__":
    main()

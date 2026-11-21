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
        self.update = {"folder": None, "state": "idle"}
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


# ---------------------------------------------------------------- update checking

def git(folder, *args, timeout=30):
    return run_quiet(["git", "-C", str(folder), *args], timeout=timeout)


def initialised(folder):
    return (folder / ".env").exists() and (folder / "generated" / "pomerium.yaml").exists()


def plan_for(folder, files):
    """What an update touching these files needs done, in order."""
    files = set(files)
    core_changed = bool(files & {"sallyport_core.py", "sallyport"})
    gui_changed = bool(files & {"sallyport_gui.py", "sallyport_core.py", "sallyport"})
    compose = bool(files & {"compose.yaml", "compose.dev.yaml"})
    init_needed = initialised(folder) and (compose or core_changed or any(f.startswith(("sql/", "tools/")) for f in files))
    steps = []
    if init_needed:
        steps.append({"id": "init", "text": "Regenerate the configuration (Initialise)"})
    if initialised(folder) and (init_needed or compose):
        steps.append({"id": "restart", "text": "Recreate the containers (interrupts any active sessions)"})
    if initialised(folder) and core_changed:
        steps.append({"id": "load_targets", "text": "Reload the targets"})
    notes = []
    if any(f.startswith("sql/") for f in files):
        notes.append("Database setup scripts changed. They only run when a database is first created, so an existing "
                     "install needs them applied by hand (see README, Upgrades).")
    if gui_changed:
        notes.append("This control panel's own code changed: close it and start it again afterwards to use the new version.")
    return {"steps": steps, "notes": notes, "gui_changed": gui_changed}


def compose_files(state):
    return ["-f", "compose.yaml", "-f", "compose.dev.yaml"] if stack_mode(state) == "dev" else []


def image_state(image):
    """'outdated' | 'current' | 'missing' | 'unknown' for one image, without downloading it."""
    rc, out, _ = run_quiet(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image])
    if rc != 0:
        return "missing"  # not downloaded yet: starting the stack will fetch it
    try:
        local = json.loads(out) or []
    except ValueError:
        return "unknown"
    rc, out, _ = run_quiet(["docker", "buildx", "imagetools", "inspect", image], timeout=45)
    m = re.search(r"^Digest:\s+(sha256:[0-9a-f]{64})", out or "", re.M)
    if rc != 0 or not m:
        return "unknown"
    return "current" if any(d.endswith("@" + m.group(1)) for d in local) else "outdated"


def check_images(state, folder):
    """Compare each image the stack uses with its registry, by digest only (no downloads).
    Best effort: the result says so when it could not check."""
    rc, out, _ = run_quiet(["docker", "compose", *compose_files(state), "config", "--images"], cwd=folder, timeout=40)
    if rc != 0 or not out.split():
        return {"outdated": [], "note": "Could not list the stack's container images."}
    images = sorted(set(out.split()))
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=4) as pool:
        states = dict(zip(images, pool.map(image_state, images)))
    outdated = [i for i, st in states.items() if st == "outdated"]
    unknown = [i for i, st in states.items() if st == "unknown"]
    note = f"Could not check {len(unknown)} image(s) against the registry." if unknown else ""
    return {"outdated": outdated, "note": note}


def update_worker(state, folder, u):
    def finish(**kw):
        if u.get("folder") == str(folder):
            u.update(kw)

    checks = check_environment(state)
    if not all(c["ok"] for c in checks):
        return finish(state="skipped", message="Environment checks have not all passed, so updates were not checked.")
    if not (folder / ".git").exists():
        return finish(state="skipped", message="This folder is not a git checkout, so updates cannot be checked.")
    rc, upstream, err = git(folder, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if rc != 0:
        return finish(state="skipped", message="This checkout has no upstream branch to compare with.")
    rc, out, err = git(folder, "fetch", "--quiet", timeout=90)
    if rc != 0:
        return finish(state="error", message="Could not reach the repository: " + (err or out or "git fetch failed"))
    rc, out, err = git(folder, "rev-list", "--left-right", "--count", "HEAD...@{u}")
    try:
        ahead, behind = (int(x) for x in out.split())
    except ValueError:
        return finish(state="error", message="Could not compare with the upstream branch: " + (err or out))
    rc, head, _ = git(folder, "rev-parse", "--short", "HEAD")
    if ahead and behind:
        return finish(state="diverged", head=head, ahead=ahead, behind=behind,
                      message=f"This checkout has {ahead} local commit(s) and is {behind} behind; update it by hand with git.")
    images = check_images(state, folder) if initialised(folder) else {"outdated": [], "note": ""}
    commits, plan, dirty = [], {"steps": [], "notes": [], "gui_changed": False}, False
    if behind:
        rc, dirty_out, _ = git(folder, "status", "--porcelain", "--untracked-files=no")
        dirty = bool(dirty_out)
        rc, subjects, _ = git(folder, "log", "--format=%h %s", "-n", "8", "HEAD..@{u}")
        commits = subjects.splitlines()
        rc, files, _ = git(folder, "diff", "--name-only", "HEAD..@{u}")
        plan = plan_for(folder, [f for f in files.splitlines() if f])
    if not behind and not images["outdated"]:
        note = (" " + images["note"]) if images["note"] else ""
        return finish(state="current", head=head, message="Up to date." + note)
    finish(state="available", head=head, behind=behind, commits=commits, plan=plan, dirty=dirty,
           images=images["outdated"], image_note=images["note"], message="")


def update_status(state, force=False):
    with state.lock:
        u = state.update
        if u.get("state") == "checking":
            return dict(u)
        if force or u.get("folder") != str(state.folder):
            u = state.update = {"folder": str(state.folder), "state": "checking", "message": "Checking for updates and newer container images…"}
            threading.Thread(target=update_worker, args=(state, state.folder, u), daemon=True).start()
        return dict(u)


def action_update(state, job, body):
    """Pull, then apply what the new files need. Steps that depend on the code just pulled run
    as fresh processes: this process still has the old code loaded."""
    folder = state.folder
    with state.lock:
        images_outdated = list(state.update.get("images") or [])
    rc, files, _ = git(folder, "diff", "--name-only", "HEAD..@{u}")
    plan = plan_for(folder, [f for f in files.splitlines() if f]) if rc == 0 else {"steps": [], "notes": [], "gui_changed": False}
    if files.strip() and not run_process(job, ["git", "pull", "--ff-only"], folder):
        return False
    ids = {st["id"] for st in plan["steps"]}
    me = [sys.executable, "-I", str(folder / "sallyport")]
    if "init" in ids and not run_process(job, me + ["init"], folder):
        return False
    if images_outdated and initialised(folder) and not run_process(job, compose_cmd(state, "pull"), folder):
        return False
    if "restart" in ids or images_outdated:
        args = ["up", "-d"] + (["--force-recreate"] if "restart" in ids else [])
        if not run_process(job, compose_cmd(state, *args), folder):
            return False
    if "load_targets" in ids and not run_process(job, me + ["load-targets"], folder):
        return False
    for note in plan["notes"]:
        job.add("NOTE: " + note)
    job.add("Update finished.")
    with state.lock:
        state.update = {"folder": None, "state": "idle"}  # forces a fresh check
    return True


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

    def apply_settings(state, job, body):
        if not need_checkout(state, job):
            return False
        if not run_core(job, core.cmd_init, SimpleNamespace(no_schema=False, quiet=True)):
            return False
        if not run_process(job, compose_cmd(state, "up", "-d", "--force-recreate"), state.folder):
            return False
        try:
            domain = yaml.safe_load(core.CONFIG.read_text(encoding="utf-8")).get("domain", "")
        except (OSError, yaml.YAMLError, AttributeError):
            domain = ""
        job.add(f"Settings applied. Open https://{domain}" + (" (accept the certificate warning in dev mode)" if stack_mode(state) == "dev" else ""))
        return True

    def up(state, job, body):
        return need_checkout(state, job) and run_process(job, compose_cmd(state, "up", "-d"), state.folder)

    def restart(state, job, body):
        return need_checkout(state, job) and run_process(
            job, compose_cmd(state, "up", "-d", "--force-recreate"), state.folder)

    def down(state, job, body):
        return need_checkout(state, job) and run_process(job, compose_cmd(state, "down"), state.folder)

    def load_targets(state, job, body):
        return need_checkout(state, job) and run_core(job, core.cmd_load_targets, SimpleNamespace(dry_run=False))

    def ps(state, job, body):
        return need_checkout(state, job) and run_process(job, compose_cmd(state, "ps"), state.folder)

    def logs(state, job, body):
        service = body.get("service") or ""
        if service and not re.match(r"^[a-z0-9_-]+$", service):
            job.add("error: bad service name")
            return False
        args = ["logs", "--tail", "200"] + ([service] if service else [])
        return need_checkout(state, job) and run_process(job, compose_cmd(state, *args), state.folder)

    return {"update": action_update, "clone": action_clone_or_pull, "init": init, "apply_settings": apply_settings, "up": up, "restart": restart, "down": down,
            "load_targets": load_targets, "ps": ps,
            "logs": logs}.get(name)


TITLES = {"update": "Update", "clone": "Clone / update repository", "init": "Initialise", "apply_settings": "Apply settings",
          "up": "Start", "restart": "Restart", "down": "Stop", "load_targets": "Apply targets",
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
        return False, re.sub(r"^error: ", "", str(e.code))


# ------------------------------------------------------ structured config and targets

class YamlDumper(yaml.SafeDumper):
    pass


def _represent_str(dumper, data):
    style = "|" if "\n" in data else None  # keep multi-line keys readable
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


YamlDumper.add_representer(str, _represent_str)


def dump_yaml(obj, header):
    return header + yaml.dump(obj, Dumper=YamlDumper, sort_keys=False, default_flow_style=False, allow_unicode=True)


def as_list(value):
    if isinstance(value, str):
        value = re.split(r"[\r\n]+", value)
    return [str(v).strip() for v in (value or []) if str(v).strip()]


def build_config_yaml(d):
    mode = d.get("mode") or "production"
    out = {"mode": mode, "domain": str(d.get("domain") or "").strip()}
    session = {"lifetime": str(d.get("lifetime") or "8h").strip(), "idle_timeout": str(d.get("idle_timeout") or "30m").strip()}
    if mode != "dev":
        out["acme_email"] = str(d.get("acme_email") or "").strip()
        out["acme_staging"] = bool(d.get("acme_staging"))
        prov = d.get("provider") or "oidc"
        idp = {"provider": prov}
        if prov == "oidc":
            idp["issuer"] = str(d.get("issuer") or "").strip()
        elif prov == "auth0":
            idp["domain"] = str(d.get("idp_domain") or "").strip()
        idp["client_id"] = str(d.get("client_id") or "").strip()
        idp["client_secret"] = str(d.get("client_secret") or "")
        if prov == "oidc":
            idp["scopes"] = as_list(d.get("scopes")) or ["openid", "profile", "email"]
        out["idp"] = idp
        access = {"emails": as_list(d.get("emails")), "groups": [] if prov == "google" else as_list(d.get("groups"))}
        if str(d.get("groups_claim") or "").strip():
            access["groups_claim"] = str(d["groups_claim"]).strip()
        out["access"] = access
    out["session"] = session
    return dump_yaml(out, "# Written by the Sallyport GUI. Comments added by hand are not kept when it saves.\n")


def flatten_config(data):
    idp, access, session = data.get("idp") or {}, data.get("access") or {}, data.get("session") or {}
    return {"mode": data.get("mode", "production"), "domain": data.get("domain", ""),
            "acme_email": data.get("acme_email", ""), "acme_staging": data.get("acme_staging", True),
            "provider": idp.get("provider", "oidc"), "issuer": idp.get("issuer", ""), "idp_domain": idp.get("domain", ""),
            "client_id": idp.get("client_id", ""),
            "client_secret": idp.get("client_secret", ""), "scopes": idp.get("scopes") or ["openid", "profile", "email"],
            "emails": access.get("emails") or [], "groups": access.get("groups") or [],
            "groups_claim": access.get("groups_claim", ""),
            "lifetime": session.get("lifetime", "8h"), "idle_timeout": session.get("idle_timeout", "30m")}


def read_structured(state, name):
    path = state.folder / name
    if not path.exists():
        return {"exists": False, "data": None, "status": None}
    text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return {"exists": True, "data": None, "status": f"not valid YAML: {e}"}
    if not isinstance(data, dict):
        return {"exists": True, "data": None, "status": "must contain a YAML mapping"}
    ok, msg = validate_text(name, text)
    if name == "sallyport.yaml":
        return {"exists": True, "data": flatten_config(data), "status": msg}
    return {"exists": True, "data": data.get("targets") if isinstance(data.get("targets"), list) else [],
            "status": msg}


INT_FIELDS = ("port", "max_sessions")


def build_targets_yaml(items):
    cleaned = []
    for t in items if isinstance(items, list) else []:
        if not isinstance(t, dict):
            continue
        row = {}
        for k, v in t.items():
            if v is None or v == "":
                continue
            if k in INT_FIELDS and isinstance(v, str) and v.strip().isdigit():
                v = int(v.strip())
            row[str(k)] = v
        cleaned.append(row)
    header = ("# Written by the Sallyport GUI. Contains credentials in plain text.\n"
              "# Comments added by hand are not kept when the GUI saves.\n")
    return dump_yaml({"targets": cleaned}, header)


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
                                    "checks": check_environment(self.state), "mode": stack_mode(self.state),
                                    "checkout": (self.state.folder / ".git").exists() and (self.state.folder / "compose.yaml").exists()})
        if url.path == "/api/update":
            return self.reply(200, update_status(self.state, force=(q.get("force") or ["0"])[0] == "1"))
        if url.path == "/api/job":
            job = self.state.job
            since = int((q.get("since") or ["0"])[0] or 0)
            return self.reply(200, job.snapshot(since) if job else {"title": "", "lines": [], "next": 0, "done": True, "ok": None})
        if url.path in ("/api/config", "/api/targets"):
            return self.reply(200, read_structured(self.state, "sallyport.yaml" if url.path == "/api/config" else "targets.yaml"))
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
        if path in ("/api/config/validate", "/api/config/save", "/api/targets/validate", "/api/targets/save"):
            is_cfg = path.startswith("/api/config")
            name = "sallyport.yaml" if is_cfg else "targets.yaml"
            payload = body.get("data") if is_cfg else body.get("targets")
            if (is_cfg and not isinstance(payload, dict)) or (not is_cfg and not isinstance(payload, list)):
                return self.deny(400, "bad request")
            text = build_config_yaml(payload) if is_cfg else build_targets_yaml(payload)
            ok, msg = validate_text(name, text)
            if path.endswith("/save"):
                if not ok:
                    return self.reply(200, {"ok": False, "message": msg, "saved": False})
                if not self.state.folder.exists():
                    return self.deny(400, "folder does not exist yet; clone first or create it")
                core.write_private(self.state.folder / name, text)
                return self.reply(200, {"ok": True, "message": "saved; " + msg, "saved": True})
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
    update_status(state)  # start the update check now; the page shows the result
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
<h1>Sallyport</h1><div class="sub">Local control panel &mdash; listening on 127.0.0.1 only. <button id="quit">Quit</button></div>

<div class="maintabs"><button id="tb_settings" data-t="settings" class="on">Settings &amp; system</button><button id="tb_targets" data-t="targets">Targets</button><button id="tb_raw" data-t="raw">Raw files</button></div>

<div id="tab_settings" class="tabpanel">
<div id="banner"></div>

<section><details id="envd"><summary><b>Environment checks</b> <span id="envsum" class="sub"></span></summary>
<div id="checks" class="chk">loading&hellip;</div>
<div class="row"><button id="recheck">Check again</button></div></details></section>

<section><details id="repod"><summary><b>Folder and repository</b> <span id="repsum" class="sub"></span></summary>
<div class="row"><label for="folder">Folder</label><input type="text" id="folder"></div>
<div class="row"><label for="repo">Repository</label><input type="text" id="repo"></div>
<div class="row"><button id="clone" class="p">Clone / update</button><span class="sub">clones into the folder if it is empty or new, otherwise runs <code>git pull</code></span></div></details></section>

<section><h2>Settings</h2>
<div class="sub" id="cstatus"></div>
<div class="grid">
<label for="c_mode">Mode</label><select id="c_mode"><option value="production">Production (Let's Encrypt + your IdP)</option><option value="dev">Dev (local test: private certificate, mock login)</option></select>
<label for="c_domain">Domain</label><input type="text" id="c_domain" placeholder="access.client.example (dev: access.localhost)">
</div>
<div id="prodFields"><div class="grid">
<label for="c_acme_email">ACME email</label><input type="text" id="c_acme_email" placeholder="ops@msp.example">
<label for="c_staging">Let's Encrypt staging</label><span><input type="checkbox" id="c_staging"> <label for="c_staging" class="sub">untrusted test certificates; untick for real ones</label></span>
<label for="c_provider">Identity provider</label><select id="c_provider"><option value="oidc">Generic OpenID Connect</option><option value="auth0">Auth0</option><option value="google">Google</option></select>
<label class="p_oidc" for="c_issuer">Issuer URL</label><input class="p_oidc" type="text" id="c_issuer" placeholder="https://login.example.com/tenant/v2.0">
<label class="p_auth0" for="c_idp_domain">Auth0 tenant domain</label><input class="p_auth0" type="text" id="c_idp_domain" placeholder="example.eu.auth0.com">
<label for="c_client_id">Client ID</label><input type="text" id="c_client_id">
<label for="c_secret">Client secret</label><span class="row"><input type="password" id="c_secret" autocomplete="off"><button type="button" id="c_show">Show</button></span>
<label class="p_oidc" for="c_scopes">Scopes</label><input class="p_oidc" type="text" id="c_scopes" placeholder="openid profile email">
<label for="c_emails">Allowed emails</label><textarea id="c_emails" class="small" placeholder="one per line"></textarea>
<label class="p_groups" for="c_groups">Allowed groups</label><textarea id="c_groups" class="small p_groups" placeholder="one group ID per line (optional)"></textarea>
<label class="p_groups" for="c_claim">Groups claim</label><input class="p_groups" type="text" id="c_claim" placeholder="groups">
</div>
<details id="idpHelp" open><summary><b>How to set this up with your identity provider</b></summary><div id="helpBody" class="sub"></div>
<div id="actionBox" class="hide"><div class="sub">Auth0 login Action for groups (Actions &rarr; Library &rarr; Create Action &rarr; Login / Post Login; deploy it, then add it to the Login flow):</div>
<textarea id="actionCode" class="small" readonly spellcheck="false"></textarea><div class="row"><button type="button" id="actionCopy">Copy</button></div></div></details></div>
<div id="devNote" class="sub" style="display:none">Dev mode signs you in as <code>kilgore@kilgore.trout</code> with a throwaway login. Domain must end in <code>.localhost</code>.</div>
<div class="grid">
<label for="c_life">Session lifetime</label><input type="text" id="c_life" placeholder="8h">
<label for="c_idle">Idle timeout</label><input type="text" id="c_idle" placeholder="30m">
</div>
<div class="row"><button id="c_validate">Validate</button><button id="c_save" class="p">Save settings</button><span id="cmsg" class="msg"></span><button id="c_apply" class="p hide" data-a="apply_settings">Apply settings and start now</button></div>
<div class="warn">The client secret is stored in plain text in sallyport.yaml. Saving changes nothing in the running system until you apply the settings (see Operate below).</div></section>

<section><h2>Operate</h2>
<div class="sub">New install: save your settings, press <b>Apply settings and start</b>, then switch to the Targets tab.</div>
<div class="card"><h3>Apply settings</h3>
<div class="sub">Use this the first time, and every time you change <b>Settings</b> above (domain, identity provider, who may log in, session lengths). It regenerates the generated configuration from <code>sallyport.yaml</code> and secrets, then (re)starts the stack, which ends any sessions in progress. Changing targets does not need this.</div>
<div class="row"><button data-a="apply_settings" class="p">Apply settings and start</button></div></div>
<div class="card"><h3>Stack</h3>
<div class="sub">Day-to-day controls. Start and Stop leave your data alone. Restart recreates every container and ends sessions in progress.</div>
<div class="row"><button data-a="up">Start</button><button data-a="down">Stop</button><button data-a="restart">Restart</button><button data-a="ps">Show status</button><button data-a="logs">Show recent logs</button></div></div>
</section>
</div>

<div id="tab_targets" class="tabpanel hide">
<section><h2>Targets</h2>
<div class="sub" id="tstatus"></div>
<div class="targets">
<div><div id="tlist" class="tlist"></div>
<div class="row"><button id="t_add">Add</button><button id="t_dup">Duplicate</button><button id="t_del">Delete</button></div></div>
<div id="tform" class="grid">
<label for="t_name">Name</label><input type="text" id="t_name">
<label for="t_protocol">Protocol</label><select id="t_protocol"><option>rdp</option><option>ssh</option></select>
<label for="t_host">Host</label><input type="text" id="t_host" placeholder="10.0.0.10 or server.corp">
<label for="t_port">Port</label><input type="text" id="t_port" placeholder="default for the protocol">
<label for="t_username">Username</label><input type="text" id="t_username" autocomplete="off">
<label for="t_password">Password</label><span class="row"><input type="password" id="t_password" autocomplete="off"><button type="button" id="t_show">Show</button></span>
<label class="rdp" for="t_domain">Windows domain</label><input class="rdp" type="text" id="t_domain" placeholder="optional">
<label class="rdp" for="t_security">RDP security</label><select class="rdp" id="t_security"><option>nla</option><option>tls</option><option>rdp</option><option>any</option></select>
<label class="rdp" for="t_ignore_cert">Skip certificate check</label><span class="rdp"><input type="checkbox" id="t_ignore_cert"> <span class="sub">allows interception between guacd and the target</span></span>
<label class="ssh" for="t_private_key">Private key</label><textarea class="ssh small" id="t_private_key" spellcheck="false" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
<label class="ssh" for="t_passphrase">Key passphrase</label><input class="ssh" type="password" id="t_passphrase" autocomplete="off">
<label class="ssh" for="t_host_key">Host key</label><input class="ssh" type="text" id="t_host_key" placeholder="ssh-ed25519 AAAA... (strongly recommended)">
<label for="t_clipboard">Clipboard</label><select id="t_clipboard"><option value="both">both ways</option><option value="none">none</option><option value="paste-only">paste only (you to target)</option><option value="copy-only">copy only (target to you)</option></select>
<label for="t_max_sessions">Max sessions</label><input type="text" id="t_max_sessions" placeholder="1">
</div></div>
<div class="row"><button id="t_validate">Validate</button><button id="t_save" class="p">Save targets</button><span id="tmsg" class="msg"></span><button id="t_apply" class="p hide" data-a="load_targets">Apply targets now</button></div>
<div class="warn">Credentials are stored in plain text in targets.yaml and in the database. Use dedicated, least-privilege service accounts. File transfer and printing are always off. Saving changes nothing in the running system until you apply the targets (below).</div></section>

<section><h2>Apply targets</h2>
<div class="sub">Use this after you change targets above, and once after the first start. It copies <code>targets.yaml</code> into Guacamole, adding, changing and removing connections to match. No restart; sessions already open are not affected. The stack must be running.</div>
<div class="row"><button data-a="load_targets" class="p">Apply targets</button></div></section>
</div>

<div id="tab_raw" class="tabpanel hide">
<section><h2>Raw YAML files</h2><div class="sub">For anything the forms do not cover. Saving here replaces the whole file as written.</div>
<div class="tabs row"><button data-f="sallyport.yaml" class="on">sallyport.yaml</button><button data-f="targets.yaml">targets.yaml</button><span id="fstate" class="sub"></span></div>
<textarea id="editor" spellcheck="false"></textarea>
<div class="row"><button id="validate">Validate</button><button id="save">Save</button><span id="fmsg" class="msg"></span></div></section>
</div>

<div id="outpanel"><div id="outbar" class="row"><span id="oarrow">&#9650;</span> <b>Output</b> <span id="jtitle" class="sub"></span> <span id="jspin" class="spin hide"></span> <span id="jstate" class="msg"></span><span id="jlast" class="sub"></span>
<button id="outclear" style="margin-left:auto">Clear</button></div><pre id="out" class="hide">Nothing run yet. Output from Update and the Operate buttons appears here.</pre></div>
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
function setState(t,cls,spin){const e=$("#jstate");e.textContent=t;e.className="msg "+cls;$("#jspin").classList.toggle("hide",!spin)}
function setOpen(open){$("#out").classList.toggle("hide",!open);$("#oarrow").innerHTML=open?"&#9660;":"&#9650;"}
function say(t,cls){const o=$("#out");const d=document.createElement("div");d.textContent=t;if(cls)d.className=cls;o.appendChild(d);o.scrollTop=o.scrollHeight;
  if(t.trim())$("#jlast").textContent=" — "+t.trim()}
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
  const allOk=s.checks.every(k=>k.ok);
  $("#envsum").textContent=allOk?"— all passed ✔":"— problems found ✘";
  if(!allOk)$("#envd").open=true; else if(!window._envShown)$("#envd").open=false;
  window._envShown=true;
  const rd=$("#repod");
  $("#repsum").textContent=s.checkout?"\u2014 "+s.folder+" \u2714":"\u2014 set up the folder and clone the repository \u2718";
  if(!s.checkout)rd.open=true; else if(!window._repShown)rd.open=false;
  window._repShown=true;
}
function bannerBox(cls){const b=$("#banner");b.textContent="";const d=document.createElement("div");d.className="banner "+(cls||"");b.appendChild(d);return d}
function li(ul,t){const l=document.createElement("li");l.textContent=t;ul.appendChild(l)}
let updTimer=null;
function tabBadge(on){$("#tb_settings").textContent="Settings & system"+(on?" \u25CF":"")}
async function checkUpdate(force){
  clearTimeout(updTimer);
  let u; try{u=await api("/api/update"+(force?"?force=1":""))}catch(e){return}
  if(u.state==="checking"){tabBadge(false);const d=bannerBox();const sp=document.createElement("span");sp.className="spin";d.append(sp," "+u.message);updTimer=setTimeout(()=>checkUpdate(false),1500);return}
  if(u.state==="idle"){return}
  tabBadge(u.state==="available");
  const again=(d,label)=>{const b=document.createElement("button");b.textContent=label||"Check again";b.onclick=()=>checkUpdate(true);d.append(" ",b)};
  if(u.state==="current"){const d=bannerBox();d.textContent="✔ Up to date (commit "+u.head+"). "+(u.message.replace("Up to date.","").trim()?u.message.replace("Up to date.","").trim()+" ":"");again(d);return}
  if(u.state==="skipped"){const d=bannerBox();d.textContent=u.message;return}
  if(u.state==="error"||u.state==="diverged"){const d=bannerBox("bad");d.textContent=u.message;again(d,"Retry");return}
  if(u.state==="available"){
    const d=bannerBox("upd");const h=document.createElement("b");h.textContent="Update available";d.appendChild(h);
    if(u.behind){const p=document.createElement("div");p.textContent=u.behind+" new commit(s):";d.appendChild(p);const ul=document.createElement("ul");u.commits.forEach(c=>li(ul,c));d.appendChild(ul)}
    if(u.images.length){const p=document.createElement("div");p.textContent="Newer container images:";d.appendChild(p);const ul=document.createElement("ul");u.images.forEach(c=>li(ul,c));d.appendChild(ul)}
    const steps=[];if(u.behind)steps.push("Pull the new version");u.plan.steps.forEach(x=>steps.push(x.text));
    if(u.images.length){steps.push("Download the newer images");if(!u.plan.steps.some(x=>x.id==="restart"))steps.push("Recreate the containers (interrupts any active sessions)")}
    const p=document.createElement("div");p.textContent="Updating will:";d.appendChild(p);const ol=document.createElement("ul");steps.forEach(x=>li(ol,x));d.appendChild(ol);
    u.plan.notes.forEach(n=>{const q=document.createElement("div");q.className="sub";q.textContent="⚠ "+n;d.appendChild(q)});
    if(u.image_note){const q=document.createElement("div");q.className="sub";q.textContent=u.image_note;d.appendChild(q)}
    if(u.dirty){const q=document.createElement("div");q.className="bad";q.textContent="This checkout has local changes to tracked files; the pull may refuse to run.";d.appendChild(q)}
    const row=document.createElement("div");row.className="row";
    const go=document.createElement("button");go.className="p";go.textContent="Update";go.onclick=()=>run("update",{});
    row.appendChild(go);d.appendChild(row);
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
  try{await folderSet(); $("#out").textContent=""; $("#jlast").textContent=""; since=0; setState("running\u2026","",true);setOpen(true);
    await api("/api/run",Object.assign({action},extra||{})); poll();
  }catch(e){say("error: "+e.message,"bad")}
}
async function poll(){
  if(polling)return; polling=true;
  try{for(;;){
    const j=await api("/api/job?since="+since);
    $("#jtitle").textContent=j.title?"— "+j.title:"";
    j.lines.forEach(l=>say(l)); since=j.next;
    if(j.done){ if(j.ok===true){say("✔ done","ok");setState("✔ done","ok")} else if(j.ok===false){say("✘ failed","bad");setState("✘ failed","bad")} break;}
    await new Promise(r=>setTimeout(r,700));
  }}catch(e){say("error: "+e.message,"bad")}
  polling=false; checkUpdate(false); refresh().catch(()=>{}); loadFile().catch(()=>{}); loadForms().catch(()=>{});
}
$("#outbar").onclick=()=>setOpen($("#out").classList.contains("hide"));
$("#outclear").onclick=e=>{e.stopPropagation();$("#out").textContent="";$("#jlast").textContent="";setState("","")};
$("#clone").onclick=()=>run("clone",{repo:$("#repo").value});
function showTab(t){
  $$(".tabpanel").forEach(x=>x.classList.toggle("hide",x.id!=="tab_"+t));
  $$(".maintabs button").forEach(x=>x.classList.toggle("on",x.dataset.t===t));
}
$$(".maintabs button").forEach(b=>b.onclick=()=>showTab(b.dataset.t));
$$("button[data-a]").forEach(b=>b.onclick=()=>run(b.dataset.a));
$("#recheck").onclick=async()=>{try{await folderSet();await refresh();await loadFile();await loadForms();checkUpdate(true)}catch(e){say("error: "+e.message,"bad")}};
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
    if(kind==="save"){refresh().catch(()=>{});$("#fstate").textContent="";loadForms().catch(()=>{})}
  }catch(e){m.className="msg bad";m.textContent=e.message}
}
$("#validate").onclick=()=>fileAction("validate"); $("#save").onclick=()=>fileAction("save");
$("#quit").onclick=async()=>{try{await api("/api/quit",{})}catch(e){} document.body.textContent="Stopped. You can close this tab."};

/* ---- settings form ---- */
const CF={mode:"c_mode",domain:"c_domain",acme_email:"c_acme_email",provider:"c_provider",issuer:"c_issuer",idp_domain:"c_idp_domain",client_id:"c_client_id",client_secret:"c_secret",groups_claim:"c_claim",lifetime:"c_life",idle_timeout:"c_idle"};
const lines=v=>(v||"").split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
const ACTION_CODE="exports.onExecutePostLogin = async (event, api) => {\n  if (event.authorization) {\n    api.idToken.setCustomClaim('pomerium.io/groups', event.authorization.roles);\n  }\n};\n";
function helpList(items){const ol=document.createElement("ol");items.forEach(t=>{const l=document.createElement("li");l.textContent=t;ol.appendChild(l)});return ol}
function cfgShow(){
  const dev=$("#c_mode").value==="dev", prov=$("#c_provider").value;
  $("#prodFields").classList.toggle("hide",dev); $("#devNote").style.display=dev?"":"none";
  $$(".p_oidc").forEach(e=>e.classList.toggle("hide",prov!=="oidc"));
  $$(".p_auth0").forEach(e=>e.classList.toggle("hide",prov!=="auth0"));
  $$(".p_groups").forEach(e=>e.classList.toggle("hide",prov==="google"));
  $("#c_claim").placeholder=prov==="auth0"?"pomerium.io/groups":"groups";
  const d=$("#c_domain").value.trim()||"<domain>", auth="https://authenticate."+d;
  const hb=$("#helpBody"); hb.textContent=""; $("#actionBox").classList.toggle("hide",prov!=="auth0");
  if(prov==="auth0"){
    hb.appendChild(helpList([
      "In the Auth0 dashboard: Applications → Applications → Create Application. Pomerium's guide uses the Native type. Copy the Domain, Client ID and Client Secret into the fields above.",
      "On the application's Settings tab set Application Login URI = "+auth+" ; Allowed Callback URLs = "+auth+"/oauth2/callback ; Allowed Logout URLs = "+auth+"/.pomerium/signed_out . Save.",
      "Add each person under User Management → Users (or federate the MSP's own identity provider as an enterprise connection), then list their email addresses under Allowed emails.",
      "Passkeys: enable them in your Auth0 tenant (see Auth0's documentation for the current steps; they are listed as included on the free plan).",
      "Optional groups: create Roles in Auth0 and assign them to users, add the Action below, and list the role names under Allowed groups. The groups claim defaults to pomerium.io/groups.",
      "If login fails with a client authentication error, try the Regular Web Application type instead."]));
    $("#actionCode").value=ACTION_CODE;
  }else if(prov==="google"){
    hb.appendChild(helpList([
      "Google Cloud Console → APIs & Services → OAuth consent screen: choose External and leave it in Testing, then add your people under Test users.",
      "Credentials → Create credentials → OAuth client ID → Web application. Add "+auth+"/oauth2/callback as an authorised redirect URI.",
      "Copy the Client ID and Client Secret into the fields above, and list the Google email addresses under Allowed emails. Google does not provide group claims."]));
  }else{
    hb.appendChild(helpList([
      "Register this redirect URI with your identity provider: "+auth+"/oauth2/callback",
      "Enter the provider's issuer URL, client ID and client secret above. The provider must publish OpenID Connect discovery.",
      "For groups, the provider must put them in the ID token under the claim name given above."]));
  }
}
function getCfg(){
  const d={}; for(const k in CF)d[k]=$("#"+CF[k]).value;
  d.acme_staging=$("#c_staging").checked;
  d.scopes=($("#c_scopes").value.split(/[\s,]+/)).filter(Boolean);
  d.emails=lines($("#c_emails").value); d.groups=lines($("#c_groups").value);
  return d;
}
function setCfg(d){
  d=d||{mode:"production",provider:"oidc",acme_staging:true,scopes:["openid","profile","email"],groups_claim:"",lifetime:"8h",idle_timeout:"30m"};
  for(const k in CF)$("#"+CF[k]).value=d[k]??"";
  $("#c_staging").checked=d.acme_staging!==false;
  $("#c_scopes").value=(d.scopes||[]).join(" ");
  $("#c_emails").value=(d.emails||[]).join("\n"); $("#c_groups").value=(d.groups||[]).join("\n");
  cfgShow();
}
async function loadCfg(){
  const r=await api("/api/config");
  setCfg(r.data);
  $("#cstatus").textContent=!r.exists?"No sallyport.yaml yet: showing defaults. Save creates it.":(r.data?"Current file: "+r.status:"The current file cannot be shown as a form ("+r.status+"). Fix it under Advanced.");
}
async function cfgAction(kind){
  const m=$("#cmsg");
  try{await folderSet(); const r=await api("/api/config/"+kind,{data:getCfg()});
    m.className="msg "+(r.ok?"ok":"bad"); m.textContent=(r.ok?"✔ ":"✘ ")+r.message;
    if(kind==="save"&&r.saved){await loadFile();refresh().catch(()=>{});$("#c_apply").classList.remove("hide")}
  }catch(e){m.className="msg bad";m.textContent=e.message}
}
$$("#prodFields input,#prodFields textarea,#prodFields select,#c_domain,#c_life,#c_idle,#c_mode").forEach(e=>e.addEventListener("input",()=>$("#c_apply").classList.add("hide")));
$("#c_mode").onchange=cfgShow; $("#c_domain").oninput=cfgShow; $("#c_provider").onchange=cfgShow;
$("#actionCopy").onclick=async()=>{const t=$("#actionCode");try{await navigator.clipboard.writeText(t.value)}catch(e){t.select();document.execCommand("copy")}$("#actionCopy").textContent="Copied";setTimeout(()=>$("#actionCopy").textContent="Copy",1500)};
$("#c_validate").onclick=()=>cfgAction("validate"); $("#c_save").onclick=()=>cfgAction("save");
$("#c_show").onclick=()=>{const i=$("#c_secret");i.type=i.type==="password"?"text":"password";$("#c_show").textContent=i.type==="password"?"Show":"Hide"};

/* ---- targets editor ---- */
const TF=["name","protocol","host","port","username","password","domain","security","private_key","passphrase","host_key","clipboard","max_sessions"];
const KEYS={common:["name","protocol","host","port","username","password","clipboard","max_sessions"],rdp:["domain","security","ignore_cert"],ssh:["private_key","passphrase","host_key"]};
let targets=[], sel=-1;
const blank=()=>({name:"",protocol:"rdp",host:"",security:"nla",ignore_cert:false,clipboard:"both",max_sessions:1});
function tShowFields(){const p=$("#t_protocol").value;
  $$(".rdp").forEach(e=>e.classList.toggle("hide",p!=="rdp")); $$(".ssh").forEach(e=>e.classList.toggle("hide",p!=="ssh"));}
function tFill(){
  const t=targets[sel]; $("#tform").classList.toggle("hide",!t); if(!t)return;
  for(const k of TF)$("#t_"+k).value=t[k]??(k==="clipboard"?"both":(k==="security"?"nla":""));
  $("#t_ignore_cert").checked=!!t.ignore_cert; tShowFields();
}
function tWrite(){
  const t=targets[sel]; if(!t)return;
  for(const k of TF)t[k]=$("#t_"+k).value; t.ignore_cert=$("#t_ignore_cert").checked; tShowFields(); tList();
}
function tList(){
  const box=$("#tlist"); box.textContent="";
  targets.forEach((t,i)=>{const d=document.createElement("div"); d.className=i===sel?"on":"";
    d.textContent=t.name||"(unnamed)"; const s=document.createElement("small"); s.textContent=(t.protocol||"")+" "+(t.host||""); d.appendChild(s);
    d.onclick=()=>{sel=i;tList();tFill()}; box.appendChild(d);});
}
function tSerialise(){
  return targets.map(t=>{const o={},p=t.protocol||"rdp";
    for(const k of KEYS.common.concat(KEYS[p]||[])){const v=t[k]; if(v===undefined||v===null||v==="")continue; o[k]=v;}
    if(p==="rdp")o.ignore_cert=!!t.ignore_cert; return o;});
}
async function loadTargets(){
  const r=await api("/api/targets"); targets=(r.data||[]).map(t=>Object.assign(blank(),t)); sel=targets.length?0:-1; tList(); tFill();
  $("#tstatus").textContent=!r.exists?"No targets.yaml yet. Add a target and save.":"Current file: "+r.status;
}
async function tAction(kind){
  const m=$("#tmsg");
  try{await folderSet(); const r=await api("/api/targets/"+kind,{targets:tSerialise()});
    m.className="msg "+(r.ok?"ok":"bad"); m.textContent=(r.ok?"✔ ":"✘ ")+r.message;
    if(kind==="save"&&r.saved){await loadFile();$("#tstatus").textContent="Saved.";$("#t_apply").classList.remove("hide")}
  }catch(e){m.className="msg bad";m.textContent=e.message}
}
$$("#tform input,#tform select,#tform textarea").forEach(e=>{e.oninput=tWrite;e.onchange=tWrite});
$("#tform").addEventListener("input",()=>$("#t_apply").classList.add("hide"));
$("#t_add").onclick=()=>{targets.push(blank());sel=targets.length-1;tList();tFill();$("#t_name").focus()};
$("#t_dup").onclick=()=>{if(sel<0)return;const c=JSON.parse(JSON.stringify(targets[sel]));c.name=(c.name||"target")+"-copy";targets.push(c);sel=targets.length-1;tList();tFill()};
$("#t_del").onclick=()=>{if(sel<0)return;if(!confirm("Delete target \""+(targets[sel].name||"unnamed")+"\"? (Not final until you press Save targets.)"))return;targets.splice(sel,1);sel=Math.min(sel,targets.length-1);tList();tFill()};
$("#t_validate").onclick=()=>tAction("validate"); $("#t_save").onclick=()=>tAction("save");
$("#t_show").onclick=()=>{const i=$("#t_password");i.type=i.type==="password"?"text":"password";$("#t_show").textContent=i.type==="password"?"Show":"Hide"};
async function loadForms(){await loadCfg();await loadTargets()}

setInterval(()=>api("/api/ping").catch(()=>{}),20000);
refresh().then(()=>checkUpdate(false)).then(loadFile).then(loadForms).catch(e=>{document.body.textContent="Cannot reach the Sallyport GUI: "+e.message+" (was it closed? run it again)"});
</script></body></html>
"""

if __name__ == "__main__":
    main()

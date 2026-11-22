"""Sallyport core: generate configuration and load targets.

Used by the ./sallyport command line and by the GUI (sallyport_gui.py).

Commands:
  init           read sallyport.yaml, create secrets and generated config
  load-targets   write targets.yaml into the Guacamole database

Requires Python 3 and PyYAML; dev mode also needs the cryptography package.
"""
import argparse
import base64
import uuid
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: apt install python3-yaml (or pip install pyyaml)")

ROOT = Path(__file__).resolve().parent
# Set by the Windows/Docker wrapper (sallyport.cmd), which runs this script inside
# a container on the stack's internal network instead of on the host.
IN_CONTAINER = os.environ.get("SALLYPORT_IN_CONTAINER") == "1"
GEN = ROOT / "generated"
ENV_FILE = ROOT / ".env"
CONFIG = ROOT / "sallyport.yaml"
TARGETS = ROOT / "targets.yaml"


def set_root(path):
    """Point every path at a different checkout (the GUI calls this)."""
    global ROOT, GEN, ENV_FILE, CONFIG, TARGETS
    ROOT = Path(path).resolve()
    GEN, ENV_FILE = ROOT / "generated", ROOT / ".env"
    CONFIG, TARGETS = ROOT / "sallyport.yaml", ROOT / "targets.yaml"


def write_text(path, text):
    """Always write LF line endings, even on Windows (the files are read in Linux containers)."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


DB_NAME = "guacamole_db"
DB_OWNER = "guacamole_owner"
DEFAULT_GROUP = "sallyport-users"

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
DURATION_RE = re.compile(r"^[1-9][0-9]*[smh]$")
CLAIM_RE = re.compile(r"^[A-Za-z0-9_:./-]{1,64}$")
AUTH0_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,63}$")
PROVIDERS = ("oidc", "auth0", "google")
AUTH0_GROUPS_CLAIM = "pomerium.io/groups"  # the claim name Pomerium's Auth0 guide uses
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()@+,-]{0,199}$")
GROUP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
SYSTEM_KEYS = {"name", "protocol", "host", "port", "clipboard", "max_sessions", "security", "ignore_cert", "host_key"}
CRED_KEYS = ("username", "password", "domain", "private_key", "passphrase")
HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")


def die(msg):
    sys.exit(f"error: {msg}")


def load_yaml(path):
    if not path.exists():
        die(f"{path.name} not found; copy {path.stem}.example.yaml to {path.name} and edit it")
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        die(f"{path.name} is not valid YAML: {e}")
    if not isinstance(data, dict):
        die(f"{path.name} must contain a YAML mapping")
    return data


def check_keys(section, data, allowed, required=()):
    unknown = set(data) - set(allowed)
    if unknown:
        die(f"{section}: unknown key(s) {sorted(unknown)}; allowed: {sorted(allowed)}")
    for key in required:
        if data.get(key) in (None, "", []):
            die(f"{section}: '{key}' is required")


def nonempty_str(section, key, value, maxlen=4000):
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > maxlen:
        die(f"{section}: '{key}' must be a non-empty string of at most {maxlen} characters")
    return value


# ---------------------------------------------------------------- config / init

DEV_EMAIL = "kilgore@kilgore.trout"  # the dev administrator
DEV_USERS = [  # throwaway logins on Dex's password connector; all use the password "password"
    (DEV_EMAIL, "Kilgore Trout"),
    ("billy.pilgrim@kilgore.trout", "Billy Pilgrim"),
    ("eliot.rosewater@kilgore.trout", "Eliot Rosewater"),
    ("montana.wildhack@kilgore.trout", "Montana Wildhack"),
]
DEV_PASSWORD = "password"
DEV_PASSWORD_HASH = "$2a$10$zQ.dHIMQu4ZOzPGJD.774uctjfI68B5XJP.JUB61WW25FxQfnZeG."  # bcrypt of "password"
SCHEDULE_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
DEV_CLIENT_ID = "sallyport"


def parse_session(cfg):
    session = cfg.get("session") or {}
    check_keys("session", session, {"lifetime", "idle_timeout"})
    lifetime = str(session.get("lifetime", "8h"))
    idle = str(session.get("idle_timeout", "30m"))
    for key, value in (("lifetime", lifetime), ("idle_timeout", idle)):
        if not DURATION_RE.match(value):
            die(f"session.{key} must look like 30m or 8h")
    return lifetime, idle


def parse_schedule(cfg):
    updates = cfg.get("updates") or {}
    if not isinstance(updates, dict):
        die("updates must be a mapping")
    check_keys("updates", updates, {"schedule", "critical"})
    if not isinstance(updates.get("critical", True), bool):
        die("updates.critical must be true or false")
    value = updates.get("schedule")
    if value in (None, "", False):
        return ""
    if not isinstance(value, str) or not SCHEDULE_RE.match(value):
        die("updates.schedule must be a quoted 24-hour time such as \"03:00\" (unquoted, YAML reads 03:00 as a number)")
    return value


def parse_critical(cfg):
    """Whether the hourly check for a flagged critical update is on (default on, when a schedule is set)."""
    updates = cfg.get("updates") or {}
    return bool(updates.get("critical", True)) if isinstance(updates, dict) else True


def parse_admin(cfg):
    admin = cfg.get("admin") or {}
    if not isinstance(admin, dict):
        die("admin must be a mapping")
    check_keys("admin", admin, {"emails", "groups"})
    emails = email_list("admin.emails", admin.get("emails") or [])
    groups = admin.get("groups") or []
    if not isinstance(groups, list):
        die("admin.groups must be a list")
    for g in groups:
        nonempty_str("admin.groups", "entry", g, 256)
    return emails, groups


def shared_issuer(issuer):
    """True for issuers that authenticate the general public, not one organisation's users."""
    i = (issuer or "").lower().rstrip("/")
    if i.startswith("https://accounts.google.com"):
        return True
    m = re.match(r"^https://login\.microsoftonline\.com/([^/]+)", i)
    return bool(m and m.group(1) in ("common", "organizations", "consumers"))


def validate_dev(cfg):
    check_keys("sallyport.yaml (dev mode)", cfg, {"mode", "domain", "session", "updates"}, required=("domain",))
    domain = str(cfg["domain"]).lower()
    if not DOMAIN_RE.match(domain) or not domain.endswith(".localhost"):
        die("dev mode only runs on *.localhost names (for example access.localhost); "
            "it uses a throwaway login and an untrusted certificate and must never face a network")
    lifetime, idle = parse_session(cfg)
    return {"mode": "dev", "domain": domain, "emails": [e for e, _ in DEV_USERS], "groups": [], "groups_claim": "groups",
            "domains": [], "open_idp": False, "admin_emails": [DEV_EMAIL], "admin_groups": [],
            "update_time": parse_schedule(cfg), "critical": parse_critical(cfg),
            "lifetime": lifetime, "idle": idle, "client_secret": None}


DDNS_SUB_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
DDNS_TOKEN_RE = re.compile(r"^[A-Za-z0-9-]{8,128}$")


def parse_ddns(cfg):
    """dynamic_dns: {provider: duckdns, subdomain, token} -> (domain, settings) or (None, None)."""
    dd = cfg.get("dynamic_dns")
    if dd is None:
        return None, None
    if not isinstance(dd, dict):
        die("dynamic_dns must be a mapping")
    check_keys("dynamic_dns", dd, {"provider", "subdomain", "token"}, required=("subdomain", "token"))
    if dd.get("provider", "duckdns") != "duckdns":
        die("dynamic_dns.provider must be duckdns")
    sub = str(dd["subdomain"]).strip().lower()
    sub = re.sub(r"\.duckdns\.org$", "", sub)
    if not DDNS_SUB_RE.match(sub):
        die("dynamic_dns.subdomain must be just the name you registered at duckdns.org, such as myfirm (letters, digits, hyphens)")
    token = str(dd["token"]).strip()
    if not DDNS_TOKEN_RE.match(token):
        die("dynamic_dns.token must be the token shown on your duckdns.org page")
    domain = f"{sub}.duckdns.org"
    given = cfg.get("domain")
    if given not in (None, "") and str(given).lower() != domain:
        die(f"domain must be left out (or be {domain}) when dynamic_dns is used")
    return domain, {"subdomain": sub, "token": token}


def validate_config(cfg):
    mode = cfg.get("mode", "production")
    if mode not in ("production", "dev"):
        die("mode must be production or dev")
    if mode == "dev":
        return validate_dev(cfg)
    ddns_domain, ddns = parse_ddns(cfg)
    check_keys("sallyport.yaml", cfg, {"mode", "domain", "dynamic_dns", "acme_email", "acme_staging", "idp", "access", "admin", "updates", "session"},
               required=("acme_email", "idp", "access") + (() if ddns else ("domain",)))
    domain = ddns_domain or str(cfg["domain"]).lower()
    if not DOMAIN_RE.match(domain):
        die("domain must be a valid DNS name such as access.client.example")
    email = nonempty_str("sallyport.yaml", "acme_email", cfg["acme_email"], 254)
    if "@" not in email:
        die("acme_email must be an email address")
    staging = cfg.get("acme_staging", True)
    if not isinstance(staging, bool):
        die("acme_staging must be true or false")

    idp = cfg["idp"]
    if not isinstance(idp, dict):
        die("idp must be a mapping")
    check_keys("idp", idp, {"provider", "issuer", "domain", "client_id", "client_secret", "scopes"},
               required=("client_id", "client_secret"))
    provider = idp.get("provider", "oidc")
    if provider not in PROVIDERS:
        die(f"idp.provider must be one of {list(PROVIDERS)}")
    issuer = ""
    if provider == "oidc":
        check_keys("idp", {k: v for k, v in idp.items() if k != "domain"}, {"provider", "issuer", "client_id", "client_secret", "scopes"},
                   required=("issuer",))
        if "domain" in idp:
            die("idp.domain only applies to the auth0 provider")
        issuer = nonempty_str("idp", "issuer", idp["issuer"])
        if not issuer.startswith("https://"):
            die("idp.issuer must be an https:// URL")
    elif provider == "auth0":
        if "domain" not in idp:
            die("idp: 'domain' is required for auth0 (your tenant domain, for example example.eu.auth0.com)")
        domain_in = nonempty_str("idp", "domain", idp["domain"], 253).strip().lower()
        domain_in = re.sub(r"^https://", "", domain_in).rstrip("/")
        if not AUTH0_DOMAIN_RE.match(domain_in):
            die("idp.domain must be a hostname such as example.eu.auth0.com")
        if "issuer" in idp:
            die("idp.issuer does not apply to auth0; set idp.domain")
        issuer = "https://" + domain_in
    else:  # google
        for k in ("issuer", "domain"):
            if k in idp:
                die(f"idp.{k} does not apply to google")
    for key in ("client_id", "client_secret"):
        nonempty_str("idp", key, idp[key])
    if idp["client_secret"] == "change-me":
        die("idp.client_secret is still the example value")
    scopes = idp.get("scopes", ["openid", "profile", "email"])
    if not isinstance(scopes, list) or not all(isinstance(s, str) and s for s in scopes):
        die("idp.scopes must be a list of strings")
    for value in (idp["client_secret"],):
        if "'" in value or "\n" in value:
            die("idp.client_secret may not contain a single quote or newline")

    access = cfg["access"]
    if not isinstance(access, dict):
        die("access must be a mapping")
    check_keys("access", access, {"emails", "groups", "groups_claim", "domains"})
    emails = access.get("emails") or []
    groups = access.get("groups") or []
    if not isinstance(emails, list) or not isinstance(groups, list):
        die("access.emails and access.groups must be lists")
    for e in emails:
        if not isinstance(e, str) or "@" not in e or " " in e:
            die(f"access.emails: '{e}' is not an email address")
    for g in groups:
        nonempty_str("access.groups", "entry", g, 256)
    domains = access.get("domains") or []
    if not isinstance(domains, list):
        die("access.domains must be a list")
    domains = [str(d).strip().lower() for d in domains]
    for d in domains:
        if not DOMAIN_RE.match(d):
            die(f"access.domains: '{d}' is not a domain name such as example.com")
    open_idp = not emails and not groups and not domains
    if open_idp and (provider == "google" or shared_issuer(issuer)):
        die("access lists nobody, which would admit anyone this identity provider authenticates, and this one "
            "authenticates the general public (any Google or Microsoft account). List emails, groups or domains.")
    claim = access.get("groups_claim", AUTH0_GROUPS_CLAIM if provider == "auth0" else "groups")
    if not isinstance(claim, str) or not CLAIM_RE.match(claim):
        die("access.groups_claim is not a valid claim name")
    if provider == "google" and groups:
        die("Google does not provide group claims; list people under access.emails instead")

    lifetime, idle = parse_session(cfg)
    admin_emails, admin_groups = parse_admin(cfg)
    if admin_groups and provider == "google":
        die("Google does not provide group claims; list people under admin.emails instead")

    return {
        "admin_emails": admin_emails, "admin_groups": admin_groups, "update_time": parse_schedule(cfg), "critical": parse_critical(cfg),
        "ddns": ddns, "mode": "production", "domain": domain, "acme_email": email, "staging": staging,
        "provider": provider, "issuer": issuer, "client_id": idp["client_id"], "client_secret": idp["client_secret"],
        "scopes": scopes, "emails": [e.strip() for e in emails], "groups": groups,
        "groups_claim": claim, "domains": domains, "open_idp": open_idp, "lifetime": lifetime, "idle": idle,
    }


def read_env():
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip("'")
    return env


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.chmod(path, 0o600)


def render_pomerium(c):
    dev = c["mode"] == "dev"
    policy = [{"email": {"is": e}} for e in c["emails"]]
    policy += [{f"claim/{c['groups_claim']}": g} for g in c["groups"]]
    policy += [{"domain": {"is": d}} for d in c["domains"]]
    if not policy:  # nothing listed: the identity provider alone decides (validate_config rejects public providers)
        policy = [{"authenticated_user": True}]
    if dev:
        tls = {
            "certificates": [{"cert": "/pomerium/certs/tls.crt", "key": "/pomerium/certs/tls.key"}],
            "certificate_authority_file": "/pomerium/certs/ca.crt",
        }
        idp = {"idp_provider_url": f"https://dex.{c['domain']}:5556/dex", "idp_client_id": DEV_CLIENT_ID,
               "idp_scopes": ["openid", "profile", "email"]}
    else:
        tls = {"autocert": True, "autocert_email": c["acme_email"], "autocert_use_staging": c["staging"]}
        idp = {"idp_provider_url": c["issuer"], "idp_client_id": c["client_id"], "idp_scopes": c["scopes"]}
        if c["provider"] == "google":
            idp = {"idp_client_id": c["client_id"]}          # Pomerium's Google provider has its own defaults
        elif c["provider"] == "auth0":
            idp = {"idp_provider_url": c["issuer"], "idp_client_id": c["client_id"]}
    admin_policy = [{"email": {"is": e}} for e in c["admin_emails"]]
    admin_policy += [{f"claim/{c['groups_claim']}": g} for g in c["admin_groups"]]
    config = {
        **tls,
        "authenticate_service_url": f"https://authenticate.{c['domain']}",
        "idp_provider": "oidc" if dev else c["provider"],
        **idp,
        "cookie_expire": c["lifetime"],
        "jwt_claims_headers": {"X-Pomerium-Claim-Email": "email"},
        "routes": [{
            "from": f"https://{c['domain']}",
            "to": "http://guacamole:8080",
            "pass_identity_headers": True,
            "allow_websockets": True,
            "idle_timeout": c["idle"],
            "policy": [{"allow": {"or": policy}}],
        }],
    }
    if admin_policy:
        # The admin site: its own host name, its own (much shorter) allow-list. pass_identity_headers makes
        # Pomerium sign the user's identity (X-Pomerium-Jwt-Assertion) with SIGNING_KEY, which the admin
        # service verifies itself rather than trusting a plain header.
        config["routes"].append({
            "from": f"https://admin.{c['domain']}",
            "to": "http://admin:8080",
            "pass_identity_headers": True,
            "idle_timeout": c["idle"],
            "policy": [{"allow": {"or": admin_policy}}],
        })
    header = ("# Generated by ./sallyport init from sallyport.yaml. Do not edit.\n"
              "# Secrets (shared_secret, cookie_secret, signing_key, idp_client_secret) come from the\n"
              "# environment, set in compose.yaml from .env.\n")
    return header + yaml.safe_dump(config, sort_keys=False)


CERT_REV = "|admin"  # bump when the certificate names change, so existing dev certificates are regenerated


def make_dev_certs(certs, domain):
    """Throwaway CA + server certificate for dev mode. The CA key is discarded."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError:
        die("dev mode needs the cryptography package: pip install cryptography")
    import datetime

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    now = datetime.datetime.now(datetime.timezone.utc)
    start, end = now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=30)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = (x509.CertificateBuilder().subject_name(name("Sallyport dev CA (do not trust)"))
               .issuer_name(name("Sallyport dev CA (do not trust)")).public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                            content_commitment=False, key_encipherment=False, data_encipherment=False,
                                            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
               .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sans = [domain, f"authenticate.{domain}", f"dex.{domain}", f"admin.{domain}"]
    cert = (x509.CertificateBuilder().subject_name(name(domain)).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (certs / "ca.crt").write_bytes(ca_cert.public_bytes(pem))
    (certs / "tls.crt").write_bytes(cert.public_bytes(pem))
    (certs / "tls.key").write_bytes(key.private_bytes(
        pem, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    write_text(certs / "domain", domain + CERT_REV)


def dev_certs_current(certs, domain):
    marker, crt = certs / "domain", certs / "tls.crt"
    if not (crt.exists() and marker.exists() and (certs / "tls.key").exists() and (certs / "ca.crt").exists()):
        return False
    if marker.read_text(encoding="utf-8") != domain + CERT_REV:
        return False
    try:
        import datetime
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(crt.read_bytes())
        left = cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)
        return left > datetime.timedelta(days=7)
    except Exception:
        return False


def init_dev(c, env):
    """Dev mode: private CA + server certificate, Dex config, and a throwaway SSH target."""
    domain = c["domain"]
    certs = GEN / "certs"
    certs.mkdir(exist_ok=True)
    if not dev_certs_current(certs, domain):
        make_dev_certs(certs, domain)
        print("generated a throwaway CA and certificate (valid 30 days)")
    # Dev only: the containers run as unprivileged users and must be able to read the key.
    for f in ("tls.key", "tls.crt", "ca.crt"):
        os.chmod(certs / f, 0o644)

    dex = {
        "issuer": f"https://dex.{domain}:5556/dex",
        "storage": {"type": "memory"},
        "web": {"https": "0.0.0.0:5556", "tlsCert": "/certs/tls.crt", "tlsKey": "/certs/tls.key"},
        "oauth2": {"skipApprovalScreen": True},
        "enablePasswordDB": True,
        "staticPasswords": [
            {"email": email, "hash": DEV_PASSWORD_HASH, "username": email.split("@")[0], "name": name,
             "userID": str(uuid.uuid5(uuid.NAMESPACE_DNS, email))} for email, name in DEV_USERS],
        "staticClients": [{
            "id": DEV_CLIENT_ID, "name": "Sallyport", "secret": env["IDP_CLIENT_SECRET"],
            "redirectURIs": [f"https://authenticate.{domain}/oauth2/callback"],
        }],
    }
    write_text(GEN / "dex.yaml", "# Generated by ./sallyport init (dev mode). Do not edit.\n" + yaml.safe_dump(dex, sort_keys=False))

    if not TARGETS.exists():
        write_text(
            TARGETS,
            "# Dev mode test targets: throwaway SSH and RDP containers from compose.dev.yaml.\n"
            "systems:\n  - name: sshtest\n    protocol: ssh\n    host: sshtest\n    port: 2222\n"
            "  - name: rdptest\n    protocol: rdp\n    host: rdptest\n    port: 3389\n"
            "    security: tls        # xrdp does not support NLA\n"
            "    ignore_cert: true    # xrdp uses a self-signed certificate\n"
            "logins:\n  - system: sshtest\n    everyone: true\n    username: test\n    password: test\n"
            "  - system: rdptest\n    everyone: true\n    username: abc\n    password: abc\n")
        print("wrote targets.yaml with test SSH and RDP targets")


def new_signing_key():
    """ECDSA P-256 key Pomerium signs identity assertions with; stored base64-encoded in .env."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        die("this needs the cryptography package: pip install cryptography")
    key = ec.generate_private_key(ec.SECP256R1())
    # SEC1 "EC PRIVATE KEY" PEM, the format `openssl ecparam -genkey -name prime256v1` produces and Pomerium's docs use.
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    return base64.b64encode(pem).decode()


def signing_public_pem(b64):
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_private_key(base64.b64decode(b64), password=None)
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


BRANDING_CSS = """\
/* Sallyport branding for Guacamole (generated by ./sallyport init). */
#sallyport-bar,#sallyport-admin{position:fixed;z-index:2147483000;font:600 13px/1.2 sans-serif;color:#fff;
  background:#17324d;box-shadow:0 1px 4px rgba(0,0,0,.35)}
#sallyport-bar{top:0;left:50%;transform:translateX(-50%);display:flex;align-items:center;gap:8px;
  padding:5px 16px;border-bottom-left-radius:8px;border-bottom-right-radius:8px}
#sallyport-bar svg{width:16px;height:16px;flex:none}
#sallyport-signout{color:#fff;text-decoration:none;border-left:1px solid #ffffff66;padding-left:8px}
#sallyport-signout:hover,#sallyport-signout:focus{text-decoration:underline}
#sallyport-admin{bottom:0;left:0;padding:6px 14px;border-top-right-radius:8px;text-decoration:none}
#sallyport-admin:hover,#sallyport-admin:focus{text-decoration:underline}
.sallyport-hidden{display:none !important}
"""

# Guacamole's own page is an Angular app whose markup is not a stable interface, so the bar is a fixed overlay
# added to <body> rather than an edit of its menus. It is hidden while a remote session is open.
BRANDING_JS = r"""
(function () {
  "use strict";
  var ADMIN = %(admin)s;
  // Guacamole's own Logout only ends Guacamole's session. Pomerium's login is still valid, so Guacamole signs the
  // person straight back in from the identity header. Signing out has to happen at Pomerium.
  var SIGNOUT = "/.pomerium/sign_out";
  document.addEventListener("click", function (ev) {
    var n = ev.target, label = "";
    for (var i = 0; n && n.nodeType === 1 && i < 4; i++, n = n.parentNode) {
      label = (n.textContent || "").trim();
      if (/^(log ?out|sign ?out)$/i.test(label) && n.id !== "sallyport-signout") {
        setTimeout(function () { location.href = SIGNOUT; }, 300);  // let Guacamole's own logout run first
        return;
      }
    }
  }, true);
  function build() {
    if (document.getElementById("sallyport-bar") || !document.body) { return; }
    var bar = document.createElement("div");
    bar.id = "sallyport-bar";
    bar.innerHTML = '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="none" stroke="#fff" stroke-width="1.6" ' +
      'd="M2 15V7a6 6 0 0 1 12 0v8M5.5 15V8M8 15V3M10.5 15V8M2 11.5h12"/></svg><span>Sallyport</span>';
    var out = document.createElement("a");
    out.id = "sallyport-signout";
    out.href = SIGNOUT;
    out.textContent = "Sign out";
    out.title = "End your Sallyport login completely";
    bar.appendChild(out);
    document.body.appendChild(bar);
    if (ADMIN) {
      var a = document.createElement("a");
      a.id = "sallyport-admin";
      a.href = "https://admin." + location.hostname + (location.port ? ":" + location.port : "");
      a.textContent = "Admin";
      a.title = "Manage systems, people and logins (administrators only)";
      document.body.appendChild(a);
    }
  }
  function sync() {
    build();
    var inSession = /#\/client\//.test(location.hash);
    ["sallyport-bar", "sallyport-admin"].forEach(function (id) {
      var e = document.getElementById(id);
      if (e) { e.classList.toggle("sallyport-hidden", inSession); }
    });
  }
  window.addEventListener("hashchange", sync);
  document.addEventListener("DOMContentLoaded", sync);
  new MutationObserver(sync).observe(document.documentElement, {childList: true});
  sync();
})();
"""


def make_branding(c):
    """generated/sallyport-branding.jar: a Guacamole extension (a zip with guac-manifest.json) adding the Sallyport bar."""
    manifest = {"guacamoleVersion": "*", "name": "Sallyport branding", "namespace": "sallyport",
                "css": ["sallyport.css"], "js": ["sallyport.js"]}
    admin = bool(c["mode"] == "dev" or c["admin_emails"] or c["admin_groups"])
    files = {"guac-manifest.json": json.dumps(manifest, indent=2), "sallyport.css": BRANDING_CSS,
             "sallyport.js": BRANDING_JS.lstrip() % {"admin": "true" if admin else "false"}}
    import io
    import zipfile
    GEN.mkdir(exist_ok=True)
    path = GEN / "sallyport-branding.jar"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in files.items():  # fixed timestamps, so an unchanged extension is byte-identical
            z.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), text.encode("utf-8"))
    data = buf.getvalue()
    try:
        if path.exists() and path.read_bytes() == data:
            return  # unchanged: leave the file alone (Docker may have it mounted)
    except OSError:
        pass
    try:
        # Write in place: the running Guacamole container has this file bind-mounted, and Windows refuses to
        # replace or delete a file that is in use, but allows it to be overwritten.
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o644)
    except OSError as e:
        die(f"could not write {path}: {e}. If the stack is running, stop it (docker compose down) and run init again.")


def cmd_init(args):
    c = validate_config(load_yaml(CONFIG))
    env = read_env()
    new = []
    for key, gen in (
        ("SHARED_SECRET", lambda: base64.b64encode(secrets.token_bytes(32)).decode()),
        ("COOKIE_SECRET", lambda: base64.b64encode(secrets.token_bytes(32)).decode()),
        ("POSTGRES_PASSWORD", lambda: secrets.token_hex(24)),
        ("GUAC_APP_PASSWORD", lambda: secrets.token_hex(24)),
        ("ADMIN_DB_PASSWORD", lambda: secrets.token_hex(24)),
        ("SIGNING_KEY", lambda: new_signing_key()),
    ):
        if key not in env:
            env[key] = gen()
            new.append(key)
    if c["mode"] == "dev":
        if "IDP_CLIENT_SECRET" not in env or env.get("SALLYPORT_MODE") != "dev":
            env["IDP_CLIENT_SECRET"] = secrets.token_hex(24)
        env["SALLYPORT_DOMAIN"] = c["domain"]
        env["SALLYPORT_MODE"] = "dev"
    else:
        env["IDP_CLIENT_SECRET"] = c["client_secret"]
        env["SALLYPORT_MODE"] = "production"
        env.pop("SALLYPORT_DOMAIN", None)
    # The dynamic-DNS updater is a compose profile, switched on by COMPOSE_PROFILES in .env.
    if c.get("ddns"):
        env["DUCKDNS_SUBDOMAIN"], env["DUCKDNS_TOKEN"] = c["ddns"]["subdomain"], c["ddns"]["token"]
        env["COMPOSE_PROFILES"] = "duckdns"
    else:
        for k in ("DUCKDNS_SUBDOMAIN", "DUCKDNS_TOKEN", "COMPOSE_PROFILES"):
            env.pop(k, None)
    env["ADMIN_HOST"] = "admin." + c["domain"]
    lines = ["# Generated by ./sallyport init. Contains secrets; do not commit.\n"]
    lines += [f"{k}='{v}'\n" for k, v in sorted(env.items())]
    write_private(ENV_FILE, "".join(lines))

    GEN.mkdir(exist_ok=True)
    write_text(GEN / "pomerium.yaml", render_pomerium(c))
    write_text(GEN / "admin-jwt.pub", signing_public_pem(env["SIGNING_KEY"]))
    make_branding(c)

    if c["mode"] == "dev":
        init_dev(c, env)

    initdb = GEN / "initdb"
    initdb.mkdir(exist_ok=True)
    schema = initdb / "001-schema.sql"
    if not schema.exists() or schema.stat().st_size == 0:
        if args.no_schema or IN_CONTAINER:
            if not IN_CONTAINER:
                print("skipping schema generation (--no-schema); you must supply generated/initdb/001-schema.sql")
            else:
                die("generated/initdb/001-schema.sql is missing; run sallyport.cmd init, not the script directly")
        else:
            print("generating Guacamole database schema (pulls the guacamole image)...")
            result = subprocess.run(
                ["docker", "run", "--rm", "guacamole/guacamole", "/opt/guacamole/bin/initdb.sh", "--postgresql"],
                capture_output=True, text=True, encoding="utf-8")
            if result.returncode != 0 or "CREATE TABLE" not in result.stdout:
                die(f"could not generate the schema with Docker: {result.stderr.strip() or 'unexpected output'}")
            write_text(schema, result.stdout)
    shutil.copy(ROOT / "sql" / "002-sallyport.sql", initdb / "002-sallyport.sql")
    shutil.copy(ROOT / "sql" / "003-app-role.sh", initdb / "003-app-role.sh")
    os.chmod(initdb / "003-app-role.sh", 0o755)

    quiet = getattr(args, "quiet", False)
    if quiet:
        print("wrote .env and the generated configuration")
        return
    if c["mode"] == "dev":
        d = c["domain"]
        print("wrote .env, generated/pomerium.yaml, generated/dex.yaml, generated/certs/ and generated/initdb/")
        print(f"\nDEV MODE: throwaway logins, untrusted certificate, loopback only.\n\n"
              "Next:\n  1. docker compose -f compose.yaml -f compose.dev.yaml up -d --build\n"
              "  2. ./sallyport migrate-db (creates the admin tables and loads the test targets)\n"
              f"  3. open https://{d} and accept the certificate warning (or trust generated/certs/ca.crt);\n"
              f"     first open https://dex.{d}:5556 once and accept its warning too if the login redirect fails.\n"
              f"  Sign in with one of: {', '.join(e for e, _ in DEV_USERS)} (password: {DEV_PASSWORD}).\n"
              f"  {DEV_EMAIL} is the administrator and can also open https://admin.{d}.")
        return
    print(f"wrote {ENV_FILE.name} (new secrets: {', '.join(new) or 'none, existing kept'})")
    print("wrote generated/pomerium.yaml and generated/initdb/")
    admin = f", and admin.{c['domain']}" if c["admin_emails"] or c["admin_groups"] else ""
    print(f"\nNext:\n  1. DNS: {c['domain']}, authenticate.{c['domain']}{admin} -> this server\n"
          f"  2. IdP redirect URI: https://authenticate.{c['domain']}/oauth2/callback\n"
          "  3. docker compose up -d --build\n  4. ./sallyport migrate-db")
    if c["staging"]:
        print("\nacme_staging is true: certificates will not be trusted by browsers. Set it to false\n"
              "in sallyport.yaml and re-run ./sallyport init, then docker compose up -d, once it works.")


# --------------------------------------------------------------- load-targets

RDP_SECURITY = {"nla", "tls", "rdp", "any"}
CLIPBOARD = {"both", "none", "paste-only", "copy-only"}
COMMON_KEYS = {"name", "protocol", "host", "port", "username", "password", "clipboard", "max_sessions", "users", "groups"}
PROTOCOL_KEYS = {
    "rdp": COMMON_KEYS | {"domain", "security", "ignore_cert"},
    "ssh": COMMON_KEYS | {"private_key", "passphrase", "host_key"},
}
SECRET_PARAMS = {"password", "private-key", "passphrase"}


def q(value):
    """SQL string literal. Targets are validated; values are escaped by doubling quotes."""
    return "'" + str(value).replace("'", "''") + "'"


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def target_users(t):
    """None = every user (default group); a list = only those people (may be empty = nobody)."""
    if "users" not in t:
        return None
    users = t["users"]
    section = f"target '{t['name']}'"
    if not isinstance(users, list):
        die(f"{section}: users must be a list of email addresses")
    out = []
    for u in users:
        if not isinstance(u, str) or not EMAIL_RE.match(u.strip()) or len(u) > 128 or "'" in u:
            die(f"{section}: users: '{u}' is not an email address")
        u = u.strip().lower()
        if u not in out:
            out.append(u)
    return out


def target_params(t):
    proto = t["protocol"]
    section = f"target '{t['name']}'"
    port = t.get("port", {"rdp": 3389, "ssh": 22}[proto])
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        die(f"{section}: port must be 1-65535")
    host = t["host"]
    if not isinstance(host, str) or not HOST_RE.match(host):
        die(f"{section}: host must be a hostname or IP address")
    params = [("hostname", host), ("port", str(port))]
    for key in ("username", "password"):
        if key in t:
            params.append((key, nonempty_str(section, key, t[key])))

    if proto == "rdp":
        security = t.get("security", "nla")
        if security not in RDP_SECURITY:
            die(f"{section}: security must be one of {sorted(RDP_SECURITY)}")
        ignore = t.get("ignore_cert", False)
        if not isinstance(ignore, bool):
            die(f"{section}: ignore_cert must be true or false")
        params += [("security", security), ("ignore-cert", str(ignore).lower()),
                   ("enable-drive", "false"), ("disable-download", "true"), ("disable-upload", "true"),
                   ("enable-printing", "false"), ("resize-method", "display-update")]
        if "domain" in t:
            params.append(("domain", nonempty_str(section, "domain", t["domain"], 256)))
        # username and password are optional: whatever is missing, Guacamole asks the user for at connect time
    elif proto == "ssh":
        params.append(("enable-sftp", "false"))
        if "private_key" in t:
            params.append(("private-key", nonempty_str(section, "private_key", t["private_key"])))
            if "passphrase" in t:
                params.append(("passphrase", nonempty_str(section, "passphrase", t["passphrase"])))
        if "host_key" in t:
            params.append(("host-key", nonempty_str(section, "host_key", t["host_key"])))
        # username, password and key are optional: whatever is missing, Guacamole asks the user at connect time
        if "private_key" in t and "username" not in t:
            die(f"{section}: a private_key needs a username")
        if "passphrase" in t and "private_key" not in t:
            die(f"{section}: passphrase needs a private_key")

    clipboard = t.get("clipboard", "both")
    if clipboard not in CLIPBOARD:
        die(f"{section}: clipboard must be one of {sorted(CLIPBOARD)}")
    # Guacamole: disable-copy blocks target -> user; disable-paste blocks user -> target.
    if clipboard in ("none", "paste-only"):
        params.append(("disable-copy", "true"))
    if clipboard in ("none", "copy-only"):
        params.append(("disable-paste", "true"))
    return params


def sql_ensure_users(emails):
    """Create accounts ahead of first login so permissions and group membership can be granted now.
    The password hash is random and unknowable: these accounts only ever log in through Pomerium."""
    if not emails:
        return []
    listed = ", ".join(q(u) for u in emails)
    vals = ", ".join(f"({q(u)})" for u in emails)
    return [
        "INSERT INTO guacamole_entity (name, type)\n"
        f"SELECT v.u, 'USER'::guacamole_entity_type FROM (VALUES {vals}) v(u)\n"
        "WHERE NOT EXISTS (SELECT 1 FROM guacamole_entity x WHERE x.name = v.u AND x.type = 'USER');",
        "INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date)\n"
        "SELECT e.entity_id, sha256(convert_to(random()::text || clock_timestamp()::text || e.name, 'UTF8')),\n"
        "       sha256(convert_to(clock_timestamp()::text || random()::text, 'UTF8')), now()\n"
        f"FROM guacamole_entity e WHERE e.type = 'USER' AND e.name IN ({listed})\n"
        "AND NOT EXISTS (SELECT 1 FROM guacamole_user x WHERE x.entity_id = e.entity_id);"]


def build_sql(targets, groups=None, redact=False):
    names = []
    groups = groups or {}
    out = ["-- generated by ./sallyport load-targets"]
    for g, members in groups.items():
        out.append(f"-- group {g}")
        out += sql_ensure_users(members)
        out.append(
            "INSERT INTO guacamole_entity (name, type)\n"
            f"SELECT {q(g)}, 'USER_GROUP'::guacamole_entity_type\n"
            f"WHERE NOT EXISTS (SELECT 1 FROM guacamole_entity WHERE name = {q(g)} AND type = 'USER_GROUP');")
        out.append(
            "INSERT INTO guacamole_user_group (entity_id, disabled)\n"
            f"SELECT e.entity_id, FALSE FROM guacamole_entity e WHERE e.name = {q(g)} AND e.type = 'USER_GROUP'\n"
            "AND NOT EXISTS (SELECT 1 FROM guacamole_user_group x WHERE x.entity_id = e.entity_id);")
        out.append(
            "DELETE FROM guacamole_user_group_member WHERE user_group_id IN (SELECT ug.user_group_id FROM guacamole_user_group ug\n"
            f"JOIN guacamole_entity e ON e.entity_id = ug.entity_id WHERE e.name = {q(g)} AND e.type = 'USER_GROUP');")
        if members:
            out.append(
                "INSERT INTO guacamole_user_group_member (user_group_id, member_entity_id)\n"
                "SELECT ug.user_group_id, m.entity_id FROM guacamole_user_group ug\n"
                f"JOIN guacamole_entity ge ON ge.entity_id = ug.entity_id AND ge.type = 'USER_GROUP' AND ge.name = {q(g)},\n"
                f"guacamole_entity m WHERE m.type = 'USER' AND m.name IN ({', '.join(q(u) for u in members)})\n"
                "ON CONFLICT DO NOTHING;")
    for t in targets:
        name = t["name"]
        names.append(name)
        n = q(name)
        maxs = t.get("max_sessions", 1)
        if not isinstance(maxs, int) or isinstance(maxs, bool) or not 1 <= maxs <= 50:
            die(f"target '{name}': max_sessions must be 1-50")
        proto = t["protocol"]
        where = f"connection_name = {n} AND parent_id IS NULL"
        out.append(f"-- {name}")
        out.append(
            "INSERT INTO guacamole_connection (connection_name, parent_id, protocol, max_connections, max_connections_per_user)\n"
            f"SELECT {n}, NULL, {q(proto)}, {maxs}, 1\n"
            f"WHERE NOT EXISTS (SELECT 1 FROM guacamole_connection WHERE {where});")
        out.append(
            f"UPDATE guacamole_connection SET protocol = {q(proto)}, max_connections = {maxs}, "
            f"max_connections_per_user = 1 WHERE {where};")
        out.append(
            "DELETE FROM guacamole_connection_parameter WHERE connection_id IN "
            f"(SELECT connection_id FROM guacamole_connection WHERE {where});")
        rows = []
        for key, value in target_params(t):
            shown = "***" if (redact and key in SECRET_PARAMS) else value
            rows.append(f"({q(key)}, {q(shown)})")
        out.append(
            "INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)\n"
            "SELECT c.connection_id, p.n, p.v FROM guacamole_connection c,\n"
            f"(VALUES {', '.join(rows)}) AS p(n, v)\n"
            f"WHERE c.connection_name = {n} AND c.parent_id IS NULL;")
        # Permissions are rebuilt on every load, so narrowing a target takes effect.
        out.append(
            "DELETE FROM guacamole_connection_permission WHERE connection_id IN "
            f"(SELECT connection_id FROM guacamole_connection WHERE {where});")
        users = target_users(t)
        tgroups = t.get("groups") or []
        if tgroups:
            listed = ", ".join(q(g) for g in tgroups)
            out.append(
                "INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)\n"
                "SELECT e.entity_id, c.connection_id, 'READ'::guacamole_object_permission_type\n"
                "FROM guacamole_entity e, guacamole_connection c\n"
                f"WHERE e.type = 'USER_GROUP' AND e.name IN ({listed}) AND c.connection_name = {n} AND c.parent_id IS NULL\n"
                "ON CONFLICT DO NOTHING;")
        elif users is None:
            out.append(
                "INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)\n"
                "SELECT e.entity_id, c.connection_id, 'READ'::guacamole_object_permission_type\n"
                "FROM guacamole_entity e, guacamole_connection c\n"
                f"WHERE e.name = {q(DEFAULT_GROUP)} AND e.type = 'USER_GROUP' AND c.connection_name = {n} AND c.parent_id IS NULL\n"
                "ON CONFLICT DO NOTHING;")
        elif users:
            listed = ", ".join(q(u) for u in users)
            out += sql_ensure_users(users)
            out.append(
                "INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)\n"
                "SELECT e.entity_id, c.connection_id, 'READ'::guacamole_object_permission_type\n"
                "FROM guacamole_entity e, guacamole_connection c\n"
                f"WHERE e.type = 'USER' AND e.name IN ({listed}) AND c.connection_name = {n} AND c.parent_id IS NULL\n"
                "ON CONFLICT DO NOTHING;")
    # Sallyport owns all top-level connections: anything not in targets.yaml is removed.
    if names:
        listed = ", ".join(q(n) for n in names)
        out.append(f"DELETE FROM guacamole_connection WHERE parent_id IS NULL AND connection_name NOT IN ({listed});")
    else:
        out.append("DELETE FROM guacamole_connection WHERE parent_id IS NULL;")
    keep = ", ".join(q(g) for g in [DEFAULT_GROUP] + list(groups))
    out.append(f"DELETE FROM guacamole_entity WHERE type = 'USER_GROUP' AND name NOT IN ({keep});")
    return "\n".join(out) + "\n"


def email_list(section, value):
    if not isinstance(value, list):
        die(f"{section} must be a list of email addresses")
    out = []
    for u in value:
        if not isinstance(u, str) or not EMAIL_RE.match(u.strip()) or len(u) > 128 or "'" in u:
            die(f"{section}: '{u}' is not an email address")
        u = u.strip().lower()
        if u not in out:
            out.append(u)
    return out


def compile_access(data):
    """targets.yaml -> (connections, groups {name: [emails]}, users [emails]).

    The file has systems, users, groups and logins; each login becomes one Guacamole connection.
    The older flat `targets:` list is still accepted and is already one entry per connection."""
    if "targets" in data:
        check_keys("targets.yaml", data, {"targets"}, required=("targets",))
        if not isinstance(data["targets"], list):
            die("targets must be a list")
        return data["targets"], {}, []
    check_keys("targets.yaml", data, {"systems", "users", "groups", "logins"})
    systems = {}
    for sysd in data.get("systems") or []:
        if not isinstance(sysd, dict):
            die("each system must be a mapping")
        check_keys("system", sysd, SYSTEM_KEYS, required=("name", "protocol", "host"))
        name = sysd["name"]
        if not isinstance(name, str) or not NAME_RE.match(name):
            die(f"system name '{name}' must start with a letter or digit and use letters, digits, space and . _ - ( ) @ + ,")
        if name in systems:
            die(f"duplicate system name '{name}'")
        systems[name] = sysd
    users = email_list("users", data.get("users") or [])
    groups = {}
    for g in data.get("groups") or []:
        if not isinstance(g, dict):
            die("each group must be a mapping")
        check_keys("group", g, {"name", "users"}, required=("name",))
        gname = g["name"]
        if not isinstance(gname, str) or not GROUP_NAME_RE.match(gname) or gname == DEFAULT_GROUP:
            die(f"group name '{gname}' must start with a letter or digit, use letters, digits, space and . _ -, and not be '{DEFAULT_GROUP}'")
        if gname in groups:
            die(f"duplicate group name '{gname}'")
        groups[gname] = email_list(f"group '{gname}' users", g.get("users") or [])
    conns = []
    for i, lg in enumerate(data.get("logins") or [], 1):
        sec = f"logins[{i}]"
        if not isinstance(lg, dict):
            die(f"{sec} must be a mapping")
        check_keys(sec, lg, {"system", "user", "group", "everyone"} | set(CRED_KEYS), required=("system",))
        who = [k for k in ("user", "group", "everyone") if k in lg]
        if len(who) != 1:
            die(f"{sec}: set exactly one of user, group or everyone")
        if lg["system"] not in systems:
            die(f"{sec}: system '{lg['system']}' is not defined under systems")
        conn = dict(systems[lg["system"]])
        conn.update({k: lg[k] for k in CRED_KEYS if k in lg})
        if who[0] == "everyone":
            if lg["everyone"] is not True:
                die(f"{sec}: everyone must be true")
            conn["name"] = lg["system"]
        elif who[0] == "user":
            em = email_list(sec + " user", [lg["user"]])[0]
            conn["users"] = [em]
            conn["name"] = f"{lg['system']} ({em})"
        else:
            if lg["group"] not in groups:
                die(f"{sec}: group '{lg['group']}' is not defined under groups")
            conn["groups"] = [lg["group"]]
            conn["name"] = f"{lg['system']} ({lg['group']})"
        conns.append(conn)
    return conns, groups, users


def load_access(data=None):
    if data is None:
        data = load_yaml(TARGETS)
    targets, groups, users = compile_access(data)
    seen = set()
    for t in targets:
        if not isinstance(t, dict):
            die("each target must be a mapping")
        check_keys("target", t, COMMON_KEYS | {"domain", "security", "ignore_cert", "private_key", "passphrase", "host_key"},
                   required=("name", "protocol", "host"))
        name = t["name"]
        if not isinstance(name, str) or not NAME_RE.match(name):
            die(f"target name '{name}' must start with a letter or digit and use letters, digits, space and . _ - ( ) @ + ,")
        if name in seen:
            die(f"duplicate target name '{name}' (a person can have only one login per system, and a system only one for everyone)")
        seen.add(name)
        proto = t["protocol"]
        if proto not in PROTOCOL_KEYS:
            die(f"target '{name}': protocol must be one of {sorted(PROTOCOL_KEYS)}")
        extra = set(t) - PROTOCOL_KEYS[proto]
        if extra:
            die(f"target '{name}': {sorted(extra)} do not apply to {proto}")
        target_users(t)
        if t.get("groups") and any(g not in groups for g in t["groups"]):
            die(f"target '{name}': unknown group")
    return targets, groups, users


def load_targets(data=None):
    return load_access(data)[0]


INT_FIELDS = ("port", "max_sessions")
SECRET_FIELDS = ("password", "private_key", "passphrase")


def clean_document(payload):
    """Normalise a document sent by an editor: drop empty values, turn digit strings into numbers."""
    payload = payload if isinstance(payload, dict) else {}

    def rows(items):
        out = []
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
            out.append(row)
        return out

    users = [str(u).strip().lower() for u in payload.get("users") or [] if str(u).strip()]
    groups = [{"name": g.get("name", ""), "users": [str(u).strip().lower() for u in g.get("users") or [] if str(u).strip()]}
              for g in payload.get("groups") or [] if isinstance(g, dict)]
    return {"systems": rows(payload.get("systems")), "users": users, "groups": groups, "logins": rows(payload.get("logins"))}


def legacy_to_v2(items):
    """Convert the old flat `targets:` list into systems, users and logins (for the GUI)."""
    systems, seen, logins, users = [], set(), [], []
    for e in items:
        if not isinstance(e, dict):
            continue
        name = str(e.get("name", ""))
        us = e.get("users") if isinstance(e.get("users"), list) else None
        if us:
            m = re.match(r"^(.*) \(([^()]*)\)$", name)
            if m and m.group(2).startswith(str(us[0])):
                name = m.group(1)
        sysd = {"name": name, **{k: e[k] for k in e if k in SYSTEM_KEYS and k != "name"}}
        key = json.dumps(sysd, sort_keys=True)
        if key not in seen:
            seen.add(key)
            systems.append(sysd)
        if us == []:
            continue
        cred = {k: e[k] for k in CRED_KEYS if k in e}
        if us is None:
            logins.append({"system": name, "everyone": True, **cred})
        else:
            for u in us:
                logins.append({"system": name, "user": u, **cred})
                if u not in users:
                    users.append(u)
    return {"systems": systems, "users": users, "groups": [], "logins": logins}


ADMIN_ROLE = "sallyport_admin"
GUAC_TABLES = ("guacamole_entity", "guacamole_user", "guacamole_user_group", "guacamole_user_group_member",
               "guacamole_connection", "guacamole_connection_parameter", "guacamole_connection_permission")
GUAC_SEQUENCES = ("guacamole_entity_entity_id_seq", "guacamole_user_user_id_seq",
                  "guacamole_user_group_user_group_id_seq", "guacamole_connection_connection_id_seq")


def migrate_sql(password):
    """Idempotent: the admin role (limited to the tables the admin site manages) and Sallyport's own tables."""
    if not re.fullmatch(r"[0-9a-f]{16,128}", password or ""):
        die("ADMIN_DB_PASSWORD is missing or not hex in .env; run ./sallyport init first")
    return f"""-- Sallyport admin site: role and tables
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ADMIN_ROLE}') THEN CREATE ROLE {ADMIN_ROLE} LOGIN; END IF;
END $$;
ALTER ROLE {ADMIN_ROLE} PASSWORD '{password}';
CREATE TABLE IF NOT EXISTS sallyport_state (
  id integer PRIMARY KEY CHECK (id = 1), document jsonb NOT NULL, version bigint NOT NULL DEFAULT 1,
  updated_at timestamptz NOT NULL DEFAULT now(), updated_by text NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS sallyport_audit (
  id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), actor text NOT NULL,
  action text NOT NULL, detail text NOT NULL DEFAULT '');
REVOKE ALL ON sallyport_state, sallyport_audit FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON {', '.join(GUAC_TABLES)} TO {ADMIN_ROLE};
GRANT SELECT, INSERT, UPDATE ON sallyport_state TO {ADMIN_ROLE};
GRANT SELECT, INSERT ON sallyport_audit TO {ADMIN_ROLE};
GRANT USAGE, SELECT ON SEQUENCE {', '.join(GUAC_SEQUENCES)}, sallyport_audit_id_seq TO {ADMIN_ROLE};
"""


def state_sql(doc, actor, action, detail):
    """Store the targets document as the current state (version + 1) and write an audit row."""
    return ("INSERT INTO sallyport_state (id, document, version, updated_by) "
            f"VALUES (1, {q(json.dumps(doc))}::jsonb, 1, {q(actor)})\n"
            "ON CONFLICT (id) DO UPDATE SET document = EXCLUDED.document, version = sallyport_state.version + 1, "
            "updated_at = now(), updated_by = EXCLUDED.updated_by;\n"
            f"INSERT INTO sallyport_audit (actor, action, detail) VALUES ({q(actor)}, {q(action)}, {q(detail)});\n")


def run_psql(sql):
    """Run SQL as the database owner: through the stack's postgres container, or (inside the helper container) over its network."""
    base = ["psql", "-v", "ON_ERROR_STOP=1", "--single-transaction", "-q", "-At", "-U", DB_OWNER, "-d", DB_NAME, "-f", "-"]
    if IN_CONTAINER:
        env = dict(os.environ, PGPASSWORD=read_env().get("POSTGRES_PASSWORD", ""))
        return subprocess.run(["psql", "-h", "postgres"] + base[1:], input=sql, text=True, encoding="utf-8",
                              capture_output=True, env=env)
    return subprocess.run(["docker", "compose", "exec", "-T", "postgres"] + base, input=sql, text=True,
                          encoding="utf-8", capture_output=True, cwd=ROOT)


def psql_or_die(sql, what):
    r = run_psql(sql)
    if r.returncode != 0:
        die(f"{what} failed; nothing was changed (single transaction). {(r.stderr or '').strip()[:300]}")
    return r.stdout


def targets_document(data):
    """The four-list document stored in the database, from either file format."""
    if "targets" in data:
        return legacy_to_v2(data["targets"])
    return {k: data.get(k) or [] for k in ("systems", "users", "groups", "logins")}


def warn_open(targets):
    saved = ("username", "password", "private_key", "passphrase")
    everyone = [t["name"] for t in targets if "users" not in t and "groups" not in t and any(k in t for k in saved)]
    if everyone:
        print(f"note: {len(everyone)} login(s) with saved credentials are open to EVERY user who can log in, "
              "including anyone you add later: " + ", ".join(everyone))
    shared = [t["name"] for t in targets if "groups" in t and any(k in t for k in saved)]
    if shared:
        print("note: saved credentials shared by every member of a group (not one account per person): " + ", ".join(shared))


def import_targets(data, actor, action, detail):
    targets, groups, _users = load_access(data)
    warn_open(targets)
    psql_or_die(state_sql(targets_document(data), actor, action, detail) + build_sql(targets, groups), "loading targets")
    return len(targets)


def cmd_migrate_db(args):
    """Create the admin role and tables; if the database holds no targets yet, import targets.yaml (if there is one)."""
    psql_or_die(migrate_sql(read_env().get("ADMIN_DB_PASSWORD")), "database migration")
    print("admin role and tables are in place")
    if psql_or_die("SELECT count(*) FROM sallyport_state;", "reading state").strip() != "0":
        return
    if TARGETS.exists():
        n = import_targets(load_yaml(TARGETS), "cli", "import", "initial import from targets.yaml")
        print(f"imported {n} login(s) from targets.yaml. The admin site is now where targets are edited;"
              " targets.yaml is only read again by load-targets.")
    else:
        print("no targets yet: add them in the admin site")


def cmd_load_targets(args):
    """Import targets.yaml into the database, replacing what is stored there (admin site edits included)."""
    data = load_yaml(TARGETS)
    targets, groups, _users = load_access(data)
    if args.dry_run:
        warn_open(targets)
        print(build_sql(targets, groups, redact=True))
        return
    psql_or_die(migrate_sql(read_env().get("ADMIN_DB_PASSWORD")), "database migration")
    n = import_targets(data, "cli", "import", "load-targets from targets.yaml")
    print(f"loaded {n} login(s), replacing what the database held")


def cmd_export_targets(args):
    """Write the database's targets (credentials included, in plain text) to targets.yaml."""
    out = psql_or_die("SELECT document FROM sallyport_state WHERE id = 1;", "reading state").strip()
    if not out:
        die("the database holds no targets yet")
    if TARGETS.exists() and not args.force:
        die(f"{TARGETS.name} already exists; use --force to overwrite it")
    doc = json.loads(out)
    header = ("# Exported by ./sallyport export-targets. Contains credentials in plain text.\n"
              "# The database (edited in the admin site) is the source of truth; this file is a copy.\n")
    write_private(TARGETS, header + yaml.safe_dump(doc, sort_keys=False))
    print(f"wrote {TARGETS.name}")


# ------------------------------------------------------------------- updates

def now_iso():
    import datetime
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


class UpdateLog:
    """Timestamped lines to the console and to generated/update.log (trimmed to the last ~200 KB)."""

    def __init__(self):
        GEN.mkdir(exist_ok=True)
        self.path = GEN / "update.log"
        try:
            if self.path.exists() and self.path.stat().st_size > 400_000:
                self.path.write_text(self.path.read_text(encoding="utf-8", errors="replace")[-200_000:], encoding="utf-8")
        except OSError:
            pass

    def __call__(self, text):
        line = f"{now_iso()} {text}"
        print(text, flush=True)
        try:
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
        except OSError:
            pass


def compose_argv(*args):
    dev = read_env().get("SALLYPORT_MODE") == "dev"
    files = ["-f", "compose.yaml", "-f", "compose.dev.yaml"] if dev else []
    return ["docker", "compose", "--progress", "plain", *files, *args]


def sh(log, cmd, timeout=1800, check=True):
    """Run a command in the checkout, logging its output. Returns (returncode, output)."""
    log("$ " + " ".join(cmd))
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        log(f"error: {e}")
        if check:
            raise UpdateFailed(f"{cmd[0]} {cmd[1] if len(cmd) > 1 else ''} failed")
        return 1, ""
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    for line in out.splitlines()[-40:]:
        log("  " + line)
    if check and r.returncode != 0:
        raise UpdateFailed(f"{' '.join(cmd[:3])} failed (exit {r.returncode})")
    return r.returncode, out


class UpdateFailed(Exception):
    pass


def image_ids(log):
    """{image reference: local image id or ''} for every image the stack uses."""
    _, out = sh(log, compose_argv("config", "--images"), timeout=60, check=False)
    ids = {}
    for ref in sorted(set(out.split())):
        rc, got = sh(log, ["docker", "image", "inspect", "--format", "{{.Id}}", ref], timeout=30, check=False)
        ids[ref] = got.strip() if rc == 0 else ""
    return ids


def file_hashes(names):
    import hashlib
    out = {}
    for n in names:
        p = GEN / n
        out[n] = hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else ""
    return out


def stack_healthy(log, wait=240):
    """True once every service is running and none is unhealthy, on two checks 10 s apart. A container whose healthcheck
    is still 'starting' is waited for; if that is all that remains at the deadline the stack is accepted with a warning,
    because a slow healthcheck is not a failure. Anything stopped, restarting or unhealthy fails the check."""
    deadline, good, last = time.time() + wait, 0, ""
    while True:
        try:
            r = subprocess.run(compose_argv("ps", "--all", "--format", "json"), cwd=ROOT, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=60)
            out = (r.stdout or "").strip()
            data = json.loads(out) if out.startswith("[") else [json.loads(x) for x in out.splitlines() if x.strip().startswith("{")]
            rows = data if isinstance(data, list) else [data]
        except (OSError, subprocess.TimeoutExpired, ValueError):
            rows = []
        rows = [x for x in rows if not (x.get("State") == "exited" and x.get("ExitCode") == 0)]  # finished one-shot jobs
        bad = [f"{x.get('Service')} ({x.get('State')})" for x in rows if x.get("State") != "running" or x.get("Health") == "unhealthy"]
        starting = [str(x.get("Service")) for x in rows if x.get("State") == "running" and x.get("Health") == "starting"]
        status = ("not running or unhealthy: " + ", ".join(bad)) if bad or not rows else (
            "waiting for healthchecks: " + ", ".join(starting) if starting else "all services running")
        if status != last:  # one short line per change, not one per poll
            log("health: " + status)
            last = status
        good = good + 1 if rows and not bad and not starting else 0
        if good >= 2:
            return True
        if time.time() >= deadline:
            if rows and not bad and starting:
                log("health: " + ", ".join(starting) + " still reports 'starting' but is running; accepting the update")
                return True
            return False
        time.sleep(10)


def write_update_status(**kw):
    GEN.mkdir(exist_ok=True)
    write_text(GEN / "update-status.json", json.dumps({"at": now_iso(), **kw}))


def acquire_update_lock():
    GEN.mkdir(exist_ok=True)
    lock = GEN / "update.lock"
    try:
        if lock.exists() and time.time() - lock.stat().st_mtime > 3 * 3600:
            lock.unlink()  # a crashed run
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return None
    os.write(fd, str(os.getpid()).encode())
    os.close(fd)
    return lock


def helper(*args):
    return [sys.executable, "-I", str(ROOT / "sallyport"), *args]


CRITICAL_FILE = "CRITICAL_UPDATE.json"
CRITICAL_RETRY_HOURS = 6


def critical_state_path():
    return GEN / "critical-update.json"


def critical_pending():
    """The id of a critical update flagged in the upstream repository that has not been applied (and was not
    attempted in the last few hours), else ''. Fetches quietly and changes nothing but the git remote refs."""
    if not (ROOT / ".git").exists():
        return ""
    run = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    try:
        if run("fetch", "--quiet").returncode != 0:
            return ""
        r = run("show", f"@{{u}}:{CRITICAL_FILE}")
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if r.returncode != 0:
        return ""
    try:
        cid = str(json.loads(r.stdout).get("id", ""))
    except (ValueError, AttributeError):
        return ""
    if not re.match(r"^[A-Za-z0-9._-]{1,100}$", cid):
        return ""
    try:
        st = json.loads(critical_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        st = {}
    if st.get("id") == cid:
        if st.get("applied"):
            return ""
        import datetime
        try:
            last = datetime.datetime.fromisoformat(st.get("attempted", ""))
            if datetime.datetime.now().astimezone() - last < datetime.timedelta(hours=CRITICAL_RETRY_HOURS):
                return ""  # a failed, rolled-back attempt: do not hammer the stack every hour
        except ValueError:
            pass
    return cid


def mark_critical(cid, applied):
    GEN.mkdir(exist_ok=True)
    write_text(critical_state_path(), json.dumps({"id": cid, "applied": applied, "attempted": now_iso()}))


def cmd_update(args):
    """Fetch the latest code and images, recreate what changed, migrate the database, check the stack is healthy,
    and roll back if it is not. Safe to run unattended; does nothing when there is nothing new."""
    unattended = getattr(args, "unattended", False)
    critical_id = ""
    if getattr(args, "critical_only", False):
        critical_id = critical_pending()
        if not critical_id:
            return  # nothing flagged: stay silent, this runs every hour
    log = UpdateLog()
    if critical_id:
        log(f"CRITICAL UPDATE flagged upstream ({critical_id}): applying now, which interrupts any active sessions")
    lock = acquire_update_lock()
    if lock is None:
        log("another update is already running; nothing done")
        raise SystemExit(0 if unattended else "error: another update is already running")
    start_sha, moved = "", False
    before, hashes_before = {}, {}
    try:
        if not (ROOT / ".git").exists():
            raise UpdateFailed("this folder is not a git checkout")
        if not (ENV_FILE.exists() and (GEN / "pomerium.yaml").exists()):
            raise UpdateFailed("run ./sallyport init first")
        _, start_sha = sh(log, ["git", "rev-parse", "HEAD"], timeout=20)
        sh(log, ["git", "fetch", "--quiet"], timeout=120)
        _, counts = sh(log, ["git", "rev-list", "--left-right", "--count", "HEAD...@{u}"], timeout=20)
        ahead, behind = (int(x) for x in counts.split()[:2])
        if behind and ahead:
            raise UpdateFailed(f"this checkout has {ahead} local commit(s) and is {behind} behind; update it by hand")
        if behind:
            _, dirty = sh(log, ["git", "status", "--porcelain", "--untracked-files=no"], timeout=30)
            if dirty:
                raise UpdateFailed("there are local changes to tracked files; commit or discard them first")
        before = image_ids(log)
        hashes_before = file_hashes(["pomerium.yaml", "dex.yaml", "admin-jwt.pub", "sallyport-branding.jar"])
        if behind:
            sh(log, ["git", "merge", "--ff-only", "@{u}"], timeout=120)
            moved = True
        rc, _ = sh(log, compose_argv("pull", "--ignore-buildable"), check=False)
        if rc != 0:
            sh(log, compose_argv("pull", "--ignore-pull-failures"))
        sh(log, helper("init", "--quiet"), timeout=600)
        sh(log, compose_argv("build", "--pull", "admin"))
        after = image_ids(log)
        changed_images = sorted(r for r in after if after[r] != before.get(r, ""))
        config_changed = file_hashes(["pomerium.yaml", "dex.yaml", "admin-jwt.pub", "sallyport-branding.jar"]) != hashes_before
        if not (moved or changed_images or config_changed):
            log("already up to date")
            write_update_status(ok=True, changed=False, summary="Already up to date.", unattended=unattended)
            if critical_id:
                mark_critical(critical_id, True)
            return
        _, end_sha = sh(log, ["git", "rev-parse", "--short", "HEAD"], timeout=20)
        log(f"applying: code {'updated' if moved else 'unchanged'}, images changed: {', '.join(changed_images) or 'none'}, "
            f"generated configuration {'changed' if config_changed else 'unchanged'}")
        sh(log, compose_argv("up", "-d", "--build", "--remove-orphans"))
        if config_changed:
            dev = read_env().get("SALLYPORT_MODE") == "dev"
            sh(log, compose_argv("up", "-d", "--force-recreate", "--no-deps", "pomerium", "guacamole", *(["dex"] if dev else []), "admin"))
        for attempt in range(12):  # the database may still be starting
            rc, _ = sh(log, helper("migrate-db"), timeout=300, check=False)
            if rc == 0:
                break
            time.sleep(5)
        else:
            raise UpdateFailed("the database migration did not succeed")
        if not stack_healthy(log):
            raise UpdateFailed("the stack did not become healthy after the update")
        summary = f"Updated to {end_sha}." if moved else "Updated container images or configuration."
        log(summary)
        write_update_status(ok=True, changed=True, summary=summary, unattended=unattended)
        if critical_id:
            mark_critical(critical_id, True)
    except UpdateFailed as e:
        log(f"UPDATE FAILED: {e}")
        rolled = False
        if before and (moved or any(before.values())):
            try:
                log("rolling back to the previous version")
                if moved and start_sha:
                    sh(log, ["git", "reset", "--hard", start_sha], timeout=60)
                for ref, old in before.items():
                    if old:
                        sh(log, ["docker", "tag", old, ref], timeout=60, check=False)
                sh(log, helper("init", "--quiet"), timeout=600, check=False)
                sh(log, compose_argv("up", "-d", "--force-recreate"), check=False)
                rolled = stack_healthy(log, wait=120)
                log("rollback " + ("succeeded" if rolled else "did not restore a healthy stack: check it by hand"))
            except Exception as e2:  # keep the original failure the headline
                log(f"rollback error: {e2}")
        write_update_status(ok=False, changed=moved, summary=f"Update failed: {e}", rolled_back=rolled, unattended=unattended)
        if critical_id:
            mark_critical(critical_id, False)
        raise SystemExit(f"error: update failed: {e}" + (" (rolled back)" if rolled else ""))
    finally:
        try:
            lock.unlink()
        except OSError:
            pass


# ---------------------------------------------------------- scheduled updates

SCHEDULE_NAME = "Sallyport update"
CRITICAL_NAME = "Sallyport critical update check"
CRON_MARK = "# sallyport-update"


def update_argv(critical=False):
    return [sys.executable, "-I", str(ROOT / "sallyport"), "update", "--unattended"] + (["--critical-only"] if critical else [])


def cron_line(hhmm, critical=False):
    import shlex
    hh, mm = hhmm.split(":")
    cmd = " ".join(shlex.quote(a) for a in update_argv(critical))
    when = f"{(int(mm) + 17) % 60} * * * *" if critical else f"{int(mm)} {int(hh)} * * *"  # hourly, off the hour
    mark = CRON_MARK + ("-critical" if critical else "")
    return f"{when} cd {shlex.quote(str(ROOT))} && {cmd} >> {shlex.quote(str(GEN / 'update-cron.log'))} 2>&1 {mark}"


def systemd_units(hhmm, user, critical=False):
    import shlex
    cmd = " ".join(shlex.quote(a) for a in update_argv(critical))
    what = "critical update check" if critical else "unattended update"
    service = (f"[Unit]\nDescription=Sallyport {what}\nAfter=docker.service network-online.target\n\n"
               f"[Service]\nType=oneshot\nUser={user}\nWorkingDirectory={ROOT}\nExecStart={cmd}\n")
    when = "OnCalendar=hourly\nRandomizedDelaySec=600\n" if critical else f"OnCalendar=*-*-* {hhmm}:00\n"
    timer = (f"[Unit]\nDescription=Sallyport {what}, {'hourly' if critical else 'daily'}\n\n"
             f"[Timer]\n{when}Persistent=true\n\n[Install]\nWantedBy=timers.target\n")
    return service, timer


def schtasks_create_args(hhmm, critical=False):
    tr = subprocess.list2cmdline(update_argv(critical))
    if critical:
        return ["schtasks", "/Create", "/F", "/TN", CRITICAL_NAME, "/SC", "HOURLY", "/MO", "1", "/ST", f"00:{(int(hhmm[3:]) + 17) % 60:02d}", "/TR", tr]
    return ["schtasks", "/Create", "/F", "/TN", SCHEDULE_NAME, "/SC", "DAILY", "/ST", hhmm, "/TR", tr]


def have(cmd):
    return shutil.which(cmd) is not None


def use_systemd():
    return os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0 and have("systemctl") and Path("/run/systemd/system").exists()


def crontab_lines():
    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    return [] if r.returncode != 0 else [ln for ln in r.stdout.splitlines()]


def set_crontab(lines):
    r = subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, capture_output=True)
    if r.returncode != 0:
        die("could not update the crontab: " + (r.stderr or "").strip())


def schedule_remove():
    if os.name == "nt":
        for name in (SCHEDULE_NAME, CRITICAL_NAME):
            subprocess.run(["schtasks", "/Delete", "/F", "/TN", name], capture_output=True)
    elif use_systemd() or Path("/etc/systemd/system/sallyport-update.timer").exists():
        for unit in ("sallyport-update", "sallyport-critical"):
            if have("systemctl"):
                subprocess.run(["systemctl", "disable", "--now", unit + ".timer"], capture_output=True)
            for n in (unit + ".timer", unit + ".service"):
                try:
                    (Path("/etc/systemd/system") / n).unlink()
                except OSError:
                    pass
        if have("systemctl"):
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    if os.name != "nt" and have("crontab"):
        lines = crontab_lines()
        if any(CRON_MARK in ln for ln in lines):
            set_crontab([ln for ln in lines if CRON_MARK not in ln])


def schedule_install(hhmm, critical=True):
    schedule_remove()
    if os.name == "nt":
        for crit in ([False, True] if critical else [False]):
            r = subprocess.run(schtasks_create_args(hhmm, crit), capture_output=True, text=True)
            if r.returncode != 0:
                die("schtasks failed: " + (r.stderr or r.stdout).strip())
        return "Windows Task Scheduler (runs while you are signed in, because Docker Desktop does)"
    if use_systemd():
        import pwd
        user = pwd.getpwuid(ROOT.stat().st_uid).pw_name
        units = ["sallyport-update"] + (["sallyport-critical"] if critical else [])
        for unit in units:
            service, timer = systemd_units(hhmm, user, unit.endswith("critical"))
            Path(f"/etc/systemd/system/{unit}.service").write_text(service)
            Path(f"/etc/systemd/system/{unit}.timer").write_text(timer)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        for unit in units:
            subprocess.run(["systemctl", "enable", "--now", unit + ".timer"], check=True)
        return f"a systemd timer, running as {user}"
    if not have("crontab"):
        die("no scheduler found: run as root on a systemd host, or install cron")
    set_crontab(crontab_lines() + [cron_line(hhmm)] + ([cron_line(hhmm, True)] if critical else []))
    return "your user crontab"


def schedule_status():
    if os.name == "nt":
        r = subprocess.run(["schtasks", "/Query", "/TN", SCHEDULE_NAME], capture_output=True, text=True)
        return r.returncode == 0, "Windows Task Scheduler"
    if Path("/etc/systemd/system/sallyport-update.timer").exists():
        return True, "a systemd timer"
    if have("crontab") and any(CRON_MARK in ln for ln in crontab_lines()):
        return True, "your user crontab"
    return False, ""


def cmd_schedule(args):
    c = validate_config(load_yaml(CONFIG))
    if args.action == "status":
        on, where = schedule_status()
        print(f"installed: {where}" if on else "no scheduled update is installed")
        return
    if args.action == "remove" or (args.action == "apply" and not c["update_time"]):
        schedule_remove()
        print("scheduled update removed" if args.action == "remove" else
              "updates.schedule is empty in sallyport.yaml, so no scheduled update is installed")
        return
    if not c["update_time"]:
        die("set updates.schedule (for example \"03:00\") in sallyport.yaml first")
    where = schedule_install(c["update_time"], c["critical"])
    print(f"scheduled an unattended update every day at {c['update_time']} (this computer's local time) using {where}")
    print("also checking hourly for an update flagged critical, which is applied immediately, interrupting sessions"
          if c["critical"] else "hourly critical-update check is off (updates.critical: false)")



def main():
    parser = argparse.ArgumentParser(prog="sallyport", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="create secrets and generated configuration")
    p.add_argument("--no-schema", action="store_true", help="skip Docker schema generation (testing only)")
    p.add_argument("--quiet", action="store_true", help="print one line instead of the next-steps text")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("update", help="pull the latest code and images, recreate what changed, check health, roll back on failure")
    p.add_argument("--unattended", action="store_true", help="for scheduled runs: exit quietly if another update is running")
    p.add_argument("--critical-only", action="store_true", help="only update if the repository flags a critical update not yet applied")
    p.set_defaults(func=cmd_update)
    p = sub.add_parser("schedule", help="install, remove or show the scheduled unattended update")
    p.add_argument("action", choices=["apply", "remove", "status"], help="apply installs or removes it to match updates.schedule")
    p.set_defaults(func=cmd_schedule)
    p = sub.add_parser("migrate-db", help="create the admin role and tables; import targets.yaml if the database is empty")
    p.set_defaults(func=cmd_migrate_db)
    p = sub.add_parser("load-targets", help="import targets.yaml into the database, replacing its targets")
    p.add_argument("--dry-run", action="store_true", help="print the SQL with secrets redacted and exit")
    p.set_defaults(func=cmd_load_targets)
    p = sub.add_parser("export-targets", help="write the database's targets to targets.yaml")
    p.add_argument("--force", action="store_true", help="overwrite an existing targets.yaml")
    p.set_defaults(func=cmd_export_targets)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

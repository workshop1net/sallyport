"""Sallyport core: generate configuration and load targets.

Used by the ./sallyport command line and by the GUI (sallyport_gui.py).

Commands:
  init           read sallyport.yaml, create secrets and generated config
  load-targets   write targets.yaml into the Guacamole database

Requires Python 3 and PyYAML; dev mode also needs the cryptography package.
"""
import argparse
import base64
import os
import re
import secrets
import shutil
import subprocess
import sys
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
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
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

DEV_EMAIL = "kilgore@kilgore.trout"  # the fixed user Dex's mock connector signs in
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


def validate_dev(cfg):
    check_keys("sallyport.yaml (dev mode)", cfg, {"mode", "domain", "session"}, required=("domain",))
    domain = str(cfg["domain"]).lower()
    if not DOMAIN_RE.match(domain) or not domain.endswith(".localhost"):
        die("dev mode only runs on *.localhost names (for example access.localhost); "
            "it uses a throwaway login and an untrusted certificate and must never face a network")
    lifetime, idle = parse_session(cfg)
    return {"mode": "dev", "domain": domain, "emails": [DEV_EMAIL], "groups": [], "groups_claim": "groups",
            "lifetime": lifetime, "idle": idle, "client_secret": None}


def validate_config(cfg):
    mode = cfg.get("mode", "production")
    if mode not in ("production", "dev"):
        die("mode must be production or dev")
    if mode == "dev":
        return validate_dev(cfg)
    check_keys("sallyport.yaml", cfg, {"mode", "domain", "acme_email", "acme_staging", "idp", "access", "session"},
               required=("domain", "acme_email", "idp", "access"))
    domain = str(cfg["domain"]).lower()
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
    check_keys("access", access, {"emails", "groups", "groups_claim"})
    emails = access.get("emails") or []
    groups = access.get("groups") or []
    if not isinstance(emails, list) or not isinstance(groups, list):
        die("access.emails and access.groups must be lists")
    for e in emails:
        if not isinstance(e, str) or "@" not in e or " " in e:
            die(f"access.emails: '{e}' is not an email address")
    for g in groups:
        nonempty_str("access.groups", "entry", g, 256)
    if not emails and not groups:
        die("access must list at least one email or group, or nobody could log in")
    claim = access.get("groups_claim", AUTH0_GROUPS_CLAIM if provider == "auth0" else "groups")
    if not isinstance(claim, str) or not CLAIM_RE.match(claim):
        die("access.groups_claim is not a valid claim name")
    if provider == "google" and groups:
        die("Google does not provide group claims; list people under access.emails instead")

    lifetime, idle = parse_session(cfg)

    return {
        "mode": "production", "domain": domain, "acme_email": email, "staging": staging,
        "provider": provider, "issuer": issuer, "client_id": idp["client_id"], "client_secret": idp["client_secret"],
        "scopes": scopes, "emails": [e.strip() for e in emails], "groups": groups,
        "groups_claim": claim, "lifetime": lifetime, "idle": idle,
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
    header = ("# Generated by ./sallyport init from sallyport.yaml. Do not edit.\n"
              "# Secrets (shared_secret, cookie_secret, idp_client_secret) come from the\n"
              "# environment, set in compose.yaml from .env.\n")
    return header + yaml.safe_dump(config, sort_keys=False)


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
    sans = [domain, f"authenticate.{domain}", f"dex.{domain}"]
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
    write_text(certs / "domain", domain)


def dev_certs_current(certs, domain):
    marker, crt = certs / "domain", certs / "tls.crt"
    if not (crt.exists() and marker.exists() and (certs / "tls.key").exists() and (certs / "ca.crt").exists()):
        return False
    if marker.read_text(encoding="utf-8") != domain:
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
        "connectors": [{"type": "mockCallback", "id": "mock", "name": "Sallyport dev login"}],
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
            "targets:\n  - name: sshtest\n    protocol: ssh\n    host: sshtest\n    port: 2222\n"
            "    username: test\n    password: test\n"
            "  - name: rdptest\n    protocol: rdp\n    host: rdptest\n    port: 3389\n"
            "    username: abc\n    password: abc\n    security: tls   # xrdp does not support NLA\n"
            "    ignore_cert: true   # xrdp uses a self-signed certificate\n")
        print("wrote targets.yaml with test SSH and RDP targets")


def cmd_init(args):
    c = validate_config(load_yaml(CONFIG))
    env = read_env()
    new = []
    for key, gen in (
        ("SHARED_SECRET", lambda: base64.b64encode(secrets.token_bytes(32)).decode()),
        ("COOKIE_SECRET", lambda: base64.b64encode(secrets.token_bytes(32)).decode()),
        ("POSTGRES_PASSWORD", lambda: secrets.token_hex(24)),
        ("GUAC_APP_PASSWORD", lambda: secrets.token_hex(24)),
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
    lines = ["# Generated by ./sallyport init. Contains secrets; do not commit.\n"]
    lines += [f"{k}='{v}'\n" for k, v in sorted(env.items())]
    write_private(ENV_FILE, "".join(lines))

    GEN.mkdir(exist_ok=True)
    write_text(GEN / "pomerium.yaml", render_pomerium(c))

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
        print(f"\nDEV MODE: throwaway login, untrusted certificate, loopback only.\n\n"
              "Next:\n  1. docker compose -f compose.yaml -f compose.dev.yaml up -d\n"
              "  2. load-targets (loads the test SSH target)\n"
              f"  3. open https://{d} and accept the certificate warning (or trust generated/certs/ca.crt);\n"
              f"     first open https://dex.{d}:5556 once and accept its warning too if the login redirect fails.\n"
              "  Sign-in is automatic as kilgore@kilgore.trout (Dex's mock connector).")
        return
    print(f"wrote {ENV_FILE.name} (new secrets: {', '.join(new) or 'none, existing kept'})")
    print("wrote generated/pomerium.yaml and generated/initdb/")
    print(f"\nNext:\n  1. DNS: {c['domain']} and authenticate.{c['domain']} -> this server\n"
          f"  2. IdP redirect URI: https://authenticate.{c['domain']}/oauth2/callback\n"
          "  3. docker compose up -d\n  4. ./sallyport load-targets")
    if c["staging"]:
        print("\nacme_staging is true: certificates will not be trusted by browsers. Set it to false\n"
              "in sallyport.yaml and re-run ./sallyport init, then docker compose up -d, once it works.")


# --------------------------------------------------------------- load-targets

RDP_SECURITY = {"nla", "tls", "rdp", "any"}
CLIPBOARD = {"both", "none", "paste-only", "copy-only"}
COMMON_KEYS = {"name", "protocol", "host", "port", "username", "password", "clipboard", "max_sessions"}
PROTOCOL_KEYS = {
    "rdp": COMMON_KEYS | {"domain", "security", "ignore_cert"},
    "ssh": COMMON_KEYS | {"private_key", "passphrase", "host_key"},
}
SECRET_PARAMS = {"password", "private-key", "passphrase"}


def q(value):
    """SQL string literal. Targets are validated; values are escaped by doubling quotes."""
    return "'" + str(value).replace("'", "''") + "'"


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
        if "username" not in t or "password" not in t:
            die(f"{section}: rdp targets need username and password")
    elif proto == "ssh":
        params.append(("enable-sftp", "false"))
        if "private_key" in t:
            params.append(("private-key", nonempty_str(section, "private_key", t["private_key"])))
            if "passphrase" in t:
                params.append(("passphrase", nonempty_str(section, "passphrase", t["passphrase"])))
        if "host_key" in t:
            params.append(("host-key", nonempty_str(section, "host_key", t["host_key"])))
        if "username" not in t:
            die(f"{section}: ssh targets need a username")
        if "password" not in t and "private_key" not in t:
            die(f"{section}: ssh targets need a password or private_key")

    clipboard = t.get("clipboard", "both")
    if clipboard not in CLIPBOARD:
        die(f"{section}: clipboard must be one of {sorted(CLIPBOARD)}")
    # Guacamole: disable-copy blocks target -> user; disable-paste blocks user -> target.
    if clipboard in ("none", "paste-only"):
        params.append(("disable-copy", "true"))
    if clipboard in ("none", "copy-only"):
        params.append(("disable-paste", "true"))
    return params


def build_sql(targets, redact=False):
    names = []
    out = ["-- generated by ./sallyport load-targets"]
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
        out.append(
            "INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)\n"
            "SELECT e.entity_id, c.connection_id, 'READ'::guacamole_object_permission_type\n"
            "FROM guacamole_entity e, guacamole_connection c\n"
            f"WHERE e.name = {q(DEFAULT_GROUP)} AND e.type = 'USER_GROUP' AND c.connection_name = {n} AND c.parent_id IS NULL\n"
            "ON CONFLICT DO NOTHING;")
    # Sallyport owns all top-level connections: anything not in targets.yaml is removed.
    if names:
        listed = ", ".join(q(n) for n in names)
        out.append(f"DELETE FROM guacamole_connection WHERE parent_id IS NULL AND connection_name NOT IN ({listed});")
    else:
        out.append("DELETE FROM guacamole_connection WHERE parent_id IS NULL;")
    return "\n".join(out) + "\n"


def load_targets(data=None):
    if data is None:
        data = load_yaml(TARGETS)
    check_keys("targets.yaml", data, {"targets"}, required=("targets",))
    targets = data["targets"]
    if not isinstance(targets, list):
        die("targets must be a list")
    seen = set()
    for t in targets:
        if not isinstance(t, dict):
            die("each target must be a mapping")
        check_keys("target", t, COMMON_KEYS | {"domain", "security", "ignore_cert", "private_key", "passphrase", "host_key"},
                   required=("name", "protocol", "host"))
        name = t["name"]
        if not isinstance(name, str) or not NAME_RE.match(name):
            die(f"target name '{name}' must start with a letter or digit and use letters, digits, space . _ -")
        if name in seen:
            die(f"duplicate target name '{name}'")
        seen.add(name)
        proto = t["protocol"]
        if proto not in PROTOCOL_KEYS:
            die(f"target '{name}': protocol must be one of {sorted(PROTOCOL_KEYS)}")
        extra = set(t) - PROTOCOL_KEYS[proto]
        if extra:
            die(f"target '{name}': {sorted(extra)} do not apply to {proto}")
    return targets


def cmd_load_targets(args):
    targets = load_targets()
    if args.dry_run:
        print(build_sql(targets, redact=True))
        return
    sql = build_sql(targets)
    psql = ["psql", "-v", "ON_ERROR_STOP=1", "--single-transaction", "-q", "-U", DB_OWNER, "-d", DB_NAME, "-f", "-"]
    if IN_CONTAINER:
        env = dict(os.environ, PGPASSWORD=read_env().get("POSTGRES_PASSWORD", ""))
        result = subprocess.run(["psql", "-h", "postgres"] + psql[1:], input=sql, text=True, encoding="utf-8", env=env)
    else:
        result = subprocess.run(["docker", "compose", "exec", "-T", "postgres"] + psql,
                                input=sql, text=True, encoding="utf-8", cwd=ROOT)
    if result.returncode != 0:
        die("loading targets failed; nothing was changed (single transaction)")
    print(f"loaded {len(targets)} target(s)")


def main():
    parser = argparse.ArgumentParser(prog="sallyport", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="create secrets and generated configuration")
    p.add_argument("--no-schema", action="store_true", help="skip Docker schema generation (testing only)")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("load-targets", help="load targets.yaml into Guacamole")
    p.add_argument("--dry-run", action="store_true", help="print the SQL with secrets redacted and exit")
    p.set_defaults(func=cmd_load_targets)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

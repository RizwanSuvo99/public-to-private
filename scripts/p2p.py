#!/usr/bin/env python3
"""
p2p.py - public-to-private exposure helper for BTCL server-01 + MikroTik-01.

Publishes private services to the internet through:
  * MikroTik dst-nat port forwarding (RTP ranges, WireGuard, custom TCP/UDP)
  * nginx HTTP/HTTPS reverse-proxy vhosts on server-01

Every mutating command prints a plan and does nothing unless --apply is given.
Every MikroTik rule created here carries comment "p2p:<name>" so it can be
listed and removed cleanly. Passwords are never written to the repo; they come
from environment variables or a RAM-only session file (see `login`).

Requires: python3 (stdlib only), sshpass, ssh. The machine running this must
reach the private network (e.g. over the office VPN).
"""

import argparse
import getpass
import ipaddress
import json
import os
import re
import shlex
import socket
import stat
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Topology defaults (private addresses only - safe to publish)
# ---------------------------------------------------------------------------
SERVER_HOST = os.environ.get("P2P_SERVER_HOST", "192.168.24.101")
SERVER_USER = os.environ.get("P2P_SERVER_USER", "telcobright")
SERVER_PORT = os.environ.get("P2P_SERVER_PORT", "22")
MT_HOST = os.environ.get("P2P_MIKROTIK_HOST", "192.168.24.1")
MT_USER = os.environ.get("P2P_MIKROTIK_USER", "admin")
MT_PORT = os.environ.get("P2P_MIKROTIK_PORT", "22")
PUBLIC_IP = os.environ.get("P2P_PUBLIC_IP", "114.130.145.76")

NGINX = "/usr/sbin/nginx"
NGINX_AVAILABLE = "/etc/nginx/sites-available"
NGINX_ENABLED = "/etc/nginx/sites-enabled"
NGINX_BACKUPS = "/etc/nginx/backups"
ACME_WEBROOT = "/var/www/acme"
MANAGED_MARK = "# Managed-By: public-to-private (p2p)"

# Certificates already present on server-01, tried in order by --cert auto.
CERT_STORES = {
    "alaapcloud": ("/etc/nginx/ssl/alaapcloud/fullchain.crt", "/etc/nginx/ssl/alaapcloud/privkey.key"),
    "btclip": ("/etc/nginx/ssl/btclip-le/fullchain.crt", "/etc/nginx/ssl/btclip-le/privkey.key"),
}

SESSION_FILE = f"/dev/shm/p2p-session-{os.getuid()}.json"
SESSION_TTL = 8 * 3600
TAG = "p2p:"
SEP = "|~|"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def info(msg):
    print(f"[*] {msg}")


def ok(msg):
    print(f"[ok] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def die(msg, code=1):
    print(f"[x] {msg}", file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
def load_session():
    try:
        st = os.stat(SESSION_FILE)
    except FileNotFoundError:
        return {}
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        warn(f"ignoring {SESSION_FILE}: wrong owner or permissions")
        return {}
    if time.time() - st.st_mtime > SESSION_TTL:
        os.remove(SESSION_FILE)
        return {}
    with open(SESSION_FILE) as fh:
        return json.load(fh)


def password(kind):
    env = {"server": "P2P_SERVER_PASS", "mikrotik": "P2P_MIKROTIK_PASS"}[kind]
    value = os.environ.get(env) or load_session().get(kind)
    if not value:
        die(f"{kind} password missing: set {env} or run `p2p.py login` first")
    return value


def cmd_login(args):
    creds = {}
    for kind, env, label in (("server", "P2P_SERVER_PASS", f"{SERVER_USER}@{SERVER_HOST}"),
                             ("mikrotik", "P2P_MIKROTIK_PASS", f"{MT_USER}@{MT_HOST}")):
        value = os.environ.get(env)
        if not value:
            if not sys.stdin.isatty():
                die(f"{env} not set and no terminal to prompt on")
            value = getpass.getpass(f"Password for {label}: ")
        creds[kind] = value
    fd = os.open(SESSION_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(creds, fh)
    ok(f"session stored in RAM ({SESSION_FILE}, expires in {SESSION_TTL // 3600}h). Run `logout` when done.")


def cmd_logout(args):
    try:
        os.remove(SESSION_FILE)
        ok("session removed")
    except FileNotFoundError:
        ok("no session to remove")


# ---------------------------------------------------------------------------
# SSH transport
# ---------------------------------------------------------------------------
SSH_OPTS = ["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "PubkeyAuthentication=no", "-o", "LogLevel=ERROR"]


def _ssh(user, host, port, pw, remote_cmd, stdin=None, timeout=180):
    env = dict(os.environ, SSHPASS=pw)
    argv = ["sshpass", "-e", "ssh", *SSH_OPTS, "-p", str(port), f"{user}@{host}", remote_cmd]
    try:
        res = subprocess.run(argv, input=stdin, capture_output=True, text=True, env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        die(f"ssh to {host} timed out")
    if res.returncode == 5:
        die(f"authentication failed for {user}@{host}")
    return res


def mt(cmd, check=True):
    """Run a RouterOS CLI command/script on MikroTik and return stdout."""
    res = _ssh(MT_USER, MT_HOST, MT_PORT, password("mikrotik"), cmd)
    out = (res.stdout or "") + (res.stderr or "")
    if check and (res.returncode != 0 or re.search(r"^(failure|syntax error|expected |bad command|input does not match)", out, re.M)):
        die(f"MikroTik command failed:\n  {cmd}\n{out.strip()}")
    return res.stdout


_sudo_mode = None


def srv(script, check=True, timeout=300):
    """Run a bash script as root on server-01. Returns CompletedProcess."""
    global _sudo_mode
    pw = password("server")
    if _sudo_mode is None:
        probe = _ssh(SERVER_USER, SERVER_HOST, SERVER_PORT, pw, "sudo -n true")
        _sudo_mode = "nopasswd" if probe.returncode == 0 else "passwd"
    if _sudo_mode == "nopasswd":
        res = _ssh(SERVER_USER, SERVER_HOST, SERVER_PORT, pw, "sudo bash -s", stdin=script, timeout=timeout)
    else:
        res = _ssh(SERVER_USER, SERVER_HOST, SERVER_PORT, pw, "sudo -S -p '' bash -s", stdin=pw + "\n" + script, timeout=timeout)
    if check and res.returncode != 0:
        die(f"server-01 script failed (rc={res.returncode}):\n{res.stdout}{res.stderr}")
    return res


# ---------------------------------------------------------------------------
# MikroTik model
# ---------------------------------------------------------------------------
NAT_FIELDS = [".id", "disabled", "chain", "action", "protocol", "dst-address", "dst-port",
              "in-interface", "to-addresses", "to-ports", "comment"]
FILTER_FIELDS = [".id", "disabled", "chain", "action", "protocol", "dst-address", "dst-port", "comment"]


def mt_rows(menu, where, fields):
    # `get $i <prop>` errors on unset properties; reading from the record array yields "" instead
    parts = " . \"%s\" . " % SEP
    getters = parts.join("$i" if f == ".id" else f'($r->"{f}")' for f in fields)
    script = f':foreach i in=[{menu} find {where}] do={{ :local r [{menu} get $i]; :put ({getters}) }}'
    rows = []
    for line in mt(script).splitlines():
        line = line.rstrip("\r")
        if SEP not in line:
            continue
        vals = line.split(SEP)
        if len(vals) != len(fields):
            continue
        rows.append(dict(zip(fields, vals)))
    return rows


def parse_ports(spec):
    """'25,465,587' / '50000-50100' / '' -> list of (lo, hi); [] means any port."""
    out = []
    for part in filter(None, (spec or "").split(",")):
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.append((int(lo), int(hi)))
        else:
            out.append((int(part), int(part)))
    return out


def port_range(spec):
    m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", spec or "")
    if not m:
        die(f"bad port spec '{spec}' (use 5000 or 16384-32768)")
    lo = int(m.group(1))
    hi = int(m.group(2) or lo)
    if not (1 <= lo <= hi <= 65535):
        die(f"bad port range '{spec}'")
    return lo, hi


def fmt_range(lo, hi):
    return str(lo) if lo == hi else f"{lo}-{hi}"


def overlaps(a, b):
    return a[0] <= b[1] and b[0] <= a[1]


def addr_matches(rule_addr, ip):
    """Does a RouterOS dst-address value match ip? None means 'unsure'."""
    if not rule_addr:
        return True
    if rule_addr.startswith("!"):
        return None
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(rule_addr, strict=False)
    except ValueError:
        return None


def dstnat_hits(public_ip, proto, lo, hi):
    """Enabled dst-nat rules that would catch public_ip:proto/lo-hi."""
    hits = []
    for r in mt_rows("/ip firewall nat", "chain=dstnat", NAT_FIELDS):
        if r["disabled"] == "true" or r["action"] != "dst-nat":
            continue
        if r["protocol"] and r["protocol"] != proto:
            continue
        am = addr_matches(r["dst-address"], public_ip)
        if am is False:
            continue
        ports = parse_ports(r["dst-port"])
        if ports and not any(overlaps(p, (lo, hi)) for p in ports):
            continue
        r["_unsure"] = am is None
        hits.append(r)
    return hits


def describe_rule(r):
    bits = [f"id={r['.id']}", f"proto={r['protocol'] or 'any'}", f"dst={r['dst-address'] or 'any'}:{r['dst-port'] or 'any'}",
            f"-> {r['to-addresses']}:{r['to-ports'] or '(same)'}"]
    if r.get("in-interface"):
        bits.append(f"in={r['in-interface']}")
    if r.get("comment"):
        bits.append(f'"{r["comment"]}"')
    return " ".join(bits)


def first_forward_drop_id():
    rows = mt_rows("/ip firewall filter", "chain=forward action=drop disabled=no", [".id"])
    return rows[0][".id"] if rows else None


def mt_backup():
    name = time.strftime("p2p-backup-%Y%m%d-%H%M%S")
    mt(f"/ip firewall export file={name}")
    ok(f"MikroTik firewall exported to router file {name}.rsc")
    # keep only the 10 newest p2p backups (router flash is small)
    files = mt(':foreach f in=[/file find where name~"^p2p-backup-"] do={ :put [/file get $f name] }').split()
    for old in sorted(files)[:-10]:
        mt(f'/file remove [find name="{old}"]', check=False)


def tag_where(name):
    """RouterOS find-expression matching rules tagged p2p:<name>."""
    return f'comment~"^{TAG}{name.replace(".", "[.]")}( |\\$)"'


def valid_name(name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,47}", name or ""):
        die("name must be 1-48 chars of letters, digits, '.', '_' or '-'")
    return name


# ---------------------------------------------------------------------------
# Forwarding
# ---------------------------------------------------------------------------
TYPE_DEFAULTS = {
    "rtp": {"proto": "udp", "port": None},
    "wireguard": {"proto": "udp", "port": "51820"},
    "custom": {"proto": None, "port": None},
}


def plan_forward(name, ftype, protos, public_ip, pub, to_ip, to_ports):
    """Return (cmds, notes) to create a forward; die on conflicts."""
    comment = f"{TAG}{name}"
    existing = mt_rows("/ip firewall nat", tag_where(name), NAT_FIELDS)
    if existing:
        die(f"a forward named '{name}' already exists ({len(existing)} rule(s)); pick another name or remove it")
    cmds, notes = [], []
    drop_id = first_forward_drop_id()
    for proto in protos:
        hits = dstnat_hits(public_ip, proto, *pub)
        for h in hits:
            same = (h["to-addresses"] == to_ip and h["dst-address"] == public_ip
                    and parse_ports(h["dst-port"]) == [pub] and h["to-ports"] in ("", fmt_range(*to_ports)))
            if same:
                notes.append(f"{proto}/{fmt_range(*pub)} is ALREADY forwarded to {to_ip} by: {describe_rule(h)}")
                break
            tag = "may conflict" if h["_unsure"] else "CONFLICT"
            die(f"{tag}: {public_ip} {proto}/{fmt_range(*pub)} already caught by dst-nat {describe_rule(h)}")
        else:
            to_ports_arg = "" if to_ports == pub else f" to-ports={fmt_range(*to_ports)}"
            cmds.append(f'/ip firewall nat add chain=dstnat action=dst-nat protocol={proto} '
                        f'dst-address={public_ip} dst-port={fmt_range(*pub)} to-addresses={to_ip}{to_ports_arg} '
                        f'comment="{comment} {ftype} {proto}/{fmt_range(*pub)}"')
            place = f" place-before={drop_id}" if drop_id else ""
            cmds.append(f'/ip firewall filter add chain=forward action=accept protocol={proto} '
                        f'dst-address={to_ip} dst-port={fmt_range(*to_ports)}{place} '
                        f'comment="{comment} {ftype} {proto}/{fmt_range(*to_ports)}"')
    return cmds, notes


def server_listening(protos, lo, hi):
    """Ports in lo-hi with a listener on server-01, per protocol."""
    res = srv("ss -Hlntu | awk '{print $1, $5}'", check=False)
    found = {p: set() for p in protos}
    for line in res.stdout.splitlines():
        try:
            netid, local = line.split()
            port = int(local.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            continue
        if netid in found and lo <= port <= hi:
            found[netid].add(port)
    return found


def target_notes(ftype, protos, to_ip, to_ports):
    notes = []
    if to_ip == SERVER_HOST:
        listening = server_listening(protos, *to_ports)
        for p in protos:
            n = len(listening[p])
            if n == 0:
                notes.append(f"nothing on server-01 is listening on {p}/{fmt_range(*to_ports)} yet")
            else:
                notes.append(f"server-01 has {n} {p} listener(s) inside {fmt_range(*to_ports)}")
        if ftype == "rtp":
            res = srv("grep -hoE 'external_(rtp|sip)_ip=[^\"]*' /usr/local/freeswitch/conf/vars.xml /etc/freeswitch/vars.xml 2>/dev/null | sort -u", check=False)
            if res.stdout.strip():
                notes.append("FreeSWITCH advertises: " + ", ".join(res.stdout.split())
                             + f" - for media from the internet the SIP profile must advertise {PUBLIC_IP} (not changed by this tool)")
        if ftype == "wireguard":
            res = srv("wg show all listen-port 2>/dev/null", check=False)
            if res.stdout.strip():
                notes.append("WireGuard listen ports on server-01: " + res.stdout.strip().replace("\n", ", "))
    elif "tcp" in protos and to_ports[0] == to_ports[1]:
        res = srv(f"timeout 3 bash -c '</dev/tcp/{to_ip}/{to_ports[0]}' && echo open || echo closed", check=False)
        notes.append(f"tcp {to_ip}:{to_ports[0]} as seen from server-01: {res.stdout.strip() or 'unknown'}")
    return notes


def tcp_probe(ip, port, timeout=4):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def cmd_forward_add(args):
    name = valid_name(args.name)
    d = TYPE_DEFAULTS[args.type]
    proto = args.proto or d["proto"]
    if not proto:
        die("--proto is required for custom forwards (tcp, udp or both)")
    protos = ["tcp", "udp"] if proto == "both" else [proto]
    port_spec = args.port or d["port"]
    if not port_spec:
        die(f"--port is required for {args.type} forwards")
    pub = port_range(port_spec)
    to_ports = port_range(args.to_port) if args.to_port else pub
    if (to_ports[1] - to_ports[0]) != (pub[1] - pub[0]):
        die("public and target port ranges must be the same size")
    if pub[0] != pub[1] and to_ports != pub:
        die("port ranges are forwarded 1:1; use the same range for --port and --to-port")
    try:
        ipaddress.ip_address(args.to_ip)
        ipaddress.ip_address(args.public_ip)
    except ValueError as e:
        die(str(e))

    cmds, notes = plan_forward(name, args.type, protos, args.public_ip, pub, args.to_ip, to_ports)
    notes += target_notes(args.type, protos, args.to_ip, to_ports)

    print(f"\nPLAN  forward '{name}' ({args.type})")
    print(f"  {args.public_ip} {'+'.join(protos)}/{fmt_range(*pub)}  ->  {args.to_ip}:{fmt_range(*to_ports)}")
    for n in notes:
        print(f"  note: {n}")
    if not cmds:
        ok("nothing to do")
        return
    print("  MikroTik commands:")
    for c in cmds:
        print(f"    {c}")
    if not args.apply:
        print("\n(dry run - re-run with --apply to execute)")
        return

    mt_backup()
    for c in cmds:
        mt(c)
    created = mt_rows("/ip firewall nat", tag_where(name), NAT_FIELDS)
    ok(f"created {len(created)} dst-nat rule(s) and {len(cmds) - len(created)} forward-accept rule(s) tagged {TAG}{name}")
    if "tcp" in protos:
        port = pub[0]
        state = "open" if tcp_probe(args.public_ip, port) else "no answer"
        info(f"tcp probe {args.public_ip}:{port} (via hairpin from this machine): {state}")


def cmd_forward_remove(args):
    name = valid_name(args.name)
    where = tag_where(name)
    nat = mt_rows("/ip firewall nat", where, NAT_FIELDS)
    flt = mt_rows("/ip firewall filter", where, FILTER_FIELDS)
    if not nat and not flt:
        die(f"no rules tagged {TAG}{name}")
    print(f"\nPLAN  remove forward '{name}'")
    for r in nat:
        print(f"  nat    {describe_rule(r)}")
    for r in flt:
        print(f"  filter id={r['.id']} {r['protocol']} dst={r['dst-address']}:{r['dst-port']} \"{r['comment']}\"")
    if not args.apply:
        print("\n(dry run - re-run with --apply to execute)")
        return
    mt_backup()
    if nat:
        mt(f"/ip firewall nat remove [find {where}]")
    if flt:
        mt(f"/ip firewall filter remove [find {where}]")
    ok(f"removed {len(nat)} nat + {len(flt)} filter rule(s)")


# ---------------------------------------------------------------------------
# nginx reverse proxy
# ---------------------------------------------------------------------------
DOMAIN_RE = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
BACKEND_RE = re.compile(r"https?://[A-Za-z0-9.\-\[\]:]+(:\d{1,5})?(/[^\s;{}'\"]*)?")


def nginx_server_blocks():
    """Parse `nginx -T` into [{file, listens:[port], names:[...]}]."""
    res = srv(f"{NGINX} -T 2>/dev/null", check=False)
    blocks, cur_file = [], None
    depth, block = 0, None
    for raw in res.stdout.splitlines():
        m = re.match(r"# configuration file (.+):$", raw)
        if m:
            cur_file = m.group(1)
            continue
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if block is None and re.match(r"server\s*\{", line):
            block = {"file": cur_file, "listens": [], "names": []}
            depth = 0
        if block is not None:
            lm = re.match(r"listen\s+(?:\[[^\]]*\]:|[\d.]+:)?(\d+)", line)
            if lm:
                block["listens"].append(int(lm.group(1)))
            nm = re.match(r"server_name\s+([^;]+);", line)
            if nm:
                block["names"] += nm.group(1).split()
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                blocks.append(block)
                block = None
    return blocks


def name_matches(pattern, domain):
    if pattern == domain:
        return True
    if pattern.startswith("*."):
        return domain.endswith(pattern[1:]) and domain.count(".") == pattern.count(".")
    if pattern.startswith("."):
        return domain == pattern[1:] or domain.endswith(pattern)
    return False


def blocks_serving(blocks, domain, port):
    return [b for b in blocks if port in b["listens"] and any(name_matches(n, domain) for n in b["names"])]


def cert_covers(store):
    crt, key = CERT_STORES[store]
    res = srv(f"test -r {crt} && test -r {key} && openssl x509 -in {crt} -noout -checkend 604800 >/dev/null "
              f"&& openssl x509 -in {crt} -noout -ext subjectAltName 2>/dev/null | grep -o 'DNS:[^,]*' | cut -d: -f2",
              check=False)
    return res.stdout.split() if res.returncode == 0 else []


def pick_cert(choice, domain):
    """-> (kind, crt, key); kind in store-name | letsencrypt | none."""
    if choice == "none":
        return "none", None, None
    if choice == "letsencrypt":
        return "letsencrypt", f"/etc/letsencrypt/live/{domain}/fullchain.pem", f"/etc/letsencrypt/live/{domain}/privkey.pem"
    if choice in CERT_STORES:
        sans = cert_covers(choice)
        if not any(name_matches(s, domain) for s in sans):
            die(f"certificate '{choice}' does not cover {domain} (or expires within 7 days). SANs: {', '.join(sans) or 'unreadable'}")
        return (choice, *CERT_STORES[choice])
    if ":" in choice:
        crt, key = choice.split(":", 1)
        res = srv(f"test -r {shlex.quote(crt)} && test -r {shlex.quote(key)}", check=False)
        if res.returncode != 0:
            die(f"cannot read {crt} / {key} on server-01")
        return "custom", crt, key
    # auto
    for store in CERT_STORES:
        if any(name_matches(s, domain) for s in cert_covers(store)):
            return (store, *CERT_STORES[store])
    return "letsencrypt", f"/etc/letsencrypt/live/{domain}/fullchain.pem", f"/etc/letsencrypt/live/{domain}/privkey.pem"


def render_vhost(domain, backend, port, cert, crt, key, websocket, max_body, with_http80, http80_only=False, backend_host=None):
    ts = time.strftime("%Y-%m-%d %H:%M")
    out = [
        "# ======================================================",
        f"# Domain: {domain}",
        f"# Backend: {backend}",
        MANAGED_MARK,
        f"# Created: {ts}",
        "# ======================================================",
        "",
    ]
    if with_http80:
        redirect = "https://$host$request_uri" if port == 443 else f"https://$host:{port}$request_uri"
        out += [
            "server {",
            "    listen 80;",
            f"    server_name {domain};",
            "",
            "    # ACME HTTP-01 must be served on :80 without redirecting",
            "    location ^~ /.well-known/acme-challenge/ {",
            f"        root {ACME_WEBROOT};",
            '        default_type "text/plain";',
            "        try_files $uri =404;",
            "    }",
            "",
            "    location / {",
            f"        return 301 {redirect};",
            "    }",
            "}",
            "",
        ]
    if http80_only:
        return "\n".join(out)
    listen = f"{port} ssl http2" if cert != "none" else f"{port}"
    out += ["server {", f"    listen {listen};", f"    server_name {domain};", ""]
    if cert != "none":
        out += [
            f"    ssl_certificate     {crt};",
            f"    ssl_certificate_key {key};",
            "    ssl_protocols TLSv1.2 TLSv1.3;",
            "    ssl_ciphers HIGH:!aNULL:!MD5;",
            "    ssl_prefer_server_ciphers on;",
            '    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
            "",
        ]
    out += [
        f"    client_max_body_size {max_body};",
        "",
        "    location / {",
        f"        proxy_pass {backend};",
        "        proxy_http_version 1.1;",
    ]
    if websocket:
        out += [
            "        proxy_set_header Upgrade $http_upgrade;",
            '        proxy_set_header Connection "upgrade";',
            "        proxy_cache_bypass $http_upgrade;",
            "        proxy_read_timeout 3600s;",
            "        proxy_send_timeout 3600s;",
        ]
    else:
        out += [
            "        proxy_read_timeout 60s;",
            "        proxy_send_timeout 60s;",
        ]
    out += [
        f"        proxy_set_header Host {backend_host or '$host'};",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
        "        proxy_connect_timeout 30s;",
        "    }",
        "}",
        "",
    ]
    return "\n".join(out)


def install_vhost_script(avail, enabled, content, backup_dir):
    """Write vhost, nginx -t, reload; roll back on failure."""
    delim = "P2P_EOF_" + str(int(time.time()))
    return f"""set -u
mkdir -p {backup_dir}
[ -e {avail} ] && cp -a {avail} {backup_dir}/
cat > {avail}.p2p-new <<'{delim}'
{content}
{delim}
mv {avail}.p2p-new {avail}
ln -sfn {avail} {enabled}
if {NGINX} -t 2>/tmp/p2p-nginx-test.log; then
  systemctl reload nginx && echo P2P_RELOADED
else
  cat /tmp/p2p-nginx-test.log
  if [ -e {backup_dir}/$(basename {avail}) ]; then cp -a {backup_dir}/$(basename {avail}) {avail}; else rm -f {avail} {enabled}; fi
  {NGINX} -t >/dev/null 2>&1 && echo P2P_ROLLED_BACK
  exit 3
fi
"""


def ensure_web_forward(port, notes, cmds_out):
    """Make sure PUBLIC_IP tcp/port reaches server-01 on MikroTik."""
    hits = dstnat_hits(PUBLIC_IP, "tcp", port, port)
    if any(h["to-addresses"] == SERVER_HOST for h in hits):
        notes.append(f"MikroTik already forwards {PUBLIC_IP} tcp/{port} to server-01")
        return
    if hits:
        die(f"{PUBLIC_IP} tcp/{port} is forwarded elsewhere: {describe_rule(hits[0])}")
    c, _ = plan_forward(f"web-{port}", "custom", ["tcp"], PUBLIC_IP, (port, port), SERVER_HOST, (port, port))
    cmds_out += c


def cmd_proxy_add(args):
    domain = args.domain.lower().strip(".")
    if not DOMAIN_RE.fullmatch(domain):
        die(f"invalid domain '{domain}'")
    if not BACKEND_RE.fullmatch(args.backend):
        die("backend must look like http://192.168.24.50:8080 or http://10.10.194.250:3000/path")
    port = args.listen_port or (80 if args.cert == "none" else 443)

    blocks = nginx_server_blocks()
    clash = blocks_serving(blocks, domain, port)
    if clash:
        die(f"{domain} is already served on :{port} by {', '.join(sorted({b['file'] for b in clash}))}")
    need_http80 = args.cert != "none" and not blocks_serving(blocks, domain, 80)

    avail = f"{NGINX_AVAILABLE}/{domain}.conf"
    enabled = f"{NGINX_ENABLED}/zz-{domain}.conf"
    res = srv(f"ls -1 {avail} {NGINX_ENABLED}/*{domain}* 2>/dev/null", check=False)
    if res.stdout.strip():
        die(f"config file(s) already exist for {domain}: {res.stdout.split()} - remove or pick another domain")

    cert, crt, key = pick_cert(args.cert, domain)
    notes = []
    try:
        resolved = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except socket.gaierror:
        resolved = []
    if PUBLIC_IP in resolved:
        notes.append(f"DNS: {domain} resolves to {PUBLIC_IP}")
    else:
        notes.append(f"DNS: {domain} resolves to {resolved or 'nothing'}, not {PUBLIC_IP} - create/fix the A record")
        if cert == "letsencrypt":
            die(f"Let's Encrypt needs {domain} -> {PUBLIC_IP} in public DNS first")
    probe = srv(f"curl -sk -o /dev/null -m 5 -w '%{{http_code}}' {shlex.quote(args.backend)}", check=False)
    code = probe.stdout.strip() or "000"
    notes.append(f"backend {args.backend} answers HTTP {code} from server-01" if code != "000"
                 else f"backend {args.backend} is NOT reachable from server-01 right now")

    mt_cmds = []
    ensure_web_forward(port, notes, mt_cmds)
    if need_http80 and port != 80:
        ensure_web_forward(80, notes, mt_cmds)

    if args.backend_host and not DOMAIN_RE.fullmatch(args.backend_host) and not re.fullmatch(r"[\d.]+(:\d+)?", args.backend_host):
        die(f"invalid --backend-host '{args.backend_host}'")
    content = render_vhost(domain, args.backend, port, cert, crt, key, args.websocket, args.max_body, need_http80,
                           backend_host=args.backend_host)
    print(f"\nPLAN  reverse proxy https://{domain}{'' if port == 443 else ':' + str(port)}  ->  {args.backend}")
    print(f"  cert: {cert}{' (' + crt + ')' if crt else ''}   websocket: {args.websocket}   :80 redirect block: {need_http80}")
    print(f"  files: {avail}  (enabled as {enabled})")
    for n in notes:
        print(f"  note: {n}")
    for c in mt_cmds:
        print(f"  MikroTik: {c}")
    print("  --- vhost ---")
    print("  " + content.replace("\n", "\n  "))
    if not args.apply:
        print("(dry run - re-run with --apply to execute)")
        return

    if mt_cmds:
        mt_backup()
        for c in mt_cmds:
            mt(c)
        ok("MikroTik forward(s) added")

    backup_dir = f"{NGINX_BACKUPS}/p2p-{time.strftime('%Y%m%d-%H%M%S')}"
    if cert == "letsencrypt":
        stage1 = render_vhost(domain, args.backend, port, cert, crt, key, args.websocket, args.max_body, True, http80_only=True)
        r = srv(install_vhost_script(avail, enabled, stage1, backup_dir), check=False)
        if "P2P_RELOADED" not in r.stdout:
            die(f"nginx rejected the ACME stage config:\n{r.stdout}{r.stderr}")
        email = f"-m {shlex.quote(args.email)} --agree-tos" if args.email else "--agree-tos --register-unsafely-without-email"
        r = srv(f"certbot certonly --webroot -w {ACME_WEBROOT} -d {domain} --non-interactive --keep-until-expiring {email} 2>&1 && "
                "mkdir -p /etc/letsencrypt/renewal-hooks/deploy && "
                "f=/etc/letsencrypt/renewal-hooks/deploy/p2p-reload-nginx.sh; "
                "[ -e $f ] || { printf '#!/bin/sh\\nsystemctl reload nginx\\n' > $f; chmod 755 $f; }", check=False, timeout=300)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            die("certbot failed - the :80 ACME vhost is left in place; fix DNS/port 80 and re-run, or run `proxy remove`")
        ok("Let's Encrypt certificate issued (auto-renew via certbot.timer, nginx reload hook installed)")

    r = srv(install_vhost_script(avail, enabled, content, backup_dir), check=False)
    if "P2P_RELOADED" not in r.stdout:
        die(f"nginx -t failed, change rolled back:\n{r.stdout}{r.stderr}")
    ok(f"nginx reloaded with {avail}")

    scheme = "http" if cert == "none" else "https"
    r = srv(f"curl -sk -o /dev/null -m 10 -w '%{{http_code}}' --resolve {domain}:{port}:127.0.0.1 {scheme}://{domain}:{port}/", check=False)
    info(f"local check on server-01: {scheme}://{domain}:{port}/ -> HTTP {r.stdout.strip() or '000'}")


def cmd_proxy_remove(args):
    domain = args.domain.lower().strip(".")
    if not DOMAIN_RE.fullmatch(domain):
        die(f"invalid domain '{domain}'")
    avail = f"{NGINX_AVAILABLE}/{domain}.conf"
    enabled = f"{NGINX_ENABLED}/zz-{domain}.conf"
    res = srv(f"test -e {avail} && grep -c '{MANAGED_MARK}' {avail}; ls -1 {enabled} 2>/dev/null", check=False)
    lines = res.stdout.split()
    if not lines:
        die(f"{avail} not found")
    managed = lines[0] not in ("0", "")
    if not managed and not args.force:
        die(f"{avail} was not created by this tool; re-run with --force to remove it anyway")
    print(f"\nPLAN  remove reverse proxy {domain}")
    print(f"  move {avail} (+ link {enabled}) to {NGINX_BACKUPS}/p2p-<timestamp>/, nginx -t, reload")
    if args.delete_cert:
        print(f"  certbot delete --cert-name {domain}")
    print("  MikroTik 80/443 forwards are shared and are left untouched")
    if not args.apply:
        print("\n(dry run - re-run with --apply to execute)")
        return
    backup_dir = f"{NGINX_BACKUPS}/p2p-{time.strftime('%Y%m%d-%H%M%S')}"
    r = srv(f"""set -u
mkdir -p {backup_dir}
mv {avail} {backup_dir}/
rm -f {enabled}
if {NGINX} -t 2>/tmp/p2p-nginx-test.log; then systemctl reload nginx && echo P2P_RELOADED
else cat /tmp/p2p-nginx-test.log; mv {backup_dir}/{domain}.conf {avail}; ln -sfn {avail} {enabled}; exit 3; fi
""", check=False)
    if "P2P_RELOADED" not in r.stdout:
        die(f"nginx -t failed after removal, restored:\n{r.stdout}{r.stderr}")
    ok(f"removed; backup kept in {backup_dir}")
    if args.delete_cert:
        r = srv(f"certbot delete --cert-name {domain} --non-interactive 2>&1", check=False)
        (ok if r.returncode == 0 else warn)(f"certbot delete {domain}: {r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.returncode}")


# ---------------------------------------------------------------------------
# Read-only commands
# ---------------------------------------------------------------------------
def cmd_check(args):
    ident = mt(":put [/system identity get name]; :put [/system resource get version]").split("\n")
    ok(f"MikroTik {MT_HOST}: identity={ident[0].strip()} RouterOS={ident[1].strip() if len(ident) > 1 else '?'}")
    r = srv(f"hostname; {NGINX} -v 2>&1; {NGINX} -t 2>&1 | tail -1")
    ok(f"server-01 {SERVER_HOST}: " + " | ".join(r.stdout.split("\n")[:3]))
    ok(f"sudo mode on server-01: {_sudo_mode}")


def cmd_list(args):
    ip = args.public_ip
    print(f"\n== MikroTik dst-nat rules for {ip} ==")
    rows = [r for r in mt_rows("/ip firewall nat", "chain=dstnat", NAT_FIELDS) if addr_matches(r["dst-address"], ip)]
    for r in rows:
        flag = "X " if r["disabled"] == "true" else "  "
        mark = "*" if r["comment"].startswith(TAG) else " "
        print(f" {mark}{flag}{(r['protocol'] or 'any'):4} {r['dst-port'] or 'any':>13} -> {r['to-addresses']}:{r['to-ports'] or '(same)':13} {r['comment']}")
    print("   (* = managed by this tool, X = disabled)")
    print("\n== nginx server blocks on server-01 ==")
    for b in nginx_server_blocks():
        f = (b["file"] or "?").replace(NGINX_ENABLED + "/", "").replace(NGINX_AVAILABLE + "/", "")
        print(f"   {','.join(map(str, b['listens'])) or '-':10} {' '.join(b['names'])[:60]:60} {f}")
    res = srv(f"grep -l '{MANAGED_MARK}' {NGINX_AVAILABLE}/*.conf 2>/dev/null", check=False)
    managed = [os.path.basename(p) for p in res.stdout.split()]
    print(f"\n   managed by this tool: {', '.join(managed) or 'none'}")


def cmd_port_check(args):
    lo, hi = port_range(args.port)
    protos = ["tcp", "udp"] if args.proto == "both" else [args.proto]
    free = True
    for p in protos:
        for h in dstnat_hits(args.public_ip, p, lo, hi):
            free = False
            print(f"  {p}/{fmt_range(lo, hi)} taken: {describe_rule(h)}")
    if free:
        ok(f"{args.public_ip} {'+'.join(protos)}/{fmt_range(lo, hi)} is free on MikroTik")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    if subprocess.run(["which", "sshpass"], capture_output=True).returncode != 0:
        die("sshpass is not installed (apt install sshpass)")
    ap = argparse.ArgumentParser(prog="p2p.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("login", help="store passwords in a RAM-only session file").set_defaults(fn=cmd_login)
    sub.add_parser("logout", help="delete the session file").set_defaults(fn=cmd_logout)
    sub.add_parser("check", help="test SSH to both devices").set_defaults(fn=cmd_check)

    p = sub.add_parser("list", help="show dst-nat rules for the public IP and nginx vhosts")
    p.add_argument("--public-ip", default=PUBLIC_IP)
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("port-check", help="is a public port/range free on MikroTik?")
    p.add_argument("--proto", choices=["tcp", "udp", "both"], required=True)
    p.add_argument("--port", required=True)
    p.add_argument("--public-ip", default=PUBLIC_IP)
    p.set_defaults(fn=cmd_port_check)

    fw = sub.add_parser("forward", help="MikroTik port forwarding").add_subparsers(dest="action", required=True)
    p = fw.add_parser("add")
    p.add_argument("--name", required=True, help="short id, becomes comment p2p:<name>")
    p.add_argument("--type", choices=list(TYPE_DEFAULTS), default="custom")
    p.add_argument("--proto", choices=["tcp", "udp", "both"])
    p.add_argument("--port", help="public port or range, e.g. 5000 or 16384-32768")
    p.add_argument("--to-ip", default=SERVER_HOST, help=f"private target (default {SERVER_HOST})")
    p.add_argument("--to-port", help="private port (single-port forwards only; default = same)")
    p.add_argument("--public-ip", default=PUBLIC_IP)
    p.add_argument("--apply", action="store_true")
    p.set_defaults(fn=cmd_forward_add)
    p = fw.add_parser("remove")
    p.add_argument("--name", required=True)
    p.add_argument("--apply", action="store_true")
    p.set_defaults(fn=cmd_forward_remove)

    px = sub.add_parser("proxy", help="nginx reverse proxy on server-01").add_subparsers(dest="action", required=True)
    p = px.add_parser("add")
    p.add_argument("--domain", required=True)
    p.add_argument("--backend", required=True, help="e.g. http://192.168.24.104:3000")
    p.add_argument("--cert", default="auto",
                   help="auto | alaapcloud | btclip | letsencrypt | none | /path/crt:/path/key")
    p.add_argument("--listen-port", type=int, help="public HTTPS port (default 443)")
    p.add_argument("--websocket", action="store_true")
    p.add_argument("--max-body", default="50M")
    p.add_argument("--backend-host", help="Host header sent to the backend (default: the public domain)")
    p.add_argument("--email", help="Let's Encrypt account email (optional)")
    p.add_argument("--apply", action="store_true")
    p.set_defaults(fn=cmd_proxy_add)
    p = px.add_parser("remove")
    p.add_argument("--domain", required=True)
    p.add_argument("--force", action="store_true", help="allow removing a vhost not created by this tool")
    p.add_argument("--delete-cert", action="store_true", help="also delete its Let's Encrypt certificate")
    p.add_argument("--apply", action="store_true")
    p.set_defaults(fn=cmd_proxy_remove)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

---
name: public-to-private
description: Use when a service on BTCL server-01 (192.168.24.101) or another host behind MikroTik-01 (192.168.24.1) must be reachable from the internet - RTP/media UDP port ranges, WireGuard, custom TCP/UDP port forwarding, nginx HTTP/HTTPS reverse proxy for a domain - or when listing, checking or removing such public-to-private mappings.
---

# Public-to-Private Exposure (server-01 + MikroTik-01)

## Overview

Internet traffic hits MikroTik-01's public IP `114.130.145.76` (WAN `sfp-sfpplus14`). The router dst-nats it to a private
host, and for web traffic nginx on server-01 terminates TLS and reverse-proxies to the backend. All work goes through
`scripts/p2p.py`. It plans first, changes nothing without `--apply`, backs up before every change, and tags every
MikroTik rule with `comment="p2p:<name>"`.

The operator must be on the private network (office VPN). Needs `python3` and `sshpass` locally.

## Step 1: Credentials (every session)

Passwords are **never** written into this skill, the repo, or any file on disk.

1. Run `python3 <skill-dir>/scripts/p2p.py check`. If it succeeds, credentials are already available (env vars
   `P2P_SERVER_PASS` / `P2P_MIKROTIK_PASS`, or a live RAM session). Go to step 2.
2. Otherwise, ask the user for the **server-01 password** (user `telcobright`) and the **MikroTik-01 password** (user `admin`).
   Mention that they can avoid typing passwords in chat by exporting the two env vars before starting the agent.
3. Store them once in the RAM-only session (`/dev/shm`, mode 600, 8h expiry). Single-quote each password and escape
   embedded `'` as `'\''`:
   ```bash
   P2P_SERVER_PASS='<server pw>' P2P_MIKROTIK_PASS='<mikrotik pw>' python3 <skill-dir>/scripts/p2p.py login
   python3 <skill-dir>/scripts/p2p.py check
   ```
4. When the work is finished, run `python3 <skill-dir>/scripts/p2p.py logout`. Skip this if the credentials came from env vars.

Never echo, log or save the passwords anywhere else.

## Step 2: Gather the request, then plan

Ask only for what is missing:

| Need | Ask for |
|---|---|
| RTP / media | UDP port range, target IP (default server-01) |
| WireGuard | UDP port (default 51820), target IP |
| Custom forward | tcp/udp/both, public port, target IP, target port |
| Reverse proxy | domain, backend URL (`http://ip:port`, any host server-01 can reach), WebSocket? public port (default 443) |

Each forward needs a short `--name` (letters, digits, `.`, `_`, `-`). Proxies are identified by `--domain`.

Always run the command **without `--apply` first** and show the user the plan, including its conflicts and notes.
Several requests can go into one confirmation message. Apply only after the user confirms.

How to read the plan notes:
- `N listener(s) inside <range>` is informational. For RTP ranges these are live media sockets, which is normal.
- `backend ... answers HTTP 4xx/5xx` means the app is up but may reject the domain (see Common Mistakes). Tell the user before applying.
- `backend ... NOT reachable` means stop and confirm the backend IP/port with the user.
- `DNS: ... not 114.130.145.76` means the A record must be fixed first. Let's Encrypt plans abort on this.

## Quick Reference

```bash
P=<skill-dir>/scripts/p2p.py
python3 $P list                                   # all dst-nat on .76 + nginx vhosts (* = managed by p2p)
python3 $P port-check --proto udp --port 16384-32768

python3 $P forward add --name fs-rtp  --type rtp --port 16384-32768 [--to-ip 192.168.24.101]
python3 $P forward add --name wg-srv1 --type wireguard [--port 51820] [--to-ip ...]
python3 $P forward add --name api-x   --proto tcp --port 8085 --to-ip 192.168.24.104 --to-port 8080
python3 $P forward remove --name api-x

python3 $P proxy add --domain app.alaapcloud.gov.bd --backend http://192.168.24.104:3000 [--websocket] \
    [--cert auto|alaapcloud|btclip|letsencrypt|none|/crt:/key] [--listen-port 443] [--backend-host H] [--max-body 50M]
python3 $P proxy remove --domain app.alaapcloud.gov.bd [--delete-cert] [--force]
# add --apply to any add/remove after the user approves the dry-run plan
```

## What the tool does

- **forward add**: adds two rules, a dst-nat (`.76:port -> target:port`) and a `forward accept` rule (placed before
  the first forward `drop`). It does not add a NAT-table "input" rule: no rule ever jumps to that chain, so it does nothing.
  It refuses on overlap with any enabled dst-nat for that IP, proto and ports, and reports "already forwarded" if the exact mapping exists.
- **proxy add**: writes `/etc/nginx/sites-available/<domain>.conf`, links it as `sites-enabled/zz-<domain>.conf`, and adds a `:80`
  ACME + redirect block if nothing serves that domain on :80 yet. Then it runs `nginx -t` and reloads; if the test fails it rolls back automatically.
  `--cert auto` uses an existing cert only if its SANs cover the domain. Otherwise it gets a Let's Encrypt cert through the
  webroot `/var/www/acme`, which needs public DNS pointing at `.76`. It also makes sure MikroTik forwards tcp 80/443 (or `--listen-port`) to server-01.
- **Backups**: MikroTik `/ip firewall export file=p2p-backup-<ts>` (keeps the newest 10); nginx files go to `/etc/nginx/backups/p2p-<ts>/`.

## Common Mistakes

| Symptom | Fix |
|---|---|
| RTP forwarded but one-way/no audio | FreeSWITCH advertises `external_rtp_ip=192.168.24.101`. The SIP profile must advertise `114.130.145.76`. The tool only warns about this. Change FreeSWITCH only if the user explicitly asks. |
| Plan or live proxy shows backend 403/400/"Invalid Host" | The backend app checks the Host header (e.g. a Vite/Next `allowedHosts`). Add the domain on the app side, or re-create the proxy with `--backend-host <name it accepts>`. |
| `CONFLICT` on a port | Pick another public port, or remove the old mapping. Never delete untagged rules without the user's explicit approval. |
| certbot fails | The A record isn't pointing at `114.130.145.76` yet, or :80 is not reaching server-01. Fix it, then re-run. |
| `proxy remove` refuses | The vhost was not created by this tool. Only use `--force` when the user explicitly confirms. |
| UDP forward shows no probe | Expected: only TCP gets a reachability probe. Verify UDP from an outside client. |
| Want a different public IP | Use `--public-ip 114.130.145.75`. It defaults to `.76`; `.75` carries the SSH jump ports. |

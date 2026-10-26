# public-to-private (agent skill)

An AI-agent skill (Claude Code / Agent Skills format) that exposes private services behind **MikroTik-01**
through **BTCL server-01** to the internet:

- RTP / media UDP port-range forwarding
- WireGuard port forwarding
- Custom TCP/UDP port forwarding (incl. port translation)
- nginx HTTP/HTTPS reverse proxy (existing certs or Let's Encrypt)
- List / check / remove mappings

Every change is planned first (dry run), backed up, applied only with `--apply`, and tagged so it can be removed cleanly.

**No credentials are stored in this repository.** The agent asks for the server and MikroTik passwords when the skill
is used and keeps them only in RAM (`/dev/shm`, 8h expiry, `logout` to wipe).

## Requirements

- Access to the private network `192.168.24.0/24` (office VPN)
- `python3` (stdlib only) and `sshpass` (`sudo apt install sshpass`)

## Install

```bash
git clone <this repo> ~/.claude/skills/public-to-private      # personal skill
# or: copy the folder into <project>/.claude/skills/public-to-private
```

Then ask the agent something like *"forward UDP 16384-32768 to server-01 for RTP"* or
*"reverse proxy app.alaapcloud.gov.bd to http://192.168.24.104:3000"*.

## Manual use

```bash
python3 scripts/p2p.py login        # prompts for both passwords (or reads P2P_SERVER_PASS / P2P_MIKROTIK_PASS)
python3 scripts/p2p.py list
python3 scripts/p2p.py forward add --name wg-test --type wireguard            # dry run
python3 scripts/p2p.py forward add --name wg-test --type wireguard --apply
python3 scripts/p2p.py forward remove --name wg-test --apply
python3 scripts/p2p.py logout
```

Run `python3 scripts/p2p.py <command> --help` for all options.

## Defaults (override with env vars)

| Setting | Default | Env var |
|---|---|---|
| server-01 | `telcobright@192.168.24.101:22` | `P2P_SERVER_HOST`, `P2P_SERVER_USER`, `P2P_SERVER_PORT` |
| MikroTik-01 | `admin@192.168.24.1:22` | `P2P_MIKROTIK_HOST`, `P2P_MIKROTIK_USER`, `P2P_MIKROTIK_PORT` |
| Public IP | `114.130.145.76` | `P2P_PUBLIC_IP` |

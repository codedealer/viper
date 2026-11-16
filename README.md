# Viper

One-command VLESS/REALITY VPN server: a commodity nginx + Xray box with no
custom backend. Viper renders every artifact for a server from a single
`viper.<name>.yml`, deploys it over SSH, and keeps it verifiable — the
decoy website, the Let's Encrypt cert, the subscription, the Xray unit —
with idempotent, check-then-act pipeline steps.

```
client ──VLESS/REALITY──▶ xray :443  (nginx serves the borrowed LE cert via Reality)
client ──HTTPS──────────▶ nginx :443 (decoy page at /, /login; subscription at /<hash>/sub.txt)
                             └─ loopback :8443  (web vhost behind the Reality dest)
```

Server secrets (Reality keypair, client UUIDs, sub hash, SSH host key) live
in `state/<name>.yml` — chmod 600, gitignored, written locally **before**
anything touches the server.

## Quick start

1. **Provision a fresh VPS** (Ubuntu 24.04, root SSH access). Note its IPv4.
2. **Point DNS**: create an `A` record `vpn.example.com → <ip>`. Wait until it
   resolves (the deploy preflight checks the A record → ip).
3. **Write the config** — `viper.main.yml` at the repo root:

   ```yaml
   ip: 203.0.113.10
   domain: vpn.example.com
   xray: v26.3.27            # hard pin; install step verifies on drift
   sshPort: 22
   sshKey: /home/me/.ssh/id_ed25519   # optional; default SSH key resolution
   # allowIPv6: false        # v4-only is the default; `true` keeps the
                              # provider's IPv6 (opt-out of the disable step)
   clients:
     - name: default
       limitIp: 0            # 0 = unlimited concurrent ips
   ```

   (Every field and its default is in the [knob reference](#knob-reference).)
4. **Deploy**:

   ```sh
   pnpm viper deploy --name main
   ```

   The pipeline runs: preflight (OS, disk, ssh port, DNS, host-key capture) →
   packages → hardening (tz, unattended-upgrades, sshd, fail2ban, BBR,
   Configure IPv6, ufw) → pinned Xray install → Xray deploy + verify
   (unit active, listening on :443, REALITY handshake probe) → nginx
   (stock default site removed first, then acme.sh, LE cert, decoy page,
   subscription, web vhost, public-path verifies). Every step is
   check-then-act, so re-running `deploy` on a live server is safe.

   If the VPS IP changed after the config was written, override it for this
   run only: `pnpm viper deploy --name main --ip 198.51.100.9` (no file
   writes; a notice is printed).
5. **Import the subscription** in [Happ](https://happ.dev/). The deploy tail
   prints the subscription URL and the copy-paste lines:

   ```
   Subscription: https://vpn.example.com/<subHash>/sub.txt
   vless://<uuid>@vpn.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=...&fp=chrome&pbk=...&sid=...&type=tcp&headerType=none#default
   ```

   If the config has a `routing:` block, the tail (and the `sub.txt` body)
   additionally carry the Happ routing profile line:

   ```
   happ://routing/onadd/<base64 routing profile>
   ```

6. **Verify**: `pnpm viper status --name main` — live panel showing Xray
   version/unit state, host CPU/RAM/disk, per-client traffic, a Warnings
   panel (xray/nginx error logs, failed units, fail2ban bans, cert expiry,
   disk pressure), the REALITY handshake check, the borrowed LE cert, and
   the subscription mtime.

## Command reference

All commands run from the repo root: `pnpm viper <cmd> [--name <server>] [--ip <ip>]`.
`--name` resolves the server (required when more than one
`viper.<name>.yml` exists; the sole server is the default). `--ip` is a
per-run IPv4 override for the SSH target + the preflight DNS check — no file
writes. `-h`/`--help` prints usage.

| Command | SSH | What it does |
|---|---|---|
| `render` | no | Render all artifacts to `generated/<name>/` (`config.json`, `sub.txt`, `index.html`, nginx vhosts); creates `state/<name>.yml` if missing; prints the subscription. |
| `sub` | no | Ensure state, then print the subscription URL + lines. Local only — no VPS access. |
| `deploy` | yes | Full fresh-VPS pipeline (see quick start). Idempotent — safe to re-run on a live server. |
| `update` | yes | No-disruption redeploy: re-render, Xray deploy (validate-before-swap) + verify, nginx steps. No preflight/packages/hardening/Xray install. A healthy cert-issue is skipped (rc 2) → zero Let's Encrypt budget consumption. |
| `status` | yes | Live TUI (ink) over one persistent SSH connection, refreshing every 5 s. `q`/Ctrl-C quit, `r` re-run the checks (handshake probe + cert). The Warnings panel surfaces recent xray/nginx error lines, failed systemd units, the fail2ban sshd ban count, cert days remaining (warns < 14 d), and root-disk use% (warns ≥ 80%). When stdout is not a TTY, prints a single plain-text snapshot and exits. |
| `rotate` | yes | Full credential rotation: new Reality keypair, new UUID for every client, new sub hash (new sub path). Persists the new state locally first, then runs the `update` pipeline. **The old subscription is invalid afterwards** — re-import the new one (printed with a warning). Requires an existing state file. |
| `teardown` | yes | Remove viper's Xray (unit, binary, geo assets, config) and nginx artifacts (viper vhosts, acme renewal cron, page + subscription files). Requires an existing state file. See [teardown](#teardown) for what is kept. |

## Knob reference

Every field of `viper.<name>.yml`, with its default. `src/config.ts` is the
single source of truth — unknown keys are rejected, so this table and the
validator stay in sync.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `ip` | string | — (required) | Server IPv4. Used for the SSH target and the preflight DNS A-record check. |
| `domain` | string | — (required) | The public domain (A record → `ip`). SNI, cert, subscription host. |
| `xray` | string | — (required) | Hard version pin, `vN.N.N` (e.g. `v26.3.27`). Install verifies the binary; a drift triggers an in-place re-install. |
| `sshPort` | int | `22` | SSH port for the deploy connection. |
| `sshKey` | string | default SSH resolution | Path to the private key for SSH. |
| `listen` | string | `0.0.0.0` | Xray inbound listen address. |
| `port` | int | `443` | Public Xray/VLESS port (behind the nginx-borrowed LE cert). |
| `webPort` | int | `8443` | Loopback nginx web vhost port — Xray Reality `dest`. |
| `fingerprint` | enum | `chrome` | REALITY TLS fingerprint: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`. |
| `flow` | enum | `xtls-rprx-vision` | XTLS flow; `""` disables flow. |
| `shortId` | string | auto | Reality shortId (0–16 hex chars, even length). Omit to auto-generate once into `state/<name>.yml`; a pinned value here always wins. |
| `maxTimediff` | int | `0` | Xray `maxTimediff` (ms); `0` = unset. |
| `xver` | int | `0` | REALITY `xver` (0–255). |
| `logLevel` | enum | `warning` | Xray log level: `debug`, `info`, `warning`, `error`. |
| `sniffing` | bool | `true` | Xray DNS sniffing (routing for non-HTTP traffic). |
| `harden` | bool | `true` | Gates the hardening steps (timezone, unattended-upgrades, sshd hardening, fail2ban, ufw). |
| `bbr` | bool | `true` | Gates the BBR congestion-control step. |
| `allowIPv6` | bool | `false` | M8 network posture: the server is IPv4-only by default — the deploy's `Configure IPv6` step disables kernel IPv6 (persisted to `/etc/sysctl.d/99-viper-ipv6.conf`) so there is no v6 egress or inbound listener. `true` never disables, and re-enables if a previous deploy disabled it (detached interface bounce + poll; a missing v6 address is non-fatal — reboot completes it). Deploy-only knob: changing it on a live box means re-running `deploy` (idempotent); `viper status` shows the actual state. |
| `clients` | list | `[{ name: default }]` | One entry per user: `name` (unique; used as the stat label + subscription tag) and `limitIp` (0–65535, default `0` = unlimited concurrent IPs). Each client gets a UUID in `state/<name>.yml`. |
| `routing` | block | absent | **Opt-in Happ routing profile.** Presence = ship a `happ://routing/onadd/{base64}` line in `sub.txt` (and the deploy/sub tail); absence = no routing line. `name` is required; all other keys are Happ's profile field names (the documented set plus builder-sourced `RouteOrder`), validated against that set, and merged over Happ's documented default profile (unset fields keep the defaults). Rule order is pinned by viper: `RouteOrder` — default `block-direct-proxy` (block → direct → proxy); the six accepted values are listed in the example below. |

`routing` block (all profile fields optional — unset fields fall back to the pinned
defaults: Happ's documented defaults, plus `RouteOrder` pinned to `block-direct-proxy`):

```yaml
routing:            # absent → no routing line in sub.txt
  name: Viper       # required; Happ profile name (a stable name makes
                    # re-imports update the profile in place)
  GlobalProxy: true             # bool (rendered as "true"/"false")
  RemoteDNSType: DoH            # DoH | DoU
  RemoteDNSDomain: https://cloudflare-dns.com/dns-query
  RemoteDNSIP: 1.1.1.1
  DomesticDNSType: DoU
  DomesticDNSDomain: ""         # empty string is legal with DoU
  DomesticDNSIP: 8.8.8.8
  Geoipurl: https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
  Geositeurl: https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
  DomainStrategy: IPIfNonMatch  # IPIfNonMatch | AsIs
  FakeDNS: false                # bool
  RouteOrder: block-direct-proxy  # rule order (Happ's routing builder); viper pins the
                                  # app default: block → direct → proxy. Also accepted:
                                  # block-proxy-direct, proxy-direct-block,
                                  # proxy-block-direct, direct-proxy-block, direct-block-proxy
  # rule stack (evaluated per `RouteOrder`; strings or string maps, no syntax validation)
  BlockSites: ["geosite:ads"]
  BlockIp: ["geoip:ads"]
  DirectSites: ["geosite:geolocation-cn"]
  DirectIp: ["geoip:cn"]
  ProxySites: []
  ProxyIp: []
  # also accepted: LastUpdated, DnsHosts (host → IP map)
```

## Stories

### Re-deploy (`update`)

Config or artifacts changed (new client added, fingerprint changed, page
tweaked)? `pnpm viper update --name main` re-renders and re-pushes the Xray
config (validated with `xray -test` **before** any swap — an invalid config
leaves the running one untouched) and the nginx artifacts (`nginx -t` gated).
No hardening, no package work, no Xray install, and a valid cert is skipped —
an unchanged config means no restart at all (zero disruption).

### Credential rotation (`rotate`)

`pnpm viper rotate --name main` regenerates the Reality keypair, a fresh
UUIDv4 for **every** client, and a new sub hash — the subscription path
changes, so the old subscription URL dies with it. The new state is persisted
locally (chmod 600) before any remote step, then the `update` pipeline pushes
the new credentials. The command prints the new subscription with an explicit
warning; re-import it in every client. `hostKey`, `installedPackages` and a
state-pinned `shortId` are preserved.

### Teardown

`pnpm viper teardown --name main` removes viper's footprint:

- **Removed**: xray unit (stopped + disabled), the xray binary + geoip/geosite
  assets, `/etc/xray/config.json`, viper's nginx vhosts, the acme renewal
  cron entry, the deployed page/subscription files.
- **Kept (deliberately)**: the nginx package, `/root/.acme.sh/`, and all
  hardening (ufw, sshd drop-in, fail2ban, BBR, unattended-upgrades, and the
  M8 IPv6 disable — teardown keeps the network posture; un-hardening is out
  of scope). The local `state/<name>.yml` is also kept, so
  re-deploy stays possible.
- **Cert + renewal caveat (read before decommissioning).** Teardown removes
  the acme.sh *renewal cron entry* only — `/root/.acme.sh/` (the issued cert
  **and its private key**) is never touched by viper. Without the cron, the
  surviving cert is **not auto-renewed** and will expire (~90 days after it
  was issued) unless another mechanism takes over renewal.

  **Sensitivity:** `/root/.acme.sh/<domain>/` holds the private key. If it is
  lost, re-issuing is a *new* certificate. **Back up `/root/.acme.sh/<domain>/` manually before decommissioning a VPS**; viper-side cert backup/export is deliberately out of scope for v1 (backups are manual).

## Security notes

- **`state/<name>.yml` is a secret.** It holds the Reality keypair (whoever
  holds the private key can impersonate the server), the client UUIDs and the
  sub hash. It is created chmod 600 and gitignored — never commit it, never
  paste it into a ticket. `generated/` is gitignored too (it embeds the same
  secrets).
- **Host-key pinning.** The server's SSH host key is captured into
  `state/<name>.yml` on first deploy and verified on every later connect. A
  mismatch aborts before any step runs — either the box was re-imaged (delete
  `state/<name>.yml` to re-key) or something is intercepting the connection.
- **Decoy-page correlation warning.** The decoy login page is one fixed static
  artifact, identical across all viper servers. Do **not** run several viper
  servers with the identical live decoy page concurrently — an identical page
  (plus an identical certificate shape) is a correlation fingerprint that ties
  the servers together. Per-server variation is a future item.
- **Hardening.** `deploy` applies ufw (only the ssh port + 80/443 in), an
  sshd drop-in (keys only, no root password), fail2ban, BBR and
  unattended-upgrades. There is no un-hardening command; `teardown` leaves
  the hardening in place.
- **Xray log rotation.** viper installs `/etc/logrotate.d/xray` to rotate
  `/var/log/xray/*.log` (daily, keep 14, `copytruncate` — Xray holds its log
  fds open, so rename+create would not rotate until a restart). Re-asserted
  on every `deploy`/`update`; removed by `teardown`.
- **Let's Encrypt renewal.** The cert is issued via acme.sh (HTTP-01 on port
  80) and renewed by an acme.sh cron — 90-day certs, renewed well inside
  validity. Renewal needs port 80 reachable from the internet; if the ACME
  vhost is removed or port 80 blocked, renewals fail silently until the next
  `deploy`/`update` re-asserts them.

## Development

```sh
pnpm install
pnpm typecheck    # tsc --noEmit
pnpm test         # node --test (unit: renderers, state, steps vs a fake SSH remote)
pnpm build        # vite → dist/index.js (single bundle; ssh2 external)
pnpm viper --help # run the CLI directly (tsx src/cli.ts)
```

Layout: `src/cli.ts` (dispatch) · `src/config.ts` (schema) · `src/state.ts`
(secrets) · `src/keys.ts` (generators) · `src/render/*` (artifacts) ·
`src/steps/*` (pipeline steps) · `src/pipeline.ts` (composition) ·
`src/rotate.ts` (pure rotation) · `src/status.ts` + `src/status-tui.tsx`
(live status) · `src/ssh.ts` (SSH engine) · `test/fake-remote.ts` (in-memory
SSH double).
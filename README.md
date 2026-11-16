# MC Sentinel

A Minecraft server security intelligence and moderation platform. It has three parts:

1. **Discovery engine.** A Copenheimer-style, rate-limited Server List Ping scanner. It builds a searchable index of
   public server metadata and never shows connection endpoints.
2. **Identity verification.** Real Mojang UUID lookups, offline-mode UUID derivation, and premium vs. cracked
   checks.
3. **Moderation federation.** Participating servers push their own login, logout and punishment records. These
   power session analytics, cross-server ban-evasion indicators and cracked-account impersonation detection.

The backend is FastAPI + SQLite. The dashboard is a dependency-free single page that the backend serves.

## Quick start

```bash
cd backend
pip install -r requirements.txt
MCSEC_ADMIN_TOKEN=change-me python -m mcsec    # http://127.0.0.1:8080
```

Or with Docker:

```bash
MCSEC_ADMIN_TOKEN=change-me docker compose up --build
```

Sign in to the dashboard with the admin token. Put a TLS reverse proxy (Caddy, nginx) in front of it before
exposing it beyond localhost.

Run the tests (they start a fake Minecraft server and scan it for real):

```bash
cd backend && pip install -r requirements-dev.txt && pytest
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `MCSEC_ADMIN_TOKEN` | random per run | Dashboard / admin API bearer token |
| `MCSEC_DB` | `mcsec.sqlite3` | SQLite path |
| `MCSEC_HOST` / `MCSEC_PORT` | `127.0.0.1` / `8080` | Bind address |
| `MCSEC_SCAN_RATE` | `50` | Default connections/second per job |
| `MCSEC_SCAN_RATE_MAX` | `1000` | Hard ceiling a job cannot exceed |
| `MCSEC_SCAN_CONCURRENCY` | `200` | Open sockets per job |
| `MCSEC_SCAN_TIMEOUT` | `3` | Seconds per connection |
| `MCSEC_MAX_TARGETS` | `1048576` | Max addresses×ports per job (a /12 at one port) |
| `MCSEC_ALLOW_PRIVATE` | `0` | Allow private/reserved ranges (lab testing only) |
| `MCSEC_EXCLUDE_FILE` | – | File of CIDRs that are never scanned |
| `MCSEC_MOJANG_ENABLED` | `1` | Set `0` for offline/air-gapped use |
| `MCSEC_FED_STALE` | `900` | Seconds before a silent participant's open sessions show as "unknown" |

## 1. Discovery engine

* Accepts IPs, CIDR ranges, hostnames and `host:port`, over one or more ports.
* Sends only the standard status handshake (the multiplayer-screen ping). It never logs in.
* Records: description/MOTD, version, protocol, software (Paper, Purpur, Velocity, Forge…), mod loader and mod
  count, players online/max, whether the player list is hidden, secure-chat enforcement, favicon presence and
  latency.
* "Re-check known servers" re-pings the index to build player-count and uptime time series.

### Endpoint censorship

* Hosts and ports live only in the `endpoints` table, which only `scanner.py` reads. Every other part of the
  system refers to a server by an opaque `srv_…` ID.
* API responses and exports use an explicit field allowlist (`PUBLIC_SERVER_FIELDS` in `api.py`).
* Domains and IPs inside MOTDs are replaced with `[address hidden]` before storage.
* Scan job summaries don't echo target ranges. Unhandled errors return a generic 500, so tracebacks can't leak
  anything.
* `test_scan_discovers_and_never_leaks_endpoint` asserts that no response or export contains the endpoint.

### Responsible scanning

Internet-wide scanning is legal in most jurisdictions but still affects other people's networks. Before running
large jobs:

* **Keep the rate modest.** The default is 50 conn/s, with a hard ceiling set by `MCSEC_SCAN_RATE_MAX`.
* **Identify yourself.** Set reverse DNS on the scanning IP and host a page there explaining the research, with
  an opt-out contact.
* **Honor opt-outs immediately.** Add the range under *Exclusions*. Excluding a range also **purges** any data
  already collected from it.
* **Check your hosting provider's acceptable-use policy.** Many VPS providers forbid scanning without prior
  notice.
* **Expect a sweep to take time.** At 1000 conn/s, a full IPv4 sweep of one port takes roughly 50 days. Split it
  into jobs under the per-job cap.

## 2. Identity verification and cracked-account detection

* **UUID kinds.** Online-mode accounts have Mojang-issued **v4** UUIDs. Offline-mode servers assign
  `md5("OfflinePlayer:" + name)` as a **v3** UUID, which anyone can generate for any name.
* **Verify by name.** Checks for a premium account, returns the canonical spelling and premium UUID, and shows the
  name's offline UUID (its "impersonation surface").
* **Verify by UUID.** Reports the version and kind, checks whether Mojang knows the UUID and returns its current
  name. It also checks whether an offline UUID really derives from the name it was seen with.
* **Compare.** Tells you whether a UUID reported by your server is the genuine premium account for a name, its
  offline clone, or neither.
* **When Mojang is unreachable,** results say so ("Could not verify") instead of guessing.

## 3. Moderation federation

Servers opt in by registering in the dashboard. Each gets an API key, which is shown once and stored as a hash.

```http
POST /api/ingest/events
X-Api-Key: mcs_...
Content-Type: application/json

{"events": [
  {"type": "login",  "uuid": "…", "username": "Steve", "ip_hash": "<hex>", "ts": 1763300000},
  {"type": "logout", "uuid": "…"},
  {"type": "warn",   "uuid": "…", "reason": "spam"},
  {"type": "ban",    "uuid": "…", "reason": "x-ray", "expires_ts": null},
  {"type": "unban",  "uuid": "…"},
  {"type": "heartbeat", "online_uuids": ["…"]}
]}
```

Event types: `login logout heartbeat warn kick mute unmute ban unban`. `ts` is optional and defaults to the receive
time.

**Raw IPs are rejected.** Participants send `ip_hash = HMAC-SHA256(federation_salt, ip)` as hex. The salt is shown
on the Federation page and in the registration response. Because the hash is keyed, the platform can tell when two
connections share a network without ever learning an address:

```python
import hmac, hashlib
ip_hash = hmac.new(SALT.encode(), player_ip.encode(), hashlib.sha256).hexdigest()
```

Any existing moderation system can feed this endpoint: a LiteBans or AdvancedBan DB export job, a proxy log
shipper, or a Discord bot. Sending a heartbeat every few minutes with the online UUIDs closes sessions whose
logout event was missed.

### Analytics

* **Activity:** login/logout history, estimated playtime, average and longest session, logins per day, activity by
  hour (UTC) and over the last 30 days, and per-server presence (online, offline, or unknown when the server has
  stopped reporting).
* **Moderation history:** warnings, mutes, kicks and bans, with active, expired and revoked state.
* **Exports:** reports as Markdown, CSV or JSON. Network hashes are never exported.

### Risk indicators

Each indicator carries a severity, a confidence level, its evidence and a caveat.

| Code | Meaning |
|---|---|
| `OFFLINE_IDENTITY` | v3 UUID, so the identity is unauthenticated (informational) |
| `NONSTANDARD_OFFLINE_UUID` | v3 UUID that doesn't derive from its name (auth plugin or spoofing) |
| `PREMIUM_NAME_CONFLICT` | Cracked identity using a name that a premium account owns |
| `DUPLICATE_NAME` | The same name is used by other UUIDs |
| `SIMULTANEOUS_SAME_NAME` | The same name under different UUIDs is online on two servers at once |
| `SIMULTANEOUS_SAME_UUID` | The same UUID is online on two servers at once |
| `SHARED_NETWORK_WITH_BANNED` | Shares an IP hash with an actively banned identity (high if it logged in after the ban) |
| `NAME_REUSE_AFTER_BAN` | A banned identity's name reappears under a new UUID |
| `ALT_CLUSTER` | Network shared with 3 or more other identities |
| `MULTI_SERVER_BANS` | Actively banned on 2 or more participating servers |

**None of these prove that two accounts belong to the same person.** Shared networks (households, schools, VPNs,
CGNAT) and common names produce false positives. The dashboard shows this caveat next to every indicator.

## Player data policy (what this tool deliberately does not do)

* **Player names from public status pings are not indexed or searchable.** The ping's player sample holds at most
  about 12 names and is often hidden or randomized, so it can't support "is X on this server". Indexing it across
  every scanned server would also build a tracker of where named people play, on servers that never agreed to
  share that. Samples are counted (to report "sample showed N of M") and then discarded.
* Player search, presence, history and ban-evasion analysis use **only federation data**, from servers that opted
  in.
* The tool never joins servers, attempts logins, or probes offline-mode servers.

## API overview

All `/api/*` routes except `/api/health` and `/api/ingest/events` require `Authorization: Bearer <admin token>`.

| Method | Path | |
|---|---|---|
| GET | `/api/stats` | Dashboard counters |
| POST | `/api/scan/jobs` | `{targets, ports, rate?, concurrency?}` |
| GET | `/api/scan/jobs[/{id}]` | Job progress |
| POST | `/api/scan/jobs/{id}/cancel` | |
| POST | `/api/scan/recheck` | Re-ping all indexed servers |
| GET/POST/DELETE | `/api/exclusions` | Opt-out ranges (POST also purges) |
| GET | `/api/servers` | Search/filter: `q software version online mod_loader min_players sort limit offset` |
| GET | `/api/servers/{id}` | Detail + history |
| GET | `/api/servers/export?format=csv\|json` | |
| GET | `/api/uuid/verify?q=&name=` | Identity verification |
| GET | `/api/players/search?q=` | Confirmed and possible matches |
| GET | `/api/players/{uuid}/profile` | Analytics + risk |
| GET | `/api/players/{uuid}/report?format=md\|csv\|json` | |
| GET | `/api/alerts?days=` | Federation-wide alerts |
| GET/POST | `/api/federation/servers` | List / register participants |
| POST | `/api/ingest/events` | Participant ingest (`X-Api-Key`) |

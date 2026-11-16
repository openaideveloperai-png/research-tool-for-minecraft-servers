"""HTTP API + static dashboard."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .analysis import Analyzer
from .config import Settings
from .db import Database
from .federation import Event, Federation
from .mojang import MojangClient, normalize_uuid, offline_uuid, uuid_kind
from .scanner import Scanner

# The ONLY server columns any response or export may contain. host/port are
# intentionally absent; tests assert no endpoint string ever leaves the API.
PUBLIC_SERVER_FIELDS = (
    "server_id", "name", "motd", "version_name", "protocol", "software", "mod_loader", "mods_count",
    "players_online", "players_max", "sample_size", "sample_hidden", "enforces_secure_chat", "has_favicon",
    "latency_ms", "online", "first_seen", "last_seen", "last_checked", "times_seen",
)
_SERVER_COLS = ", ".join(PUBLIC_SERVER_FIELDS)


def _public_server(row: dict) -> dict:
    out = {k: row.get(k) for k in PUBLIC_SERVER_FIELDS}
    for b in ("online", "sample_hidden", "has_favicon"):
        out[b] = bool(out[b]) if out[b] is not None else None
    if out["enforces_secure_chat"] is not None:
        out["enforces_secure_chat"] = bool(out["enforces_secure_chat"])
    out["player_sample_note"] = (
        "Player list hidden by server" if out["sample_hidden"] else
        f"Status sample listed {out['sample_size']} of {out['players_online']} players (names not stored)"
        if out["players_online"] else "No players reported")
    return out


class ScanRequest(BaseModel):
    targets: list[str] = Field(..., min_length=1, max_length=1000)
    ports: list[int] = Field(default_factory=lambda: [25565], max_length=32)
    rate: float | None = Field(default=None, gt=0)
    concurrency: int | None = Field(default=None, gt=0)


class ExclusionRequest(BaseModel):
    cidr: str
    reason: str | None = None


class FedRegister(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    online_mode: bool | None = None


class IngestRequest(BaseModel):
    events: list[Event] = Field(..., min_length=1, max_length=5000)


def create_app(settings: Settings | None = None, mojang_transport=None) -> FastAPI:
    s = settings or Settings()
    if not s.admin_token:
        s.admin_token = secrets.token_urlsafe(24)
        print(f"[mc-sentinel] MCSEC_ADMIN_TOKEN not set; generated one for this run: {s.admin_token}")

    db = Database(s.db_path)
    scanner = Scanner(db, s)
    mojang = MojangClient(db, s, transport=mojang_transport)
    fed = Federation(db)
    analyzer = Analyzer(db, mojang, s.federation_stale_seconds)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db.execute("UPDATE scan_jobs SET status='interrupted' WHERE status='running'")
        yield
        for j in list(scanner.jobs):
            scanner.cancel(j)

    app = FastAPI(title="MC Sentinel", version=__version__, lifespan=lifespan)
    app.state.db, app.state.scanner, app.state.fed, app.state.settings = db, scanner, fed, s

    def admin(authorization: str = Header(default="")):
        token = authorization.removeprefix("Bearer ").strip()
        if not secrets.compare_digest(token, s.admin_token):
            raise HTTPException(401, "admin token required")

    def participant(x_api_key: str = Header(default="")):
        f = fed.authenticate(x_api_key)
        if not f:
            raise HTTPException(401, "valid participant X-Api-Key required")
        return f

    A = [Depends(admin)]

    # ------------------------------------------------------------ meta
    @app.get("/api/health")
    def health():
        return {"ok": True, "version": __version__}

    @app.get("/api/stats", dependencies=A)
    def stats():
        day = time.time() - 86400
        one = lambda q, p=(): db.one(q, p)["n"]  # noqa: E731
        return {
            "servers_indexed": one("SELECT COUNT(*) AS n FROM servers"),
            "servers_online": one("SELECT COUNT(*) AS n FROM servers WHERE online=1"),
            "servers_seen_24h": one("SELECT COUNT(*) AS n FROM servers WHERE last_seen > ?", (day,)),
            "players_reported": one("SELECT COALESCE(SUM(players_online),0) AS n FROM servers WHERE online=1"),
            "scan_jobs_running": sum(1 for j in scanner.jobs.values() if j.task and not j.task.done()),
            "federation_servers": one("SELECT COUNT(*) AS n FROM fed_servers WHERE active=1"),
            "federation_identities": one("SELECT COUNT(DISTINCT uuid) AS n FROM fed_sessions"),
            "active_bans": one("SELECT COUNT(*) AS n FROM fed_punishments WHERE kind='ban' AND active=1 "
                               "AND (expires_ts IS NULL OR expires_ts > ?)", (time.time(),)),
            "online_now": one("SELECT COUNT(*) AS n FROM fed_sessions s JOIN fed_servers f ON f.fed_id=s.fed_id "
                              "WHERE s.logout_ts IS NULL AND f.last_report > ?",
                              (time.time() - s.federation_stale_seconds,)),
            "software": db.query("SELECT COALESCE(software,'Unknown') AS label, COUNT(*) AS n FROM servers "
                                 "GROUP BY label ORDER BY n DESC LIMIT 10"),
            "versions": db.query("SELECT COALESCE(NULLIF(version_name,''),'Unknown') AS label, COUNT(*) AS n "
                                 "FROM servers GROUP BY label ORDER BY n DESC LIMIT 10"),
        }

    # ------------------------------------------------------------ discovery
    @app.post("/api/scan/jobs", dependencies=A)
    async def start_scan(req: ScanRequest):
        try:
            job_id = scanner.start_scan(req.targets, req.ports, req.rate, req.concurrency)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return scanner.job_view(job_id)

    @app.post("/api/scan/recheck", dependencies=A)
    async def recheck():
        return scanner.job_view(scanner.start_recheck())

    @app.get("/api/scan/jobs", dependencies=A)
    def list_jobs():
        rows = db.query("SELECT job_id FROM scan_jobs ORDER BY created DESC LIMIT 50")
        return [scanner.job_view(r["job_id"]) for r in rows]

    @app.get("/api/scan/jobs/{job_id}", dependencies=A)
    def get_job(job_id: str):
        j = scanner.job_view(job_id)
        if not j:
            raise HTTPException(404)
        return j

    @app.post("/api/scan/jobs/{job_id}/cancel", dependencies=A)
    def cancel_job(job_id: str):
        return {"cancelled": scanner.cancel(job_id)}

    @app.get("/api/scan/policy", dependencies=A)
    def scan_policy():
        return {"default_rate": s.scan_rate, "max_rate": s.scan_rate_max, "concurrency": s.scan_concurrency,
                "timeout_s": s.scan_timeout, "max_targets_per_job": s.max_targets_per_job,
                "reserved_ranges_excluded": not s.allow_private,
                "exclusion_count": db.one("SELECT COUNT(*) AS n FROM exclusions")["n"]}

    # Exclusions are opt-out ranges; showing them to the operator is fine (they
    # are not discovered servers), but they are never echoed into exports.
    @app.get("/api/exclusions", dependencies=A)
    def list_excl():
        return db.query("SELECT cidr, reason, added FROM exclusions ORDER BY added DESC")

    @app.post("/api/exclusions", dependencies=A)
    def add_excl(req: ExclusionRequest):
        try:
            net = str(ipaddress.ip_network(req.cidr.strip(), strict=False))
        except ValueError:
            raise HTTPException(400, "invalid CIDR")
        db.execute("INSERT OR REPLACE INTO exclusions(cidr, reason, added) VALUES (?,?,?)",
                   (net, req.reason, time.time()))
        # Opt-out also purges anything already collected from that range.
        purged = 0
        for row in db.query("SELECT server_id, host FROM endpoints"):
            try:
                if ipaddress.ip_address(row["host"]) in ipaddress.ip_network(net):
                    for t in ("status_history", "servers", "endpoints"):
                        db.execute(f"DELETE FROM {t} WHERE server_id=?", (row["server_id"],))
                    purged += 1
            except ValueError:
                continue
        return {"cidr": net, "purged_servers": purged}

    @app.delete("/api/exclusions", dependencies=A)
    def del_excl(cidr: str):
        db.execute("DELETE FROM exclusions WHERE cidr=?", (cidr,))
        return {"ok": True}

    # ------------------------------------------------------------ server index
    def _server_query(q, software, version, online, min_players, mod_loader, sort, limit, offset):
        where, params = [], []
        if q:
            where.append("(name LIKE ? OR motd LIKE ? OR version_name LIKE ?)")
            params += [f"%{q}%"] * 3
        if software:
            where.append("COALESCE(software,'Unknown') = ?")
            params.append(software)
        if version:
            where.append("version_name LIKE ?")
            params.append(f"%{version}%")
        if online is not None:
            where.append("online = ?")
            params.append(int(online))
        if min_players:
            where.append("players_online >= ?")
            params.append(min_players)
        if mod_loader:
            where.append("mod_loader IS NOT NULL" if mod_loader == "any" else "mod_loader LIKE ?")
            if mod_loader != "any":
                params.append(f"%{mod_loader}%")
        order = {"players": "players_online DESC", "recent": "last_seen DESC", "first": "first_seen DESC",
                 "latency": "latency_ms ASC", "name": "name COLLATE NOCASE"}.get(sort, "players_online DESC")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = db.one(f"SELECT COUNT(*) AS n FROM servers {w}", params)["n"]
        rows = db.query(f"SELECT {_SERVER_COLS} FROM servers {w} ORDER BY {order} LIMIT ? OFFSET ?",
                        (*params, limit, offset))
        return total, [_public_server(r) for r in rows]

    @app.get("/api/servers", dependencies=A)
    def servers(q: str = "", software: str = "", version: str = "", online: bool | None = None,
                min_players: int = 0, mod_loader: str = "", sort: str = "players",
                limit: int = Query(50, le=500), offset: int = 0):
        total, items = _server_query(q, software, version, online, min_players, mod_loader, sort, limit, offset)
        return {"total": total, "items": items}

    @app.get("/api/servers/export", dependencies=A)
    def export_servers(format: str = "csv", q: str = "", software: str = "", version: str = "",
                       online: bool | None = None, min_players: int = 0, mod_loader: str = ""):
        _, items = _server_query(q, software, version, online, min_players, mod_loader, "players", 100000, 0)
        if format == "json":
            return Response(json.dumps(items, indent=2), media_type="application/json",
                            headers={"Content-Disposition": "attachment; filename=servers.json"})
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(PUBLIC_SERVER_FIELDS) + ["player_sample_note"])
        w.writeheader()
        w.writerows(items)
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=servers.csv"})

    @app.get("/api/servers/{server_id}", dependencies=A)
    def server_detail(server_id: str):
        row = db.one(f"SELECT {_SERVER_COLS} FROM servers WHERE server_id=?", (server_id,))
        if not row:
            raise HTTPException(404)
        hist = db.query("SELECT ts, online, players_online, players_max, latency_ms FROM status_history "
                        "WHERE server_id=? ORDER BY ts DESC LIMIT 500", (server_id,))
        uptime = (sum(h["online"] for h in hist) / len(hist)) if hist else None
        return {**_public_server(row), "history": hist[::-1],
                "observed_uptime": round(uptime, 3) if uptime is not None else None,
                "peak_players": max((h["players_online"] or 0 for h in hist), default=None)}

    # ------------------------------------------------------------ identity
    @app.get("/api/uuid/verify", dependencies=A)
    async def verify(q: str, name: str | None = None):
        return await mojang.verify(q, context_name=name)

    @app.get("/api/uuid/offline", dependencies=A)
    def offline(name: str):
        return {"name": name, "offline_uuid": offline_uuid(name)}

    @app.get("/api/players/search", dependencies=A)
    async def player_search(q: str = Query(..., min_length=1, max_length=40)):
        return await analyzer.search(q)

    def _uuid_or_404(u: str) -> str:
        nu = normalize_uuid(u)
        if not nu:
            raise HTTPException(400, "invalid uuid")
        if not (db.one("SELECT 1 FROM fed_sessions WHERE uuid=? LIMIT 1", (nu,))
                or db.one("SELECT 1 FROM fed_punishments WHERE uuid=? LIMIT 1", (nu,))):
            raise HTTPException(404, "no records for this UUID in participating servers")
        return nu

    @app.get("/api/players/{u}/profile", dependencies=A)
    async def player_profile(u: str):
        return await analyzer.profile(_uuid_or_404(u))

    @app.get("/api/players/{u}/report", dependencies=A)
    async def player_report(u: str, format: str = "md"):
        p = await analyzer.profile(_uuid_or_404(u))
        fname = f"moderation-report-{p['uuid'][:8]}"
        if format == "json":
            return Response(json.dumps(p, indent=2), media_type="application/json",
                            headers={"Content-Disposition": f"attachment; filename={fname}.json"})
        if format == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["section", "server", "name/kind", "start", "end", "detail"])
            iso = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t)) if t else ""  # noqa: E731
            for s_ in p["sessions"]:
                w.writerow(["session", s_["server"], s_["username"], iso(s_["login_ts"]), iso(s_["logout_ts"]),
                            s_["duration"] or "open"])
            for x in p["punishments"]:
                w.writerow(["punishment", x["server"], x["kind"], iso(x["issued_ts"]), iso(x["expires_ts"]),
                            ("ACTIVE " if x["active"] else "") + (x["reason"] or "")])
            for i in p["risk"]["indicators"]:
                w.writerow(["indicator", "", i["code"], "", "", f"{i['severity']}/{i['confidence']}: "
                            + " | ".join(i["evidence"])])
            return Response(buf.getvalue(), media_type="text/csv",
                            headers={"Content-Disposition": f"attachment; filename={fname}.csv"})
        return PlainTextResponse(render_markdown(p), headers={
            "Content-Disposition": f"attachment; filename={fname}.md"})

    @app.get("/api/alerts", dependencies=A)
    def alerts(days: int = Query(30, ge=1, le=365)):
        return analyzer.alerts(days)

    # ------------------------------------------------------------ federation admin
    @app.get("/api/federation/servers", dependencies=A)
    def fed_list():
        return {"servers": fed.list_servers(), "ip_salt": fed.ip_salt}

    @app.post("/api/federation/servers", dependencies=A)
    def fed_register(req: FedRegister):
        return fed.register(req.name, req.description, req.online_mode)

    @app.post("/api/federation/servers/{fed_id}/rotate", dependencies=A)
    def fed_rotate(fed_id: str):
        k = fed.rotate_key(fed_id)
        if not k:
            raise HTTPException(404)
        return {"api_key": k}

    @app.post("/api/federation/servers/{fed_id}/active", dependencies=A)
    def fed_active(fed_id: str, active: bool):
        if not fed.set_active(fed_id, active):
            raise HTTPException(404)
        return {"ok": True}

    # ------------------------------------------------------------ participant ingest
    @app.post("/api/ingest/events")
    def ingest(req: IngestRequest, f=Depends(participant)):
        return fed.ingest(f["fed_id"], req.events)

    # ------------------------------------------------------------ frontend
    fe = Path(s.frontend_dir)
    if fe.exists():
        app.mount("/static", StaticFiles(directory=fe), name="static")

        @app.get("/")
        def index():
            return FileResponse(fe / "index.html")

    @app.exception_handler(Exception)
    async def unhandled(request, exc):  # never leak internals (or endpoints) in tracebacks
        return JSONResponse({"detail": "internal error"}, status_code=500)

    return app


def render_markdown(p: dict) -> str:
    iso = lambda t: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else "-"  # noqa: E731
    v = p["verification"]
    st = p["stats"]
    L = [f"# Moderation report: {p['names'][0]['name'] if p['names'] else p['uuid']}", "",
         f"- **UUID:** `{p['uuid']}` ({p['uuid_kind']} identity)",
         f"- **Verification verdict:** {v.get('verdict')}",
         f"- **Names used:** {', '.join(n['name'] for n in p['names']) or '-'}",
         f"- **Risk:** {p['risk']['level']} ({p['risk']['score']}/100)",
         f"- **Generated:** {iso(time.time())}", "",
         "> " + p["risk"]["disclaimer"], "", "## Activity", "",
         f"- Sessions: {st['sessions']} ({st['open_sessions']} open, {st['unclean_closes']} without clean logout)",
         f"- Estimated playtime: {st['total_playtime'] or 'Data unavailable'}",
         f"- Average session: {st['avg_session'] or 'Data unavailable'}",
         f"- First / last seen: {iso(st['first_seen'])} / {iso(st['last_seen'])}",
         f"- Logins per day: {st['logins_per_day'] if st['logins_per_day'] is not None else '-'}",
         f"- _{st['playtime_note']}_", "", "## Presence on participating servers", ""]
    for s in p["presence"]:
        L.append(f"- **{s['server']}**: {s['status']}, {s['sessions']} sessions, last seen {iso(s['last_seen'])}")
    L += ["", "## Moderation history", ""]
    if not p["punishments"]:
        L.append("No warnings, mutes, kicks or bans recorded by participating servers.")
    for x in p["punishments"]:
        L.append(f"- {iso(x['issued_ts'])} **{x['kind'].upper()}** on {x['server']}"
                 f"{' (active)' if x['active'] else ''}: {x['reason'] or 'no reason given'}")
    L += ["", "## Risk indicators", ""]
    if not p["risk"]["indicators"]:
        L.append("None.")
    for i in p["risk"]["indicators"]:
        L.append(f"### {i['title']}  \n`{i['code']}` · severity **{i['severity']}** · confidence "
                 f"**{i['confidence']}**")
        L += [f"- {e}" for e in i["evidence"]]
        if i.get("note"):
            L.append(f"\n_{i['note']}_")
        L.append("")
    L += ["## Verification checks", ""] + [f"- [{c['result']}] {c['detail']}" for c in v.get("checks", [])]
    return "\n".join(L) + "\n"

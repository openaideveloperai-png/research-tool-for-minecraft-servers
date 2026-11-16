"""Player search, activity analytics, cracked-account and ban-evasion indicators.

All player-level data here comes from the moderation federation, i.e. from
servers that opted in. Indicators are evidence of *linkage*, never proof that
two accounts are the same person. Every indicator carries its evidence and a
confidence level, and the UI shows the caveat next to it.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict

from .db import Database
from .federation import expire_punishments, fed_names
from .mojang import MojangClient, normalize_uuid, offline_uuid, uuid_kind

SEVERITY_WEIGHT = {"info": 0, "low": 10, "medium": 25, "high": 45}
CONFIDENCE_FACTOR = {"low": 0.4, "medium": 0.7, "high": 1.0}
LINKAGE_CAVEAT = ("Linkage evidence, not proof of identity. Shared networks (households, schools, "
                  "VPNs, CGNAT) and common names produce false positives. Review before acting.")


def _fmt_dur(sec: float) -> str:
    sec = int(sec)
    h, m = divmod(sec // 60, 60)
    return f"{h}h {m:02d}m" if h else f"{m}m"


class Analyzer:
    def __init__(self, db: Database, mojang: MojangClient, stale_seconds: int):
        self.db = db
        self.mojang = mojang
        self.stale = stale_seconds

    # ------------------------------------------------------------ helpers
    def _presence_status(self, fed: dict, open_session: bool, now: float) -> str:
        if not open_session:
            return "offline"
        if fed.get("last_report") and now - fed["last_report"] <= self.stale:
            return "online"
        return "unknown"  # server stopped reporting; open session may be stale

    def _identity_summary(self, u: str, feds: dict, now: float) -> dict:
        rows = self.db.query("SELECT fed_id, username, login_ts, logout_ts FROM fed_sessions WHERE uuid=?", (u,))
        per = defaultdict(lambda: {"sessions": 0, "first": None, "last": None, "open": False, "names": set()})
        for r in rows:
            p = per[r["fed_id"]]
            p["sessions"] += 1
            p["names"].add(r["username"])
            p["first"] = min(p["first"] or r["login_ts"], r["login_ts"])
            p["last"] = max(p["last"] or 0, r["logout_ts"] or r["login_ts"])
            p["open"] = p["open"] or r["logout_ts"] is None
        servers = []
        for fid, p in per.items():
            f = feds.get(fid, {})
            servers.append({
                "server": f.get("name", "(removed)"), "description": f.get("description"),
                "server_online_mode": None if f.get("online_mode") is None else bool(f["online_mode"]),
                "sessions": p["sessions"], "first_seen": p["first"], "last_seen": p["last"],
                "status": self._presence_status(f, p["open"], now), "names": sorted(p["names"]),
            })
        servers.sort(key=lambda s: s["last_seen"] or 0, reverse=True)
        return {"uuid": u, "uuid_kind": uuid_kind(u), "servers": servers}

    # ------------------------------------------------------------ search
    async def search(self, q: str) -> dict:
        expire_punishments(self.db)
        now = time.time()
        feds = fed_names(self.db)
        verification = await self.mojang.verify(q)
        nu = normalize_uuid(q)

        results = []
        if nu:
            if self.db.one("SELECT 1 FROM fed_sessions WHERE uuid=? LIMIT 1", (nu,)) or \
               self.db.one("SELECT 1 FROM fed_punishments WHERE uuid=? LIMIT 1", (nu,)):
                s = self._identity_summary(nu, feds, now)
                s.update(match="confirmed", reason="Exact UUID match in participating servers' records.")
                results.append(s)
            names = {r["username_lc"] for r in self.db.query(
                "SELECT DISTINCT username_lc FROM fed_sessions WHERE uuid=?", (nu,))}
            for name in names:
                for r in self.db.query("SELECT DISTINCT uuid FROM fed_sessions WHERE username_lc=? AND uuid!=?",
                                       (name, nu)):
                    s = self._identity_summary(r["uuid"], feds, now)
                    s.update(match="possible",
                             reason=f"Different UUID using the same name '{name}'. Same name is not the same "
                                    "person; this may be an impersonator or an unrelated player.")
                    results.append(s)
        elif verification.get("input_type") == "username":
            name_lc = q.lower()
            premium = verification.get("premium_uuid")
            off = verification.get("offline_uuid")
            uuids = {r["uuid"] for r in self.db.query(
                "SELECT DISTINCT uuid FROM fed_sessions WHERE username_lc=?", (name_lc,))}
            uuids |= {r["uuid"] for r in self.db.query(
                "SELECT DISTINCT uuid FROM fed_punishments WHERE username_lc=?", (name_lc,))}
            premium_checked = verification.get("mojang", {}).get("status") in ("found", "not_found")
            for u in sorted(uuids):
                s = self._identity_summary(u, feds, now)
                if premium and u == premium:
                    s.update(match="confirmed", reason="UUID matches the premium Mojang account for this name.")
                elif u == off:
                    s.update(match="possible", reason=(
                        "Offline-mode UUID derived from this name. Anyone can produce it; it is not "
                        "authenticated as the premium owner." if premium else
                        "Offline-mode UUID derived from this name (no premium account owns it)." if premium_checked
                        else "Offline-mode UUID derived from this name. Mojang could not be reached to check "
                             "whether a premium account owns the name."))
                elif not premium_checked and uuid_kind(u) == "online":
                    s.update(match="possible", reason="Online-mode UUID using this name. Likely the premium "
                                                      "account, but Mojang could not be reached to confirm it.")
                else:
                    s.update(match="possible", reason="Same username, unrelated UUID (renamed account, custom "
                                                      "auth plugin, or a different player).")
                results.append(s)
            results.sort(key=lambda s: s["match"] != "confirmed")

        return {
            "query": q,
            "verification": verification,
            "results": results,
            "sources": {
                "federation": {"servers": len(feds), "note": "Records from participating servers only."},
                "public_scan": {
                    "available": False,
                    "note": "Not searchable. Public status samples are partial (max ~12 names, often hidden), "
                            "and indexing names from servers that never opted in would turn this into a "
                            "cross-server tracker. Samples are counted for server analytics and discarded.",
                },
            },
        }

    # ------------------------------------------------------------ profile
    async def profile(self, u: str) -> dict:
        expire_punishments(self.db)
        now = time.time()
        feds = fed_names(self.db)
        sessions = self.db.query(
            "SELECT fed_id, username, login_ts, logout_ts, clean_close, ip_hash IS NOT NULL AS has_ip "
            "FROM fed_sessions WHERE uuid=? ORDER BY login_ts DESC", (u,))
        pun = self.db.query(
            "SELECT fed_id, kind, reason, issued_ts, expires_ts, active, revoked_ts FROM fed_punishments "
            "WHERE uuid=? ORDER BY issued_ts DESC", (u,))
        names = Counter(s["username"] for s in sessions)
        primary_name = names.most_common(1)[0][0] if names else None
        if not primary_name:
            r = self.db.one("SELECT username FROM fed_punishments WHERE uuid=? AND username IS NOT NULL", (u,))
            primary_name = r["username"] if r else None
        verification = await self.mojang.verify(u, context_name=primary_name)
        if uuid_kind(u) == "offline" and primary_name:
            from dataclasses import asdict
            verification["name_lookup"] = asdict(await self.mojang.by_name(primary_name))

        closed = [s for s in sessions if s["logout_ts"]]
        durations = [s["logout_ts"] - s["login_ts"] for s in closed]
        total = sum(durations)
        hours = [0] * 24
        weekdays = [0] * 7
        days: Counter = Counter()
        for s in sessions:
            t = time.gmtime(s["login_ts"])
            hours[t.tm_hour] += 1
            weekdays[t.tm_wday] += 1
            days[time.strftime("%Y-%m-%d", t)] += 1
        last30 = []
        for i in range(29, -1, -1):
            d = time.strftime("%Y-%m-%d", time.gmtime(now - i * 86400))
            last30.append({"day": d, "logins": days.get(d, 0)})
        first = min((s["login_ts"] for s in sessions), default=None)
        span_days = max(1.0, (now - first) / 86400) if first else None

        identity = self._identity_summary(u, feds, now)
        out = {
            "uuid": u,
            "uuid_kind": uuid_kind(u),
            "names": [{"name": n, "sessions": c} for n, c in names.most_common()],
            "verification": verification,
            "presence": identity["servers"],
            "stats": {
                "sessions": len(sessions),
                "closed_sessions": len(closed),
                "open_sessions": len(sessions) - len(closed),
                "unclean_closes": sum(1 for s in closed if not s["clean_close"]),
                "total_playtime_s": total,
                "total_playtime": _fmt_dur(total) if closed else None,
                "avg_session_s": total / len(closed) if closed else None,
                "avg_session": _fmt_dur(total / len(closed)) if closed else None,
                "longest_session": _fmt_dur(max(durations)) if durations else None,
                "first_seen": first,
                "last_seen": max((s["logout_ts"] or s["login_ts"] for s in sessions), default=None),
                "logins_per_day": round(len(sessions) / span_days, 2) if span_days else None,
                "servers": len(identity["servers"]),
                "playtime_note": "Estimated from closed sessions only; open sessions are excluded and sessions "
                                 "closed by a missed logout end at the next login or heartbeat.",
            },
            "activity": {"hour_utc": hours, "weekday": weekdays, "last30": last30},
            "sessions": [{
                "server": feds.get(s["fed_id"], {}).get("name", "(removed)"),
                "username": s["username"], "login_ts": s["login_ts"], "logout_ts": s["logout_ts"],
                "duration": _fmt_dur(s["logout_ts"] - s["login_ts"]) if s["logout_ts"] else None,
                "clean_close": None if s["logout_ts"] is None else bool(s["clean_close"]),
            } for s in sessions[:500]],
            "punishments": [{
                "server": feds.get(p["fed_id"], {}).get("name", "(removed)"),
                **{k: p[k] for k in ("kind", "reason", "issued_ts", "expires_ts", "revoked_ts")},
                "active": bool(p["active"]),
            } for p in pun],
        }
        out["risk"] = self.risk(u, primary_name, verification, now)
        return out

    # ------------------------------------------------------------ indicators
    def _overlaps(self, where: str, params: tuple, now: float) -> list[dict]:
        return self.db.query(
            "SELECT a.uuid AS a_uuid, a.username AS a_name, a.fed_id AS a_fed, a.login_ts AS a_in, "
            "a.logout_ts AS a_out, a.clean_close AS a_clean, "
            "b.uuid AS b_uuid, b.username AS b_name, b.fed_id AS b_fed, b.login_ts AS b_in, "
            "b.logout_ts AS b_out, b.clean_close AS b_clean "
            "FROM fed_sessions a JOIN fed_sessions b ON a.id < b.id AND a.fed_id != b.fed_id "
            "AND a.login_ts < COALESCE(b.logout_ts, ?) AND b.login_ts < COALESCE(a.logout_ts, ?) "
            f"WHERE {where} LIMIT 200", (now, now, *params))

    def risk(self, u: str, name: str | None, verification: dict, now: float) -> dict:
        feds = fed_names(self.db)
        fn = lambda fid: feds.get(fid, {}).get("name", "(removed)")  # noqa: E731
        ind: list[dict] = []

        def add(code, title, severity, confidence, evidence, note=None):
            ind.append({"code": code, "title": title, "severity": severity, "confidence": confidence,
                        "evidence": evidence, "note": note})

        kind = uuid_kind(u)
        if kind == "offline":
            add("OFFLINE_IDENTITY", "Offline-mode (cracked) identity", "info", "high",
                [f"UUID {u} is version 3, derived from a name rather than issued by Mojang."],
                "Not wrongdoing by itself. Any client can claim this identity on an offline-mode server.")
            if name and offline_uuid(name) != u:
                add("NONSTANDARD_OFFLINE_UUID", "Offline UUID does not derive from the name it uses", "low",
                    "medium", [f"offline_uuid('{name}') = {offline_uuid(name)}, but records use {u}."],
                    "Common with auth plugins (AuthMe variants, hybrid login) or renamed accounts.")

        names = {r["username_lc"]: r["username"] for r in self.db.query(
            "SELECT DISTINCT username_lc, username FROM fed_sessions WHERE uuid=?", (u,))}

        # Premium-name conflict: cracked identity using a registered premium name.
        lk = verification.get("name_lookup") or {}
        if kind == "offline" and name:
            if lk.get("status") == "found":
                add("PREMIUM_NAME_CONFLICT", "Cracked identity using a premium account's name", "medium",
                    "medium", [f"'{name}' is registered to premium UUID {lk['uuid']}.",
                               f"This identity ({u}) is the unauthenticated offline variant."],
                    "Possible impersonation, or the real owner playing on an offline-mode server. Not proof.")
            elif lk.get("status") == "unavailable":
                add("PREMIUM_NAME_UNCHECKED", "Could not check whether this name belongs to a premium account",
                    "info", "low", [f"Mojang API unavailable: {lk.get('error')}"])

        # Duplicate names across identities
        for lc, disp in names.items():
            others = self.db.query("SELECT DISTINCT uuid FROM fed_sessions WHERE username_lc=? AND uuid!=?", (lc, u))
            if others:
                kinds = Counter(uuid_kind(o["uuid"]) for o in others)
                add("DUPLICATE_NAME", f"Name '{disp}' used by {len(others)} other identit"
                    f"{'y' if len(others) == 1 else 'ies'}", "low", "high",
                    [f"{o['uuid']} ({uuid_kind(o['uuid'])})" for o in others[:10]]
                    + [f"Kinds: {dict(kinds)}"],
                    "Duplicate usage of a name shows account duplication, not that the accounts share an owner.")

        # Simultaneous sessions
        for o in self._overlaps("(a.uuid=? OR b.uuid=?) AND (a.uuid=b.uuid OR a.username_lc=b.username_lc)",
                                (u, u), now):
            same_uuid = o["a_uuid"] == o["b_uuid"]
            stale = (o["a_out"] is None or o["b_out"] is None)
            ev = [f"{o['a_name']} ({o['a_uuid']}) on {fn(o['a_fed'])} from "
                  f"{time.strftime('%Y-%m-%d %H:%M', time.gmtime(o['a_in']))} UTC",
                  f"{o['b_name']} ({o['b_uuid']}) on {fn(o['b_fed'])} from "
                  f"{time.strftime('%Y-%m-%d %H:%M', time.gmtime(o['b_in']))} UTC"]
            if same_uuid:
                add("SIMULTANEOUS_SAME_UUID", "Same UUID online on two servers at once",
                    "medium", "low" if stale else "medium", ev,
                    "For an offline UUID this means two different clients used the same name. For a premium UUID "
                    "it may be a missed logout event." + (" One session has no logout yet." if stale else ""))
            else:
                add("SIMULTANEOUS_SAME_NAME", "Same name, different UUIDs, online at the same time",
                    "high", "medium" if stale else "high", ev,
                    "Two clients cannot be one player at once: at least one is not the account's usual owner.")

        # Ban evasion: shared connection fingerprint with a banned identity
        my_ips = [r["ip_hash"] for r in self.db.query(
            "SELECT DISTINCT ip_hash FROM fed_sessions WHERE uuid=? AND ip_hash IS NOT NULL", (u,))]
        if my_ips:
            qs = ",".join("?" for _ in my_ips)
            banned = self.db.query(
                f"SELECT DISTINCT p.uuid, p.username, p.fed_id, p.issued_ts, p.reason FROM fed_punishments p "
                f"WHERE p.kind='ban' AND p.active=1 AND p.uuid!=? AND (p.ip_hash IN ({qs}) OR p.uuid IN "
                f"(SELECT uuid FROM fed_sessions WHERE ip_hash IN ({qs})))", (u, *my_ips, *my_ips))
            for b in banned:
                after = self.db.one(
                    f"SELECT MIN(login_ts) AS t FROM fed_sessions WHERE uuid=? AND ip_hash IN ({qs}) "
                    "AND login_ts > ?", (u, *my_ips, b["issued_ts"]))
                logged_after = bool(after and after["t"])
                add("SHARED_NETWORK_WITH_BANNED", "Shares a connection fingerprint with a banned account",
                    "high" if logged_after else "medium", "medium" if logged_after else "low",
                    [f"Banned: {b['username'] or b['uuid']} on {fn(b['fed_id'])} at "
                     f"{time.strftime('%Y-%m-%d', time.gmtime(b['issued_ts']))}"
                     + (f" ({b['reason']})" if b["reason"] else ""),
                     "This identity logged in from the same hashed network "
                     + ("AFTER the ban was issued." if logged_after else "(before the ban only).")],
                    LINKAGE_CAVEAT)
            cluster = self.db.one(
                f"SELECT COUNT(DISTINCT uuid) AS n FROM fed_sessions WHERE ip_hash IN ({qs}) AND uuid!=?",
                (*my_ips, u))
            if cluster and cluster["n"] >= 3:
                add("ALT_CLUSTER", f"Network shared with {cluster['n']} other identities", "low", "low",
                    [f"{cluster['n']} distinct UUIDs seen behind the same hashed network(s)."], LINKAGE_CAVEAT)

        # Name reuse after ban: banned identity's name re-appears under a new UUID
        for lc, disp in names.items():
            for b in self.db.query(
                    "SELECT uuid, fed_id, issued_ts FROM fed_punishments WHERE kind='ban' AND active=1 "
                    "AND username_lc=? AND uuid!=?", (lc, u)):
                later = self.db.one("SELECT MIN(login_ts) AS t FROM fed_sessions WHERE uuid=? AND username_lc=? "
                                    "AND login_ts > ?", (u, lc, b["issued_ts"]))
                if later and later["t"]:
                    add("NAME_REUSE_AFTER_BAN", "Banned player's name reappeared under a new UUID", "high", "medium",
                        [f"{b['uuid']} banned on {fn(b['fed_id'])} at "
                         f"{time.strftime('%Y-%m-%d', time.gmtime(b['issued_ts']))}",
                         f"'{disp}' logged in as {u} at {time.strftime('%Y-%m-%d', time.gmtime(later['t']))}"],
                        "On offline-mode servers, anyone can pick any name. Correlate with other evidence.")

        # Multi-server bans
        bans = self.db.query("SELECT DISTINCT fed_id FROM fed_punishments WHERE uuid=? AND kind='ban' AND active=1",
                             (u,))
        if len(bans) >= 2:
            add("MULTI_SERVER_BANS", f"Actively banned on {len(bans)} participating servers", "medium", "high",
                [fn(b["fed_id"]) for b in bans])

        score = min(100, round(sum(SEVERITY_WEIGHT[i["severity"]] * CONFIDENCE_FACTOR[i["confidence"]]
                                   for i in ind)))
        level = "high" if score >= 60 else "elevated" if score >= 30 else "low" if score > 0 else "none"
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        ind.sort(key=lambda i: order[i["severity"]])
        return {"score": score, "level": level, "indicators": ind,
                "disclaimer": "Indicators show account duplication or linkage evidence. None of them prove two "
                              "accounts belong to the same person."}

    # ------------------------------------------------------------ global alerts
    def alerts(self, since_days: int = 30) -> list[dict]:
        expire_punishments(self.db)
        now = time.time()
        since = now - since_days * 86400
        feds = fed_names(self.db)
        fn = lambda fid: feds.get(fid, {}).get("name", "(removed)")  # noqa: E731
        out = []
        for o in self._overlaps("a.login_ts > ? AND a.username_lc=b.username_lc", (since,), now):
            same = o["a_uuid"] == o["b_uuid"]
            out.append({
                "type": "simultaneous_same_uuid" if same else "simultaneous_same_name",
                "severity": "medium" if same else "high",
                "ts": max(o["a_in"], o["b_in"]),
                "title": f"'{o['a_name']}' online on {fn(o['a_fed'])} and {fn(o['b_fed'])} at once"
                         + ("" if same else " under different UUIDs"),
                "uuids": sorted({o["a_uuid"], o["b_uuid"]}),
            })
        for r in self.db.query(
                "SELECT s.uuid, s.username, s.fed_id, MIN(s.login_ts) AS t, p.uuid AS banned_uuid, "
                "p.username AS banned_name, p.fed_id AS ban_fed FROM fed_sessions s JOIN fed_punishments p "
                "ON p.kind='ban' AND p.active=1 AND p.uuid != s.uuid AND s.login_ts > p.issued_ts "
                "AND (s.username_lc = p.username_lc OR (s.ip_hash IS NOT NULL AND s.ip_hash = p.ip_hash)) "
                "WHERE s.login_ts > ? GROUP BY s.uuid, p.uuid LIMIT 200", (since,)):
            out.append({
                "type": "possible_ban_evasion", "severity": "high", "ts": r["t"],
                "title": f"{r['username']} on {fn(r['fed_id'])} linked to banned "
                         f"{r['banned_name'] or r['banned_uuid']} ({fn(r['ban_fed'])})",
                "uuids": [r["uuid"], r["banned_uuid"]],
            })
        for r in self.db.query(
                "SELECT username_lc, GROUP_CONCAT(DISTINCT uuid) AS uuids, MAX(login_ts) AS t FROM fed_sessions "
                "WHERE login_ts > ? GROUP BY username_lc HAVING COUNT(DISTINCT uuid) > 1 LIMIT 200", (since,)):
            us = r["uuids"].split(",")
            out.append({"type": "duplicate_name", "severity": "low", "ts": r["t"],
                        "title": f"Name '{r['username_lc']}' used by {len(us)} identities", "uuids": us})
        out.sort(key=lambda a: a["ts"], reverse=True)
        return out

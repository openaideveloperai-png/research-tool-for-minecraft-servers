"""Moderation federation: participating servers push their own records.

Only servers that registered and hold an API key contribute data. Raw IP
addresses are never accepted. Participants send `ip_hash`, an HMAC-SHA256 of
the player's IP keyed with the federation's shared salt. That lets the platform
compare connections across servers without learning any address.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any

from pydantic import BaseModel, Field, field_validator

from .db import Database
from .mojang import NAME_RE, normalize_uuid

EVENT_TYPES = {"login", "logout", "heartbeat", "warn", "kick", "mute", "ban", "unban", "unmute"}
PUNISHMENT_TYPES = {"warn", "kick", "mute", "ban"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def ip_hash(salt: str, ip: str) -> str:
    """Reference implementation participants use client-side."""
    return hmac.new(salt.encode(), ip.strip().encode(), hashlib.sha256).hexdigest()


class Event(BaseModel):
    type: str
    ts: float | None = Field(default=None, description="unix seconds; defaults to receive time")
    uuid: str | None = None
    username: str | None = None
    ip_hash: str | None = None
    reason: str | None = Field(default=None, max_length=500)
    expires_ts: float | None = None
    online_uuids: list[str] | None = Field(default=None, description="heartbeat: UUIDs currently online")

    @field_validator("type")
    @classmethod
    def _type(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in EVENT_TYPES:
            raise ValueError(f"type must be one of {sorted(EVENT_TYPES)}")
        return v

    @field_validator("uuid")
    @classmethod
    def _uuid(cls, v: str | None) -> str | None:
        if v is None:
            return v
        n = normalize_uuid(v)
        if not n:
            raise ValueError("invalid uuid")
        return n

    @field_validator("username")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        if v is not None and not NAME_RE.match(v):
            raise ValueError("invalid username")
        return v

    @field_validator("ip_hash")
    @classmethod
    def _iph(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.lower()
        if not HEX64.match(v):
            raise ValueError("ip_hash must be a 64-char hex HMAC-SHA256; raw IPs are not accepted")
        return v


class Federation:
    def __init__(self, db: Database):
        self.db = db
        row = db.one("SELECT value FROM meta WHERE key='fed_ip_salt'")
        if row:
            self.ip_salt = row["value"]
        else:
            self.ip_salt = secrets.token_hex(32)
            db.execute("INSERT INTO meta(key, value) VALUES ('fed_ip_salt', ?)", (self.ip_salt,))

    # ------------------------------------------------------------ servers
    def register(self, name: str, description: str | None, online_mode: bool | None) -> dict:
        fed_id = "fed_" + secrets.token_hex(6)
        key = "mcs_" + secrets.token_urlsafe(32)
        self.db.execute(
            "INSERT INTO fed_servers(fed_id, name, description, online_mode, api_key_hash, created) "
            "VALUES (?,?,?,?,?,?)",
            (fed_id, name.strip()[:80], (description or "").strip()[:500],
             None if online_mode is None else int(online_mode), hash_key(key), time.time()))
        return {"fed_id": fed_id, "api_key": key, "ip_salt": self.ip_salt}

    def rotate_key(self, fed_id: str) -> str | None:
        if not self.db.one("SELECT 1 FROM fed_servers WHERE fed_id=?", (fed_id,)):
            return None
        key = "mcs_" + secrets.token_urlsafe(32)
        self.db.execute("UPDATE fed_servers SET api_key_hash=? WHERE fed_id=?", (hash_key(key), fed_id))
        return key

    def set_active(self, fed_id: str, active: bool) -> bool:
        cur = self.db.execute("UPDATE fed_servers SET active=? WHERE fed_id=?", (int(active), fed_id))
        return cur.rowcount > 0

    def authenticate(self, api_key: str) -> dict | None:
        if not api_key:
            return None
        row = self.db.one("SELECT fed_id, name, active FROM fed_servers WHERE api_key_hash=?",
                          (hash_key(api_key),))
        return row if row and row["active"] else None

    def list_servers(self) -> list[dict]:
        rows = self.db.query(
            "SELECT f.fed_id, f.name, f.description, f.online_mode, f.created, f.last_report, f.active, "
            "(SELECT COUNT(*) FROM fed_sessions s WHERE s.fed_id=f.fed_id) AS sessions, "
            "(SELECT COUNT(*) FROM fed_punishments p WHERE p.fed_id=f.fed_id) AS punishments, "
            "(SELECT COUNT(*) FROM fed_sessions s WHERE s.fed_id=f.fed_id AND s.logout_ts IS NULL) AS open_sessions "
            "FROM fed_servers f ORDER BY f.created")
        return rows

    # ------------------------------------------------------------ ingest
    def ingest(self, fed_id: str, events: list[Event]) -> dict:
        now = time.time()
        accepted, rejected = 0, []
        events = sorted(events, key=lambda e: e.ts or now)
        with self.db.transaction():
            for i, ev in enumerate(events):
                ts = ev.ts or now
                if ts > now + 300:
                    rejected.append({"index": i, "error": "timestamp in the future"})
                    continue
                if ev.type not in ("heartbeat",) and not ev.uuid:
                    rejected.append({"index": i, "error": "uuid required"})
                    continue
                if ev.type in ("login",) and not ev.username:
                    rejected.append({"index": i, "error": "username required for login"})
                    continue
                self.db.execute(
                    "INSERT INTO fed_events(fed_id, ts, type, uuid, username, ip_hash, detail) VALUES (?,?,?,?,?,?,?)",
                    (fed_id, ts, ev.type, ev.uuid, ev.username, ev.ip_hash,
                     json.dumps({k: v for k, v in (("reason", ev.reason), ("expires_ts", ev.expires_ts)) if v})))
                getattr(self, f"_on_{ev.type}", self._on_punishment)(fed_id, ts, ev)
                accepted += 1
            self.db.execute("UPDATE fed_servers SET last_report=? WHERE fed_id=?", (now, fed_id))
        return {"accepted": accepted, "rejected": rejected}

    def _close_open(self, fed_id: str, u: str, ts: float, clean: bool) -> int:
        cur = self.db.execute(
            "UPDATE fed_sessions SET logout_ts=?, clean_close=? WHERE fed_id=? AND uuid=? AND logout_ts IS NULL "
            "AND login_ts<=?", (ts, int(clean), fed_id, u, ts))
        return cur.rowcount

    def _on_login(self, fed_id: str, ts: float, ev: Event) -> None:
        self._close_open(fed_id, ev.uuid, ts, clean=False)  # missed logout
        self.db.execute(
            "INSERT INTO fed_sessions(fed_id, uuid, username, username_lc, ip_hash, login_ts) VALUES (?,?,?,?,?,?)",
            (fed_id, ev.uuid, ev.username, ev.username.lower(), ev.ip_hash, ts))

    def _on_logout(self, fed_id: str, ts: float, ev: Event) -> None:
        self._close_open(fed_id, ev.uuid, ts, clean=True)

    def _on_heartbeat(self, fed_id: str, ts: float, ev: Event) -> None:
        if ev.online_uuids is None:
            return
        online = {normalize_uuid(u) for u in ev.online_uuids}
        for row in self.db.query("SELECT uuid FROM fed_sessions WHERE fed_id=? AND logout_ts IS NULL", (fed_id,)):
            if row["uuid"] not in online:
                self._close_open(fed_id, row["uuid"], ts, clean=False)

    def _on_punishment(self, fed_id: str, ts: float, ev: Event) -> None:
        if ev.type == "unban" or ev.type == "unmute":
            kind = "ban" if ev.type == "unban" else "mute"
            self.db.execute(
                "UPDATE fed_punishments SET active=0, revoked_ts=? WHERE id = (SELECT id FROM fed_punishments "
                "WHERE fed_id=? AND uuid=? AND kind=? AND active=1 ORDER BY issued_ts DESC LIMIT 1)",
                (ts, fed_id, ev.uuid, kind))
            return
        if ev.type not in PUNISHMENT_TYPES:
            return
        name = ev.username
        if not name:
            r = self.db.one("SELECT username FROM fed_sessions WHERE uuid=? ORDER BY login_ts DESC LIMIT 1",
                            (ev.uuid,))
            name = r["username"] if r else None
        iph = ev.ip_hash
        if not iph:
            r = self.db.one("SELECT ip_hash FROM fed_sessions WHERE uuid=? AND ip_hash IS NOT NULL "
                            "ORDER BY login_ts DESC LIMIT 1", (ev.uuid,))
            iph = r["ip_hash"] if r else None
        active = 0 if ev.type in ("warn", "kick") else 1
        self.db.execute(
            "INSERT INTO fed_punishments(fed_id, uuid, username, username_lc, kind, reason, issued_ts, expires_ts, "
            "active, ip_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (fed_id, ev.uuid, name, name.lower() if name else None, ev.type, ev.reason, ts, ev.expires_ts,
             active, iph))


def expire_punishments(db: Database) -> None:
    db.execute("UPDATE fed_punishments SET active=0 WHERE active=1 AND expires_ts IS NOT NULL AND expires_ts < ?",
               (time.time(),))


def fed_names(db: Database) -> dict[str, dict[str, Any]]:
    return {r["fed_id"]: r for r in db.query(
        "SELECT fed_id, name, description, online_mode, last_report FROM fed_servers")}

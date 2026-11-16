"""Minecraft identity verification.

* Online-mode (premium) accounts have random version-4 UUIDs issued by Mojang.
* Offline-mode servers derive a version-3 UUID: md5("OfflinePlayer:" + name).
  Anyone can produce the offline UUID for any name, which is the root of
  cracked-account impersonation.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid as uuidlib
from dataclasses import dataclass, asdict

import httpx

from .config import Settings
from .db import Database

NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,16}$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")


def offline_uuid(name: str) -> str:
    """Exactly matches Java's UUID.nameUUIDFromBytes(("OfflinePlayer:"+name).getBytes(UTF_8))."""
    h = bytearray(hashlib.md5(("OfflinePlayer:" + name).encode("utf-8")).digest())
    h[6] = (h[6] & 0x0F) | 0x30
    h[8] = (h[8] & 0x3F) | 0x80
    return str(uuidlib.UUID(bytes=bytes(h)))


def normalize_uuid(s: str) -> str | None:
    s = s.strip()
    if not UUID_RE.match(s):
        return None
    return str(uuidlib.UUID(s.replace("-", "")))


def uuid_version(u: str) -> int | None:
    try:
        return uuidlib.UUID(u).version
    except ValueError:
        return None


def uuid_kind(u: str) -> str:
    v = uuid_version(u)
    if v == 4:
        return "online"      # Mojang-issued
    if v == 3:
        return "offline"     # name-derived (cracked / offline-mode)
    return "unknown"


@dataclass
class Lookup:
    status: str                 # found | not_found | unavailable | skipped
    uuid: str | None = None
    name: str | None = None
    source: str | None = None
    error: str | None = None


class MojangClient:
    def __init__(self, db: Database, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.db = db
        self.s = settings
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=6.0, transport=self._transport,
                                 headers={"User-Agent": "mc-sentinel/0.1 (moderation research)"})

    def _cache_get(self, key: str) -> Lookup | None:
        row = self.db.one("SELECT value, fetched FROM mojang_cache WHERE key=?", (key,))
        if row and time.time() - row["fetched"] < self.s.mojang_cache_seconds:
            return Lookup(**json.loads(row["value"]))
        return None

    def _cache_put(self, key: str, lk: Lookup) -> None:
        if lk.status in ("found", "not_found"):
            self.db.execute("INSERT OR REPLACE INTO mojang_cache(key, value, fetched) VALUES (?,?,?)",
                            (key, json.dumps(asdict(lk)), time.time()))

    async def by_name(self, name: str) -> Lookup:
        if not self.s.mojang_enabled:
            return Lookup("skipped", error="Mojang lookups disabled")
        if not NAME_RE.match(name):
            return Lookup("not_found", error="not a valid Java Edition username")
        key = "name:" + name.lower()
        if (c := self._cache_get(key)):
            return c
        last_err = None
        async with self._client() as client:
            for url in (self.s.mojang_name_url, self.s.mojang_name_url_fallback):
                if not url:
                    continue
                try:
                    r = await client.get(url.format(name=name))
                except httpx.HTTPError as e:
                    last_err = type(e).__name__
                    continue
                if r.status_code == 200:
                    d = r.json()
                    lk = Lookup("found", normalize_uuid(d["id"]), d.get("name"), "mojang")
                    self._cache_put(key, lk)
                    return lk
                if r.status_code in (204, 404):
                    lk = Lookup("not_found", source="mojang")
                    self._cache_put(key, lk)
                    return lk
                last_err = f"HTTP {r.status_code}"
        return Lookup("unavailable", error=last_err)

    async def by_uuid(self, u: str) -> Lookup:
        if not self.s.mojang_enabled:
            return Lookup("skipped", error="Mojang lookups disabled")
        key = "uuid:" + u
        if (c := self._cache_get(key)):
            return c
        try:
            async with self._client() as client:
                r = await client.get(self.s.mojang_profile_url.format(uuid=u.replace("-", "")))
        except httpx.HTTPError as e:
            return Lookup("unavailable", error=type(e).__name__)
        if r.status_code == 200:
            d = r.json()
            lk = Lookup("found", normalize_uuid(d["id"]), d.get("name"), "mojang-sessionserver")
        elif r.status_code in (204, 404):
            lk = Lookup("not_found", source="mojang-sessionserver")
        else:
            return Lookup("unavailable", error=f"HTTP {r.status_code}")
        self._cache_put(key, lk)
        return lk

    async def verify(self, query: str, context_name: str | None = None) -> dict:
        """Verify a username or UUID and report identity consistency.

        `context_name` is the username a UUID was seen with (e.g. from moderation
        records), used to check that an offline UUID really derives from it.
        """
        q = query.strip()
        out: dict = {"query": q, "checks": []}
        nu = normalize_uuid(q)

        def check(code: str, ok: bool | None, text: str):
            out["checks"].append({"code": code, "result": {True: "pass", False: "fail", None: "unknown"}[ok],
                                  "detail": text})

        if nu:
            kind = uuid_kind(nu)
            out.update(input_type="uuid", uuid=nu, uuid_version=uuid_version(nu), uuid_kind=kind)
            if kind == "offline":
                out["mojang"] = asdict(Lookup("skipped", error="offline UUIDs are never registered with Mojang"))
                check("uuid_v3", True, "Version-3 UUID: generated by an offline-mode server, not by Mojang. "
                                      "Identity is NOT authenticated.")
                if context_name:
                    match = offline_uuid(context_name) == nu
                    check("offline_derivation", match,
                          f"UUID {'matches' if match else 'does NOT match'} the standard offline UUID for "
                          f"'{context_name}'" + ("" if match else " (custom auth plugin, renamed account, or "
                                                                   "spoofed data)"))
                out["verdict"] = "offline_identity"
            elif kind == "online":
                lk = await self.by_uuid(nu)
                out["mojang"] = asdict(lk)
                if lk.status == "found":
                    out["current_name"] = lk.name
                    out["offline_uuid_for_name"] = offline_uuid(lk.name) if lk.name else None
                    check("mojang_registered", True, f"Registered Mojang account, current name '{lk.name}'.")
                    if context_name and lk.name and context_name.lower() != lk.name.lower():
                        check("name_consistency", False,
                              f"Seen as '{context_name}' but the account is currently named '{lk.name}' "
                              "(could be a rename since that record).")
                    out["verdict"] = "verified_premium"
                elif lk.status == "not_found":
                    check("mojang_registered", False, "Version-4 UUID not known to Mojang: deleted/migrated "
                                                      "account, or fabricated UUID.")
                    out["verdict"] = "unregistered_v4"
                else:
                    check("mojang_registered", None, f"Mojang API unavailable ({lk.error}).")
                    out["verdict"] = "unverified"
            else:
                check("uuid_version", False, f"Unusual UUID version {uuid_version(nu)}.")
                out["verdict"] = "unknown"
            return out

        if not NAME_RE.match(q):
            out.update(input_type="invalid", verdict="invalid")
            check("format", False, "Not a valid Java username (1-16 chars, A-Z a-z 0-9 _) or UUID.")
            return out

        out.update(input_type="username", username=q, offline_uuid=offline_uuid(q))
        lk = await self.by_name(q)
        out["mojang"] = asdict(lk)
        if lk.status == "found":
            out["premium_uuid"] = lk.uuid
            check("premium_name", True, f"Name is registered to premium account {lk.uuid} "
                                        f"(canonical spelling '{lk.name}').")
            check("impersonation_surface", None,
                  f"Any offline-mode server will accept '{q}' from anyone and assign offline UUID "
                  f"{out['offline_uuid']}. That UUID is not proof of being the premium owner.")
            out["verdict"] = "premium_name"
        elif lk.status == "not_found":
            check("premium_name", False, "No premium account uses this name. It can only exist on "
                                         "offline-mode servers.")
            out["verdict"] = "no_premium_account"
        else:
            check("premium_name", None, f"Mojang API unavailable ({lk.error or lk.status}).")
            out["verdict"] = "unverified"
        return out

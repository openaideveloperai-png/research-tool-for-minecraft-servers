"""Minecraft Server List Ping (Java Edition, 1.7+ status protocol).

This is the same public query the in-game multiplayer screen sends. It never logs
in, never authenticates and never sends a player name.
"""

from __future__ import annotations

import asyncio
import json
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = 767  # any value works for a status request
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
ANON_UUID = "00000000-0000-0000-0000-000000000000"


class SLPError(Exception):
    pass


def encode_varint(value: int) -> bytes:
    value &= 0xFFFFFFFF
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    result = 0
    for i in range(5):
        if offset + i >= len(data):
            raise SLPError("truncated varint")
        b = data[offset + i]
        result |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            if result & (1 << 31):
                result -= 1 << 32
            return result, offset + i + 1
    raise SLPError("varint too long")


async def _read_varint(reader: asyncio.StreamReader) -> int:
    result = 0
    for i in range(5):
        b = (await reader.readexactly(1))[0]
        result |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return result
    raise SLPError("varint too long")


def _encode_string(s: str) -> bytes:
    raw = s.encode("utf-8")
    return encode_varint(len(raw)) + raw


def _packet(packet_id: int, payload: bytes = b"") -> bytes:
    body = encode_varint(packet_id) + payload
    return encode_varint(len(body)) + body


def build_handshake(host: str, port: int) -> bytes:
    payload = (encode_varint(PROTOCOL_VERSION) + _encode_string(host)
               + struct.pack(">H", port) + encode_varint(1))
    return _packet(0x00, payload)


async def _read_packet(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    length = await _read_varint(reader)
    if length <= 0 or length > MAX_RESPONSE_BYTES:
        raise SLPError(f"bad packet length {length}")
    data = await reader.readexactly(length)
    pid, off = decode_varint(data)
    return pid, data[off:]


# ---------------------------------------------------------------- parsing

_FORMAT_CODE = re.compile(r"§.")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|gg|io|co|uk|de|fr|pl|ru|br|eu|us|me|xyz|fun|club|online|"
    r"network|tk|ml|ga|cf|nl|es|it|ca|au|cz|sk|tr|lt|lv|ee|ro|hu|se|no|dk|fi|be|"
    r"at|ch|pt|gr|in|jp|kr|cn|tw|vn|id|ph|my|sg|nz|mx|ar|cl|pe|ua|by|kz|games?|"
    r"world|space|site|pro|info|biz|host|cloud|zone|live|play|mc|city|pw|cc|to|ws|"
    r"su|lol|one|top|dev|app|tech|land)\b(?::\d{1,5})?",
    re.IGNORECASE,
)
_IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE)


def redact_endpoints(text: str) -> str:
    """Remove anything that looks like an address, so a MOTD like
    'Join play.example.net' can't leak the connection endpoint."""
    if not text:
        return text
    text = _IPV4.sub("[address hidden]", text)
    text = _IPV6.sub("[address hidden]", text)
    text = _DOMAIN.sub("[address hidden]", text)
    return text


def flatten_chat(component: Any) -> str:
    if component is None:
        return ""
    if isinstance(component, str):
        return component
    if isinstance(component, list):
        return "".join(flatten_chat(c) for c in component)
    if isinstance(component, dict):
        text = component.get("text", "")
        if not text and "translate" in component:
            text = str(component["translate"])
        return str(text) + "".join(flatten_chat(c) for c in component.get("extra", []) or [])
    return str(component)


def clean_text(s: str) -> str:
    s = _FORMAT_CODE.sub("", s)
    lines = [ln.strip() for ln in s.splitlines()]
    return "\n".join(ln for ln in lines if ln)


_SOFTWARE = [
    ("velocity", "Velocity"), ("waterfall", "Waterfall"), ("bungeecord", "BungeeCord"),
    ("folia", "Folia"), ("purpur", "Purpur"), ("pufferfish", "Pufferfish"),
    ("paper", "Paper"), ("spigot", "Spigot"), ("craftbukkit", "CraftBukkit"),
    ("forge", "Forge"), ("neoforge", "NeoForge"), ("fabric", "Fabric"), ("quilt", "Quilt"),
    ("mohist", "Mohist"), ("arclight", "Arclight"), ("geyser", "Geyser"),
]


@dataclass
class StatusResult:
    online: bool
    latency_ms: float | None = None
    name: str = ""
    motd: str = ""
    version_name: str = ""
    protocol: int | None = None
    software: str | None = None
    mod_loader: str | None = None
    mods_count: int | None = None
    players_online: int | None = None
    players_max: int | None = None
    sample_size: int = 0
    sample_hidden: bool = False
    enforces_secure_chat: bool | None = None
    has_favicon: bool = False
    raw_keys: list[str] = field(default_factory=list)


def parse_status(payload: dict, latency_ms: float | None = None) -> StatusResult:
    """Parse a status JSON. Player sample names/UUIDs are counted and discarded:
    they are NOT returned or stored (see README, 'Player data policy')."""
    desc = clean_text(flatten_chat(payload.get("description", "")))
    desc = redact_endpoints(desc)
    name = desc.split("\n", 1)[0][:120] if desc else ""

    version = payload.get("version") or {}
    version_name = clean_text(str(version.get("name", "")))[:120]
    protocol = version.get("protocol")
    protocol = int(protocol) if isinstance(protocol, (int, float)) else None

    software = None
    low = version_name.lower()
    for key, label in _SOFTWARE:
        if key in low:
            software = label
            break

    mod_loader = None
    mods_count = None
    if isinstance(payload.get("forgeData"), dict):
        mod_loader = "Forge/NeoForge"
        mods = payload["forgeData"].get("mods")
        mods_count = len(mods) if isinstance(mods, list) else None
    elif isinstance(payload.get("modinfo"), dict):
        mod_loader = str(payload["modinfo"].get("type") or "Forge (legacy)")
        mods = payload["modinfo"].get("modList")
        mods_count = len(mods) if isinstance(mods, list) else None
    elif payload.get("isModded") or "fabric" in low:
        mod_loader = "Fabric"

    players = payload.get("players") or {}
    p_online = players.get("online")
    p_max = players.get("max")
    sample = players.get("sample") or []
    if not isinstance(sample, list):
        sample = []
    anon = [p for p in sample if isinstance(p, dict) and p.get("id") == ANON_UUID]
    sample_hidden = bool(
        (isinstance(p_online, int) and p_online > 0 and not sample) or (sample and len(anon) == len(sample))
    )

    return StatusResult(
        online=True,
        latency_ms=latency_ms,
        name=name or "(no description)",
        motd=desc[:1000],
        version_name=version_name,
        protocol=protocol,
        software=software,
        mod_loader=mod_loader,
        mods_count=mods_count,
        players_online=int(p_online) if isinstance(p_online, (int, float)) else None,
        players_max=int(p_max) if isinstance(p_max, (int, float)) else None,
        sample_size=len(sample),
        sample_hidden=sample_hidden,
        enforces_secure_chat=payload.get("enforcesSecureChat"),
        has_favicon=bool(payload.get("favicon")),
        raw_keys=sorted(payload.keys()),
    )


async def ping(host: str, port: int = 25565, timeout: float = 3.0) -> StatusResult:
    """Query a server's public status. Raises SLPError / OSError / TimeoutError."""

    async def _run() -> StatusResult:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            writer.write(build_handshake(host, port) + _packet(0x00))
            await writer.drain()
            pid, data = await _read_packet(reader)
            if pid != 0x00:
                raise SLPError(f"unexpected packet id {pid}")
            slen, off = decode_varint(data)
            raw = data[off:off + slen].decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as e:
                raise SLPError("invalid status JSON") from e
            if not isinstance(payload, dict):
                raise SLPError("status JSON is not an object")

            latency = None
            try:
                token = int(time.time() * 1000) & 0x7FFFFFFFFFFFFFFF
                t0 = time.perf_counter()
                writer.write(_packet(0x01, struct.pack(">q", token)))
                await writer.drain()
                pid, _ = await asyncio.wait_for(_read_packet(reader), timeout=timeout)
                if pid == 0x01:
                    latency = round((time.perf_counter() - t0) * 1000, 1)
            except Exception:
                pass
            return parse_status(payload, latency)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    return await asyncio.wait_for(_run(), timeout=timeout * 2)

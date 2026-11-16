"""Discovery engine: rate-limited Server List Ping sweeps over IP ranges.

Responsible-scanning controls built in:
  * global token-bucket rate limit (connections/second) with a hard ceiling
  * reserved / private ranges excluded unless MCSEC_ALLOW_PRIVATE=1
  * operator exclusion list (DB + optional file) for opt-out requests
  * per-job target cap
  * only the public status query is sent; nothing ever logs in

Endpoints are written to the `endpoints` table and referenced everywhere else
by an opaque random server_id.
"""

from __future__ import annotations

import asyncio
import ipaddress
import secrets
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .config import Settings
from .db import Database
from . import slp

RESERVED_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "255.255.255.255/32",
)]
LOOPBACK = ipaddress.ip_network("127.0.0.0/8")


class TokenBucket:
    def __init__(self, rate: float):
        self.rate = max(rate, 0.1)
        self.capacity = max(1.0, self.rate)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.rate)


@dataclass
class Target:
    host: str
    port: int


@dataclass
class JobState:
    job_id: str
    task: asyncio.Task | None = None
    cancelled: bool = False
    errors: dict[str, int] = field(default_factory=dict)


class Scanner:
    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.s = settings
        self.jobs: dict[str, JobState] = {}

    # ------------------------------------------------------------ exclusions
    def exclusion_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets = []
        if not self.s.allow_private:
            nets.extend(RESERVED_V4)
        for row in self.db.query("SELECT cidr FROM exclusions"):
            try:
                nets.append(ipaddress.ip_network(row["cidr"], strict=False))
            except ValueError:
                pass
        if self.s.exclude_file and Path(self.s.exclude_file).exists():
            for line in Path(self.s.exclude_file).read_text().splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    try:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        pass
        return nets

    def is_excluded(self, ip: str, nets) -> bool:
        addr = ipaddress.ip_address(ip)
        if self.s.allow_private and addr in LOOPBACK:
            return any(addr in n for n in nets)
        if addr.version == 6 and not self.s.allow_private and (
                addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast):
            return True
        return any(addr.version == n.version and addr in n for n in nets)

    # ------------------------------------------------------------ targets
    @staticmethod
    def parse_spec(spec: str) -> tuple[str, int | None]:
        spec = spec.strip()
        if spec.startswith("[") and "]" in spec:  # [v6]:port
            host, _, rest = spec[1:].partition("]")
            return host, int(rest[1:]) if rest.startswith(":") else None
        if spec.count(":") == 1:
            host, port = spec.split(":")
            return host, int(port)
        return spec, None

    def count_targets(self, specs: list[str], ports: list[int]) -> int:
        total = 0
        for spec in specs:
            host, port = self.parse_spec(spec)
            nports = 1 if port else len(ports)
            try:
                net = ipaddress.ip_network(host, strict=False)
                total += net.num_addresses * nports
            except ValueError:
                total += nports
        return total

    def iter_targets(self, specs: list[str], ports: list[int]) -> Iterator[Target]:
        for spec in specs:
            host, port = self.parse_spec(spec)
            plist = [port] if port else ports
            try:
                net = ipaddress.ip_network(host, strict=False)
                hosts = net.hosts() if net.num_addresses > 2 else iter(net)
                for ip in hosts:
                    for p in plist:
                        yield Target(str(ip), p)
            except ValueError:
                for p in plist:
                    yield Target(host, p)  # hostname, resolved at probe time

    # ------------------------------------------------------------ persistence
    def _server_id_for(self, host: str, port: int) -> str:
        row = self.db.one("SELECT server_id FROM endpoints WHERE host=? AND port=?", (host, port))
        if row:
            return row["server_id"]
        sid = "srv_" + secrets.token_hex(8)
        self.db.execute("INSERT INTO endpoints(server_id, host, port) VALUES (?,?,?)", (sid, host, port))
        return sid

    def record(self, host: str, port: int, res: slp.StatusResult) -> str:
        now = time.time()
        sid = self._server_id_for(host, port)
        existing = self.db.one("SELECT server_id FROM servers WHERE server_id=?", (sid,))
        vals = dict(
            last_seen=now, last_checked=now, online=1, name=res.name, motd=res.motd,
            version_name=res.version_name, protocol=res.protocol, software=res.software,
            mod_loader=res.mod_loader, mods_count=res.mods_count, players_online=res.players_online,
            players_max=res.players_max, sample_size=res.sample_size, sample_hidden=int(res.sample_hidden),
            enforces_secure_chat=None if res.enforces_secure_chat is None else int(res.enforces_secure_chat),
            has_favicon=int(res.has_favicon), latency_ms=res.latency_ms,
        )
        if existing:
            sets = ", ".join(f"{k}=?" for k in vals)
            self.db.execute(f"UPDATE servers SET {sets}, times_seen=times_seen+1 WHERE server_id=?",
                            (*vals.values(), sid))
        else:
            cols = ", ".join(vals)
            qs = ", ".join("?" for _ in vals)
            self.db.execute(f"INSERT INTO servers(server_id, first_seen, times_seen, {cols}) VALUES (?,?,1,{qs})",
                            (sid, now, *vals.values()))
        self.db.execute(
            "INSERT INTO status_history(server_id, ts, online, players_online, players_max, latency_ms) "
            "VALUES (?,?,?,?,?,?)", (sid, now, 1, res.players_online, res.players_max, res.latency_ms))
        return sid

    def record_offline(self, server_id: str) -> None:
        now = time.time()
        self.db.execute("UPDATE servers SET online=0, last_checked=? WHERE server_id=?", (now, server_id))
        self.db.execute("INSERT INTO status_history(server_id, ts, online) VALUES (?,?,0)", (server_id, now))

    # ------------------------------------------------------------ jobs
    def _new_job(self, kind: str, summary: str, total: int, rate: float) -> str:
        job_id = "job_" + secrets.token_hex(6)
        self.db.execute(
            "INSERT INTO scan_jobs(job_id, created, status, kind, summary, total, rate) VALUES (?,?,?,?,?,?,?)",
            (job_id, time.time(), "running", kind, summary, total, rate))
        self.jobs[job_id] = JobState(job_id)
        return job_id

    def start_scan(self, specs: list[str], ports: list[int], rate: float | None,
                   concurrency: int | None) -> str:
        specs = [s for s in (x.strip() for x in specs) if s]
        if not specs:
            raise ValueError("no targets given")
        ports = sorted({int(p) for p in (ports or [25565]) if 1 <= int(p) <= 65535}) or [25565]
        total = self.count_targets(specs, ports)
        if total > self.s.max_targets_per_job:
            raise ValueError(f"{total} targets exceeds per-job cap of {self.s.max_targets_per_job} "
                             "(MCSEC_MAX_TARGETS); split the range into several jobs")
        rate = min(rate or self.s.scan_rate, self.s.scan_rate_max)
        conc = max(1, min(concurrency or self.s.scan_concurrency, 2000))
        # Summary deliberately omits the address ranges: the UI never shows endpoints.
        summary = f"{len(specs)} target spec(s), {len(ports)} port(s)"
        job_id = self._new_job("discovery", summary, total, rate)
        targets = self.iter_targets(specs, ports)
        self.jobs[job_id].task = asyncio.create_task(self._run(job_id, targets, rate, conc))
        return job_id

    def start_recheck(self, rate: float | None = None) -> str:
        rows = self.db.query("SELECT e.server_id, e.host, e.port FROM endpoints e "
                             "JOIN servers s ON s.server_id = e.server_id")
        rate = min(rate or self.s.scan_rate, self.s.scan_rate_max)
        job_id = self._new_job("recheck", f"re-query {len(rows)} known server(s)", len(rows), rate)
        targets = (Target(r["host"], r["port"]) for r in rows)
        self.jobs[job_id].task = asyncio.create_task(
            self._run(job_id, targets, rate, self.s.scan_concurrency, mark_offline=True))
        return job_id

    def cancel(self, job_id: str) -> bool:
        st = self.jobs.get(job_id)
        if not st or not st.task or st.task.done():
            return False
        st.cancelled = True
        st.task.cancel()
        return True

    async def _run(self, job_id: str, targets: Iterator[Target], rate: float, conc: int,
                   mark_offline: bool = False) -> None:
        bucket = TokenBucket(rate)
        sem = asyncio.Semaphore(conc)
        excl = self.exclusion_networks()
        counters = {"done": 0, "found": 0, "skipped": 0}
        st = self.jobs[job_id]
        last_flush = time.monotonic()

        def flush(final_status: str | None = None, error: str | None = None):
            if final_status:
                self.db.execute(
                    "UPDATE scan_jobs SET done=?, found=?, skipped=?, status=?, finished=?, error=? WHERE job_id=?",
                    (counters["done"], counters["found"], counters["skipped"], final_status, time.time(),
                     error, job_id))
            else:
                self.db.execute("UPDATE scan_jobs SET done=?, found=?, skipped=? WHERE job_id=?",
                                (counters["done"], counters["found"], counters["skipped"], job_id))

        async def probe(t: Target):
            try:
                ip = t.host
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    infos = await asyncio.get_running_loop().getaddrinfo(t.host, t.port, type=socket.SOCK_STREAM)
                    ip = infos[0][4][0]
                if self.is_excluded(ip, excl):
                    counters["skipped"] += 1
                    return
                await bucket.take()
                try:
                    res = await slp.ping(t.host, t.port, timeout=self.s.scan_timeout)
                    self.record(t.host, t.port, res)
                    counters["found"] += 1
                except (OSError, asyncio.TimeoutError, slp.SLPError, asyncio.IncompleteReadError) as e:
                    key = type(e).__name__
                    st.errors[key] = st.errors.get(key, 0) + 1
                    if mark_offline:
                        row = self.db.one("SELECT server_id FROM endpoints WHERE host=? AND port=?",
                                          (t.host, t.port))
                        if row:
                            self.record_offline(row["server_id"])
            except (OSError, socket.gaierror):
                st.errors["ResolveError"] = st.errors.get("ResolveError", 0) + 1
            finally:
                counters["done"] += 1
                sem.release()

        pending: set[asyncio.Task] = set()
        try:
            for t in targets:
                await sem.acquire()
                task = asyncio.create_task(probe(t))
                pending.add(task)
                task.add_done_callback(pending.discard)
                if time.monotonic() - last_flush > 1:
                    flush()
                    last_flush = time.monotonic()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            flush("completed")
        except asyncio.CancelledError:
            for task in pending:
                task.cancel()
            flush("cancelled")
        except Exception as e:  # pragma: no cover - defensive
            flush("failed", type(e).__name__)

    def job_view(self, job_id: str) -> dict | None:
        row = self.db.one("SELECT job_id, created, finished, status, kind, summary, total, done, found, skipped, "
                          "rate, error FROM scan_jobs WHERE job_id=?", (job_id,))
        if not row:
            return None
        st = self.jobs.get(job_id)
        row["errors"] = dict(st.errors) if st else {}
        if row["status"] == "running" and not st:
            row["status"] = "interrupted"  # process restarted mid-job
        return row

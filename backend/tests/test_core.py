import json
import time

import pytest

from mcsec.federation import ip_hash
from mcsec.mojang import offline_uuid, uuid_kind
from mcsec.slp import decode_varint, encode_varint, parse_status, redact_endpoints

from conftest import PREMIUM, STATUS


def wait_job(client, job_id, timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = client.get(f"/api/scan/jobs/{job_id}").json()
        if j["status"] != "running":
            return j
        time.sleep(0.1)
    raise AssertionError("job did not finish")


# ---------------------------------------------------------------- protocol
@pytest.mark.parametrize("n", [0, 1, 127, 128, 255, 25565, 2097151, 2147483647, -1])
def test_varint_roundtrip(n):
    assert decode_varint(encode_varint(n))[0] == n


def test_offline_uuid_matches_java():
    # Java: UUID.nameUUIDFromBytes("OfflinePlayer:Notch".getBytes(UTF_8))
    assert offline_uuid("Notch") == "b50ad385-829d-3141-a216-7e7d7539ba7f"
    assert uuid_kind(offline_uuid("Notch")) == "offline"
    assert uuid_kind("069a79f4-44e9-4726-a5be-fca90e38aaf5") == "online"


def test_parse_status_discards_names_and_redacts():
    r = parse_status(STATUS)
    assert r.name == "SkyBlock Research Realm"
    assert "secret-host" not in r.motd and "127.0.0.1" not in r.motd
    assert r.software == "Paper" and r.players_online == 7 and r.sample_size == 2
    assert "SecretPlayerOne" not in json.dumps(r.__dict__)


def test_redaction_variants():
    for s in ["mc.example.com", "1.2.3.4:25565", "Play at hub.my-server.gg!", "2001:db8::1:2:3:4"]:
        assert "[address hidden]" in redact_endpoints(s), s


# ---------------------------------------------------------------- discovery
def test_scan_discovers_and_never_leaks_endpoint(client, fake_server):
    port = fake_server.port
    r = client.post("/api/scan/jobs", json={"targets": ["127.0.0.1/32"], "ports": [port]})
    assert r.status_code == 200, r.text
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "completed" and job["found"] == 1

    servers = client.get("/api/servers").json()
    assert servers["total"] == 1
    srv = servers["items"][0]
    assert srv["name"] == "SkyBlock Research Realm" and srv["players_online"] == 7
    detail = client.get(f"/api/servers/{srv['server_id']}").json()
    assert len(detail["history"]) == 1

    # Re-check adds history
    wait_job(client, client.post("/api/scan/recheck").json()["job_id"])
    assert len(client.get(f"/api/servers/{srv['server_id']}").json()["history"]) == 2

    # Nothing anywhere may contain the endpoint or the sampled player names.
    bodies = [client.get(u).text for u in (
        "/api/servers", f"/api/servers/{srv['server_id']}", "/api/servers/export?format=csv",
        "/api/servers/export?format=json", "/api/stats", "/api/scan/jobs", f"/api/scan/jobs/{job['job_id']}",
        "/api/servers?q=127")]
    for b in bodies:
        assert "127.0.0.1" not in b
        assert f":{port}" not in b and f'"{port}"' not in b and f",{port}," not in b
        assert "secret-host" not in b
        assert "SecretPlayer" not in b
    # and the sampled names never reach the database
    db = client.app.state.db
    dump = json.dumps([db.query(f"SELECT * FROM {t}") for t in ("servers", "status_history", "scan_jobs")])
    assert "SecretPlayer" not in dump


def test_reserved_ranges_blocked_by_default(tmp_path, fake_server):
    from fastapi.testclient import TestClient
    from mcsec.api import create_app
    from mcsec.config import Settings
    s = Settings()
    s.db_path, s.admin_token, s.allow_private = str(tmp_path / "x.db"), "t", False
    with TestClient(create_app(s)) as c:
        c.headers["Authorization"] = "Bearer t"
        j = c.post("/api/scan/jobs", json={"targets": ["127.0.0.1"], "ports": [fake_server.port]}).json()
        j = wait_job(c, j["job_id"])
        assert j["found"] == 0 and j["skipped"] == 1


def test_exclusion_purges_and_skips(client, fake_server):
    j = client.post("/api/scan/jobs", json={"targets": ["127.0.0.1"], "ports": [fake_server.port]}).json()
    wait_job(client, j["job_id"])
    assert client.get("/api/servers").json()["total"] == 1
    r = client.post("/api/exclusions", json={"cidr": "127.0.0.0/8", "reason": "opt-out"}).json()
    assert r["purged_servers"] == 1
    assert client.get("/api/servers").json()["total"] == 0
    j = client.post("/api/scan/jobs", json={"targets": ["127.0.0.1"], "ports": [fake_server.port]}).json()
    assert wait_job(client, j["job_id"])["skipped"] == 1


def test_target_cap(client):
    r = client.post("/api/scan/jobs", json={"targets": ["0.0.0.0/0"]})
    assert r.status_code == 400 and "cap" in r.json()["detail"]


def test_auth_required(client):
    assert client.get("/api/servers", headers={"Authorization": ""}).status_code == 401
    assert client.post("/api/ingest/events", json={"events": [{"type": "heartbeat"}]},
                       headers={"X-Api-Key": "nope"}).status_code == 401


# ---------------------------------------------------------------- identity
def test_verify_username_and_uuid(client):
    v = client.get("/api/uuid/verify", params={"q": "Notch"}).json()
    assert v["verdict"] == "premium_name" and v["premium_uuid"] == "069a79f4-44e9-4726-a5be-fca90e38aaf5"
    assert v["offline_uuid"] == offline_uuid("Notch")
    v = client.get("/api/uuid/verify", params={"q": "NoSuchPlayerXyz"}).json()
    assert v["verdict"] == "no_premium_account"
    v = client.get("/api/uuid/verify", params={"q": offline_uuid("Notch"), "name": "Notch"}).json()
    assert v["verdict"] == "offline_identity"
    assert any(c["code"] == "offline_derivation" and c["result"] == "pass" for c in v["checks"])
    v = client.get("/api/uuid/verify", params={"q": PREMIUM["Notch"]}).json()
    assert v["verdict"] == "verified_premium" and v["current_name"] == "Notch"


# ---------------------------------------------------------------- federation
def _register(client, name, online_mode):
    return client.post("/api/federation/servers", json={"name": name, "description": f"{name} desc",
                                                        "online_mode": online_mode}).json()


def test_federation_flow_and_indicators(client):
    a = _register(client, "Premium Survival", True)
    b = _register(client, "Cracked Factions", False)
    salt = a["ip_salt"]
    home, other = ip_hash(salt, "203.0.113.5"), ip_hash(salt, "198.51.100.9")
    notch = "069a79f4-44e9-4726-a5be-fca90e38aaf5"
    fake_notch = offline_uuid("Notch")
    griefer = offline_uuid("Griefer123")
    alt = offline_uuid("TotallyNew")
    now = time.time()

    def push(reg, events):
        r = client.post("/api/ingest/events", json={"events": events}, headers={"X-Api-Key": reg["api_key"]})
        assert r.status_code == 200, r.text
        return r.json()

    push(a, [
        {"type": "login", "ts": now - 7200, "uuid": notch, "username": "Notch", "ip_hash": other},
        {"type": "logout", "ts": now - 3600, "uuid": notch},
        {"type": "login", "ts": now - 600, "uuid": notch, "username": "Notch", "ip_hash": other},
    ])
    push(b, [
        # impersonator online at the same time as the real Notch
        {"type": "login", "ts": now - 500, "uuid": fake_notch, "username": "Notch", "ip_hash": home},
        # griefer banned, then an alt shows up from the same network
        {"type": "login", "ts": now - 90000, "uuid": griefer, "username": "Griefer123", "ip_hash": home},
        {"type": "logout", "ts": now - 86000, "uuid": griefer},
        {"type": "warn", "ts": now - 86500, "uuid": griefer, "reason": "spam"},
        {"type": "ban", "ts": now - 85000, "uuid": griefer, "reason": "griefing spawn"},
        {"type": "login", "ts": now - 3000, "uuid": alt, "username": "TotallyNew", "ip_hash": home},
        {"type": "logout", "ts": now - 1000, "uuid": alt},
        {"type": "heartbeat", "ts": now - 10, "online_uuids": [fake_notch]},
    ])
    r = push(b, [{"type": "login", "ts": now, "uuid": alt}])  # missing username
    assert r["accepted"] == 0 and r["rejected"]
    bad = client.post("/api/ingest/events", json={"events": [{"type": "login", "uuid": alt, "username": "x",
                                                               "ip_hash": "203.0.113.5"}]},
                      headers={"X-Api-Key": b["api_key"]})
    assert bad.status_code == 422  # raw IPs refused

    # Player search by name: real account confirmed, cracked one only "possible"
    s = client.get("/api/players/search", params={"q": "Notch"}).json()
    by = {x["uuid"]: x for x in s["results"]}
    assert by[notch]["match"] == "confirmed" and by[fake_notch]["match"] == "possible"
    assert by[notch]["servers"][0]["status"] == "online"
    assert s["sources"]["public_scan"]["available"] is False

    # Impersonator profile
    p = client.get(f"/api/players/{fake_notch}/profile").json()
    codes = {i["code"] for i in p["risk"]["indicators"]}
    assert {"OFFLINE_IDENTITY", "PREMIUM_NAME_CONFLICT", "DUPLICATE_NAME", "SIMULTANEOUS_SAME_NAME"} <= codes

    # Ban-evasion candidate
    p = client.get(f"/api/players/{alt}/profile").json()
    codes = {i["code"]: i for i in p["risk"]["indicators"]}
    assert codes["SHARED_NETWORK_WITH_BANNED"]["severity"] == "high"
    assert p["stats"]["total_playtime"] == "33m"

    # Banned player's history
    p = client.get(f"/api/players/{griefer}/profile").json()
    assert [x["kind"] for x in p["punishments"]] == ["ban", "warn"] and p["punishments"][0]["active"]

    kinds = {a["type"] for a in client.get("/api/alerts").json()}
    assert {"simultaneous_same_name", "possible_ban_evasion", "duplicate_name"} <= kinds

    for fmt in ("md", "csv", "json"):
        rep = client.get(f"/api/players/{alt}/report", params={"format": fmt})
        assert rep.status_code == 200 and "TotallyNew" in rep.text
        assert home not in rep.text  # network hashes are not exported

    # Unban clears the evasion indicator
    push(b, [{"type": "unban", "uuid": griefer}])
    p = client.get(f"/api/players/{alt}/profile").json()
    assert "SHARED_NETWORK_WITH_BANNED" not in {i["code"] for i in p["risk"]["indicators"]}

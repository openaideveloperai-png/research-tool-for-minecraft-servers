import asyncio
import json
import struct
import sys
import threading
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcsec.slp import encode_varint, decode_varint  # noqa: E402

PREMIUM = {"jeb_": "853c80ef3c3749fdaa49938b674adae6", "Notch": "069a79f444e94726a5befca90e38aaf5"}


class FakeMinecraftServer:
    """Speaks just enough of the status protocol to answer a Server List Ping."""

    def __init__(self, status: dict):
        self.status = status
        self.port = None
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    async def _handle(self, reader, writer):
        try:
            async def read_packet():
                n = 0
                for i in range(5):
                    b = (await reader.readexactly(1))[0]
                    n |= (b & 0x7F) << (7 * i)
                    if not b & 0x80:
                        break
                data = await reader.readexactly(n)
                pid, off = decode_varint(data)
                return pid, data[off:]

            await read_packet()  # handshake
            await read_packet()  # status request
            body = json.dumps(self.status).encode()
            payload = encode_varint(0) + encode_varint(len(body)) + body
            writer.write(encode_varint(len(payload)) + payload)
            await writer.drain()
            pid, data = await read_packet()  # ping
            pong = encode_varint(1) + data
            writer.write(encode_varint(len(pong)) + pong)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        server = self.loop.run_until_complete(asyncio.start_server(self._handle, "127.0.0.1", 0))
        self.port = server.sockets[0].getsockname()[1]
        self.ready.set()
        self.loop.run_forever()

    def start(self):
        self.thread.start()
        self.ready.wait(5)
        return self

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)


STATUS = {
    "version": {"name": "Paper 1.21.1", "protocol": 767},
    "players": {"max": 100, "online": 7, "sample": [
        {"name": "SecretPlayerOne", "id": "4566e69f-c907-48ee-8d71-d7ba5aa00d20"},
        {"name": "SecretPlayerTwo", "id": "11111111-2222-3333-4444-555555555555"}]},
    "description": {"text": "§aSkyBlock Research Realm\n§7Join at play.secret-host.net or 127.0.0.1:25565",
                    "extra": [{"text": " !"}]},
    "enforcesSecureChat": True,
    "favicon": "data:image/png;base64,AAAA",
}


@pytest.fixture
def fake_server():
    srv = FakeMinecraftServer(STATUS).start()
    yield srv
    srv.stop()


def mojang_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/users/profiles/minecraft/" in path:
            name = path.rsplit("/", 1)[1]
            for n, u in PREMIUM.items():
                if n.lower() == name.lower():
                    return httpx.Response(200, json={"id": u, "name": n})
            return httpx.Response(404)
        if "/session/minecraft/profile/" in path:
            u = path.rsplit("/", 1)[1]
            for n, pu in PREMIUM.items():
                if pu == u:
                    return httpx.Response(200, json={"id": pu, "name": n})
            return httpx.Response(204)
        return httpx.Response(404)
    return httpx.MockTransport(handler)


@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient
    from mcsec.api import create_app
    from mcsec.config import Settings

    s = Settings()
    s.db_path = str(tmp_path / "t.sqlite3")
    s.admin_token = "test-token"
    s.allow_private = True
    s.scan_rate = 200
    s.scan_timeout = 2
    app = create_app(s, mojang_transport=mojang_transport())
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer test-token"
        yield c

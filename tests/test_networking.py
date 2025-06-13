"""
Tests for DHT / networking helpers using pytest-asyncio and monkey-patching.

Target module: dht/dht.py
"""
import json
from contextlib import asynccontextmanager
from importlib import import_module, reload

import pytest

MODULE_PATH = "dht.dht"          # adjust if you move the source file


# ────────────────────────── fixtures & stubs ──────────────────────────
@pytest.fixture
def mod(monkeypatch):
    """
    Import the target module fresh for each test and patch its kad_server
    with a lightweight in-memory implementation.
    """
    m = import_module(MODULE_PATH)
    reload(m)

    class _DummyKad(dict):
        async def listen(self, _): ...
        async def bootstrap(self, *_): ...
        async def get(self, k):   return super().get(k)
        async def set(self, k, v): super().__setitem__(k, v)
        def bootstrappable_neighbors(self): return True

    m.kad_server = _DummyKad()
    monkeypatch.setattr(m, "kad_server", m.kad_server)
    return m


@asynccontextmanager
async def _fake_aiohttp(text: str):
    """Stub that mimics aiohttp.ClientSession().get(...)."""
    class _Resp:
        async def text(self): return text
        async def __aenter__(self): return self
        async def __aexit__(self, *exc): ...

    class _Session:
        def get(self, *_):          # sync like real aiohttp
            return _Resp()
        async def __aenter__(self): return self
        async def __aexit__(self, *exc): ...

    yield _Session()


# ────────────────────────────── tests ────────────────────────────────
@pytest.mark.parametrize(
    "inp,exp",
    [(b"hello", "hello"), ("world", "world"), (None, None)],
)
def test_b2s(mod, inp, exp):
    assert mod.b2s(inp) == exp


@pytest.mark.asyncio
async def test_get_external_ip(monkeypatch, mod):
    async with _fake_aiohttp("203.0.113.9") as fake_session:
        monkeypatch.setattr(mod.aiohttp, "ClientSession", lambda: fake_session)
        ip1 = await mod.get_external_ip()
        ip2 = await mod.get_external_ip()  # should return cached value
        assert ip1 == ip2 == "203.0.113.9"


@pytest.mark.asyncio
async def test_announce_gossip_port(monkeypatch, mod):
    wallet_stub = {"publicKey": "PK"}   # minimal wallet placeholder
    mod.own_ip = "198.51.100.7"

    await mod.announce_gossip_port(
        wallet_stub,
        ip="198.51.100.7",
        port=9000,
        gossip_node=None,
    )

    key = f"gossip_{mod.VALIDATOR_ID}"
    stored_raw = await mod.kad_server.get(key)
    assert stored_raw is not None
    stored = json.loads(stored_raw)
    assert stored == {"ip": "198.51.100.7", "port": 9000}


@pytest.mark.asyncio
async def test_register_validator_once(mod):
    await mod.register_validator_once()
    first = await mod.kad_server.get(mod.VALIDATORS_LIST_KEY)

    # Call again; list should remain unchanged (idempotent behaviour)
    await mod.register_validator_once()
    second = await mod.kad_server.get(mod.VALIDATORS_LIST_KEY)

    assert first == second
    assert mod.VALIDATOR_ID in json.loads(first)

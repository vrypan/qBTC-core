# tests/test_rpc_block.py
"""
Unit-tests for the RPC methods in rpc/rpc.py:

* getblocktemplate – should include the txids of pending transactions.
* submitblock      – “happy path” with heavy validation logic stubbed out.
"""

from __future__ import annotations

import importlib
import struct
import time
import json

import pytest
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
#  Load the FastAPI app we’re testing
# ─────────────────────────────────────────────────────────────────────────────
rpc_mod = importlib.import_module("rpc.rpc")   # rpc/rpc.py
rpc_app = rpc_mod.rpc_app                      # FastAPI instance that serves “/”


# ─────────────────────────────────────────────────────────────────────────────
#  Helper: craft a *minimal* raw Bitcoin block (header + 1-byte coinbase)
# ─────────────────────────────────────────────────────────────────────────────
def _make_raw_block(prev_hash: str, merkle_hash: str, timestamp: int,
                    bits: int = 0x1F00FFFF) -> str:
    header  = struct.pack("<I", 1)                     # version
    header += bytes.fromhex(prev_hash)[::-1]           # prev block (LE)
    header += bytes.fromhex(merkle_hash)[::-1]         # merkle    (LE)
    header += struct.pack("<I", timestamp)             # time
    header += struct.pack("<I", bits)                  # bits
    header += struct.pack("<I", 0)                     # nonce

    # varint(1) + fake 1-byte coinbase + empty “[]” tx list
    payload = header + b"\x01" + b"\x00" + b"[]"
    return payload.hex()


# ─────────────────────────────────────────────────────────────────────────────
#  GETBLOCKTEMPLATE  – the template must list current pending-tx IDs
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.stub_verify
def test_getblocktemplate_contains_pending_txids(monkeypatch, _stub_database):
    from state import state as state_mod

    # Seed one pending transaction
    state_mod.pending_transactions.clear()
    state_mod.pending_transactions["txABC"] = {
        "txid": "txABC",
        "outputs": [
            {"utxo_index": 0, "sender": "alice", "receiver": "bob", "amount": "1"}
        ],
        "body": {"msg_str": "", "pubkey": "", "signature": ""},
        "timestamp": int(time.time() * 1000),
    }

    # Fake “height / tip” for the template
    monkeypatch.setattr("rpc.rpc.get_current_height",
                        lambda db: (0, "0" * 64), raising=True)

    client  = TestClient(rpc_app)
    resp    = client.post(
        "/",
        json={"id": 1, "method": "getblocktemplate", "params": []},
    )

    assert resp.status_code == 200
    body  = resp.json()
    txids = [tx["txid"] for tx in body["result"]["transactions"]]
    assert "txABC" in txids


# ─────────────────────────────────────────────────────────────────────────────
#  SUBMITBLOCK  – happy-path with heavy checks replaced by stubs
# ─────────────────────────────────────────────────────────────────────────────
def test_submitblock_happy(monkeypatch, _stub_database):
    # ── 1. Stub CPU-expensive / Bitcoin-specific helpers ───────────────────
    monkeypatch.setattr("rpc.rpc.validate_pow", lambda blk: True, raising=True)
    monkeypatch.setattr("rpc.rpc.scriptpubkey_to_address",
                        lambda spk: "miner_addr", raising=True)
    monkeypatch.setattr("rpc.rpc.parse_tx",
                        lambda raw, off: ({"outputs": [{"script_pubkey": "00"}]}, 1),
                        raising=True)
    monkeypatch.setattr("rpc.rpc.bits_to_target", lambda bits: 0, raising=False)

    fake_hash = bytes.fromhex("aa" * 32)
    monkeypatch.setattr("rpc.rpc.sha256d", lambda _: fake_hash, raising=True)
    monkeypatch.setattr("rpc.rpc.calculate_merkle_root",
                        lambda txids: "aa" * 32, raising=True)

    # Fake local chain height / tip
    monkeypatch.setattr("rpc.rpc.get_current_height",
                        lambda db: (0, "0" * 64), raising=True)

    # ── 2. Stub JSON decoder so the tx-parsing loop gets a valid skeleton ──
    def _fake_raw_decode(self, s: str, idx: int = 0):
        dummy_tx = {
            "inputs":  [],
            "outputs": [{"utxo_index": 0, "sender": "", "receiver": "", "amount": "0", "spent": False}],
            "body":    {"msg_str": "", "pubkey": "", "signature": ""},
        }
        return dummy_tx, len(s)            # consume the whole blob

    monkeypatch.setattr("rpc.rpc.json.JSONDecoder.raw_decode",
                        _fake_raw_decode, raising=True)

    # serialize_transaction just needs to return some hex
    monkeypatch.setattr("rpc.rpc.serialize_transaction", lambda tx: "00", raising=True)

    # ── 3. Dummy gossip client to assert broadcast was triggered ───────────
    class DummyGossip:
        def __init__(self):
            self.called = False
        async def randomized_broadcast(self, msg):  # noqa: D401
            self.called = True

    rpc_mod.rpc_app.state.gossip_client = DummyGossip()

    # ── 4. Craft block + POST submitblock ──────────────────────────────────
    raw_hex = _make_raw_block("00" * 32, "aa" * 32, int(time.time()))
    client  = TestClient(rpc_app)
    resp    = client.post(
        "/",
        json={"id": 2, "method": "submitblock", "params": [raw_hex]},
    )

    # ── 5. Assertions ──────────────────────────────────────────────────────
    assert resp.status_code == 200
    body = resp.json()
    assert body["error"] is None
    assert rpc_mod.rpc_app.state.gossip_client.called is True

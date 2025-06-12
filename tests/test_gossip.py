# tests/test_gossip.py
import asyncio
import json
import time
from unittest.mock import AsyncMock

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# 1. Fresh transaction is stored
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.stub_verify          # <<–– uses stub verifier
async def test_handle_valid_transaction(node, dummy_writer):
    now_ms = int(time.time() * 1000)
    tx_msg = {
        "type": "transaction",
        "timestamp": now_ms,
        "tx_id": "tx-abc",
        "body": {"msg_str": "hello", "signature": "sig", "pubkey": "pk"},
    }

    # clear global dict before running
    import state.state as state_mod
    state_mod.pending_transactions.clear()

    await node.handle_gossip_message(tx_msg, ("somepeer", 1234), dummy_writer)

    assert "tx-abc" in state_mod.pending_transactions
    assert "tx-abc" in node.seen_tx


# ──────────────────────────────────────────────────────────────────────────────
# 2. Stale transaction is ignored
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.stub_verify          # <<–– uses stub verifier
async def test_stale_message(node, dummy_writer):
    stale_ts = int(time.time() * 1000) - 90_000  # older than 60 s
    msg = {"type": "transaction", "timestamp": stale_ts, "tx_id": "old", "body": {}}

    await node.handle_gossip_message(msg, ("peer", 1), dummy_writer)

    from state.state import pending_transactions
    assert "old" not in pending_transactions
    assert "old" not in node.seen_tx


# ──────────────────────────────────────────────────────────────────────────────
# 3. randomized_broadcast chooses √N peers
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_randomized_broadcast_picks_sqrt(monkeypatch, node):
    node.dht_peers = {("ip", p) for p in range(16)}     # 16 peers → expect 4

    async_mock = AsyncMock(return_value=None)
    monkeypatch.setattr(node, "_send_message", async_mock)

    await node.randomized_broadcast({"foo": "bar"})
    assert async_mock.await_count == 4


# ──────────────────────────────────────────────────────────────────────────────
# 4. _send_message retries & drops failing peer after 3 attempts
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_send_message_retry_and_drop(monkeypatch, node):
    async def _always_fail(*a, **k):
        raise ConnectionRefusedError

    monkeypatch.setattr("asyncio.open_connection", _always_fail)

    peer = ("1.1.1.1", 9999)
    node.dht_peers.add(peer)

    await node._send_message(peer, b"payload")
    assert peer not in node.dht_peers
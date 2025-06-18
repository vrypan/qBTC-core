"""
Test backward compatibility for broadcast_tx endpoint
"""
import base64
import json
import time
import importlib
from fastapi.testclient import TestClient
import pytest

# Import the FastAPI app
web_mod = importlib.import_module("web.web")
app = web_mod.app


@pytest.mark.stub_verify
def test_broadcast_tx_old_format_compatibility(_stub_database):
    """
    Test that old format (sender:receiver:amount) is automatically upgraded
    to new format with timestamp and chain_id
    """
    # Fake gossip client
    class DummyGossip:
        def __init__(self):
            self.received = None

        async def randomized_broadcast(self, tx: dict):
            self.received = tx

    dummy_gossip = DummyGossip()
    app.state.gossip_client = dummy_gossip

    # Seed DB with UTXO
    sender = "bqs1senderwallet000000000000000000000000"
    receiver = "bqs1receiverwallet00000000000000000000000"
    amount = "1"
    db = _stub_database
    db[b"utxo:coinbase001"] = json.dumps({
        "txid": "coinbase001",
        "utxo_index": 0,
        "sender": "",
        "receiver": sender,
        "amount": "10",
        "spent": False,
    }).encode()

    # Use OLD format (no timestamp, no chain_id)
    msg_str = f"{sender}:{receiver}:{amount}"
    payload = {
        "request_type": "broadcast_tx",
        "message": base64.b64encode(msg_str.encode()).decode(),
        "signature": base64.b64encode(b"dummy-sig").decode(),
        "pubkey": base64.b64encode(b"dummy-pub").decode(),
    }

    client = TestClient(app)
    resp = client.post("/worker", json=payload)

    # Should succeed
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert "txid" in body

    # Check that the transaction was upgraded with timestamp and chain_id
    assert dummy_gossip.received is not None
    tx_body = dummy_gossip.received["body"]
    msg_parts = tx_body["msg_str"].split(":")
    
    # Should have 5 parts now: sender:receiver:amount:timestamp:chain_id
    assert len(msg_parts) == 5
    assert msg_parts[0] == sender
    assert msg_parts[1] == receiver
    assert msg_parts[2] == amount
    # Check timestamp is reasonable (within last minute)
    timestamp = int(msg_parts[3])
    assert timestamp > (time.time() - 60) * 1000
    assert timestamp < (time.time() + 60) * 1000
    # Check chain_id is 1 (default)
    assert msg_parts[4] == "1"


@pytest.mark.stub_verify
def test_broadcast_tx_wrong_chain_id(_stub_database):
    """
    Test that transactions with wrong chain_id are rejected
    """
    # Fake gossip client
    class DummyGossip:
        def __init__(self):
            self.received = None

        async def randomized_broadcast(self, tx: dict):
            self.received = tx

    dummy_gossip = DummyGossip()
    app.state.gossip_client = dummy_gossip

    # Seed DB with UTXO
    sender = "bqs1senderwallet000000000000000000000000"
    receiver = "bqs1receiverwallet00000000000000000000000"
    amount = "1"
    db = _stub_database
    db[b"utxo:coinbase001"] = json.dumps({
        "txid": "coinbase001",
        "utxo_index": 0,
        "sender": "",
        "receiver": sender,
        "amount": "10",
        "spent": False,
    }).encode()

    # Use new format with WRONG chain_id
    timestamp = str(int(time.time() * 1000))
    wrong_chain_id = "999"
    msg_str = f"{sender}:{receiver}:{amount}:{timestamp}:{wrong_chain_id}"
    payload = {
        "request_type": "broadcast_tx",
        "message": base64.b64encode(msg_str.encode()).decode(),
        "signature": base64.b64encode(b"dummy-sig").decode(),
        "pubkey": base64.b64encode(b"dummy-pub").decode(),
    }

    client = TestClient(app)
    resp = client.post("/worker", json=payload)

    # Should fail with validation error
    assert resp.status_code == 400
    body = resp.json()
    # Check for error in nested structure
    error_msg = ""
    if "error" in body and isinstance(body["error"], dict):
        error_msg = body["error"].get("message", "")
    elif "detail" in body:
        error_msg = body["detail"]
    assert "Invalid chain ID" in error_msg
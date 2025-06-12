"""
Unit-tests for wallet.wallet
Run with:  pytest -q
"""

from __future__ import annotations
import importlib
import json
import os
import sys
import pathlib
import pytest

# --------------------------------------------------------------------------
#  Resolve project root then import the module under test
# --------------------------------------------------------------------------
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
wallet = importlib.import_module("wallet.wallet")   # wallet/wallet.py

# --------------------------------------------------------------------------
#  Shared fixtures
# --------------------------------------------------------------------------
@pytest.fixture(scope="session")
def password() -> str:
    return "S3cr3t-pw-for-tests"


@pytest.fixture
def wallet_json(password: str) -> dict:
    """Fresh in-memory wallet for tests that don’t need disk I/O."""
    return wallet.generate_wallet(password)


# --------------------------------------------------------------------------
#  Tests
# --------------------------------------------------------------------------
def test_generate_unlock_roundtrip(wallet_json: dict, password: str):
    """Encrypted wallet → unlock → same public key & address."""
    plain = wallet.unlock_wallet(wallet_json, password)

    assert plain["publicKey"] == wallet_json["publicKey"]
    assert plain["address"].startswith("bqs")

    # secret key is long hex (> 4 KB) and even length
    assert len(plain["privateKey"]) > 4_000
    assert len(plain["privateKey"]) % 2 == 0


def test_sign_and_verify(wallet_json: dict, password: str):
    """Valid signature verifies; tampered msg fails."""
    plain = wallet.unlock_wallet(wallet_json, password)

    message = "pytest ♥ post-quantum"
    sig = wallet.sign_transaction(message, plain["privateKey"])

    assert wallet.verify_transaction(message, sig, plain["publicKey"]) is True
    # mutate message
    assert wallet.verify_transaction(message + "x", sig, plain["publicKey"]) is False


def test_unlock_with_wrong_password_exits(wallet_json: dict):
    """unlock_wallet should sys.exit(1) on wrong PW, raising SystemExit."""
    with pytest.raises(SystemExit):
        wallet.unlock_wallet(wallet_json, "wrong-pw")


def test_get_or_create_creates_then_loads(tmp_path, password: str, monkeypatch):
    """
    • First call with no existing file → file created.  
    • Second call → loaded without regenerating.
    getpass.getpass is monkey-patched to avoid terminal prompts.
    """
    wfile = tmp_path / "wallet.json"

    monkeypatch.setattr("getpass.getpass", lambda prompt="": password)

    first = wallet.get_or_create_wallet(fname=str(wfile), password=password)
    assert wfile.exists()

    # Delete 'password' arg to force codepath that reads from file & prompts
    second = wallet.get_or_create_wallet(fname=str(wfile))
    assert first["address"] == second["address"]


def test_sign_with_malformed_privkey_raises():
    """Hex string with odd length (malformed) must raise RuntimeError."""
    bad_hex = "abc"   # odd length, invalid
    with pytest.raises(RuntimeError):
        wallet.sign_transaction("msg", bad_hex)
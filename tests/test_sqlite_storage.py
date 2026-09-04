"""
Unit tests for ACID SQLite persistence engine with WAL mode.
"""

import os
import tempfile

import pytest

from payment_communities.domain.channel import Channel
from payment_communities.protocols.shachain import ShachainGenerator, ShachainReceiver
from payment_communities.storage.sqlite import SqliteStorageEngine


@pytest.fixture
def sqlite_engine():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "test_network.db")
        yield SqliteStorageEngine(db_path)


def test_sqlite_preimages(sqlite_engine):
    sqlite_engine.save_preimage("hash_1", "preimage_1")
    sqlite_engine.save_preimage("hash_2", "preimage_2")

    preimages = sqlite_engine.load_preimages()
    assert preimages["hash_1"] == "preimage_1"
    assert preimages["hash_2"] == "preimage_2"


def test_sqlite_watchtower_hints(sqlite_engine):
    sqlite_engine.save_watchtower_hint("hint_abc", "blob_encrypted_123")
    assert sqlite_engine.lookup_watchtower_hint("hint_abc") == "blob_encrypted_123"
    assert sqlite_engine.lookup_watchtower_hint("hint_unknown") is None


def test_sqlite_channel_crud(sqlite_engine):
    ch = Channel(
        channel_id="ch_alice_bob_1",
        sender_alias="Alice",
        receiver_alias="Bob",
        sender_pubkey_hex="02" * 33,
        receiver_pubkey_hex="03" * 33,
        capacity_sat=100_000,
        balance_sender_sat=70_000,
        balance_receiver_sat=30_000,
    )

    sqlite_engine.save_channel(ch)
    loaded = sqlite_engine.load_channel("ch_alice_bob_1")
    assert loaded is not None
    assert loaded.channel_id == "ch_alice_bob_1"
    assert loaded.balance_sender_sat == 70_000
    assert loaded.balance_receiver_sat == 30_000

    all_channels = sqlite_engine.load_all_channels()
    assert "ch_alice_bob_1" in all_channels

    sqlite_engine.delete_channel("ch_alice_bob_1")
    assert sqlite_engine.load_channel("ch_alice_bob_1") is None


def test_sqlite_shachain_persistence(sqlite_engine):
    ch = Channel(
        channel_id="ch_1",
        sender_alias="Alice",
        receiver_alias="Bob",
        sender_pubkey_hex="02" * 33,
        receiver_pubkey_hex="03" * 33,
        capacity_sat=100_000,
        balance_sender_sat=50_000,
        balance_receiver_sat=50_000,
    )
    sqlite_engine.save_channel(ch)

    gen = ShachainGenerator()
    receiver = ShachainReceiver()
    for i in range(25):
        receiver.add_secret(gen.get_secret(i), i)

    sqlite_engine.save_shachain("ch_1", receiver)

    loaded_receiver = sqlite_engine.load_shachain("ch_1")
    assert loaded_receiver is not None
    assert loaded_receiver.last_index == receiver.last_index

    # Verify secret derivation from loaded receiver
    for i in range(25):
        assert loaded_receiver.get_secret(i) == gen.get_secret(i)


def test_sqlite_clear(sqlite_engine):
    sqlite_engine.save_preimage("h1", "p1")
    sqlite_engine.save_watchtower_hint("hint1", "blob1")
    sqlite_engine.clear()

    assert len(sqlite_engine.load_preimages()) == 0
    assert len(sqlite_engine.load_all_watchtower_hints()) == 0

"""
Tests for state persistence storage engine.
"""

from payment_communities.domain.channel import Channel, ChannelState
from payment_communities.storage.engine import StorageEngine


def test_storage_save_load_clear(tmp_path):
    storage = StorageEngine(data_dir=str(tmp_path), filename="test_state.json")

    channel = Channel(
        channel_id="chan_Alice_Bob",
        sender_alias="Alice",
        receiver_alias="Bob",
        sender_pubkey_hex="02" + "00" * 32,
        receiver_pubkey_hex="03" + "11" * 32,
        capacity_sat=100_000,
        balance_sender_sat=80_000,
        balance_receiver_sat=20_000,
        state=ChannelState.OPEN,
    )

    channels = {"Alice-Bob": channel}
    preimages = {"hash123": "preimage123"}

    storage.save_state(channels, preimages)

    loaded = storage.load_state()
    assert "Alice-Bob" in loaded.channels, "Saved channel must be reloaded"
    assert loaded.channels["Alice-Bob"].capacity_sat == 100_000, "Capacity mismatch"
    assert loaded.known_preimages.get("hash123") == "preimage123", "Preimage mismatch"

    storage.clear_state()
    cleared = storage.load_state()
    assert len(cleared.channels) == 0, "Cleared state must be empty"

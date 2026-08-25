import pytest
from node import Node
from channel import ChannelState, HTLCContract
from bitcoin_utils import generate_secret, bytes_to_hex

@pytest.fixture
def nodes():
    alice = Node("Alice")
    bob = Node("Bob")
    return alice, bob

def test_channel_opening(nodes):
    alice, bob = nodes
    channel = alice.open_channel(bob, capacity_sat=100_000)

    assert channel.capacity_sat == 100_000
    assert channel.balance_sender_sat == 100_000
    assert channel.balance_receiver_sat == 0
    assert channel.state == ChannelState.OPEN
    assert channel.sender_alias == "Alice"
    assert channel.receiver_alias == "Bob"

def test_htlc_addition_and_validation(nodes):
    alice, bob = nodes
    channel = alice.open_channel(bob, capacity_sat=100_000)

    _, hash_bytes = generate_secret()
    hash_hex = bytes_to_hex(hash_bytes)

    # Valid HTLC
    ok = alice.route_htlc_payment("Bob", amount_sat=30_000, payment_hash=hash_hex, locktime=200, htlc_id="htlc_1")
    assert ok is True
    assert channel.balance_sender_sat == 70_000
    assert "htlc_1" in channel.active_htlcs

    # Insufficient funds HTLC -> should fail
    fail_ok = alice.route_htlc_payment("Bob", amount_sat=80_000, payment_hash=hash_hex, locktime=200, htlc_id="htlc_2")
    assert fail_ok is False
    assert channel.balance_sender_sat == 70_000

def test_htlc_preimage_redemption_with_verification(nodes):
    alice, bob = nodes
    channel = alice.open_channel(bob, capacity_sat=100_000)

    preimage_bytes, hash_bytes = generate_secret()
    preimage_hex = bytes_to_hex(preimage_bytes)
    hash_hex = bytes_to_hex(hash_bytes)

    alice.route_htlc_payment("Bob", amount_sat=40_000, payment_hash=hash_hex, locktime=200, htlc_id="htlc_redeem")

    # Invalid preimage -> should fail redemption
    invalid_preimage_hex = "00" * 32
    fail_claim = alice.fulfill_htlc("Bob", "htlc_redeem", invalid_preimage_hex)
    assert fail_claim is False
    assert channel.balance_receiver_sat == 0

    # Valid preimage -> should succeed
    success_claim = alice.fulfill_htlc("Bob", "htlc_redeem", preimage_hex)
    assert success_claim is True
    assert channel.balance_receiver_sat == 40_000
    assert len(channel.active_htlcs) == 0

def test_htlc_timelock_expiration_refund(nodes):
    alice, bob = nodes
    channel = alice.open_channel(bob, capacity_sat=100_000)

    _, hash_bytes = generate_secret()
    hash_hex = bytes_to_hex(hash_bytes)

    alice.route_htlc_payment("Bob", amount_sat=20_000, payment_hash=hash_hex, locktime=150, htlc_id="htlc_refund")
    assert channel.balance_sender_sat == 80_000

    # Attempt refund before locktime -> fails
    assert alice.refund_htlc("Bob", "htlc_refund", current_block_height=140) is False
    assert channel.balance_sender_sat == 80_000

    # Attempt refund after locktime -> succeeds
    assert alice.refund_htlc("Bob", "htlc_refund", current_block_height=151) is True
    assert channel.balance_sender_sat == 100_000
    assert len(channel.active_htlcs) == 0

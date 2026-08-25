import pytest
from node import Node
from channel import ChannelState

def test_single_hop_channel_payment():
    alice = Node("Alice")
    bob = Node("Bob")
    alice.open_channel(bob, 50_000)

    preimage, payment_hash = bob.create_invoice()
    assert len(preimage) == 64
    assert len(payment_hash) == 64

    # Alice offers HTLC to Bob
    ok = alice.route_htlc_payment("Bob", 10_000, payment_hash, locktime=100, htlc_id="h1")
    assert ok is True

    channel = alice.channels["Bob"]
    assert channel.balance_sender_sat == 40_000
    assert "h1" in channel.active_htlcs

    # Bob fulfills HTLC
    fulfilled = alice.fulfill_htlc("Bob", "h1", preimage)
    assert fulfilled is True
    assert channel.balance_receiver_sat == 10_000
    assert len(channel.active_htlcs) == 0

def test_htlc_locktime_expiration_refund():
    alice = Node("Alice")
    bob = Node("Bob")
    channel = alice.open_channel(bob, 50_000)

    preimage, payment_hash = bob.create_invoice()
    alice.route_htlc_payment("Bob", 15_000, payment_hash, locktime=500, htlc_id="h2")

    assert channel.balance_sender_sat == 35_000

    # Attempt refund before timelock expires -> should fail
    refund_too_early = alice.refund_htlc("Bob", "h2", current_block_height=400)
    assert refund_too_early is False

    # Refund after timelock expires -> should succeed
    refund_success = alice.refund_htlc("Bob", "h2", current_block_height=501)
    assert refund_success is True
    assert channel.balance_sender_sat == 50_000
    assert len(channel.active_htlcs) == 0

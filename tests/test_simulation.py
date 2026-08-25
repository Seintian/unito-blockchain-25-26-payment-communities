import pytest

from payment_communities.node import Node


@pytest.fixture
def nodes():
    alice_node = Node("Alice")
    bob_node = Node("Bob")
    return alice_node, bob_node


def test_single_hop_channel_payment(nodes):
    alice_node, bob_node = nodes
    alice_node.open_channel(bob_node, capacity_sat=50_000)

    preimage_hex, payment_hash_hex = bob_node.create_invoice()
    assert len(preimage_hex) == 64, "Preimage hex must be 64 characters"
    assert len(payment_hash_hex) == 64, "Payment hash hex must be 64 characters"

    offer_success = alice_node.route_htlc_payment(
        target_peer_alias="Bob",
        amount_sat=10_000,
        payment_hash=payment_hash_hex,
        locktime=100,
        htlc_id="h1",
    )
    assert offer_success is True, "Offering HTLC of 10,000 sat must succeed"

    channel = alice_node.channels["Bob"]
    assert channel.balance_sender_sat == 40_000, (
        "Sender balance must be deducted by 10,000 sat"
    )
    assert "h1" in channel.active_htlcs, (
        "HTLC contract h1 must be present in active_htlcs"
    )

    fulfill_success = alice_node.fulfill_htlc("Bob", "h1", preimage_hex)
    assert fulfill_success is True, "Fulfilling HTLC with valid preimage must succeed"
    assert channel.balance_receiver_sat == 10_000, (
        "Receiver balance must be increased by 10,000 sat"
    )
    assert len(channel.active_htlcs) == 0, (
        "Active HTLCs list must be empty after fulfillment"
    )


def test_htlc_locktime_expiration_refund(nodes):
    alice_node, bob_node = nodes
    channel = alice_node.open_channel(bob_node, capacity_sat=50_000)

    _preimage_hex, payment_hash_hex = bob_node.create_invoice()
    alice_node.route_htlc_payment(
        target_peer_alias="Bob",
        amount_sat=15_000,
        payment_hash=payment_hash_hex,
        locktime=500,
        htlc_id="h2",
    )
    assert channel.balance_sender_sat == 35_000, (
        "Sender balance must reflect locked HTLC"
    )

    refund_before_timelock = alice_node.refund_htlc(
        "Bob", "h2", current_block_height=400
    )
    assert refund_before_timelock is False, "Refund before timelock expiry must fail"

    refund_after_timelock = alice_node.refund_htlc(
        "Bob", "h2", current_block_height=501
    )
    assert refund_after_timelock is True, "Refund after timelock expiry must succeed"
    assert channel.balance_sender_sat == 50_000, "Sender balance must be fully restored"
    assert len(channel.active_htlcs) == 0, "Active HTLC list must be empty after refund"

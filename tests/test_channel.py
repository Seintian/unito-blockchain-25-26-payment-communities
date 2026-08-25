import pytest

from bitcoin_utils import bytes_to_hex, generate_secret
from channel import ChannelState
from node import Node


@pytest.fixture
def Alice_and_Bob():
    alice_node = Node("Alice")
    bob_node = Node("Bob")
    return alice_node, bob_node


@pytest.fixture
def open_channel(Alice_and_Bob):
    alice_node, bob_node = Alice_and_Bob
    channel = alice_node.open_channel(bob_node, capacity_sat=100_000)
    return alice_node, bob_node, channel


def test_channel_opening(open_channel):
    _alice_node, _bob_node, channel = open_channel

    assert channel.capacity_sat == 100_000, "Channel capacity satoshis mismatch"
    assert channel.balance_sender_sat == 100_000, (
        "Sender initial balance should equal capacity"
    )
    assert channel.balance_receiver_sat == 0, "Receiver initial balance should be 0"
    assert channel.state == ChannelState.OPEN, "Channel initial state must be OPEN"
    assert channel.sender_alias == "Alice", "Sender alias mismatch"
    assert channel.receiver_alias == "Bob", "Receiver alias mismatch"


@pytest.mark.parametrize("payment_amount", [10_000, 50_000, 100_000])
def test_htlc_addition_and_validation(open_channel, payment_amount):
    alice_node, _bob_node, channel = open_channel
    _, hash_bytes = generate_secret()
    hash_hex = bytes_to_hex(hash_bytes)

    offer_success = alice_node.route_htlc_payment(
        target_peer_alias="Bob",
        amount_sat=payment_amount,
        payment_hash=hash_hex,
        locktime=200,
        htlc_id=f"htlc_{payment_amount}",
    )
    assert offer_success is True, (
        f"Offering valid HTLC of {payment_amount} sat should succeed"
    )
    assert channel.balance_sender_sat == 100_000 - payment_amount, (
        "Sender balance must reflect locked HTLC"
    )
    assert f"htlc_{payment_amount}" in channel.active_htlcs, (
        "HTLC contract should be in active_htlcs"
    )


def test_htlc_exceeding_capacity_fails(open_channel):
    alice_node, _bob_node, channel = open_channel
    _, hash_bytes = generate_secret()
    hash_hex = bytes_to_hex(hash_bytes)

    offer_success = alice_node.route_htlc_payment(
        target_peer_alias="Bob",
        amount_sat=150_000,  # Exceeds 100,000 capacity
        payment_hash=hash_hex,
        locktime=200,
        htlc_id="htlc_excessive",
    )
    assert offer_success is False, "HTLC exceeding sender balance must fail"
    assert channel.balance_sender_sat == 100_000, (
        "Sender balance should remain unchanged on failure"
    )


def test_htlc_preimage_redemption_with_verification(open_channel):
    alice_node, _bob_node, channel = open_channel
    preimage_bytes, hash_bytes = generate_secret()
    preimage_hex = bytes_to_hex(preimage_bytes)
    hash_hex = bytes_to_hex(hash_bytes)

    alice_node.route_htlc_payment(
        target_peer_alias="Bob",
        amount_sat=40_000,
        payment_hash=hash_hex,
        locktime=200,
        htlc_id="htlc_redeem",
    )

    # Attempt claim with invalid preimage
    invalid_preimage_hex = "00" * 32
    invalid_claim_success = alice_node.fulfill_htlc(
        "Bob", "htlc_redeem", invalid_preimage_hex
    )
    assert invalid_claim_success is False, (
        "Redeeming HTLC with invalid preimage must fail"
    )
    assert channel.balance_receiver_sat == 0, (
        "Receiver balance must remain 0 on invalid claim"
    )

    # Claim with valid preimage
    valid_claim_success = alice_node.fulfill_htlc("Bob", "htlc_redeem", preimage_hex)
    assert valid_claim_success is True, (
        "Redeeming HTLC with valid preimage must succeed"
    )
    assert channel.balance_receiver_sat == 40_000, (
        "Receiver balance must increase by HTLC amount"
    )
    assert len(channel.active_htlcs) == 0, (
        "Active HTLC list must be cleared after fulfillment"
    )


@pytest.mark.parametrize(
    "current_height,expected_success", [(140, False), (150, True), (151, True)]
)
def test_htlc_timelock_expiration_refund(
    open_channel, current_height, expected_success
):
    alice_node, _bob_node, channel = open_channel
    _, hash_bytes = generate_secret()
    hash_hex = bytes_to_hex(hash_bytes)

    alice_node.route_htlc_payment(
        target_peer_alias="Bob",
        amount_sat=20_000,
        payment_hash=hash_hex,
        locktime=150,
        htlc_id="htlc_timelock",
    )

    refund_success = alice_node.refund_htlc(
        "Bob", "htlc_timelock", current_block_height=current_height
    )
    assert refund_success is expected_success, (
        f"Timelock refund at height {current_height} expectation mismatch"
    )

    if expected_success:
        assert channel.balance_sender_sat == 100_000, (
            "Sender balance must be fully restored after refund"
        )
        assert len(channel.active_htlcs) == 0, (
            "Active HTLC list must be empty after refund"
        )

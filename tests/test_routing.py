import pytest

from node import Node


@pytest.fixture
def network_topology():
    alice_node = Node("Alice")
    bob_node = Node("Bob")
    dave_node = Node("Dave")

    alice_node.open_channel(bob_node, capacity_sat=100_000)
    bob_node.open_channel(dave_node, capacity_sat=100_000)
    return alice_node, bob_node, dave_node


@pytest.mark.parametrize("payment_amount_sat", [10_000, 35_000, 75_000])
def test_multihop_payment_routing(network_topology, payment_amount_sat):
    alice_node, bob_node, dave_node = network_topology

    # Dave generates invoice (Preimage R & Hash H)
    preimage_hex, hash_hex = dave_node.create_invoice()

    locktime_alice_to_bob = 200
    locktime_bob_to_dave = 150  # Staggered timelocks: T1 > T2

    # Step 1: Alice -> Bob HTLC offer
    alice_to_bob_success = alice_node.route_htlc_payment(
        target_peer_alias="Bob",
        amount_sat=payment_amount_sat,
        payment_hash=hash_hex,
        locktime=locktime_alice_to_bob,
        htlc_id="h_ab",
    )
    assert alice_to_bob_success is True, "Alice to Bob HTLC offer must succeed"

    # Step 2: Bob -> Dave HTLC forward
    bob_to_dave_success = bob_node.route_htlc_payment(
        target_peer_alias="Dave",
        amount_sat=payment_amount_sat,
        payment_hash=hash_hex,
        locktime=locktime_bob_to_dave,
        htlc_id="h_bd",
    )
    assert bob_to_dave_success is True, "Bob to Dave HTLC forward must succeed"

    # Step 3: Dave claims payment from Bob revealing Preimage R
    dave_claim_success = bob_node.fulfill_htlc("Dave", "h_bd", preimage_hex)
    assert dave_claim_success is True, "Dave claiming payment from Bob must succeed"
    assert bob_node.channels["Dave"].balance_receiver_sat == payment_amount_sat, (
        "Dave balance mismatch"
    )

    # Step 4: Bob claims payment from Alice using revealed Preimage R
    bob_claim_success = alice_node.fulfill_htlc("Bob", "h_ab", preimage_hex)
    assert bob_claim_success is True, "Bob claiming payment from Alice must succeed"
    assert alice_node.channels["Bob"].balance_receiver_sat == payment_amount_sat, (
        "Bob balance mismatch"
    )

    # Conservation of satoshis across off-chain channels
    channel_ab = alice_node.channels["Bob"]
    channel_bd = bob_node.channels["Dave"]

    total_ab = channel_ab.balance_sender_sat + channel_ab.balance_receiver_sat
    total_bd = channel_bd.balance_sender_sat + channel_bd.balance_receiver_sat

    assert total_ab == 100_000, "Alice-Bob total channel capacity must be conserved"
    assert total_bd == 100_000, "Bob-Dave total channel capacity must be conserved"

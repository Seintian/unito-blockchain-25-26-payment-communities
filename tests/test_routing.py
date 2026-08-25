import pytest
from src.node import Node

@pytest.fixture
def network_nodes():
    alice = Node("Alice")
    bob = Node("Bob")
    dave = Node("Dave")

    alice.open_channel(bob, 100_000)
    bob.open_channel(dave, 100_000)
    return alice, bob, dave

def test_multihop_payment_routing(network_nodes):
    alice, bob, dave = network_nodes

    # Dave generates invoice
    preimage_hex, hash_hex = dave.create_invoice()

    payment_amount = 35_000
    locktime_ab = 200
    locktime_bd = 150  # Staggered: T1 > T2

    # Step 1: Alice -> Bob
    ok_ab = alice.route_htlc_payment("Bob", payment_amount, hash_hex, locktime_ab, "h_ab")
    assert ok_ab is True

    # Step 2: Bob -> Dave
    ok_bd = bob.route_htlc_payment("Dave", payment_amount, hash_hex, locktime_bd, "h_bd")
    assert ok_bd is True

    # Step 3: Dave claims from Bob
    claimed_dave = bob.fulfill_htlc("Dave", "h_bd", preimage_hex)
    assert claimed_dave is True
    assert bob.channels["Dave"].balance_receiver_sat == 35_000

    # Step 4: Bob claims from Alice using same preimage
    claimed_bob = alice.fulfill_htlc("Bob", "h_ab", preimage_hex)
    assert claimed_bob is True
    assert alice.channels["Bob"].balance_receiver_sat == 35_000

    # Balance conservation check
    ab_chan = alice.channels["Bob"]
    bd_chan = bob.channels["Dave"]
    
    assert ab_chan.balance_sender_sat + ab_chan.balance_receiver_sat == 100_000
    assert bd_chan.balance_sender_sat + bd_chan.balance_receiver_sat == 100_000

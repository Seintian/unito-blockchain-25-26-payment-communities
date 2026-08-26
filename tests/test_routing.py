import pytest

from payment_communities.domain.node import Node
from payment_communities.exceptions import RouteNotFoundError
from payment_communities.network.routing import NetworkGraph, calculate_routing_fee


@pytest.fixture
def network_topology():
    alice_node = Node("Alice")
    bob_node = Node("Bob")
    dave_node = Node("Dave")

    alice_node.open_channel(bob_node, capacity_sat=100_000)
    bob_node.open_channel(dave_node, capacity_sat=100_000)
    return alice_node, bob_node, dave_node


def test_routing_fee_calculation():
    fee = calculate_routing_fee(10_000, base_fee_sat=1, fee_rate_ppm=1000)
    assert fee == 1 + 10, "10,000 sat at 1000 ppm + 1 base fee must equal 11 sat"


def test_dijkstra_pathfinding(network_topology):
    alice_node, bob_node, _dave_node = network_topology
    graph = NetworkGraph()

    for ch in alice_node.channels.values():
        graph.add_channel(ch)
    for ch in bob_node.channels.values():
        graph.add_channel(ch)

    route = graph.find_path("Alice", "Dave", amount_sat=25_000)
    assert route.path == ["Alice", "Bob", "Dave"], "Derived route path mismatch"
    assert len(route.hops) == 2, "Multi-hop payment must have 2 hops"


def test_pathfinding_insufficient_liquidity_raises_error(network_topology):
    alice_node, bob_node, _dave_node = network_topology
    graph = NetworkGraph()

    for ch in alice_node.channels.values():
        graph.add_channel(ch)
    for ch in bob_node.channels.values():
        graph.add_channel(ch)

    with pytest.raises(RouteNotFoundError):
        graph.find_path("Alice", "Dave", amount_sat=200_000)


def test_multihop_payment_routing(network_topology):
    alice_node, bob_node, dave_node = network_topology

    preimage_hex, hash_hex = dave_node.create_invoice()

    payment_amount_sat = 25_000
    locktime_alice_to_bob = 200
    locktime_bob_to_dave = 150

    alice_to_bob_success = alice_node.route_htlc_payment(
        target_peer_alias="Bob",
        amount_sat=payment_amount_sat,
        payment_hash=hash_hex,
        locktime=locktime_alice_to_bob,
        htlc_id="h_ab",
    )
    assert alice_to_bob_success is True

    bob_to_dave_success = bob_node.route_htlc_payment(
        target_peer_alias="Dave",
        amount_sat=payment_amount_sat,
        payment_hash=hash_hex,
        locktime=locktime_bob_to_dave,
        htlc_id="h_bd",
    )
    assert bob_to_dave_success is True

    dave_claim_success = bob_node.fulfill_htlc("Dave", "h_bd", preimage_hex)
    assert dave_claim_success is True

    bob_claim_success = alice_node.fulfill_htlc("Bob", "h_ab", preimage_hex)
    assert bob_claim_success is True

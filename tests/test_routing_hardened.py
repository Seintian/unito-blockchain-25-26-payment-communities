"""
Hardened Network Routing & Dijkstra Cumulative Fee Capacity Test Suite.
Verifies that multi-hop routing paths properly account for cumulative downstream fee reserves
on intermediate channels. If a direct/short path has enough capacity for the base amount but
NOT enough for base amount + downstream fees, the pathfinder correctly falls back to an
alternative route with sufficient capacity or reports a clean routing failure.
"""

import pytest

from payment_communities.domain.node import Node
from payment_communities.exceptions import RouteNotFoundError
from payment_communities.network.routing import NetworkGraph


class TestRoutingHardened:
    """Hardened tests for cumulative fee pathfinding."""

    def test_cumulative_fee_capacity_rerouting(self):
        """
        Topology:
        Alice -> Bob -> Dave (Path 1: low hops, Bob->Dave has 10,000 capacity, Alice->Bob has 10,050 capacity)
        Alice -> Charlie -> Dave (Path 2: larger capacity 50,000)

        Payment amount = 10,000 sat.
        Bob charges base fee = 100 sat (so Alice->Bob needs 10,100 sat).
        Alice->Bob capacity is 10,050 (< 10,100).
        Router must select Alice -> Charlie -> Dave because Alice->Bob lacks cumulative fee capacity.
        """
        alice = Node("Alice")
        bob = Node("Bob")
        charlie = Node("Charlie")
        dave = Node("Dave")

        graph = NetworkGraph()

        # Path 1: Alice -> Bob (capacity 10,050)
        #         Bob -> Dave (capacity 10,000)
        ch_ab = alice.open_channel(bob, capacity_sat=10_050)
        ch_ab.balance_sender_sat = 10_050
        ch_ab.balance_receiver_sat = 0

        ch_bd = bob.open_channel(dave, capacity_sat=10_000)
        ch_bd.balance_sender_sat = 10_000
        ch_bd.balance_receiver_sat = 0

        # Path 2: Alice -> Charlie (capacity 50,000)
        #         Charlie -> Dave (capacity 50,000)
        ch_ac = alice.open_channel(charlie, capacity_sat=50_000)
        ch_ac.balance_sender_sat = 50_000
        ch_ac.balance_receiver_sat = 0

        ch_cd = charlie.open_channel(dave, capacity_sat=50_000)
        ch_cd.balance_sender_sat = 50_000
        ch_cd.balance_receiver_sat = 0

        graph.add_channel(ch_ab)
        graph.add_channel(ch_bd)
        graph.add_channel(ch_ac)
        graph.add_channel(ch_cd)

        # Bob charges 100 sat base fee
        route = graph.find_path("Alice", "Dave", amount_sat=10_000, base_fee_sat=100)

        assert route is not None
        # Must have routed via Charlie because Alice->Bob capacity (10,050) < required (10,100)
        assert route.path == ["Alice", "Charlie", "Dave"]
        assert route.hops[0].receiver_alias == "Charlie"
        assert route.hops[1].receiver_alias == "Dave"

    def test_routing_failure_when_no_path_satisfies_cumulative_fees(self):
        """Routing fails cleanly with RouteNotFoundError when all paths lack capacity for cumulative fees."""
        alice = Node("Alice")
        bob = Node("Bob")
        dave = Node("Dave")

        graph = NetworkGraph()

        # Alice -> Bob has exactly 10,000 capacity. Bob charges 200 sat fee.
        # Required capacity for Alice->Bob is 10,200 > 10,000.
        ch_ab = alice.open_channel(bob, capacity_sat=10_000)
        ch_ab.balance_sender_sat = 10_000
        ch_ab.balance_receiver_sat = 0

        ch_bd = bob.open_channel(dave, capacity_sat=10_000)
        ch_bd.balance_sender_sat = 10_000
        ch_bd.balance_receiver_sat = 0

        graph.add_channel(ch_ab)
        graph.add_channel(ch_bd)

        with pytest.raises(RouteNotFoundError):
            graph.find_path("Alice", "Dave", amount_sat=10_000, base_fee_sat=200)

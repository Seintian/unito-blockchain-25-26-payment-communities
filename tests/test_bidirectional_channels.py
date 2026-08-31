"""
Hardened Bidirectional Channel & Multi-Party Lifecycle Test Suite.
Verifies bidirectional balance accounting, simultaneous in-flight HTLC routing in both directions,
concurrent fulfillments, timeouts, and state invariants.
"""

import pytest

from payment_communities.domain.channel import (
    HTLCContract,
)
from payment_communities.domain.node import Node
from payment_communities.exceptions import (
    HTLCExpiredError,
    InsufficientBalanceError,
)


class TestBidirectionalChannels:
    """Hardened tests for full bidirectional channel operations."""

    def test_bidirectional_htlc_offering_and_redemption(self):
        """Alice -> Bob and Bob -> Alice simultaneous HTLC offers and fulfillment."""
        alice = Node("Alice")
        bob = Node("Bob")
        ch = alice.open_channel(bob, capacity_sat=100_000)
        ch.balance_sender_sat = 50_000
        ch.balance_receiver_sat = 50_000

        # 1. Alice offers HTLC to Bob for 10,000 sat
        preimage_a, hash_a = alice.create_invoice()
        htlc_a = HTLCContract(
            htlc_id="htlc_alice_1",
            payment_hash=hash_a,
            amount_sat=10_000,
            locktime=200,
            offerer_alias="Alice",
        )
        assert ch.add_htlc(htlc_a) is True
        assert ch.balance_sender_sat == 40_000
        assert ch.balance_receiver_sat == 50_000

        # 2. Bob offers HTLC to Alice for 15,000 sat
        preimage_b, hash_b = bob.create_invoice()
        htlc_b = HTLCContract(
            htlc_id="htlc_bob_1",
            payment_hash=hash_b,
            amount_sat=15_000,
            locktime=200,
            offerer_alias="Bob",
        )
        assert ch.add_htlc(htlc_b) is True
        assert ch.balance_sender_sat == 40_000
        assert ch.balance_receiver_sat == 35_000

        # 3. Bob redeems Alice's HTLC using preimage_a -> credits Bob
        assert ch.redeem_htlc("htlc_alice_1", preimage_a) is True
        assert ch.balance_receiver_sat == 45_000
        assert ch.balance_sender_sat == 40_000

        # 4. Alice redeems Bob's HTLC using preimage_b -> credits Alice
        assert ch.redeem_htlc("htlc_bob_1", preimage_b) is True
        assert ch.balance_sender_sat == 55_000
        assert ch.balance_receiver_sat == 45_000

        # Capacity invariant maintained
        assert ch.balance_sender_sat + ch.balance_receiver_sat == 100_000

    def test_bidirectional_htlc_timeouts_and_refunds(self):
        """Alice and Bob timeout in-flight HTLCs, restoring respective sender balances."""
        alice = Node("Alice")
        bob = Node("Bob")
        ch = alice.open_channel(bob, capacity_sat=100_000)
        ch.balance_sender_sat = 60_000
        ch.balance_receiver_sat = 40_000

        # Alice offers 20k, Bob offers 10k
        _p_a, hash_a = alice.create_invoice()
        _p_b, hash_b = bob.create_invoice()

        ch.add_htlc(
            HTLCContract(
                htlc_id="ha",
                payment_hash=hash_a,
                amount_sat=20_000,
                locktime=150,
                offerer_alias="Alice",
            )
        )
        ch.add_htlc(
            HTLCContract(
                htlc_id="hb",
                payment_hash=hash_b,
                amount_sat=10_000,
                locktime=160,
                offerer_alias="Bob",
            )
        )

        assert ch.balance_sender_sat == 40_000
        assert ch.balance_receiver_sat == 30_000

        # Refund Alice's HTLC at block 155
        with pytest.raises(HTLCExpiredError):
            ch.refund_htlc("hb", current_block_height=155)  # Bob's expires at 160

        assert ch.refund_htlc("ha", current_block_height=155) is True
        assert ch.balance_sender_sat == 60_000  # 40k + 20k refunded

        # Refund Bob's HTLC at block 165
        assert ch.refund_htlc("hb", current_block_height=165) is True
        assert ch.balance_receiver_sat == 40_000  # 30k + 10k refunded

        assert ch.balance_sender_sat + ch.balance_receiver_sat == 100_000

    def test_bidirectional_node_routing_wrapper(self):
        """Node-level wrapper routing payments bidirectionally."""
        alice = Node("Alice")
        bob = Node("Bob")
        ch = alice.open_channel(bob, capacity_sat=100_000)
        ch.balance_sender_sat = 50_000
        ch.balance_receiver_sat = 50_000

        preimage_b, hash_b = bob.create_invoice()

        # Alice routes payment to Bob
        success_a = alice.route_htlc_payment(
            target_peer_alias="Bob",
            amount_sat=12_000,
            payment_hash=hash_b,
            locktime=150,
            htlc_id="ab_1",
        )
        assert success_a is True
        assert ch.balance_sender_sat == 38_000

        # Bob fulfills HTLC
        assert bob.fulfill_htlc("Alice", "ab_1", preimage_b) is True
        assert ch.balance_receiver_sat == 62_000

        # Bob routes payment back to Alice
        preimage_a, hash_a = alice.create_invoice()
        success_b = bob.route_htlc_payment(
            target_peer_alias="Alice",
            amount_sat=22_000,
            payment_hash=hash_a,
            locktime=150,
            htlc_id="ba_1",
        )
        assert success_b is True
        assert ch.balance_receiver_sat == 40_000

        # Alice fulfills HTLC
        assert alice.fulfill_htlc("Bob", "ba_1", preimage_a) is True
        assert ch.balance_sender_sat == 60_000
        assert ch.balance_sender_sat + ch.balance_receiver_sat == 100_000

    def test_overdraft_prevention_on_both_sides(self):
        """Ensures neither sender nor receiver can overdraft their side."""
        alice = Node("Alice")
        bob = Node("Bob")
        ch = alice.open_channel(bob, capacity_sat=100_000)
        ch.balance_sender_sat = 20_000
        ch.balance_receiver_sat = 80_000

        _p, h = alice.create_invoice()

        # Alice tries to spend 25k (has 20k)
        with pytest.raises(InsufficientBalanceError):
            ch.add_htlc(
                HTLCContract(
                    htlc_id="err1",
                    payment_hash=h,
                    amount_sat=25_000,
                    locktime=100,
                    offerer_alias="Alice",
                )
            )

        # Bob tries to spend 85k (has 80k)
        with pytest.raises(InsufficientBalanceError):
            ch.add_htlc(
                HTLCContract(
                    htlc_id="err2",
                    payment_hash=h,
                    amount_sat=85_000,
                    locktime=100,
                    offerer_alias="Bob",
                )
            )

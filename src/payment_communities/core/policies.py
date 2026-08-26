"""
Policy Pattern Interfaces & Concrete Domain Policies.
Provides modular policies for routing fees, liquidity lease fees, timelock deltas, and state revocation.
"""

from abc import ABC, abstractmethod

from payment_communities.config import (
    DEFAULT_CLTV_DELTA_BLOCKS,
    DEFAULT_LEASE_FEE_BASE_SAT,
    DEFAULT_LEASE_FEE_BASIS_PPM,
    DEFAULT_ROUTING_BASE_FEE_SAT,
    DEFAULT_ROUTING_FEE_RATE_PPM,
    DEFAULT_TO_SELF_DELAY_BLOCKS,
    PPM_DENOMINATOR,
)


class FeePolicy(ABC):
    """Abstract policy interface for calculating payment channel transaction fees."""

    @abstractmethod
    def calculate_fee(self, amount_sat: int) -> int:
        """Calculates fee in satoshis for a given payment amount or requested capacity."""


class RoutingFeePolicy(FeePolicy):
    """
    Standard Lightning Network Hop Routing Fee Policy.
    fee = base_fee + floor(amount * fee_rate_ppm / 1,000,000)
    """

    def __init__(
        self,
        base_fee_sat: int = DEFAULT_ROUTING_BASE_FEE_SAT,
        fee_rate_ppm: int = DEFAULT_ROUTING_FEE_RATE_PPM,
    ):
        self.base_fee_sat = base_fee_sat
        self.fee_rate_ppm = fee_rate_ppm

    def calculate_fee(self, amount_sat: int) -> int:
        proportional_fee = (amount_sat * self.fee_rate_ppm) // PPM_DENOMINATOR
        return self.base_fee_sat + proportional_fee


class LeaseFeePolicy(FeePolicy):
    """
    BOLT #7 Inbound Channel Liquidity Lease Fee Policy.
    lease_fee = base_lease_fee + floor(capacity * lease_basis_ppm / 1,000,000)
    """

    def __init__(
        self,
        base_fee_sat: int = DEFAULT_LEASE_FEE_BASE_SAT,
        fee_rate_ppm: int = DEFAULT_LEASE_FEE_BASIS_PPM,
    ):
        self.base_fee_sat = base_fee_sat
        self.fee_rate_ppm = fee_rate_ppm

    def calculate_fee(self, amount_sat: int) -> int:
        """Calculates total lease fee for a given requested capacity amount."""
        proportional_fee = (amount_sat * self.fee_rate_ppm) // PPM_DENOMINATOR
        return self.base_fee_sat + proportional_fee


class TimelockPolicy:
    """
    Timelock Delta Policy evaluating CLTV multi-hop safety deltas and CSV to_self_delay windows.
    """

    def __init__(
        self,
        cltv_delta: int = DEFAULT_CLTV_DELTA_BLOCKS,
        to_self_delay: int = DEFAULT_TO_SELF_DELAY_BLOCKS,
    ):
        self.cltv_delta = cltv_delta
        self.to_self_delay = to_self_delay

    def calculate_next_hop_locktime(self, current_locktime: int) -> int:
        """Subtracts CLTV delta safety margin for next outgoing hop."""
        return max(0, current_locktime - self.cltv_delta)

    def is_locktime_safe(self, incoming_locktime: int, outgoing_locktime: int) -> bool:
        """Validates that incoming timelock exceeds outgoing timelock by at least cltv_delta."""
        return incoming_locktime - outgoing_locktime >= self.cltv_delta


class RevocationPolicy:
    """
    Poon-Dryja State Revocation Policy evaluating commitment state freshness.
    """

    def is_state_revoked(
        self, sequence_number: int, revoked_sequences: set[int]
    ) -> bool:
        return sequence_number in revoked_sequences

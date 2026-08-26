"""
Policy Pattern implementations for Payment Communities protocol rules.
Encapsulates domain calculation policies: FeePolicy, TimelockPolicy, RevocationPolicy, CapacityPolicy, RoutingPolicy.
"""

from abc import ABC, abstractmethod

from payment_communities.config import (
    DEFAULT_CLTV_DELTA_BLOCKS,
    DEFAULT_LEASE_FEE_BASE_SAT,
    DEFAULT_LEASE_FEE_BASIS_PPM,
    DEFAULT_ROUTING_BASE_FEE_SAT,
    DEFAULT_ROUTING_FEE_RATE_PPM,
    DEFAULT_TO_SELF_DELAY_BLOCKS,
    MAX_CHANNEL_CAPACITY_SAT,
    MIN_CHANNEL_CAPACITY_SAT,
)


class FeePolicy(ABC):
    """Abstract Strategy/Policy for fee calculation algorithms."""

    @abstractmethod
    def calculate_fee(self, amount_sat: int) -> int:
        """Calculates total fee for an amount in satoshis."""


class RoutingFeePolicy(FeePolicy):
    """
    Standard Lightning Network multi-hop routing fee policy.
    Fee = base_fee_sat + (amount_sat * fee_rate_ppm / 1,000,000)
    """

    def __init__(
        self,
        base_fee_sat: int = DEFAULT_ROUTING_BASE_FEE_SAT,
        fee_rate_ppm: int = DEFAULT_ROUTING_FEE_RATE_PPM,
    ):
        self.base_fee_sat = base_fee_sat
        self.fee_rate_ppm = fee_rate_ppm

    def calculate_fee(self, amount_sat: int) -> int:
        proportional_fee = (amount_sat * self.fee_rate_ppm) // 1_000_000
        return self.base_fee_sat + proportional_fee


class RoutingPolicy(RoutingFeePolicy):
    """Alias for RoutingFeePolicy."""


class LeaseFeePolicy(FeePolicy):
    """
    BOLT #7 Inbound Liquidity Advertisement lease fee policy.
    Fee = base_fee_sat + (amount_sat * fee_rate_ppm / 1,000,000)
    """

    def __init__(
        self,
        base_fee_sat: int = DEFAULT_LEASE_FEE_BASE_SAT,
        fee_rate_ppm: int = DEFAULT_LEASE_FEE_BASIS_PPM,
    ):
        self.base_fee_sat = base_fee_sat
        self.fee_rate_ppm = fee_rate_ppm

    def calculate_fee(self, amount_sat: int) -> int:
        proportional_fee = (amount_sat * self.fee_rate_ppm) // 1_000_000
        return self.base_fee_sat + proportional_fee


class CapacityPolicy:
    """Policy governing channel capacity bounds."""

    def __init__(
        self,
        min_capacity_sat: int = MIN_CHANNEL_CAPACITY_SAT,
        max_capacity_sat: int = MAX_CHANNEL_CAPACITY_SAT,
    ):
        self.min_capacity_sat = min_capacity_sat
        self.max_capacity_sat = max_capacity_sat

    def is_valid_capacity(self, capacity_sat: int) -> bool:
        return self.min_capacity_sat <= capacity_sat <= self.max_capacity_sat


class TimelockPolicy:
    """Policy calculating staggered timelocks across multi-hop payment paths."""

    def __init__(
        self,
        cltv_delta_blocks: int = DEFAULT_CLTV_DELTA_BLOCKS,
        to_self_delay_blocks: int = DEFAULT_TO_SELF_DELAY_BLOCKS,
    ):
        self.cltv_delta_blocks = cltv_delta_blocks
        self.to_self_delay_blocks = to_self_delay_blocks

    def calculate_hop_locktime(self, current_height: int, hop_distance: int) -> int:
        """Calculates required CLTV locktime for a hop at distance from destination."""
        return current_height + (hop_distance * self.cltv_delta_blocks)


class RevocationPolicy:
    """Policy governing Poon-Dryja state revocation validation."""

    def is_state_revoked(
        self, commitment_number: int, revealed_secrets_set: set[int]
    ) -> bool:
        """Evaluates whether commitment_number is present in revealed secrets set."""
        return commitment_number in revealed_secrets_set

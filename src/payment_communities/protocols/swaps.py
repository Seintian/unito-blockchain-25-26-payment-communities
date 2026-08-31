"""
Atomic Submarine Swaps (L1 <-> L2) & Inbound Liquidity Advertisements Engine (BOLT #7 Extension).
Enables trustless cross-layer liquidity rebalancing (Loop In / Loop Out) and on-demand
inbound channel capacity leasing using LeaseFeePolicy.
"""

from enum import StrEnum

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import CScript
from pydantic import BaseModel

from payment_communities.bitcoin.contracts import ScriptFactory
from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.config import (
    DEFAULT_FUNDING_WEIGHT,
    DEFAULT_LEASE_FEE_BASE_SAT,
    DEFAULT_LEASE_FEE_BASIS_PPM,
    DEFAULT_LEASE_MAX_CAPACITY_SAT,
)
from payment_communities.domain.core.policies import LeaseFeePolicy


class SwapType(StrEnum):
    LOOP_IN = "LOOP_IN"
    LOOP_OUT = "LOOP_OUT"


class SwapState(StrEnum):
    PENDING = "PENDING"
    FULFILLED = "FULFILLED"
    EXPIRED = "EXPIRED"


class SubmarineSwap(BaseModel):
    """Encapsulates an atomic Submarine Swap session across L1 and L2."""

    swap_id: str
    swap_type: SwapType
    amount_sat: int
    payment_hash_hex: str
    preimage_hex: str | None = None
    locktime: int
    state: SwapState = SwapState.PENDING


def create_submarine_swap_script(
    user_pubkey_bytes: bytes,
    provider_pubkey_bytes: bytes,
    payment_hash_bytes: bytes,
    locktime: int,
) -> CScript:
    """
    Constructs an L1 P2WSH HTLC Script for atomic Submarine Swaps.
    """
    return ScriptFactory.create_htlc(
        sender_pubkey=user_pubkey_bytes,
        receiver_pubkey=provider_pubkey_bytes,
        payment_hash=payment_hash_bytes,
        locktime=locktime,
    )


def create_submarine_swap_funding_tx(
    funder_utxo_txid: str,
    funder_utxo_vout: int,
    funder_pubkey_bytes: bytes,
    swap_amount_sat: int,
    swap_redeem_script: CScript,
) -> CMutableTransaction:
    """
    Constructs an L1 Submarine Swap funding transaction spending to P2WSH HTLC script.
    """
    return (
        TransactionBuilder()
        .add_input(funder_utxo_txid, funder_utxo_vout)
        .add_p2wsh_output(swap_amount_sat, swap_redeem_script)
        .build()
    )


class LiquidityAd(BaseModel):
    """
    Node advertisement format for leasing inbound channel liquidity (BOLT #7).
    """

    node_alias: str
    node_pubkey_hex: str
    lease_fee_base_sat: int = DEFAULT_LEASE_FEE_BASE_SAT
    lease_fee_basis_ppm: int = DEFAULT_LEASE_FEE_BASIS_PPM
    funding_weight: int = DEFAULT_FUNDING_WEIGHT
    max_capacity_sat: int = DEFAULT_LEASE_MAX_CAPACITY_SAT

    def get_fee_policy(self) -> LeaseFeePolicy:
        """Returns LeaseFeePolicy instance based on ad parameters."""
        return LeaseFeePolicy(
            base_fee_sat=self.lease_fee_base_sat,
            fee_rate_ppm=self.lease_fee_basis_ppm,
        )

    def calculate_lease_fee(self, requested_capacity_sat: int) -> int:
        """Calculates total lease fee using policy."""
        return self.get_fee_policy().calculate_fee(requested_capacity_sat)

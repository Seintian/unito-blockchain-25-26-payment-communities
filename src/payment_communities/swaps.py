"""
Atomic Submarine Swaps (L1 <-> L2) & Inbound Liquidity Advertisements Engine (BOLT #7 Extension).
Enables trustless cross-layer liquidity rebalancing (Loop In / Loop Out) and on-demand
inbound channel capacity leasing.
"""

from enum import Enum

from bitcoin.core import CMutableTransaction, CMutableTxIn, CMutableTxOut, COutPoint
from bitcoin.core.script import CScript
from pydantic import BaseModel

from payment_communities.bitcoin_utils import (
    hex_to_bytes,
    script_to_p2wsh_address,
)
from payment_communities.config import (
    DEFAULT_FUNDING_WEIGHT,
    DEFAULT_LEASE_FEE_BASE_SAT,
    DEFAULT_LEASE_FEE_BASIS_PPM,
    DEFAULT_LEASE_MAX_CAPACITY_SAT,
    PPM_DENOMINATOR,
)
from payment_communities.contracts import create_htlc_script


class SwapType(str, Enum):
    LOOP_IN = "LOOP_IN"  # L1 BTC -> L2 Lightning Channel
    LOOP_OUT = "LOOP_OUT"  # L2 Lightning Channel -> L1 BTC


class SwapState(str, Enum):
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
    return create_htlc_script(
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
    txid_bytes = hex_to_bytes(funder_utxo_txid)
    txin = CMutableTxIn(COutPoint(txid_bytes, funder_utxo_vout))

    p2wsh_addr = script_to_p2wsh_address(swap_redeem_script)
    txout = CMutableTxOut(swap_amount_sat, p2wsh_addr.to_scriptPubKey())

    return CMutableTransaction([txin], [txout])


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

    def calculate_lease_fee(self, requested_capacity_sat: int) -> int:
        """
        Calculates total lease fee: base_fee + floor(capacity * ppm / 1,000,000)
        """
        proportional_fee = (
            requested_capacity_sat * self.lease_fee_basis_ppm
        ) // PPM_DENOMINATOR
        return self.lease_fee_base_sat + proportional_fee

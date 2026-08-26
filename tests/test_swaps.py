"""
Unit tests for Submarine Swaps & Inbound Liquidity Advertisements.
"""

from payment_communities.bitcoin.utils import generate_keypair, generate_secret
from payment_communities.protocols.swaps import (
    LiquidityAd,
    SubmarineSwap,
    SwapState,
    SwapType,
    create_submarine_swap_funding_tx,
    create_submarine_swap_script,
)


def test_submarine_swap_creation_and_script():
    _preimage, hash_digest = generate_secret()
    _user_sec, user_pub = generate_keypair()
    _provider_sec, provider_pub = generate_keypair()

    swap = SubmarineSwap(
        swap_id="swap_123",
        swap_type=SwapType.LOOP_IN,
        amount_sat=100_000,
        payment_hash_hex=hash_digest.hex(),
        locktime=144,
    )
    assert swap.state == SwapState.PENDING

    script = create_submarine_swap_script(
        user_pubkey_bytes=user_pub,
        provider_pubkey_bytes=provider_pub,
        payment_hash_bytes=hash_digest,
        locktime=144,
    )
    assert len(script) > 0

    tx = create_submarine_swap_funding_tx(
        funder_utxo_txid="00" * 32,
        funder_utxo_vout=0,
        funder_pubkey_bytes=user_pub,
        swap_amount_sat=100_000,
        swap_redeem_script=script,
    )
    assert len(tx.vin) == 1
    assert len(tx.vout) == 1
    assert tx.vout[0].nValue == 100_000


def test_liquidity_ad_lease_fee_calculation():
    ad = LiquidityAd(
        node_alias="BobRouting",
        node_pubkey_hex="02" + "00" * 32,
        lease_fee_base_sat=500,
        lease_fee_basis_ppm=2000,
    )

    # 1,000,000 sat capacity * 2000 / 1,000,000 = 2000 sat + 500 base = 2500 sat fee
    fee = ad.calculate_lease_fee(1_000_000)
    assert fee == 2500

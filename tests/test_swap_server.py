"""
Unit tests for automated Submarine Swap Coordinator daemon (Loop In & Loop Out).
"""

from payment_communities.bitcoin.contracts import sign_p2wsh_input
from payment_communities.bitcoin.interpreter import ScriptInterpreter
from payment_communities.bitcoin.utils import generate_keypair, sha256
from payment_communities.protocols.swap_server import (
    SwapCoordinator,
    create_submarine_swap_refund_tx,
)
from payment_communities.protocols.swaps import SwapState, SwapType


def test_swap_coordinator_loop_in_claim():
    _user_wif, user_pub = generate_keypair()
    coord = SwapCoordinator()

    preimage = b"secret_preimage_32_bytes_long!!"
    payment_hash = sha256(preimage)
    amount_sat = 150_000

    swap, script = coord.initiate_loop_in(
        swap_id="swap_in_1",
        user_pubkey_bytes=user_pub,
        payment_hash_bytes=payment_hash,
        amount_sat=amount_sat,
        locktime=288,
    )

    assert swap.swap_type == SwapType.LOOP_IN
    assert swap.state == SwapState.PENDING

    coord.register_funding_utxo("swap_in_1", "cc" * 32, 0)
    claim_tx = coord.complete_loop_in_with_preimage("swap_in_1", preimage)

    assert swap.state == SwapState.FULFILLED
    assert swap.preimage_hex == preimage.hex()

    # Verify transaction with ScriptInterpreter
    interp = ScriptInterpreter(
        witness_script=script,
        tx=claim_tx,
        input_index=0,
        amount_sat=amount_sat,
        initial_stack=list(claim_tx.wit.vtxinwit[0].scriptWitness.stack[:-1]),
    )
    assert interp.execute() is True


def test_swap_coordinator_loop_in_refund():
    user_wif, user_pub = generate_keypair()
    coord = SwapCoordinator()

    preimage = b"another_secret_32_bytes_long!!!"
    payment_hash = sha256(preimage)
    amount_sat = 80_000

    _swap, script = coord.initiate_loop_in(
        swap_id="swap_in_2",
        user_pubkey_bytes=user_pub,
        payment_hash_bytes=payment_hash,
        amount_sat=amount_sat,
        locktime=100,
    )

    coord.register_funding_utxo("swap_in_2", "dd" * 32, 0)

    # User initiates refund
    unsigned_refund = create_submarine_swap_refund_tx(
        funding_txid="dd" * 32,
        funding_vout=0,
        refunder_pubkey_bytes=user_pub,
        amount_sat=amount_sat,
        locktime=100,
        swap_redeem_script=script,
    )

    refund_sig = sign_p2wsh_input(
        tx=unsigned_refund,
        input_idx=0,
        redeem_script=script,
        private_key_wif=str(user_wif),
        amount_sat=amount_sat,
    )

    signed_refund = create_submarine_swap_refund_tx(
        funding_txid="dd" * 32,
        funding_vout=0,
        refunder_pubkey_bytes=user_pub,
        amount_sat=amount_sat,
        locktime=100,
        swap_redeem_script=script,
        refund_sig_bytes=refund_sig,
    )

    # Verify refund script execution
    interp = ScriptInterpreter(
        witness_script=script,
        tx=signed_refund,
        input_index=0,
        amount_sat=amount_sat,
        initial_stack=list(signed_refund.wit.vtxinwit[0].scriptWitness.stack[:-1]),
    )
    assert interp.execute() is True

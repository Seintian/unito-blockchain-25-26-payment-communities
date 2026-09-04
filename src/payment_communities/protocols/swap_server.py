"""
Submarine Swap Server Coordinator Daemon (Loop In & Loop Out).

Provides automated atomic cross-layer liquidity rebalancing:
- Loop In: On-chain BTC -> Off-chain LN sats.
  * Server watches on-chain funding HTLC.
  * Server sends LN payment to user.
  * When user settles LN HTLC, server gets preimage and sweeps on-chain HTLC.
- Loop Out: Off-chain LN sats -> On-chain BTC.
  * User locks LN HTLC.
  * Server broadcasts on-chain HTLC.
  * When user claims on-chain HTLC, server reads preimage from witness and settles LN HTLC.
"""

import hashlib

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import CScript
from pydantic import BaseModel

from payment_communities.bitcoin.contracts import (
    ScriptFactory,
    create_p2wpkh_scriptPubKey,
    sign_p2wsh_input,
)
from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.bitcoin.utils import generate_keypair
from payment_communities.exceptions import PaymentCommunityError
from payment_communities.protocols.swaps import SubmarineSwap, SwapState, SwapType


def create_submarine_swap_claim_tx(
    funding_txid: str,
    funding_vout: int,
    claimer_pubkey_bytes: bytes,
    amount_sat: int,
    preimage_bytes: bytes,
    swap_redeem_script: CScript,
    claim_sig_bytes: bytes = b"",
) -> CMutableTransaction:
    """
    Constructs an on-chain transaction spending from the submarine swap P2WSH HTLC
    via the preimage success path (OP_TRUE).
    """
    claimer_spk = create_p2wpkh_scriptPubKey(claimer_pubkey_bytes)
    # Deduct 500 sat miner fee
    miner_fee_sat = 500
    out_amount_sat = max(0, amount_sat - miner_fee_sat)

    builder = (
        TransactionBuilder()
        .add_input(funding_txid, funding_vout)
        .add_output(out_amount_sat, claimer_spk)
    )

    if claim_sig_bytes:
        # Witness stack: [sig, preimage, OP_TRUE, redeem_script]
        witness = [claim_sig_bytes, preimage_bytes, b"\x01", bytes(swap_redeem_script)]
        builder.add_witness_stack(witness)

    return builder.build()


def create_submarine_swap_refund_tx(
    funding_txid: str,
    funding_vout: int,
    refunder_pubkey_bytes: bytes,
    amount_sat: int,
    locktime: int,
    swap_redeem_script: CScript,
    refund_sig_bytes: bytes = b"",
) -> CMutableTransaction:
    """
    Constructs an on-chain transaction refunding the submarine swap P2WSH HTLC
    after timeout via the refund path (OP_FALSE).
    """
    refunder_spk = create_p2wpkh_scriptPubKey(refunder_pubkey_bytes)
    miner_fee_sat = 500
    out_amount_sat = max(0, amount_sat - miner_fee_sat)

    builder = (
        TransactionBuilder()
        .add_input(funding_txid, funding_vout, sequence=0)
        .set_locktime(locktime)
        .add_output(out_amount_sat, refunder_spk)
    )

    if refund_sig_bytes:
        # Witness stack: [sig, OP_FALSE, redeem_script]
        witness = [refund_sig_bytes, b"", bytes(swap_redeem_script)]
        builder.add_witness_stack(witness)

    return builder.build()


class SwapServerConfig(BaseModel):
    server_alias: str = "LoopServer"
    server_wif_key: str
    server_pubkey_hex: str
    min_swap_sat: int = 1000
    max_swap_sat: int = 10_000_000
    service_fee_ppm: int = 1000  # 0.1%


class SwapCoordinator:
    """
    Submarine swap coordinator managing active Loop In and Loop Out swaps.
    """

    def __init__(self, config: SwapServerConfig | None = None) -> None:
        if config is None:
            wif, pub = generate_keypair()
            config = SwapServerConfig(
                server_wif_key=str(wif),
                server_pubkey_hex=pub.hex(),
            )
        self.config = config
        self.swaps: dict[str, SubmarineSwap] = {}
        self.swap_scripts: dict[str, CScript] = {}
        self.onchain_funding: dict[str, tuple[str, int]] = {}  # swap_id -> (txid, vout)

    def initiate_loop_in(
        self,
        swap_id: str,
        user_pubkey_bytes: bytes,
        payment_hash_bytes: bytes,
        amount_sat: int,
        locktime: int = 288,  # ~2 days in blocks
    ) -> tuple[SubmarineSwap, CScript]:
        """
        Initiates a Loop In swap (User funds on-chain HTLC, Server pays LN).
        """
        server_pub = bytes.fromhex(self.config.server_pubkey_hex)
        redeem_script = ScriptFactory.create_htlc(
            sender_pubkey=user_pubkey_bytes,
            receiver_pubkey=server_pub,
            payment_hash=payment_hash_bytes,
            locktime=locktime,
        )

        swap = SubmarineSwap(
            swap_id=swap_id,
            swap_type=SwapType.LOOP_IN,
            amount_sat=amount_sat,
            payment_hash_hex=payment_hash_bytes.hex(),
            locktime=locktime,
            state=SwapState.PENDING,
        )

        self.swaps[swap_id] = swap
        self.swap_scripts[swap_id] = redeem_script
        return swap, redeem_script

    def initiate_loop_out(
        self,
        swap_id: str,
        user_pubkey_bytes: bytes,
        payment_hash_bytes: bytes,
        amount_sat: int,
        locktime: int = 144,
    ) -> tuple[SubmarineSwap, CScript]:
        """
        Initiates a Loop Out swap (Server funds on-chain HTLC, User claims on-chain).
        """
        server_pub = bytes.fromhex(self.config.server_pubkey_hex)
        redeem_script = ScriptFactory.create_htlc(
            sender_pubkey=server_pub,
            receiver_pubkey=user_pubkey_bytes,
            payment_hash=payment_hash_bytes,
            locktime=locktime,
        )

        swap = SubmarineSwap(
            swap_id=swap_id,
            swap_type=SwapType.LOOP_OUT,
            amount_sat=amount_sat,
            payment_hash_hex=payment_hash_bytes.hex(),
            locktime=locktime,
            state=SwapState.PENDING,
        )

        self.swaps[swap_id] = swap
        self.swap_scripts[swap_id] = redeem_script
        return swap, redeem_script

    def register_funding_utxo(self, swap_id: str, txid: str, vout: int) -> None:
        """Notifies coordinator that on-chain funding transaction has been broadcast."""
        if swap_id not in self.swaps:
            raise PaymentCommunityError(f"Swap {swap_id} not registered")
        self.onchain_funding[swap_id] = (txid, vout)

    def complete_loop_in_with_preimage(
        self, swap_id: str, preimage_bytes: bytes
    ) -> CMutableTransaction:
        """
        Server sweeps on-chain funding HTLC using discovered preimage after paying off-chain.
        """
        swap = self.swaps.get(swap_id)
        if not swap:
            raise PaymentCommunityError(f"Swap {swap_id} not found")
        if swap.swap_type != SwapType.LOOP_IN:
            raise PaymentCommunityError(f"Swap {swap_id} is not a Loop In swap")

        if hashlib.sha256(preimage_bytes).hexdigest() != swap.payment_hash_hex:
            raise PaymentCommunityError("Preimage does not match swap payment hash")

        txid, vout = self.onchain_funding[swap_id]
        redeem_script = self.swap_scripts[swap_id]
        server_pub = bytes.fromhex(self.config.server_pubkey_hex)

        # Build unsigned claim transaction to compute sighash
        unsigned_tx = create_submarine_swap_claim_tx(
            funding_txid=txid,
            funding_vout=vout,
            claimer_pubkey_bytes=server_pub,
            amount_sat=swap.amount_sat,
            preimage_bytes=preimage_bytes,
            swap_redeem_script=redeem_script,
        )

        # Sign with server WIF key
        sig = sign_p2wsh_input(
            tx=unsigned_tx,
            input_idx=0,
            redeem_script=redeem_script,
            private_key_wif=self.config.server_wif_key,
            amount_sat=swap.amount_sat,
        )

        # Build fully signed claim transaction with witness stack
        signed_claim_tx = create_submarine_swap_claim_tx(
            funding_txid=txid,
            funding_vout=vout,
            claimer_pubkey_bytes=server_pub,
            amount_sat=swap.amount_sat,
            preimage_bytes=preimage_bytes,
            swap_redeem_script=redeem_script,
            claim_sig_bytes=sig,
        )

        swap.preimage_hex = preimage_bytes.hex()
        swap.state = SwapState.FULFILLED
        return signed_claim_tx

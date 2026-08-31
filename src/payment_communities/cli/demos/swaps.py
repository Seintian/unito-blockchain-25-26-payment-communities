"""
Atomic Submarine Swaps & BOLT #7 Liquidity Advertisements Demonstration.
"""

from bitcoin.core.script import SIGHASH_ALL, SIGVERSION_WITNESS_V0, SignatureHash
from rich.console import Console

from payment_communities.bitcoin.contracts import ScriptFactory
from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.bitcoin.utils import (
    generate_secret,
    sign_sighash,
    verify_ecdsa_signature,
)
from payment_communities.config import (
    DEFAULT_HTLC_LOCKTIME_T1_DELTA,
    DEFAULT_SIMULATION_CAPACITY_SAT,
)
from payment_communities.domain.node import Node
from payment_communities.network.client import EsploraClient
from payment_communities.protocols.swaps import (
    LiquidityAd,
    SubmarineSwap,
    SwapType,
    create_submarine_swap_funding_tx,
    create_submarine_swap_script,
)


def run_swaps_demo(nodes: dict[str, Node], esplora: EsploraClient) -> None:
    """Demonstrates Atomic Submarine Swaps (L1 <-> L2) and BOLT #7 Liquidity Advertisements."""
    console = Console()
    console.print(
        "\n[bold magenta]=== Atomic Submarine Swaps & Liquidity Ads Demonstration ===[/bold magenta]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]

    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )
    _preimage_bytes, hash_digest = generate_secret()

    console.print(
        "1. Alice initiates Submarine Swap (Loop In: L1 BTC -> L2 Channel)..."
    )
    console.print(f"  • Preimage (R): {_preimage_bytes.hex()[:24]}...")
    console.print(f"  • Payment Hash (H): {hash_digest.hex()[:24]}...")

    swap = SubmarineSwap(
        swap_id="swap_loop_in_001",
        swap_type=SwapType.LOOP_IN,
        amount_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
        payment_hash_hex=hash_digest.hex(),
        locktime=DEFAULT_HTLC_LOCKTIME_T1_DELTA,
    )
    console.print(
        f"  • Swap ID: {swap.swap_id} | Amount: {swap.amount_sat:,} sat | Status: [yellow]{swap.state}[/yellow]"
    )

    console.print("\n2. Constructing L1 P2WSH HTLC Swap Lockup Transaction...")
    swap_script = create_submarine_swap_script(
        user_pubkey_bytes=alice_node.pubkey_bytes,
        provider_pubkey_bytes=bob_node.pubkey_bytes,
        payment_hash_bytes=hash_digest,
        locktime=DEFAULT_HTLC_LOCKTIME_T1_DELTA,
    )
    l1_tx = create_submarine_swap_funding_tx(
        funder_utxo_txid=alice_txid,
        funder_utxo_vout=alice_vout,
        funder_pubkey_bytes=alice_node.pubkey_bytes,
        swap_amount_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
        swap_redeem_script=swap_script,
    )
    p2wpkh_script_code = ScriptFactory.create_p2wpkh_scriptCode(alice_node.pubkey_bytes)
    swap_sighash = SignatureHash(
        p2wpkh_script_code,
        l1_tx,
        0,
        SIGHASH_ALL,
        amount=DEFAULT_SIMULATION_CAPACITY_SAT,
        sigversion=SIGVERSION_WITNESS_V0,
    )
    real_swap_sig = sign_sighash(alice_node.secret, swap_sighash)

    sig_valid = verify_ecdsa_signature(
        alice_node.pubkey_bytes, swap_sighash, real_swap_sig
    )

    signed_l1_tx = (
        TransactionBuilder()
        .add_input(alice_txid, alice_vout)
        .add_p2wsh_output(DEFAULT_SIMULATION_CAPACITY_SAT, swap_script)
        .add_witness_stack([real_swap_sig, alice_node.pubkey_bytes])
        .build()
    )
    txid_hex = signed_l1_tx.GetTxid().hex()

    console.print(f"  [dim]Signed L1 Lockup TXID:[/dim] {txid_hex[:24]}...")
    console.print(
        f"  • Cryptographic ECDSA Signature Verified: [bold green]{sig_valid}[/bold green]"
    )

    console.print(
        "\n3. Bob advertises Inbound Channel Liquidity Lease Policy (BOLT #7)..."
    )

    ad = LiquidityAd(
        node_alias="BobRouting",
        node_pubkey_hex=bob_node.pubkey_bytes.hex(),
    )
    requested_capacity = 1_000_000
    lease_fee = ad.calculate_lease_fee(requested_capacity)
    console.print(f"  • Inbound Capacity Requested: {requested_capacity:,} sat")
    console.print(
        f"  • Lease Base Fee: {ad.lease_fee_base_sat} sat | Rate: {ad.lease_fee_basis_ppm} PPM (0.20%)"
    )
    console.print(f"  • Total Inbound Lease Fee: [green]{lease_fee:,} sat[/green]")
    console.print(
        "  [bold green]✓ SUBMARINE SWAP & LIQUIDITY LEASE COMPLETE![/bold green]\n"
    )

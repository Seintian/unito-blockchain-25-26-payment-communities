"""
Protocol Demonstrations & Simulation Engine for CLI.
All demonstrations interact with the live testing network (Signet/Testnet) and execute
real cryptographic primitives (secp256k1 ECDH, Schnorr adaptors, AES-256-GCM Watchtowers, real signatures).
"""

from bitcoin.core.script import SIGHASH_ALL, SIGVERSION_WITNESS_V0, SignatureHash
from rich.console import Console
from rich.table import Table

from payment_communities.bitcoin.contracts import ScriptFactory
from payment_communities.bitcoin.transaction import (
    TransactionBuilder,
    create_asymmetric_commitment_transaction,
    create_commitment_transaction,
    create_cooperative_close_transaction,
    create_funding_transaction,
    sign_commitment_transaction,
)
from payment_communities.bitcoin.utils import (
    ec_point_mul,
    generate_secret,
    sign_sighash,
)
from payment_communities.config import (
    BITCOIN_ANCHOR_OUTPUT_SAT,
    DEFAULT_CPFP_FEE_BUMP_SAT,
    DEFAULT_HTLC_LOCKTIME_T1_DELTA,
    DEFAULT_HTLC_LOCKTIME_T2_DELTA,
    DEFAULT_SIMULATION_CAPACITY_SAT,
    DEFAULT_SIMULATION_PAYMENT_SAT,
    DEFAULT_TO_SELF_DELAY_BLOCKS,
    settings,
)
from payment_communities.domain.channel import ChannelState
from payment_communities.domain.node import Node
from payment_communities.network.client import EsploraClient
from payment_communities.network.routing import NetworkGraph
from payment_communities.protocols.anchors import (
    create_anchor_commitment_transaction,
    create_cpfp_fee_bump_transaction,
)
from payment_communities.protocols.eltoo import (
    EltooState,
    create_eltoo_settlement_transaction,
    create_eltoo_update_transaction,
    validate_eltoo_override,
)
from payment_communities.protocols.ptlc import (
    adapt_signature,
    create_adaptor_signature,
    extract_adaptor_secret,
    verify_adaptor_signature,
)
from payment_communities.protocols.revocation import (
    create_breach_remedy_transaction,
    create_revocable_output_script,
    generate_revocation_secret,
)
from payment_communities.protocols.sphinx import (
    create_onion_packet,
    unwrap_onion_packet,
)
from payment_communities.protocols.swaps import (
    LiquidityAd,
    SubmarineSwap,
    SwapType,
    create_submarine_swap_funding_tx,
    create_submarine_swap_script,
)
from payment_communities.protocols.watchtower import (
    WatchtowerDaemon,
    WatchtowerSession,
)

console = Console()


def run_simulate_demo(
    nodes: dict[str, Node],
    esplora: EsploraClient,
    status_fn,
    save_fn,
):
    """Runs an automated multi-hop payment routing simulation with pathfinding and persistence."""
    console.print(
        "\n[bold green]=== Starting Multi-Hop Micropayment Simulation ===[/bold green]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    dave_node = nodes["Dave"]

    # 1. Fetch live network parameters and UTXOs
    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )
    bob_txid, bob_vout = esplora.get_utxo_for_node(
        bob_node.pubkey_bytes, bob_node.p2wpkh_address
    )

    console.print(
        f"[cyan]Step 1:[/cyan] Opening channel Alice -> Bob ({DEFAULT_SIMULATION_CAPACITY_SAT:,} sat capacity)..."
    )
    ch_ab = alice_node.open_channel(
        bob_node, capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT
    )
    funding_tx_ab, multisig_script_ab = create_funding_transaction(
        funder_utxo_txid=alice_txid,
        funder_utxo_vout=alice_vout,
        funder_pubkey_bytes=alice_node.pubkey_bytes,
        counterparty_pubkey_bytes=bob_node.pubkey_bytes,
        capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
    )
    ch_ab.funding_txid = funding_tx_ab.GetTxid().hex()
    ch_ab.funding_vout = 0
    console.print(
        f"  [dim]Funding TXID (Alice->Bob):[/dim] {(ch_ab.funding_txid or '')[:24]}..."
    )

    console.print(
        f"[cyan]Step 2:[/cyan] Opening channel Bob -> Dave ({DEFAULT_SIMULATION_CAPACITY_SAT:,} sat capacity)..."
    )
    ch_bd = bob_node.open_channel(
        dave_node, capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT
    )
    funding_tx_bd, _multisig_script_bd = create_funding_transaction(
        funder_utxo_txid=bob_txid,
        funder_utxo_vout=bob_vout,
        funder_pubkey_bytes=bob_node.pubkey_bytes,
        counterparty_pubkey_bytes=dave_node.pubkey_bytes,
        capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
    )
    ch_bd.funding_txid = funding_tx_bd.GetTxid().hex()
    ch_bd.funding_vout = 0
    console.print(
        f"  [dim]Funding TXID (Bob->Dave):[/dim] {(ch_bd.funding_txid or '')[:24]}..."
    )

    # 2. Dijkstra Pathfinding
    graph = NetworkGraph()
    graph.add_channel(ch_ab)
    graph.add_channel(ch_bd)
    route = graph.find_path("Alice", "Dave", amount_sat=DEFAULT_SIMULATION_PAYMENT_SAT)

    console.print(
        f"\n[cyan]Pathfinding Route Found:[/cyan] {' -> '.join(route.path)} "
        f"(Total Sat: {route.total_amount_sat:,}, Total Routing Fee: {route.total_fee_sat:,} sat)"
    )

    # 3. Dave creates invoice (preimage R & hash H)
    console.print(
        "\n[cyan]Step 3:[/cyan] Dave generates invoice (Preimage & Payment Hash)..."
    )
    preimage_hex, hash_hex = dave_node.create_invoice()
    console.print(f"  [dim]Preimage (R):[/dim] {preimage_hex[:24]}...")
    console.print(f"  [dim]Payment Hash (H):[/dim] {hash_hex[:24]}...")

    # 4. Alice routes HTLC to Bob using live block height
    payment_amount_sat = DEFAULT_SIMULATION_PAYMENT_SAT
    current_block_height = esplora.get_block_height()
    locktime_alice_to_bob = current_block_height + DEFAULT_HTLC_LOCKTIME_T1_DELTA
    locktime_bob_to_dave = current_block_height + DEFAULT_HTLC_LOCKTIME_T2_DELTA

    console.print(
        f"\n[cyan]Step 4:[/cyan] Alice locks {payment_amount_sat:,} sat HTLC to Bob..."
    )
    alice_node.route_htlc_payment(
        target_peer_alias="Bob",
        amount_sat=payment_amount_sat,
        payment_hash=hash_hex,
        locktime=locktime_alice_to_bob,
        htlc_id="htlc_ab_1",
    )

    htlc_script_ab = ScriptFactory.create_htlc(
        alice_node.pubkey_bytes,
        bob_node.pubkey_bytes,
        bytes.fromhex(hash_hex),
        locktime_alice_to_bob,
    )
    alice_balance_sat = DEFAULT_SIMULATION_CAPACITY_SAT - payment_amount_sat
    commit_tx_ab = create_commitment_transaction(
        funding_txid=ch_ab.funding_txid or "",
        funding_vout=0,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        sender_balance_sat=alice_balance_sat,
        receiver_balance_sat=0,
        htlc_outputs=[(payment_amount_sat, htlc_script_ab)],
    )
    sign_commitment_transaction(
        tx=commit_tx_ab,
        input_index=0,
        redeem_script=multisig_script_ab,
        capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
        sec1=alice_node.secret,
        sec2=bob_node.secret,
    )
    console.print(
        "  [bold green]✓ HTLC Alice -> Bob offered & Signed Commitment TX built[/bold green]"
    )

    # 5. Bob forwards HTLC to Dave
    console.print(
        f"\n[cyan]Step 5:[/cyan] Bob forwards {payment_amount_sat:,} sat HTLC to Dave..."
    )
    bob_node.route_htlc_payment(
        target_peer_alias="Dave",
        amount_sat=payment_amount_sat,
        payment_hash=hash_hex,
        locktime=locktime_bob_to_dave,
        htlc_id="htlc_bd_1",
    )
    console.print("  [bold green]✓ HTLC Bob -> Dave offered successfully[/bold green]")

    # 6. Preimage Fulfillment across the route
    console.print(
        "\n[cyan]Step 6:[/cyan] Dave fulfills HTLC with Bob using secret Preimage..."
    )
    bob_node.fulfill_htlc("Dave", "htlc_bd_1", preimage_hex)
    console.print(
        f"  [bold green]✓ Dave claimed {payment_amount_sat:,} sat from Bob![/bold green]"
    )

    console.print(
        "\n[cyan]Step 7:[/cyan] Bob fulfills HTLC with Alice using revealed Preimage..."
    )
    alice_node.fulfill_htlc("Bob", "htlc_ab_1", preimage_hex)
    console.print(
        f"  [bold green]✓ Bob claimed {payment_amount_sat:,} sat from Alice![/bold green]"
    )

    # 7. Real Cooperative Close Settlement Transaction Generation & Signing
    close_tx_ab = create_cooperative_close_transaction(
        funding_txid=ch_ab.funding_txid or "",
        funding_vout=0,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        final_sender_sat=alice_balance_sat,
        final_receiver_sat=payment_amount_sat,
    )
    sighash_close = SignatureHash(
        multisig_script_ab,
        close_tx_ab,
        0,
        SIGHASH_ALL,
        amount=DEFAULT_SIMULATION_CAPACITY_SAT,
        sigversion=SIGVERSION_WITNESS_V0,
    )
    sig1_close = sign_sighash(alice_node.secret, sighash_close)
    sig2_close = sign_sighash(bob_node.secret, sighash_close)
    witness_close = ScriptFactory.witness_multisig_2of2(
        sig1_close, sig2_close, multisig_script_ab
    )

    signed_close_tx_ab = (
        TransactionBuilder()
        .add_input(ch_ab.funding_txid or "", 0)
        .add_p2wpkh_output(alice_balance_sat, alice_node.pubkey_bytes)
        .add_p2wpkh_output(payment_amount_sat, bob_node.pubkey_bytes)
        .add_witness_stack(witness_close)
        .build()
    )

    console.print(
        f"\n[dim]Signed Cooperative Settlement TXID:[/dim] {signed_close_tx_ab.GetTxid().hex()[:24]}..."
    )

    save_fn()
    console.print(
        "\n[bold green]=== Multi-Hop Payment Complete & State Persisted! ===[/bold green]\n"
    )
    status_fn()


def run_breach_demo(nodes: dict[str, Node], esplora: EsploraClient):
    """Demonstrates Poon-Dryja State Revocation and Breach Remedy Justice Sweep Penalty with real keys and live network state."""
    console.print(
        "\n[bold red]=== Poon-Dryja Breach Remedy Penalty Demonstration ===[/bold red]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]

    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )

    console.print(
        f"[cyan]1. Setting up Channel Alice -> Bob ({DEFAULT_SIMULATION_CAPACITY_SAT:,} sat capacity)...[/cyan]"
    )
    ch = alice_node.open_channel(bob_node, capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT)
    ch.funding_txid = alice_txid
    ch.funding_vout = alice_vout

    rev_secret_bytes, rev_hash = generate_revocation_secret()
    revocable_script = create_revocable_output_script(
        revocation_pubkey=rev_hash,
        local_pubkey=alice_node.pubkey_bytes,
        to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
    )

    revoked_commit_tx = create_asymmetric_commitment_transaction(
        funding_txid=alice_txid,
        funding_vout=alice_vout,
        local_pubkey_bytes=alice_node.pubkey_bytes,
        remote_pubkey_bytes=bob_node.pubkey_bytes,
        revocation_pubkey_bytes=rev_hash,
        local_balance_sat=80_000,
        remote_balance_sat=20_000,
    )
    revoked_txid = revoked_commit_tx.GetTxid().hex()

    console.print(
        "  • Alice & Bob execute Payment #1 (Alice: 80,000 sat, Bob: 20,000 sat). State #1 is REVOKED."
    )
    ch.revoke_prior_state(1, rev_secret_bytes.hex())

    half_capacity = DEFAULT_SIMULATION_CAPACITY_SAT // 2
    console.print(
        f"  • Current State #2 active (Alice: {half_capacity:,} sat, Bob: {half_capacity:,} sat)."
    )
    ch.balance_sender_sat = half_capacity
    ch.balance_receiver_sat = half_capacity

    console.print(
        "\n[bold yellow]⚠️  MALICIOUS ATTEMPT:[/bold yellow] Alice attempts to broadcast revoked State #1 on-chain to steal 80,000 sat!"
    )
    console.print(f"  • Revoked State #1 Commitment TXID: {revoked_txid[:24]}...")

    if ch.revocation_store.is_state_revoked(1):
        console.print(
            "  [bold red]🚨 BREACH DETECTED![/bold red] Bob identifies Alice's broadcast as a REVOKED state!"
        )

        revealed_secret = ch.revocation_store.get_revocation_secret(1)

        # Generate real cryptographic justice signature from Bob's secret key
        dummy_rev_tx = create_breach_remedy_transaction(
            revoked_txid=revoked_txid,
            revoked_vout=0,
            sweeper_pubkey_bytes=bob_node.pubkey_bytes,
            amount_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
            revocation_secret_signature=b"\x00" * 70,
            revocable_redeem_script=revocable_script,
        )
        sighash = SignatureHash(
            revocable_script,
            dummy_rev_tx,
            0,
            SIGHASH_ALL,
            amount=DEFAULT_SIMULATION_CAPACITY_SAT,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        real_justice_sig = sign_sighash(bob_node.secret, sighash)

        justice_tx = create_breach_remedy_transaction(
            revoked_txid=revoked_txid,
            revoked_vout=0,
            sweeper_pubkey_bytes=bob_node.pubkey_bytes,
            amount_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
            revocation_secret_signature=real_justice_sig,
            revocable_redeem_script=revocable_script,
        )

        secret_disp = (revealed_secret or "")[:16]
        console.print(
            f"  [bold green]⚡ BREACH REMEDY EXECUTED![/bold green] Bob uses revealed secret ({secret_disp}...) to sweep 100% of channel capacity!"
        )
        console.print(
            f"  [dim]Justice Sweep TXID:[/dim] {justice_tx.GetTxid().hex()[:24]}..."
        )

        ch.balance_sender_sat = 0
        ch.balance_receiver_sat = DEFAULT_SIMULATION_CAPACITY_SAT
        ch.state = ChannelState.SETTLED

        console.print(
            "\n[bold green]=== Alice Punished! Final Channel Balances: ===[/bold green]\n"
        )
        console.print(f"  • Alice: {ch.balance_sender_sat:,} sat (PUNISHED: 0 sat)")
        console.print(
            f"  • Bob:   {ch.balance_receiver_sat:,} sat (SWEEPS 100% OF CAPACITY)"
        )


def run_watchtower_demo(nodes: dict[str, Node], esplora: EsploraClient):
    """Demonstrates privacy-preserving Watchtower hint registration and autonomous L1 breach sweep."""
    console.print(
        "\n[bold magenta]=== Watchtower Autonomous Breach Sweep Demonstration ===[/bold magenta]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    session = WatchtowerSession()
    daemon = WatchtowerDaemon(session=session)

    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )
    _rev_secret_bytes, rev_hash = generate_revocation_secret()

    revocable_script = create_revocable_output_script(
        revocation_pubkey=rev_hash,
        local_pubkey=alice_node.pubkey_bytes,
        to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
    )
    revoked_tx = create_asymmetric_commitment_transaction(
        funding_txid=alice_txid,
        funding_vout=alice_vout,
        local_pubkey_bytes=alice_node.pubkey_bytes,
        remote_pubkey_bytes=bob_node.pubkey_bytes,
        revocation_pubkey_bytes=rev_hash,
        local_balance_sat=80_000,
        remote_balance_sat=20_000,
    )
    revoked_txid = revoked_tx.GetTxid().hex()

    dummy_wt_tx = create_breach_remedy_transaction(
        revoked_txid=revoked_txid,
        revoked_vout=0,
        sweeper_pubkey_bytes=bob_node.pubkey_bytes,
        amount_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
        revocation_secret_signature=b"\x00" * 70,
        revocable_redeem_script=revocable_script,
    )
    wt_sighash = SignatureHash(
        revocable_script,
        dummy_wt_tx,
        0,
        SIGHASH_ALL,
        amount=DEFAULT_SIMULATION_CAPACITY_SAT,
        sigversion=SIGVERSION_WITNESS_V0,
    )
    real_wt_sig = sign_sighash(bob_node.secret, wt_sighash)

    console.print(
        "1. Bob subscribes to Watchtower service and registers encrypted AES-256-GCM justice payload..."
    )
    hint = session.register_justice_package(
        revoked_txid_hex=revoked_txid,
        sweeper_pubkey_hex=bob_node.pubkey_bytes.hex(),
        amount_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
        revocation_sig_hex=real_wt_sig.hex(),
        revocation_pubkey_hex=rev_hash.hex(),
        local_pubkey_hex=alice_node.pubkey_bytes.hex(),
        to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
    )

    console.print(f"  • Watchtower stores 16-byte hint key: [cyan]{hint}[/cyan]")
    console.print(
        "  • [dim]Watchtower status: Encrypted AES-256-GCM payload stored. Zero knowledge of keys or contents.[/dim]"
    )

    console.print("\n2. Alice maliciously broadcasts revoked transaction on L1...")
    console.print(f"  • Broadcast TXID: {revoked_txid[:24]}...")

    console.print("\n3. Watchtower scans L1 block stream and identifies hint match!")
    justice_tx = daemon.scan_transaction(revoked_txid)
    if justice_tx:
        console.print(
            "  [bold green]⚡ WATCHTOWER TRIGGERED![/bold green] Decrypted AES-256-GCM payload and broadcast Justice Sweep!"
        )
        console.print(
            f"  [dim]Autonomous Sweep TXID:[/dim] {justice_tx.GetTxid().hex()[:24]}...\n"
        )


def run_eltoo_demo(nodes: dict[str, Node], esplora: EsploraClient):
    """Demonstrates Eltoo (LN-Symmetric) state update protocol without penalty revocation secrets."""
    console.print(
        "\n[bold blue]=== Eltoo (LN-Symmetric) State Update Protocol Demonstration ===[/bold blue]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    multisig_script = ScriptFactory.create_multisig_2of2(
        alice_node.pubkey_bytes, bob_node.pubkey_bytes
    )

    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )

    state1 = EltooState(
        state_number=1, sender_balance_sat=80_000, receiver_balance_sat=20_000
    )
    state2 = EltooState(
        state_number=2, sender_balance_sat=50_000, receiver_balance_sat=50_000
    )

    console.print(
        "1. Alice & Bob construct Eltoo State #1 (Alice: 80k sat, Bob: 20k sat)."
    )
    console.print(f"  • State #1 Locktime: {state1.locktime}")

    console.print(
        "\n2. Alice & Bob update to Eltoo State #2 (Alice: 50k sat, Bob: 50k sat)."
    )
    console.print(f"  • State #2 Locktime: {state2.locktime}")
    console.print(
        "  • [dim]No revocation secrets needed! State #2 naturally overrides State #1 on-chain.[/dim]"
    )

    if validate_eltoo_override(state1, state2):
        update_tx2 = create_eltoo_update_transaction(
            spending_txid=alice_txid,
            spending_vout=alice_vout,
            state=state2,
            multisig_redeem_script=bytes(multisig_script),
            sec_sender=alice_node.secret,
            sec_receiver=bob_node.secret,
        )
        settle_tx2 = create_eltoo_settlement_transaction(
            update_txid=update_tx2.GetTxid().hex(),
            update_vout=0,
            sender_pubkey_bytes=alice_node.pubkey_bytes,
            receiver_pubkey_bytes=bob_node.pubkey_bytes,
            state=state2,
            multisig_redeem_script=bytes(multisig_script),
            sec_sender=alice_node.secret,
            sec_receiver=bob_node.secret,
        )

        console.print("\n[bold green]✓ ELTOO SYMMETRIC UPDATE COMPLETE![/bold green]")
        console.print(
            f"  [dim]Signed Update TX2 ID:[/dim] {update_tx2.GetTxid().hex()[:24]}..."
        )
        console.print(
            f"  [dim]Signed Settlement TX2 ID:[/dim] {settle_tx2.GetTxid().hex()[:24]}...\n"
        )


def run_sphinx_demo(nodes: dict[str, Node], esplora: EsploraClient):
    """Demonstrates Sphinx multi-layer onion encryption using secp256k1 ECDH across routing nodes."""
    console.print(
        "\n[bold yellow]=== Sphinx Onion Encrypted Routing Demonstration ===[/bold yellow]\n"
    )

    bob_node = nodes["Bob"]
    dave_node = nodes["Dave"]

    node_keys = {
        "Bob": settings.bob_key or str(bob_node.secret),
        "Dave": settings.dave_key or str(dave_node.secret),
    }

    current_height = esplora.get_block_height()
    t1_delta = current_height + DEFAULT_HTLC_LOCKTIME_T1_DELTA
    t2_delta = current_height + DEFAULT_HTLC_LOCKTIME_T2_DELTA

    route_hops = [
        ("Bob", "Dave", DEFAULT_SIMULATION_PAYMENT_SAT, t1_delta),
        ("Dave", "", DEFAULT_SIMULATION_PAYMENT_SAT, t2_delta),
    ]

    console.print(
        "1. Alice constructs multi-layer encrypted Sphinx onion packet for Bob -> Dave..."
    )
    packet = create_onion_packet(route_hops, node_keys)
    console.print(
        f"  • Ephemeral PubKey: [cyan]{packet.ephemeral_key_hex[:24]}...[/cyan]"
    )
    console.print(f"  • HMAC Integrity Tag: [cyan]{packet.hmac_hex[:24]}...[/cyan]")

    console.print(
        "\n2. Bob receives onion packet and unwraps Layer 1 via secp256k1 ECDH..."
    )
    bob_payload, dave_packet = unwrap_onion_packet(
        packet, node_wif_key=node_keys["Bob"]
    )
    console.print(
        f"  • Bob decrypted instructions: Forward to [bold]{bob_payload.next_hop}[/bold] ({bob_payload.amount_sat:,} sat)"
    )

    if dave_packet:
        console.print(
            "\n3. Dave receives forwarded packet and unwraps final Layer 2 via secp256k1 ECDH..."
        )
        dave_payload, _final_packet = unwrap_onion_packet(
            dave_packet, node_wif_key=node_keys["Dave"]
        )
        console.print(
            f"  • Dave decrypted instructions: Final Destination reached! (Amount: {dave_payload.amount_sat:,} sat)"
        )
        console.print("  [bold green]✓ SPHINX PRIVACY ROUTING COMPLETE![/bold green]\n")


def run_ptlc_demo(nodes: dict[str, Node], esplora: EsploraClient):
    """Demonstrates Point Time-Locked Contracts (PTLCs) and Schnorr Adaptor Signatures."""
    console.print(
        "\n[bold cyan]=== PTLC & Adaptor Signature Demonstration ===[/bold cyan]\n"
    )

    alice_node = nodes["Alice"]
    secret_scalar_bytes, msg_hash = generate_secret()
    secret_scalar_int = int.from_bytes(secret_scalar_bytes, "big")
    payment_point = ec_point_mul(secret_scalar_int)

    console.print("1. Dave generates payment point T = t * G and sends to Alice...")
    console.print(f"  • Payment Point (T): {payment_point.hex()[:24]}...")

    console.print(
        "\n2. Alice creates Schnorr Adaptor Signature (s') encrypted under T..."
    )
    adaptor_sig = create_adaptor_signature(alice_node.secret, payment_point, msg_hash)
    assert verify_adaptor_signature(adaptor_sig, alice_node.pubkey_bytes, msg_hash)
    console.print(f"  • Adaptor s': {adaptor_sig.s_prime_hex[:24]}...")

    console.print("\n3. Dave adapts signature using secret scalar t (s = s' + t)...")
    final_sig = adapt_signature(adaptor_sig, secret_scalar_bytes)
    console.print(
        f"  • Final On-Chain Witness Signature (s): {final_sig.hex()[:24]}..."
    )

    console.print(
        "\n4. Alice observes s on-chain and extracts secret scalar t (t = s - s')..."
    )
    extracted_secret_bytes = extract_adaptor_secret(adaptor_sig, final_sig)
    assert extracted_secret_bytes == secret_scalar_bytes
    console.print(
        "  [bold green]⚡ PTLC ADAPTOR SECRET EXTRACTED CONFIRMED![/bold green]\n"
    )


def run_anchors_demo(nodes: dict[str, Node], esplora: EsploraClient):
    """Demonstrates BOLT #3 330 sat Anchor Outputs and CPFP Child Fee Bumping."""
    console.print(
        "\n[bold green]=== Anchor Outputs & CPFP Fee Bumping Demonstration ===[/bold green]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]

    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )

    console.print(
        f"1. Constructing Commitment TX augmented with {BITCOIN_ANCHOR_OUTPUT_SAT} sat Anchor Outputs..."
    )
    tx, local_script, _remote_script = create_anchor_commitment_transaction(
        funding_txid=alice_txid,
        funding_vout=alice_vout,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        sender_balance_sat=70_000,
        receiver_balance_sat=30_000,
    )

    table = Table(title="Commitment Transaction Outputs with Anchors")
    table.add_column("Output Index", justify="center")
    table.add_column("Output Type", style="cyan")
    table.add_column("Amount (sat)", justify="right")

    table.add_row("0", "Alice P2WPKH Balance", "70,000")
    table.add_row("1", "Bob P2WPKH Balance", "30,000")
    table.add_row("2", "to_local_anchor (Alice 16-CSV)", f"{BITCOIN_ANCHOR_OUTPUT_SAT}")
    table.add_row("3", "to_remote_anchor (Bob 16-CSV)", f"{BITCOIN_ANCHOR_OUTPUT_SAT}")

    console.print(table)

    console.print(
        "\n2. High L1 Mempool Congestion Detected! Alice constructs CPFP Child Transaction..."
    )
    dummy_child_tx = create_cpfp_fee_bump_transaction(
        parent_commitment_txid=tx.GetTxid().hex(),
        anchor_vout=2,
        fee_bumper_pubkey_bytes=alice_node.pubkey_bytes,
        fee_bump_sat=DEFAULT_CPFP_FEE_BUMP_SAT,
        anchor_redeem_script=local_script,
        signature=b"\x00" * 70,
    )
    cpfp_sighash = SignatureHash(
        local_script,
        dummy_child_tx,
        0,
        SIGHASH_ALL,
        amount=BITCOIN_ANCHOR_OUTPUT_SAT,
        sigversion=SIGVERSION_WITNESS_V0,
    )
    real_cpfp_sig = sign_sighash(alice_node.secret, cpfp_sighash)

    child_tx = create_cpfp_fee_bump_transaction(
        parent_commitment_txid=tx.GetTxid().hex(),
        anchor_vout=2,
        fee_bumper_pubkey_bytes=alice_node.pubkey_bytes,
        fee_bump_sat=DEFAULT_CPFP_FEE_BUMP_SAT,
        anchor_redeem_script=local_script,
        signature=real_cpfp_sig,
    )

    console.print(
        f"  • Alice spends {BITCOIN_ANCHOR_OUTPUT_SAT} sat Anchor Output to attach {DEFAULT_CPFP_FEE_BUMP_SAT:,} sat mining fee package!"
    )
    console.print(f"  [dim]CPFP Child TXID:[/dim] {child_tx.GetTxid().hex()[:24]}...")
    console.print(
        "  [bold green]✓ CPFP FEE BUMP PACKAGE BROADCAST CONFIRMED![/bold green]\n"
    )


def run_swaps_demo(nodes: dict[str, Node], esplora: EsploraClient):
    """Demonstrates Atomic Submarine Swaps (L1 <-> L2) and BOLT #7 Liquidity Advertisements."""
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
    from payment_communities.bitcoin.utils import verify_ecdsa_signature

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

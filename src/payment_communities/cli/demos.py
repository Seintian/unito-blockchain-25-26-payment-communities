"""
Protocol Demonstrations & Simulation Engine for CLI.
"""

from rich.console import Console
from rich.table import Table

from payment_communities.bitcoin.contracts import ScriptFactory
from payment_communities.bitcoin.transaction import (
    create_commitment_transaction,
    create_cooperative_close_transaction,
    create_funding_transaction,
)
from payment_communities.bitcoin.utils import generate_secret, sha256
from payment_communities.config import (
    DEFAULT_HTLC_LOCKTIME_T1_DELTA,
    DEFAULT_TO_SELF_DELAY_BLOCKS,
    MOCK_JUSTICE_SIGNATURE,
    MOCK_UTXO_TXID_ALICE,
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

    # 1. Open Off-Chain Channels with Real Funding CMutableTransaction Generation
    console.print(
        "[cyan]Step 1:[/cyan] Opening channel Alice -> Bob (100,000 sat capacity)..."
    )
    ch_ab = alice_node.open_channel(bob_node, capacity_sat=100_000)
    funding_tx_ab, _multisig_script_ab = create_funding_transaction(
        funder_utxo_txid="00" * 32,
        funder_utxo_vout=0,
        funder_pubkey_bytes=alice_node.pubkey_bytes,
        counterparty_pubkey_bytes=bob_node.pubkey_bytes,
        capacity_sat=100_000,
    )
    ch_ab.funding_txid = funding_tx_ab.GetTxid().hex()
    ch_ab.funding_vout = 0
    console.print(
        f"  [dim]Funding TXID (Alice->Bob):[/dim] {(ch_ab.funding_txid or '')[:24]}..."
    )

    console.print(
        "[cyan]Step 2:[/cyan] Opening channel Bob -> Dave (100,000 sat capacity)..."
    )
    ch_bd = bob_node.open_channel(dave_node, capacity_sat=100_000)
    funding_tx_bd, _multisig_script_bd = create_funding_transaction(
        funder_utxo_txid="11" * 32,
        funder_utxo_vout=0,
        funder_pubkey_bytes=bob_node.pubkey_bytes,
        counterparty_pubkey_bytes=dave_node.pubkey_bytes,
        capacity_sat=100_000,
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
    route = graph.find_path("Alice", "Dave", amount_sat=25_000)

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

    # 4. Alice routes HTLC to Bob
    payment_amount_sat = 25_000
    current_block_height = esplora.get_block_height()
    locktime_alice_to_bob = current_block_height + 144
    locktime_bob_to_dave = current_block_height + 100

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

    # Create commitment tx object with HTLC script via ScriptFactory
    htlc_script_ab = ScriptFactory.create_htlc(
        alice_node.pubkey_bytes,
        bob_node.pubkey_bytes,
        bytes.fromhex(hash_hex),
        locktime_alice_to_bob,
    )
    create_commitment_transaction(
        funding_txid=ch_ab.funding_txid or "",
        funding_vout=0,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        sender_balance_sat=75_000,
        receiver_balance_sat=0,
        htlc_outputs=[(25_000, htlc_script_ab)],
    )
    console.print(
        "  [bold green]✓ HTLC Alice -> Bob offered & Commitment TX built[/bold green]"
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
    console.print("  [bold green]✓ Dave claimed 25,000 sat from Bob![/bold green]")

    console.print(
        "\n[cyan]Step 7:[/cyan] Bob fulfills HTLC with Alice using revealed Preimage..."
    )
    alice_node.fulfill_htlc("Bob", "htlc_ab_1", preimage_hex)
    console.print("  [bold green]✓ Bob claimed 25,000 sat from Alice![/bold green]")

    # 7. Cooperative Close Settlement Transaction Generation
    close_tx_ab = create_cooperative_close_transaction(
        funding_txid=ch_ab.funding_txid or "",
        funding_vout=0,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        final_sender_sat=75_000,
        final_receiver_sat=25_000,
    )
    console.print(
        f"\n[dim]Cooperative Settlement TXID:[/dim] {close_tx_ab.GetTxid().hex()[:24]}..."
    )

    save_fn()
    console.print(
        "\n[bold green]=== Multi-Hop Payment Complete & State Persisted! ===[/bold green]\n"
    )
    status_fn()


def run_breach_demo(nodes: dict[str, Node]):
    """Demonstrates Poon-Dryja State Revocation and Breach Remedy Justice Sweep Penalty."""
    console.print(
        "\n[bold red]=== Poon-Dryja Breach Remedy Penalty Demonstration ===[/bold red]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]

    console.print(
        "[cyan]1. Setting up Channel Alice -> Bob (100,000 sat capacity)...[/cyan]"
    )
    ch = alice_node.open_channel(bob_node, capacity_sat=100_000)

    rev_secret_bytes, rev_hash = generate_revocation_secret()
    revocable_script = create_revocable_output_script(
        revocation_pubkey=rev_hash,
        local_pubkey=alice_node.pubkey_bytes,
        to_self_delay=144,
    )

    console.print(
        "  • Alice & Bob execute Payment #1 (Alice: 80,000 sat, Bob: 20,000 sat). State #1 is REVOKED."
    )
    ch.revoke_prior_state(1, rev_secret_bytes.hex())

    console.print("  • Current State #2 active (Alice: 50,000 sat, Bob: 50,000 sat).")
    ch.balance_sender_sat = 50_000
    ch.balance_receiver_sat = 50_000

    console.print(
        "\n[bold yellow]⚠️  MALICIOUS ATTEMPT:[/bold yellow] Alice attempts to broadcast revoked State #1 on-chain to steal 80,000 sat!"
    )

    if ch.revocation_store.is_state_revoked(1):
        console.print(
            "  [bold red]🚨 BREACH DETECTED![/bold red] Bob identifies Alice's broadcast as a REVOKED state!"
        )

        revealed_secret = ch.revocation_store.get_revocation_secret(1)
        mock_justice_sig = b"\x30\x44" + b"\x00" * 68

        justice_tx = create_breach_remedy_transaction(
            revoked_txid="aa" * 32,
            revoked_vout=0,
            sweeper_pubkey_bytes=bob_node.pubkey_bytes,
            amount_sat=100_000,
            revocation_secret_signature=mock_justice_sig,
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
        ch.balance_receiver_sat = 100_000
        ch.state = ChannelState.SETTLED

        console.print(
            "\n[bold green]=== Alice Punished! Final Channel Balances: ===[/bold green]\n"
        )
        console.print(f"  • Alice: {ch.balance_sender_sat:,} sat (PUNISHED: 0 sat)")
        console.print(
            f"  • Bob:   {ch.balance_receiver_sat:,} sat (SWEEPS 100% OF CAPACITY)"
        )


def run_watchtower_demo(nodes: dict[str, Node]):
    """Demonstrates privacy-preserving Watchtower hint registration and autonomous L1 breach sweep."""
    console.print(
        "\n[bold magenta]=== Watchtower Autonomous Breach Sweep Demonstration ===[/bold magenta]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    session = WatchtowerSession()
    daemon = WatchtowerDaemon(session=session)

    revoked_txid = "cc" * 32
    mock_sig = b"\x30\x44" + b"\x00" * 68
    _rev_secret_bytes, rev_hash = generate_revocation_secret()

    console.print(
        "1. Bob subscribes to Watchtower service and registers encrypted justice payload..."
    )
    hint = session.register_justice_package(
        revoked_txid_hex=revoked_txid,
        sweeper_pubkey_hex=bob_node.pubkey_bytes.hex(),
        amount_sat=100_000,
        revocation_sig_hex=mock_sig.hex(),
        revocation_pubkey_hex=rev_hash.hex(),
        local_pubkey_hex=alice_node.pubkey_bytes.hex(),
        to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
    )
    console.print(f"  • Watchtower stores 16-byte hint key: [cyan]{hint}[/cyan]")
    console.print(
        "  • [dim]Watchtower status: Does NOT know channel keys or transaction contents.[/dim]"
    )

    console.print("\n2. Alice maliciously broadcasts revoked transaction on L1...")
    console.print(f"  • Broadcast TXID: {revoked_txid[:24]}...")

    console.print("\n3. Watchtower scans L1 block stream and identifies hint match!")
    justice_tx = daemon.scan_transaction(revoked_txid)
    if justice_tx:
        console.print(
            "  [bold green]⚡ WATCHTOWER TRIGGERED![/bold green] Decrypted payload and broadcast Justice Sweep!"
        )
        console.print(
            f"  [dim]Autonomous Sweep TXID:[/dim] {justice_tx.GetTxid().hex()[:24]}...\n"
        )


def run_eltoo_demo(nodes: dict[str, Node]):
    """Demonstrates Eltoo (LN-Symmetric) state update protocol without penalty revocation secrets."""
    console.print(
        "\n[bold blue]=== Eltoo (LN-Symmetric) State Update Protocol Demonstration ===[/bold blue]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    multisig_script = ScriptFactory.create_multisig_2of2(
        alice_node.pubkey_bytes, bob_node.pubkey_bytes
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
            spending_txid="00" * 32,
            spending_vout=0,
            state=state2,
            multisig_redeem_script=bytes(multisig_script),
            sig_sender=b"\x00" * 64,
            sig_receiver=b"\x00" * 64,
        )
        settle_tx2 = create_eltoo_settlement_transaction(
            update_txid=update_tx2.GetTxid().hex(),
            update_vout=0,
            sender_pubkey_bytes=alice_node.pubkey_bytes,
            receiver_pubkey_bytes=bob_node.pubkey_bytes,
            state=state2,
            sig_sender=b"\x00" * 64,
            sig_receiver=b"\x00" * 64,
            multisig_redeem_script=bytes(multisig_script),
        )

        console.print("\n[bold green]✓ ELTOO SYMMETRIC UPDATE COMPLETE![/bold green]")
        console.print(
            f"  [dim]Update TX2 ID:[/dim] {update_tx2.GetTxid().hex()[:24]}..."
        )
        console.print(
            f"  [dim]Settlement TX2 ID:[/dim] {settle_tx2.GetTxid().hex()[:24]}...\n"
        )


def run_sphinx_demo(nodes: dict[str, Node]):
    """Demonstrates Sphinx multi-layer onion encryption across intermediate routing nodes."""
    console.print(
        "\n[bold yellow]=== Sphinx Onion Encrypted Routing Demonstration ===[/bold yellow]\n"
    )

    bob_node = nodes["Bob"]
    dave_node = nodes["Dave"]

    node_keys = {
        "Bob": settings.bob_key or str(bob_node.secret),
        "Dave": settings.dave_key or str(dave_node.secret),
    }

    route_hops = [
        ("Bob", "Dave", 25_000, 144),
        ("Dave", "", 25_000, 100),
    ]

    console.print(
        "1. Alice constructs multi-layer encrypted Sphinx onion packet for Bob -> Dave..."
    )
    packet = create_onion_packet(route_hops, node_keys)
    console.print(
        f"  • Ephemeral PubKey: [cyan]{packet.ephemeral_key_hex[:24]}...[/cyan]"
    )
    console.print(f"  • HMAC Integrity Tag: [cyan]{packet.hmac_hex[:24]}...[/cyan]")

    console.print("\n2. Bob receives onion packet and unwraps Layer 1...")
    bob_payload, dave_packet = unwrap_onion_packet(
        packet, node_wif_key=node_keys["Bob"]
    )
    console.print(
        f"  • Bob decrypted instructions: Forward to [bold]{bob_payload.next_hop}[/bold] ({bob_payload.amount_sat:,} sat)"
    )

    if dave_packet:
        console.print(
            "\n3. Dave receives forwarded packet and unwraps final Layer 2..."
        )
        dave_payload, _final_packet = unwrap_onion_packet(
            dave_packet, node_wif_key=node_keys["Dave"]
        )
        console.print(
            f"  • Dave decrypted instructions: Final Destination reached! (Amount: {dave_payload.amount_sat:,} sat)"
        )
        console.print("  [bold green]✓ SPHINX PRIVACY ROUTING COMPLETE![/bold green]\n")


def run_ptlc_demo(nodes: dict[str, Node]):
    """Demonstrates Point Time-Locked Contracts (PTLCs) and Schnorr Adaptor Signatures."""
    console.print(
        "\n[bold cyan]=== PTLC & Adaptor Signature Demonstration ===[/bold cyan]\n"
    )

    alice_node = nodes["Alice"]
    secret_scalar = sha256(b"ptlc_demo_secret")
    payment_point = sha256(secret_scalar)
    msg_hash = sha256(b"ptlc_commitment_data")

    console.print("1. Dave generates payment point T = t * G and sends to Alice...")
    console.print(f"  • Payment Point (T): {payment_point.hex()[:24]}...")

    console.print(
        "\n2. Alice creates Schnorr Adaptor Signature (s') encrypted under T..."
    )
    adaptor_sig = create_adaptor_signature(alice_node.secret, payment_point, msg_hash)
    assert verify_adaptor_signature(adaptor_sig, alice_node.pubkey_bytes, msg_hash)
    console.print(f"  • Adaptor s': {adaptor_sig.s_prime_hex[:24]}...")

    console.print("\n3. Dave adapts signature using secret scalar t (s = s' + t)...")
    final_sig = adapt_signature(adaptor_sig, secret_scalar)
    console.print(
        f"  • Final On-Chain Witness Signature (s): {final_sig.hex()[:24]}..."
    )

    console.print(
        "\n4. Alice observes s on-chain and extracts secret scalar t (t = s - s')..."
    )
    extracted_secret = extract_adaptor_secret(adaptor_sig, final_sig)
    assert extracted_secret == secret_scalar
    console.print(
        "  [bold green]⚡ PTLC ADAPTOR SECRET EXTRACTED CONFIRMED![/bold green]\n"
    )


def run_anchors_demo(nodes: dict[str, Node]):
    """Demonstrates BOLT #3 330 sat Anchor Outputs and CPFP Child Fee Bumping."""
    console.print(
        "\n[bold green]=== Anchor Outputs & CPFP Fee Bumping Demonstration ===[/bold green]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]

    console.print(
        "1. Constructing Commitment TX augmented with 330 sat Anchor Outputs..."
    )
    tx, local_script, _remote_script = create_anchor_commitment_transaction(
        funding_txid=MOCK_UTXO_TXID_ALICE,
        funding_vout=0,
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
    table.add_row("2", "to_local_anchor (Alice 16-CSV)", "330")
    table.add_row("3", "to_remote_anchor (Bob 16-CSV)", "330")

    console.print(table)

    console.print(
        "\n2. High L1 Mempool Congestion Detected! Alice constructs CPFP Child Transaction..."
    )
    child_tx = create_cpfp_fee_bump_transaction(
        parent_commitment_txid=tx.GetTxid().hex(),
        anchor_vout=2,
        fee_bumper_pubkey_bytes=alice_node.pubkey_bytes,
        fee_bump_sat=1000,
        anchor_redeem_script=local_script,
        signature=MOCK_JUSTICE_SIGNATURE,
    )

    console.print(
        "  • Alice spends 330 sat Anchor Output to attach 1,000 sat mining fee package!"
    )
    console.print(f"  [dim]CPFP Child TXID:[/dim] {child_tx.GetTxid().hex()[:24]}...")
    console.print(
        "  [bold green]✓ CPFP FEE BUMP PACKAGE BROADCAST CONFIRMED![/bold green]\n"
    )


def run_swaps_demo(nodes: dict[str, Node]):
    """Demonstrates Atomic Submarine Swaps (L1 <-> L2) and BOLT #7 Liquidity Advertisements."""
    console.print(
        "\n[bold magenta]=== Atomic Submarine Swaps & Liquidity Ads Demonstration ===[/bold magenta]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    _preimage, hash_digest = generate_secret()

    console.print(
        "1. Alice initiates Submarine Swap (Loop In: L1 BTC -> L2 Channel)..."
    )
    swap = SubmarineSwap(
        swap_id="swap_loop_in_001",
        swap_type=SwapType.LOOP_IN,
        amount_sat=100_000,
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
        funder_utxo_txid=MOCK_UTXO_TXID_ALICE,
        funder_utxo_vout=0,
        funder_pubkey_bytes=alice_node.pubkey_bytes,
        swap_amount_sat=100_000,
        swap_redeem_script=swap_script,
    )
    console.print(f"  [dim]L1 Lockup TXID:[/dim] {l1_tx.GetTxid().hex()[:24]}...")

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

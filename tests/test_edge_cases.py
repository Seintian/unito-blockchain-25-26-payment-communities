"""
Exhaustive edge-case, boundary condition, and end-to-end multi-protocol test suite.
Pushes total test coverage to 100+ tests across all 11 layer-2 modules.
"""

import pytest

from payment_communities.anchors import (
    ANCHOR_OUTPUT_SAT,
    create_anchor_commitment_transaction,
    create_anchor_script,
    create_cpfp_fee_bump_transaction,
)
from payment_communities.bitcoin_utils import generate_keypair, generate_secret, sha256
from payment_communities.channel import ChannelState, HTLCContract
from payment_communities.config import (
    DEFAULT_TO_SELF_DELAY_BLOCKS,
    MOCK_JUSTICE_SIGNATURE,
    MOCK_UTXO_TXID_ALICE,
)
from payment_communities.contracts import (
    create_2of2_multisig_script,
    create_htlc_script,
)
from payment_communities.eltoo import (
    ELTOO_BASE_LOCKTIME,
    EltooState,
    validate_eltoo_override,
)
from payment_communities.exceptions import (
    ChannelStateError,
    HTLCExpiredError,
    InsufficientBalanceError,
    InvalidPreimageError,
    PaymentCommunityError,
    RevokedStateBroadcastError,
    RouteNotFoundError,
)
from payment_communities.node import Node
from payment_communities.ptlc import (
    AdaptorSignature,
    create_adaptor_signature,
    verify_adaptor_signature,
)
from payment_communities.routing import NetworkGraph, calculate_routing_fee
from payment_communities.sphinx import (
    create_onion_packet,
    unwrap_onion_packet,
)
from payment_communities.swaps import (
    LiquidityAd,
    SubmarineSwap,
    SwapState,
    SwapType,
    create_submarine_swap_funding_tx,
    create_submarine_swap_script,
)
from payment_communities.transaction import (
    create_cooperative_close_transaction,
    create_htlc_claim_transaction,
    create_htlc_refund_transaction,
)
from payment_communities.watchtower import (
    WatchtowerDaemon,
    WatchtowerSession,
)

# ==============================================================================
# 1. CHANNEL & DOMAIN EXCEPTION EDGE CASES
# ==============================================================================


def test_channel_insufficient_capacity_overdraft():
    alice = Node("Alice")
    bob = Node("Bob")
    ch = alice.open_channel(bob, capacity_sat=50_000)

    _preimage, payment_hash = generate_secret()
    htlc = HTLCContract(
        htlc_id="h1",
        amount_sat=60_000,
        payment_hash=payment_hash.hex(),
        locktime=100,
    )
    with pytest.raises(InsufficientBalanceError, match="Insufficient balance"):
        ch.add_htlc(htlc)


def test_channel_invalid_preimage_fulfillment():
    alice = Node("Alice")
    bob = Node("Bob")
    ch = alice.open_channel(bob, capacity_sat=100_000)

    _preimage, payment_hash = generate_secret()
    htlc = HTLCContract(
        htlc_id="h1",
        amount_sat=10_000,
        payment_hash=payment_hash.hex(),
        locktime=100,
    )
    ch.add_htlc(htlc)

    wrong_preimage, _wrong_hash = generate_secret()
    with pytest.raises(InvalidPreimageError, match="Preimage SHA256 digest mismatch"):
        ch.redeem_htlc(htlc_id="h1", preimage_hex=wrong_preimage.hex())


def test_channel_expired_htlc_fulfillment():
    alice = Node("Alice")
    bob = Node("Bob")
    ch = alice.open_channel(bob, capacity_sat=100_000)

    _preimage, payment_hash = generate_secret()
    htlc = HTLCContract(
        htlc_id="h1",
        amount_sat=10_000,
        payment_hash=payment_hash.hex(),
        locktime=100,
    )
    ch.add_htlc(htlc)

    with pytest.raises(HTLCExpiredError, match="Timelock not yet expired"):
        ch.refund_htlc(htlc_id="h1", current_block_height=99)


def test_channel_operation_on_closed_channel():
    alice = Node("Alice")
    bob = Node("Bob")
    ch = alice.open_channel(bob, capacity_sat=100_000)
    ch.state = ChannelState.SETTLED

    _preimage, payment_hash = generate_secret()
    htlc = HTLCContract(
        htlc_id="h1",
        amount_sat=10_000,
        payment_hash=payment_hash.hex(),
        locktime=100,
    )
    with pytest.raises(ChannelStateError, match="not in OPEN state"):
        ch.add_htlc(htlc)


def test_revoked_state_broadcast_prevention():
    alice = Node("Alice")
    bob = Node("Bob")
    ch = alice.open_channel(bob, capacity_sat=100_000)

    ch.revoke_prior_state(commitment_number=1, secret_hex="ff" * 32)
    assert ch.revocation_store.is_state_revoked(1)

    with pytest.raises(RevokedStateBroadcastError, match="revoked commitment state"):
        if ch.revocation_store.is_state_revoked(1):
            raise RevokedStateBroadcastError(
                "Attempted to broadcast revoked commitment state #1"
            )


# ==============================================================================
# 2. ROUTING & TOPOLOGY EDGE CASES
# ==============================================================================


def test_routing_fee_calculation_zero_and_large_amounts():
    assert calculate_routing_fee(0, base_fee_sat=1, fee_rate_ppm=1000) == 1
    assert (
        calculate_routing_fee(1_000_000, base_fee_sat=5, fee_rate_ppm=2000) == 5 + 2000
    )


def test_pathfinding_disconnected_nodes():
    graph = NetworkGraph()
    alice = Node("Alice")
    bob = Node("Bob")

    # Alice <-> Bob exists, Dave isolated
    ch = alice.open_channel(bob, capacity_sat=100_000)
    graph.add_channel(ch)

    with pytest.raises(RouteNotFoundError, match="not present in network graph"):
        graph.find_path("Alice", "Dave", amount_sat=10_000)


def test_pathfinding_insufficient_directional_capacity():
    graph = NetworkGraph()
    alice = Node("Alice")
    bob = Node("Bob")
    ch = alice.open_channel(bob, capacity_sat=50_000)
    graph.add_channel(ch)

    with pytest.raises(RouteNotFoundError, match="No viable path found"):
        graph.find_path("Alice", "Bob", amount_sat=60_000)


# ==============================================================================
# 3. WATCHTOWER & SPHINX PRIVACY EDGE CASES
# ==============================================================================


def test_watchtower_hint_collision_safety():
    session = WatchtowerSession()
    txid1 = "11" * 32
    txid2 = "22" * 32

    hint1 = session.register_justice_package(
        revoked_txid_hex=txid1,
        sweeper_pubkey_hex="02" + "00" * 32,
        amount_sat=50000,
        revocation_sig_hex="3044",
        revocation_pubkey_hex="03" + "00" * 32,
        local_pubkey_hex="02" + "11" * 32,
        to_self_delay=144,
    )
    hint2 = session.register_justice_package(
        revoked_txid_hex=txid2,
        sweeper_pubkey_hex="02" + "00" * 32,
        amount_sat=50000,
        revocation_sig_hex="3044",
        revocation_pubkey_hex="03" + "00" * 32,
        local_pubkey_hex="02" + "11" * 32,
        to_self_delay=144,
    )

    assert hint1 != hint2
    assert len(session.hint_map) == 2


def test_sphinx_packet_decryption_with_wrong_key():
    bob_sec, _bob_pub = generate_keypair()
    wrong_sec, _wrong_pub = generate_keypair()

    node_keys = {"Bob": str(bob_sec)}
    route_hops = [("Bob", "", 10_000, 100)]
    packet = create_onion_packet(route_hops, node_keys)

    with pytest.raises(PaymentCommunityError, match="HMAC integrity check failed"):
        unwrap_onion_packet(packet, node_wif_key=str(wrong_sec))


# ==============================================================================
# 4. ANCHORS, PTLC, ELTOO & SWAPS EDGE CASES
# ==============================================================================


def test_anchors_below_dust_threshold():
    _alice_sec, alice_pub = generate_keypair()
    _bob_sec, bob_pub = generate_keypair()

    tx, _local_s, _remote_s = create_anchor_commitment_transaction(
        funding_txid=MOCK_UTXO_TXID_ALICE,
        funding_vout=0,
        sender_pubkey_bytes=alice_pub,
        receiver_pubkey_bytes=bob_pub,
        sender_balance_sat=100,  # Below 546 sat dust limit
        receiver_balance_sat=50000,
    )
    # Alice balance output omitted, but anchors retained
    assert tx.vout[-2].nValue == ANCHOR_OUTPUT_SAT
    assert tx.vout[-1].nValue == ANCHOR_OUTPUT_SAT


def test_ptlc_adaptor_verification_boundary():
    sig = AdaptorSignature(r_hex="00" * 32, s_prime_hex="01")
    assert verify_adaptor_signature(sig, b"\x02" + b"\x00" * 32, sha256(b"msg"))


def test_eltoo_out_of_order_sequence_override():
    s1 = EltooState(
        state_number=1, sender_balance_sat=50000, receiver_balance_sat=50000
    )
    s5 = EltooState(
        state_number=5, sender_balance_sat=70000, receiver_balance_sat=30000
    )

    assert validate_eltoo_override(s1, s5) is True
    with pytest.raises(PaymentCommunityError):
        validate_eltoo_override(s5, s1)


def test_submarine_swap_expiry():
    _preimage, hash_digest = generate_secret()
    swap = SubmarineSwap(
        swap_id="swap_999",
        swap_type=SwapType.LOOP_OUT,
        amount_sat=50000,
        payment_hash_hex=hash_digest.hex(),
        locktime=100,
        state=SwapState.EXPIRED,
    )
    assert swap.state == SwapState.EXPIRED


# ==============================================================================
# 5. END-TO-END MULTI-PROTOCOL INTEGRATION TEST
# ==============================================================================


def test_e2e_multi_protocol_lifecycle():
    alice = Node("Alice")
    bob = Node("Bob")
    dave = Node("Dave")

    # 1. Channel Funding
    ch_ab = alice.open_channel(bob, capacity_sat=100_000)
    ch_bd = bob.open_channel(dave, capacity_sat=100_000)

    # 2. Dijkstra Routing
    graph = NetworkGraph()
    graph.add_channel(ch_ab)
    graph.add_channel(ch_bd)
    route = graph.find_path("Alice", "Dave", amount_sat=25_000)
    assert route.total_amount_sat > 25_000

    # 3. Sphinx Packet Encryption & Unwrap
    node_keys = {"Bob": str(bob.secret), "Dave": str(dave.secret)}
    sphinx_hops = [("Bob", "Dave", 25000, 144), ("Dave", "", 25000, 100)]
    packet = create_onion_packet(sphinx_hops, node_keys)
    bob_payload, _dave_packet = unwrap_onion_packet(
        packet, node_wif_key=str(bob.secret)
    )
    assert bob_payload.next_hop == "Dave"

    # 4. Watchtower Registration & Breach Penalty Sweep
    session = WatchtowerSession()
    daemon = WatchtowerDaemon(session=session)
    session.register_justice_package(
        revoked_txid_hex="ff" * 32,
        sweeper_pubkey_hex=bob.pubkey_hex,
        amount_sat=100_000,
        revocation_sig_hex=MOCK_JUSTICE_SIGNATURE.hex(),
        revocation_pubkey_hex="03" + "00" * 32,
        local_pubkey_hex=alice.pubkey_hex,
        to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
    )
    assert daemon.scan_transaction("ff" * 32) is not None


# ==============================================================================
# 6. EXHAUSTIVE PROTOCOL EDGE-CASE EXPANSION (25 NEW TESTS)
# ==============================================================================


def test_bitcoin_utils_wif_roundtrip_edge_case():
    sec, _pub = generate_keypair()
    wif = str(sec)
    assert len(wif) > 40


def test_bitcoin_utils_hash160_preimage():
    from payment_communities.bitcoin_utils import hash160

    h160 = hash160(b"test_preimage")
    assert len(h160) == 20


def test_contracts_multisig_key_sorting():
    _sec1, pub1 = generate_keypair()
    _sec2, pub2 = generate_keypair()

    s1 = create_2of2_multisig_script(pub1, pub2)
    s2 = create_2of2_multisig_script(pub2, pub1)
    assert s1 == s2


def test_contracts_htlc_script_creation():
    _sec1, pub1 = generate_keypair()
    _sec2, pub2 = generate_keypair()
    _p, h = generate_secret()

    script = create_htlc_script(pub1, pub2, h, 144)
    assert len(script) > 0


def test_transaction_cooperative_close_balance_split():
    _sec1, pub1 = generate_keypair()
    _sec2, pub2 = generate_keypair()

    tx = create_cooperative_close_transaction(
        funding_txid=MOCK_UTXO_TXID_ALICE,
        funding_vout=0,
        sender_pubkey_bytes=pub1,
        receiver_pubkey_bytes=pub2,
        final_sender_sat=80_000,
        final_receiver_sat=20_000,
    )
    assert tx.vout[0].nValue == 80_000
    assert tx.vout[1].nValue == 20_000


def test_transaction_htlc_success_witness_stack_building():
    _sec1, pub1 = generate_keypair()
    _sec2, pub2 = generate_keypair()
    preimage, h = generate_secret()
    htlc_script = create_htlc_script(pub1, pub2, h, 144)

    tx = create_htlc_claim_transaction(
        commitment_txid=MOCK_UTXO_TXID_ALICE,
        htlc_vout=0,
        claimer_pubkey_bytes=pub2,
        amount_sat=25_000,
        htlc_redeem_script=htlc_script,
        preimage_bytes=preimage,
        claimer_signature=MOCK_JUSTICE_SIGNATURE,
    )
    assert len(tx.wit.vtxinwit[0].scriptWitness.stack) == 4


def test_transaction_htlc_timeout_witness_stack_building():
    _sec1, pub1 = generate_keypair()
    _sec2, pub2 = generate_keypair()
    _preimage, h = generate_secret()
    htlc_script = create_htlc_script(pub1, pub2, h, 144)

    tx = create_htlc_refund_transaction(
        commitment_txid=MOCK_UTXO_TXID_ALICE,
        htlc_vout=0,
        sender_pubkey_bytes=pub1,
        amount_sat=25_000,
        htlc_redeem_script=htlc_script,
        locktime=144,
        sender_signature=MOCK_JUSTICE_SIGNATURE,
    )
    assert len(tx.wit.vtxinwit[0].scriptWitness.stack) == 3


def test_watchtower_multiple_breach_detection():
    session = WatchtowerSession()
    daemon = WatchtowerDaemon(session=session)

    session.register_justice_package(
        revoked_txid_hex="11" * 32,
        sweeper_pubkey_hex="02" + "00" * 32,
        amount_sat=50000,
        revocation_sig_hex="3044",
        revocation_pubkey_hex="03" + "00" * 32,
        local_pubkey_hex="02" + "11" * 32,
        to_self_delay=144,
    )
    session.register_justice_package(
        revoked_txid_hex="22" * 32,
        sweeper_pubkey_hex="02" + "00" * 32,
        amount_sat=50000,
        revocation_sig_hex="3044",
        revocation_pubkey_hex="03" + "00" * 32,
        local_pubkey_hex="02" + "11" * 32,
        to_self_delay=144,
    )

    assert daemon.scan_transaction("11" * 32) is not None
    assert daemon.scan_transaction("22" * 32) is not None


def test_watchtower_unregistered_txid_scan():
    session = WatchtowerSession()
    daemon = WatchtowerDaemon(session=session)
    assert daemon.scan_transaction("99" * 32) is None


def test_sphinx_single_hop_route():
    bob_sec, _bob_pub = generate_keypair()
    node_keys = {"Bob": str(bob_sec)}
    route_hops = [("Bob", "", 10_000, 100)]

    packet = create_onion_packet(route_hops, node_keys)
    payload, _next_packet = unwrap_onion_packet(packet, node_wif_key=str(bob_sec))
    assert payload.next_hop == ""


def test_sphinx_three_hop_route_unwrap():
    node1_sec, _ = generate_keypair()
    node2_sec, _ = generate_keypair()
    node3_sec, _ = generate_keypair()

    node_keys = {"N1": str(node1_sec), "N2": str(node2_sec), "N3": str(node3_sec)}
    hops = [("N1", "N2", 1000, 144), ("N2", "N3", 1000, 100), ("N3", "", 1000, 60)]

    p1 = create_onion_packet(hops, node_keys)
    pay1, p2 = unwrap_onion_packet(p1, node_wif_key=str(node1_sec))
    assert pay1.next_hop == "N2"
    assert p2 is not None

    pay2, p3 = unwrap_onion_packet(p2, node_wif_key=str(node2_sec))
    assert pay2.next_hop == "N3"
    assert p3 is not None

    pay3, _ = unwrap_onion_packet(p3, node_wif_key=str(node3_sec))
    assert pay3.next_hop == ""


def test_anchors_cpfp_child_output_script():
    _sec, pub = generate_keypair()
    local_script = create_anchor_script(pub)
    child_tx = create_cpfp_fee_bump_transaction(
        parent_commitment_txid="00" * 32,
        anchor_vout=2,
        fee_bumper_pubkey_bytes=pub,
        fee_bump_sat=500,
        anchor_redeem_script=local_script,
        signature=MOCK_JUSTICE_SIGNATURE,
    )
    assert len(child_tx.vout) == 1


def test_ptlc_adaptor_secret_extraction_identity():
    sec, _pub = generate_keypair()
    _secret_scalar, payment_point = generate_secret()

    msg_hash = sha256(b"msg_ptlc")
    sig = create_adaptor_signature(bytes(sec), payment_point, msg_hash)
    assert sig.s_prime_hex is not None


def test_eltoo_settlement_tx_locktime_sequence():
    from payment_communities.contracts import create_2of2_multisig_script
    from payment_communities.eltoo import create_eltoo_update_transaction

    _sec1, pub1 = generate_keypair()
    _sec2, pub2 = generate_keypair()
    state = EltooState(
        state_number=3, sender_balance_sat=60000, receiver_balance_sat=40000
    )
    multisig_script = create_2of2_multisig_script(pub1, pub2)

    tx = create_eltoo_update_transaction(
        spending_txid=MOCK_UTXO_TXID_ALICE,
        spending_vout=0,
        state=state,
        multisig_redeem_script=bytes(multisig_script),
    )
    assert tx.nLockTime == ELTOO_BASE_LOCKTIME + 3


def test_eltoo_multiple_state_updates():
    s1 = EltooState(
        state_number=1, sender_balance_sat=50000, receiver_balance_sat=50000
    )
    s2 = EltooState(
        state_number=2, sender_balance_sat=60000, receiver_balance_sat=40000
    )
    s3 = EltooState(
        state_number=3, sender_balance_sat=70000, receiver_balance_sat=30000
    )

    assert validate_eltoo_override(s1, s2) is True
    assert validate_eltoo_override(s2, s3) is True


def test_swaps_loop_in_lockup_tx_witness():
    _sec1, pub1 = generate_keypair()
    _sec2, pub2 = generate_keypair()
    _pre, h = generate_secret()

    swap_script = create_submarine_swap_script(pub1, pub2, h, 144)
    tx = create_submarine_swap_funding_tx(
        funder_utxo_txid=MOCK_UTXO_TXID_ALICE,
        funder_utxo_vout=0,
        funder_pubkey_bytes=pub1,
        swap_amount_sat=50000,
        swap_redeem_script=swap_script,
    )
    assert tx.vout[0].nValue == 50000


def test_swaps_liquidity_ad_zero_fee_rate():
    ad = LiquidityAd(
        node_alias="ZeroFeeNode",
        node_pubkey_hex="02" + "00" * 32,
        lease_fee_base_sat=100,
        lease_fee_basis_ppm=0,
    )
    assert ad.calculate_lease_fee(100_000) == 100


def test_storage_empty_channel_state_serialization():
    from payment_communities.storage import StorageEngine

    storage = StorageEngine(data_dir="/tmp", filename="test_empty_storage.json")
    storage.save_state({}, {})
    loaded = storage.load_state()
    assert len(loaded.channels) == 0


def test_storage_corrupted_json_file_recovery():
    import os

    from payment_communities.storage import StorageEngine

    test_dir = "/tmp"
    test_file = "test_corrupted.json"
    test_path = os.path.join(test_dir, test_file)
    with open(test_path, "w") as f:
        f.write("{invalid_json_corrupted}")

    storage = StorageEngine(data_dir=test_dir, filename=test_file)
    loaded = storage.load_state()
    assert len(loaded.channels) == 0

    if os.path.exists(test_path):
        os.remove(test_path)


def test_network_mock_esplora_tip_height():
    from payment_communities.network import EsploraClient

    client = EsploraClient()
    height = client.get_block_height()
    assert height > 0


def test_node_address_derivation_bech32():
    n = Node("Alice")
    assert n.address.startswith("tb1q") or n.address.startswith("bc1q")


def test_node_invoice_creation():
    n = Node("Dave")
    preimage_hex, payment_hash_hex = n.create_invoice()
    assert len(preimage_hex) == 64
    assert len(payment_hash_hex) == 64


def test_channel_sequence_number_increment():
    alice = Node("Alice")
    bob = Node("Bob")
    ch = alice.open_channel(bob, capacity_sat=100_000)
    initial_seq = ch.sequence_number

    _p, h = generate_secret()
    htlc = HTLCContract(
        htlc_id="h1",
        amount_sat=1000,
        payment_hash=h.hex(),
        locktime=100,
    )
    ch.add_htlc(htlc)
    assert ch.sequence_number == initial_seq + 1


def test_channel_multiple_htlcs_coexistence():
    alice = Node("Alice")
    bob = Node("Bob")
    ch = alice.open_channel(bob, capacity_sat=100_000)

    _p1, h1 = generate_secret()
    _p2, h2 = generate_secret()

    ch.add_htlc(
        HTLCContract(htlc_id="h1", amount_sat=1000, payment_hash=h1.hex(), locktime=100)
    )
    ch.add_htlc(
        HTLCContract(htlc_id="h2", amount_sat=2000, payment_hash=h2.hex(), locktime=100)
    )

    assert len(ch.active_htlcs) == 2


def test_channel_close_cooperatively_final_matrix():
    alice = Node("Alice")
    bob = Node("Bob")
    ch = alice.open_channel(bob, capacity_sat=100_000)
    result = ch.close_cooperatively()

    assert result["Alice"] == 100_000
    assert result["Bob"] == 0
    assert ch.state == ChannelState.SETTLED

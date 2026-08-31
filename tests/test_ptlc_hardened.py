"""
Hardened Point Time-Locked Contract (PTLC) & Schnorr Adaptor Signature Test Suite.
Verifies mathematical soundness of adaptor generation, adaptation, secret extraction,
Schnorr signature verification against public keys, scriptPubKey derivation, and settlement transaction.
"""

from payment_communities.bitcoin.utils import (
    ec_point_mul,
    generate_keypair,
    hash160,
    sha256,
)
from payment_communities.config import SECP256K1_ORDER
from payment_communities.protocols.ptlc import (
    adapt_signature,
    create_adaptor_signature,
    create_ptlc_settlement_transaction,
    extract_adaptor_secret,
    verify_adaptor_signature,
    verify_schnorr_signature,
)


class TestPTLCHardened:
    """Hardened test suite for Schnorr adaptor signatures and PTLC contracts."""

    def test_end_to_end_schnorr_adaptor_signature_and_extraction(self):
        """Validates the mathematical lifecycle of Schnorr Adaptor Signatures."""
        # 1. Signer (Alice) keypair: p, P = p * G
        sec_alice, pub_alice = generate_keypair()
        priv_scalar_alice = (
            int.from_bytes(bytes(sec_alice)[:32], "big") % SECP256K1_ORDER
        )

        # 2. Payment Secret (Bob) scalar: t, T = t * G
        adaptor_secret_scalar = 0x99887766554433221100FFEE % SECP256K1_ORDER
        payment_point = ec_point_mul(adaptor_secret_scalar)

        # 3. Message digest
        msg_hash = sha256(b"PTLC multi-hop settlement transaction payload #42")

        # 4. Alice creates adaptor signature (R', s')
        adaptor_sig = create_adaptor_signature(
            priv_scalar_alice, payment_point, msg_hash
        )

        # 5. Bob verifies the adaptor signature against Alice's pubkey and payment point
        assert (
            verify_adaptor_signature(adaptor_sig, pub_alice, msg_hash, payment_point)
            is True
        )

        # 6. Bob completes (adapts) the signature using secret scalar t: s = (s' + t) mod N
        completed_sig = adapt_signature(adaptor_sig, adaptor_secret_scalar)

        # 7. Consensus verification: verify Schnorr signature on-chain against Alice's pubkey
        assert (
            verify_schnorr_signature(
                pub_alice, msg_hash, adaptor_sig.r_prime, completed_sig
            )
            is True
        )

        # 8. Alice extracts the adaptor secret scalar from completed signature: t = (s - s') mod N
        extracted_secret = extract_adaptor_secret(completed_sig, adaptor_sig.s_prime)
        assert extracted_secret == adaptor_secret_scalar.to_bytes(32, "big")

    def test_forged_adaptor_signature_rejected(self):
        """Forged or corrupted adaptor signature fails verify_adaptor_signature."""
        sec_alice, pub_alice = generate_keypair()
        priv_alice = int.from_bytes(bytes(sec_alice)[:32], "big") % SECP256K1_ORDER
        t = 0x123456789ABCDEF % SECP256K1_ORDER
        T = ec_point_mul(t)
        msg_hash = sha256(b"Valid Message")

        adaptor_sig = create_adaptor_signature(priv_alice, T, msg_hash)

        # Corrupt s_prime
        from payment_communities.protocols.ptlc import AdaptorSignature

        bad_sig = AdaptorSignature(
            r_hex=adaptor_sig.r_hex,
            s_prime_hex=((adaptor_sig.s_prime + 1) % SECP256K1_ORDER)
            .to_bytes(32, "big")
            .hex(),
            payment_point_hex=T.hex(),
        )
        assert verify_adaptor_signature(bad_sig, pub_alice, msg_hash, T) is False

        # Wrong message hash
        wrong_msg = sha256(b"Tampered Message")
        assert verify_adaptor_signature(adaptor_sig, pub_alice, wrong_msg, T) is False

        # Wrong pubkey
        _sec_eve, pub_eve = generate_keypair()
        assert verify_adaptor_signature(adaptor_sig, pub_eve, msg_hash, T) is False

    def test_ptlc_settlement_tx_p2wpkh_scriptpubkey(self):
        """PTLC settlement transaction outputs valid SegWit v0 P2WPKH scriptPubKey (OP_0 <20-byte hash160>)."""
        _sec_claimer, pub_claimer = generate_keypair()
        tx = create_ptlc_settlement_transaction(
            funding_txid="aa" * 32,
            funding_vout=0,
            amount_sat=75_000,
            claimer_pubkey_bytes=pub_claimer,
        )

        assert len(tx.vout) == 1
        assert tx.vout[0].nValue == 75_000
        spk_ops = list(tx.vout[0].scriptPubKey)
        assert len(spk_ops) == 2
        assert spk_ops[0] == 0
        assert len(bytes(spk_ops[1])) == 20
        assert spk_ops[1] == hash160(pub_claimer)

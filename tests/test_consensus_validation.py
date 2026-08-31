"""
Consensus Script Verification Test Suite for Bitcoin Layer 1 and Layer 2 Transactions.
Uses python-bitcoinlib Bitcoin Core CScript execution engine (VerifyScript) to validate
real SegWit V0 witness scripts and spending conditions across all channel lifecycle paths.
"""

import pytest
from bitcoin.core.script import (
    SIGHASH_ALL,
    SIGVERSION_WITNESS_V0,
    SignatureHash,
)
from bitcoin.wallet import CBitcoinSecret

from payment_communities.bitcoin.contracts import (
    ScriptFactory,
    build_multisig_witness,
    create_2of2_multisig_script,
    create_htlc_script,
    create_p2wsh_scriptPubKey,
)
from payment_communities.bitcoin.transaction import (
    TransactionBuilder,
    create_cooperative_close_transaction,
    create_htlc_claim_transaction,
    create_htlc_refund_transaction,
    verify_transaction_witness,
)
from payment_communities.bitcoin.utils import (
    derive_revocation_privkey,
    derive_revocation_pubkey,
    generate_keypair,
    generate_secret,
    sign_sighash,
)
from payment_communities.config import (
    BITCOIN_ANCHOR_OUTPUT_SAT,
    DEFAULT_TO_SELF_DELAY_BLOCKS,
)
from payment_communities.exceptions import ScriptVerificationError
from payment_communities.protocols.anchors import (
    create_anchor_script,
    create_cpfp_fee_bump_transaction,
)
from payment_communities.protocols.revocation import (
    create_breach_remedy_transaction,
    create_revocable_output_script,
    generate_revocation_secret,
)


class TestConsensusScriptVerification:
    """Verifies all transaction spending scripts against Bitcoin Core consensus rules."""

    def test_multisig_cooperative_close_consensus_success(self):
        """2-of-2 multisig funding output spent by signed cooperative close transaction."""
        sec1, pub1 = generate_keypair()
        sec2, pub2 = generate_keypair()
        multisig_script = create_2of2_multisig_script(pub1, pub2)
        p2wsh_spk = create_p2wsh_scriptPubKey(multisig_script)

        funding_amount = 100_000
        alice_sat = 70_000
        bob_sat = 30_000

        close_tx = create_cooperative_close_transaction(
            funding_txid="11" * 32,
            funding_vout=0,
            sender_pubkey_bytes=pub1,
            receiver_pubkey_bytes=pub2,
            final_sender_sat=alice_sat,
            final_receiver_sat=bob_sat,
        )

        sighash = SignatureHash(
            multisig_script,
            close_tx,
            0,
            SIGHASH_ALL,
            amount=funding_amount,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        sig1 = sign_sighash(sec1, sighash)
        sig2 = sign_sighash(sec2, sighash)

        signed_close_tx = create_cooperative_close_transaction(
            funding_txid="11" * 32,
            funding_vout=0,
            sender_pubkey_bytes=pub1,
            receiver_pubkey_bytes=pub2,
            final_sender_sat=alice_sat,
            final_receiver_sat=bob_sat,
            sig_sender=sig1,
            sig_receiver=sig2,
            redeem_script=multisig_script,
        )

        # Bitcoin Core consensus verification
        assert verify_transaction_witness(signed_close_tx, 0, p2wsh_spk, funding_amount)

    def test_multisig_cooperative_close_invalid_signature_fails(self):
        """2-of-2 multisig with forged/wrong signature fails VerifyScript."""
        sec1, pub1 = generate_keypair()
        _sec2, pub2 = generate_keypair()
        sec_wrong, _ = generate_keypair()

        multisig_script = create_2of2_multisig_script(pub1, pub2)
        p2wsh_spk = create_p2wsh_scriptPubKey(multisig_script)
        funding_amount = 100_000

        close_tx = create_cooperative_close_transaction(
            funding_txid="11" * 32,
            funding_vout=0,
            sender_pubkey_bytes=pub1,
            receiver_pubkey_bytes=pub2,
            final_sender_sat=70_000,
            final_receiver_sat=30_000,
        )

        sighash = SignatureHash(
            multisig_script,
            close_tx,
            0,
            SIGHASH_ALL,
            amount=funding_amount,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        sig1 = sign_sighash(sec1, sighash)
        bad_sig2 = sign_sighash(sec_wrong, sighash)  # Invalid key signature

        witness = build_multisig_witness(sig1, bad_sig2, multisig_script)
        bad_close_tx = (
            TransactionBuilder()
            .add_input("11" * 32, 0)
            .add_p2wpkh_output(70_000, pub1)
            .add_p2wpkh_output(30_000, pub2)
            .add_witness_stack(witness)
            .build()
        )

        with pytest.raises(ScriptVerificationError):
            verify_transaction_witness(bad_close_tx, 0, p2wsh_spk, funding_amount)

    def test_htlc_claim_with_preimage_consensus_success(self):
        """HTLC claim output spent using secret preimage and receiver signature."""
        _sec_sender, pub_sender = generate_keypair()
        sec_receiver, pub_receiver = generate_keypair()
        preimage, payment_hash = generate_secret()
        locktime = 144
        amount_sat = 50_000

        htlc_script = create_htlc_script(
            pub_sender, pub_receiver, payment_hash, locktime
        )
        htlc_spk = create_p2wsh_scriptPubKey(htlc_script)

        claim_tx = create_htlc_claim_transaction(
            commitment_txid="22" * 32,
            htlc_vout=0,
            claimer_pubkey_bytes=pub_receiver,
            amount_sat=amount_sat,
            htlc_redeem_script=htlc_script,
            preimage_bytes=preimage,
            claimer_signature=b"\x00" * 70,
        )

        sighash = SignatureHash(
            htlc_script,
            claim_tx,
            0,
            SIGHASH_ALL,
            amount=amount_sat,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        sig_receiver = sign_sighash(sec_receiver, sighash)

        signed_claim_tx = create_htlc_claim_transaction(
            commitment_txid="22" * 32,
            htlc_vout=0,
            claimer_pubkey_bytes=pub_receiver,
            amount_sat=amount_sat,
            htlc_redeem_script=htlc_script,
            preimage_bytes=preimage,
            claimer_signature=sig_receiver,
        )

        assert verify_transaction_witness(signed_claim_tx, 0, htlc_spk, amount_sat)

    def test_htlc_claim_with_invalid_preimage_fails(self):
        """HTLC claim fails VerifyScript when wrong preimage is provided."""
        _sec_sender, pub_sender = generate_keypair()
        sec_receiver, pub_receiver = generate_keypair()
        _preimage, payment_hash = generate_secret()
        wrong_preimage, _ = generate_secret()
        amount_sat = 50_000

        htlc_script = create_htlc_script(pub_sender, pub_receiver, payment_hash, 144)
        htlc_spk = create_p2wsh_scriptPubKey(htlc_script)

        dummy_tx = create_htlc_claim_transaction(
            commitment_txid="22" * 32,
            htlc_vout=0,
            claimer_pubkey_bytes=pub_receiver,
            amount_sat=amount_sat,
            htlc_redeem_script=htlc_script,
            preimage_bytes=wrong_preimage,
            claimer_signature=b"\x00" * 70,
        )
        sighash = SignatureHash(
            htlc_script,
            dummy_tx,
            0,
            SIGHASH_ALL,
            amount=amount_sat,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        sig = sign_sighash(sec_receiver, sighash)

        bad_claim_tx = create_htlc_claim_transaction(
            commitment_txid="22" * 32,
            htlc_vout=0,
            claimer_pubkey_bytes=pub_receiver,
            amount_sat=amount_sat,
            htlc_redeem_script=htlc_script,
            preimage_bytes=wrong_preimage,
            claimer_signature=sig,
        )

        with pytest.raises(ScriptVerificationError):
            verify_transaction_witness(bad_claim_tx, 0, htlc_spk, amount_sat)

    def test_htlc_refund_timeout_consensus_success(self):
        """HTLC refund output spent by sender when locktime is met."""
        sec_sender, pub_sender = generate_keypair()
        _sec_receiver, pub_receiver = generate_keypair()
        _preimage, payment_hash = generate_secret()
        locktime = 144
        amount_sat = 50_000

        htlc_script = create_htlc_script(
            pub_sender, pub_receiver, payment_hash, locktime
        )
        htlc_spk = create_p2wsh_scriptPubKey(htlc_script)

        refund_tx = create_htlc_refund_transaction(
            commitment_txid="33" * 32,
            htlc_vout=0,
            sender_pubkey_bytes=pub_sender,
            amount_sat=amount_sat,
            htlc_redeem_script=htlc_script,
            locktime=locktime,
            sender_signature=b"\x00" * 70,
        )

        sighash = SignatureHash(
            htlc_script,
            refund_tx,
            0,
            SIGHASH_ALL,
            amount=amount_sat,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        sig_sender = sign_sighash(sec_sender, sighash)

        signed_refund_tx = create_htlc_refund_transaction(
            commitment_txid="33" * 32,
            htlc_vout=0,
            sender_pubkey_bytes=pub_sender,
            amount_sat=amount_sat,
            htlc_redeem_script=htlc_script,
            locktime=locktime,
            sender_signature=sig_sender,
        )

        assert verify_transaction_witness(signed_refund_tx, 0, htlc_spk, amount_sat)

    def test_poon_dryja_breach_remedy_consensus_success(self):
        """Poon-Dryja breach remedy spends revoked commitment output with derived revocation key."""
        _sec_alice, pub_alice = generate_keypair()
        sec_bob, pub_bob = generate_keypair()

        rev_secret_bytes, per_commit_point = generate_revocation_secret()
        revocation_pubkey = derive_revocation_pubkey(pub_bob, per_commit_point)

        revocable_script = create_revocable_output_script(
            revocation_pubkey=revocation_pubkey,
            local_pubkey=pub_alice,
            to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
        )
        script_pub_key = ScriptFactory.create_p2wsh(revocable_script)
        channel_capacity = 100_000

        rev_priv_bytes = derive_revocation_privkey(
            bytes(sec_bob)[:32], rev_secret_bytes
        )
        rev_secret_obj = CBitcoinSecret.from_secret_bytes(rev_priv_bytes)

        dummy_rev_tx = create_breach_remedy_transaction(
            revoked_txid="44" * 32,
            revoked_vout=0,
            sweeper_pubkey_bytes=pub_bob,
            amount_sat=channel_capacity,
            revocation_secret_signature=b"\x00" * 70,
            revocable_redeem_script=revocable_script,
        )
        sighash = SignatureHash(
            revocable_script,
            dummy_rev_tx,
            0,
            SIGHASH_ALL,
            amount=channel_capacity,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        real_justice_sig = sign_sighash(rev_secret_obj, sighash)

        justice_tx = create_breach_remedy_transaction(
            revoked_txid="44" * 32,
            revoked_vout=0,
            sweeper_pubkey_bytes=pub_bob,
            amount_sat=channel_capacity,
            revocation_secret_signature=real_justice_sig,
            revocable_redeem_script=revocable_script,
        )

        assert verify_transaction_witness(
            justice_tx, 0, script_pub_key, channel_capacity
        )

    def test_anchor_output_spend_consensus_success(self):
        """Anchor output (330 sat) spent by owner via 1-CSV script."""
        sec_alice, pub_alice = generate_keypair()
        anchor_script = create_anchor_script(pub_alice)
        anchor_spk = ScriptFactory.create_p2wsh(anchor_script)

        dummy_child_tx = create_cpfp_fee_bump_transaction(
            parent_commitment_txid="55" * 32,
            anchor_vout=2,
            fee_bumper_pubkey_bytes=pub_alice,
            fee_bump_sat=100,
            anchor_redeem_script=anchor_script,
            signature=b"\x00" * 70,
        )
        cpfp_sighash = SignatureHash(
            anchor_script,
            dummy_child_tx,
            0,
            SIGHASH_ALL,
            amount=BITCOIN_ANCHOR_OUTPUT_SAT,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        real_cpfp_sig = sign_sighash(sec_alice, cpfp_sighash)

        child_tx = create_cpfp_fee_bump_transaction(
            parent_commitment_txid="55" * 32,
            anchor_vout=2,
            fee_bumper_pubkey_bytes=pub_alice,
            fee_bump_sat=100,
            anchor_redeem_script=anchor_script,
            signature=real_cpfp_sig,
        )

        assert verify_transaction_witness(
            child_tx, 0, anchor_spk, BITCOIN_ANCHOR_OUTPUT_SAT
        )

    def test_anchor_cpfp_with_wallet_utxo_consensus_success(self):
        """2-input CPFP fee bumper spending Anchor output and SegWit P2WPKH wallet UTXO."""
        sec_alice, pub_alice = generate_keypair()
        anchor_script = create_anchor_script(pub_alice)
        anchor_spk = ScriptFactory.create_p2wsh(anchor_script)
        wallet_funding_sat = 20_000
        fee_bump_sat = 1_500

        dummy_tx = create_cpfp_fee_bump_transaction(
            parent_commitment_txid="66" * 32,
            anchor_vout=2,
            fee_bumper_pubkey_bytes=pub_alice,
            fee_bump_sat=fee_bump_sat,
            anchor_redeem_script=anchor_script,
            signature=b"\x00" * 70,
            wallet_utxo_txid="77" * 32,
            wallet_utxo_vout=0,
            wallet_utxo_amount_sat=wallet_funding_sat,
            wallet_signature=b"\x00" * 70,
        )

        # 1. Sign anchor input (input #0)
        sighash_anchor = SignatureHash(
            anchor_script,
            dummy_tx,
            0,
            SIGHASH_ALL,
            amount=BITCOIN_ANCHOR_OUTPUT_SAT,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        sig_anchor = sign_sighash(sec_alice, sighash_anchor)

        # 2. Sign wallet input (input #1)
        wallet_script_code = ScriptFactory.create_p2wpkh_scriptCode(pub_alice)
        sighash_wallet = SignatureHash(
            wallet_script_code,
            dummy_tx,
            1,
            SIGHASH_ALL,
            amount=wallet_funding_sat,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        sig_wallet = sign_sighash(sec_alice, sighash_wallet)

        child_tx = create_cpfp_fee_bump_transaction(
            parent_commitment_txid="66" * 32,
            anchor_vout=2,
            fee_bumper_pubkey_bytes=pub_alice,
            fee_bump_sat=fee_bump_sat,
            anchor_redeem_script=anchor_script,
            signature=sig_anchor,
            wallet_utxo_txid="77" * 32,
            wallet_utxo_vout=0,
            wallet_utxo_amount_sat=wallet_funding_sat,
            wallet_signature=sig_wallet,
        )

        # Verify input #0 (Anchor)
        assert verify_transaction_witness(
            child_tx, 0, anchor_spk, BITCOIN_ANCHOR_OUTPUT_SAT
        )

        # Verify input #1 (Wallet P2WPKH)
        from payment_communities.bitcoin.contracts import create_p2wpkh_scriptPubKey

        wallet_spk = create_p2wpkh_scriptPubKey(pub_alice)
        assert verify_transaction_witness(child_tx, 1, wallet_spk, wallet_funding_sat)

    def test_witness_program_classification_and_errors(self):
        """Tests polymorphic WitnessProgram classification and unsupported pattern handling."""
        from bitcoin.core.script import OP_0, OP_1, CScript

        from payment_communities.bitcoin.interpreter import (
            WitnessProgram,
            WitnessV0KeyHashProgram,
            WitnessV0ScriptHashProgram,
        )

        p2wpkh_spk = CScript([OP_0, b"\x11" * 20])
        prog_wpkh = WitnessProgram.from_script_pub_key(p2wpkh_spk)
        assert isinstance(prog_wpkh, WitnessV0KeyHashProgram)
        assert prog_wpkh.version == 0
        assert prog_wpkh.program == b"\x11" * 20

        p2wsh_spk = CScript([OP_0, b"\x22" * 32])
        prog_wsh = WitnessProgram.from_script_pub_key(p2wsh_spk)
        assert isinstance(prog_wsh, WitnessV0ScriptHashProgram)
        assert prog_wsh.version == 0
        assert prog_wsh.program == b"\x22" * 32

        # Invalid script length
        with pytest.raises(ScriptVerificationError):
            WitnessProgram.from_script_pub_key(CScript([OP_0]))

        # Unsupported version / length
        with pytest.raises(ScriptVerificationError):
            WitnessProgram.from_script_pub_key(CScript([OP_1, b"\x33" * 20]))

    def test_script_interpreter_branching_and_hashing(self):
        """Tests ScriptInterpreter execution of conditional branches and hash checks."""
        from bitcoin.core import CMutableTransaction, CMutableTxIn
        from bitcoin.core.script import (
            OP_0,
            OP_DROP,
            OP_DUP,
            OP_ELSE,
            OP_ENDIF,
            OP_EQUALVERIFY,
            OP_IF,
            OP_SHA256,
            CScript,
        )

        from payment_communities.bitcoin.interpreter import ScriptInterpreter
        from payment_communities.bitcoin.utils import sha256

        preimage = b"secret_preimage_value"
        target_hash = sha256(preimage)

        script = CScript(
            [
                OP_IF,
                OP_DUP,
                OP_SHA256,
                target_hash,
                OP_EQUALVERIFY,
                OP_ELSE,
                OP_DROP,
                OP_0,
                OP_ENDIF,
            ]
        )

        dummy_tx = CMutableTransaction(
            vin=[CMutableTxIn(nSequence=0)],
            vout=[],
        )

        # Successful branch with preimage and condition = 1
        interpreter_true = ScriptInterpreter(
            witness_script=script,
            tx=dummy_tx,
            input_index=0,
            amount_sat=10_000,
            initial_stack=[preimage, b"\x01"],
        )
        assert interpreter_true.execute() is True

        # Unbalanced script error
        unbalanced_script = CScript([OP_IF, OP_0])
        interpreter_err = ScriptInterpreter(
            witness_script=unbalanced_script,
            tx=dummy_tx,
            input_index=0,
            amount_sat=10_000,
            initial_stack=[b"\x01"],
        )
        with pytest.raises(ScriptVerificationError):
            interpreter_err.execute()

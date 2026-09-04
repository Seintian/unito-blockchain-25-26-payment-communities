"""
Bitcoin Assembly Script Factory & Witness Stack Builder Engine:
- 2-of-2 Multisig Funding Script (P2WSH)
- Hashed Time-Locked Contract (HTLC) Script (P2WSH)
- Witness Stack Builders for Spending HTLCs and Funding Outputs
"""

from typing import Any, cast

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import (
    OP_0,
    OP_2,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKSIG,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_IF,
    OP_SHA256,
    CScript,
)

from payment_communities.bitcoin.utils import hash160, sha256


class ScriptFactory:
    """
    Factory class producing standardized Bitcoin Assembly scripts and witness stacks.
    """

    @staticmethod
    def create_multisig_2of2(pubkey1: bytes, pubkey2: bytes) -> CScript:
        """
        Creates a 2-of-2 multisig redeem script with lexicographically sorted keys.
        RedeemScript: 2 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG
        """
        sorted_keys = sorted([pubkey1, pubkey2])
        return CScript(
            cast(Any, [OP_2, sorted_keys[0], sorted_keys[1], OP_2, OP_CHECKMULTISIG])
        )

    @staticmethod
    def create_p2wsh(redeem_script: CScript) -> CScript:
        """
        Creates a SegWit v0 P2WSH scriptPubKey.
        Format: OP_0 <32-byte-SHA256(redeem_script)>
        """
        script_hash = sha256(redeem_script)
        return CScript([OP_0, script_hash])

    @staticmethod
    def create_p2wpkh(pubkey_bytes: bytes) -> CScript:
        """
        Creates a SegWit v0 P2WPKH scriptPubKey.
        Format: OP_0 <20-byte-HASH160(pubkey)>
        """
        return CScript([OP_0, hash160(pubkey_bytes)])

    @staticmethod
    def create_p2wpkh_scriptCode(pubkey_bytes: bytes) -> CScript:
        """
        Creates BIP 143 P2WPKH scriptCode: OP_DUP OP_HASH160 <20-byte-hash160> OP_EQUALVERIFY OP_CHECKSIG
        """
        return CScript(
            [OP_DUP, OP_HASH160, hash160(pubkey_bytes), OP_EQUALVERIFY, OP_CHECKSIG]
        )

    @staticmethod
    def create_htlc(
        sender_pubkey: bytes,
        receiver_pubkey: bytes,
        payment_hash: bytes,
        locktime: int,
    ) -> CScript:
        """
        Creates an HTLC redeem script.
        """
        return CScript(
            cast(
                Any,
                [
                    OP_IF,
                    OP_SHA256,
                    payment_hash,
                    OP_EQUALVERIFY,
                    receiver_pubkey,
                    OP_CHECKSIG,
                    OP_ELSE,
                    locktime,
                    OP_CHECKLOCKTIMEVERIFY,
                    OP_DROP,
                    sender_pubkey,
                    OP_CHECKSIG,
                    OP_ENDIF,
                ],
            )
        )

    @staticmethod
    def witness_htlc_fulfill(
        signature: bytes, preimage: bytes, redeem_script: CScript
    ) -> list[bytes]:
        """Constructs witness stack for HTLC preimage claim."""
        return [signature, preimage, b"\x01", bytes(redeem_script)]

    @staticmethod
    def witness_htlc_refund(signature: bytes, redeem_script: CScript) -> list[bytes]:
        """Constructs witness stack for HTLC locktime timeout refund."""
        return [signature, b"", bytes(redeem_script)]

    @staticmethod
    def witness_multisig_2of2(
        sig1: bytes, sig2: bytes, redeem_script: CScript
    ) -> list[bytes]:
        """Constructs witness stack for spending a 2-of-2 multisig P2WSH output (with checkmultisig dummy byte)."""
        return [b"", sig1, sig2, bytes(redeem_script)]

    @staticmethod
    def create_p2tr(output_key_x_only: bytes) -> CScript:
        """
        Creates a BIP 341 Pay-to-Taproot (SegWit v1) scriptPubKey:
        Format: OP_1 <32-byte-X-only-output-key>
        """
        from bitcoin.core.script import OP_1

        if len(output_key_x_only) != 32:
            raise ValueError(
                f"Taproot output key must be 32 bytes X-only, got {len(output_key_x_only)}"
            )
        return CScript([OP_1, output_key_x_only])

    @staticmethod
    def create_second_stage_htlc_script(
        revocation_pubkey: bytes, local_delayed_pubkey: bytes, to_self_delay: int = 144
    ) -> CScript:
        """
        BOLT #3 2nd-stage HTLC Output Script (protecting HTLC-Success / HTLC-Timeout outputs):
        OP_IF
            <revocation_pubkey> OP_CHECKSIG
        OP_ELSE
            <to_self_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
            <local_delayed_pubkey> OP_CHECKSIG
        OP_ENDIF
        """
        from bitcoin.core.script import (
            OP_CHECKSEQUENCEVERIFY,
            OP_CHECKSIG,
            OP_DROP,
            OP_ELSE,
            OP_ENDIF,
            OP_IF,
        )

        return CScript(
            cast(
                Any,
                [
                    OP_IF,
                    revocation_pubkey,
                    OP_CHECKSIG,
                    OP_ELSE,
                    to_self_delay,
                    OP_CHECKSEQUENCEVERIFY,
                    OP_DROP,
                    local_delayed_pubkey,
                    OP_CHECKSIG,
                    OP_ENDIF,
                ],
            )
        )


def create_2of2_multisig_script(pubkey1: bytes, pubkey2: bytes) -> CScript:
    return ScriptFactory.create_multisig_2of2(pubkey1, pubkey2)


def create_p2wsh_scriptPubKey(redeem_script: CScript) -> CScript:
    return ScriptFactory.create_p2wsh(redeem_script)


def create_p2wpkh_scriptPubKey(pubkey_bytes: bytes) -> CScript:
    return ScriptFactory.create_p2wpkh(pubkey_bytes)


def create_p2tr_scriptPubKey(output_key_x_only: bytes) -> CScript:
    return ScriptFactory.create_p2tr(output_key_x_only)


def create_second_stage_htlc_script(
    revocation_pubkey: bytes, local_delayed_pubkey: bytes, to_self_delay: int = 144
) -> CScript:
    return ScriptFactory.create_second_stage_htlc_script(
        revocation_pubkey, local_delayed_pubkey, to_self_delay
    )


def create_htlc_script(
    sender_pubkey: bytes, receiver_pubkey: bytes, payment_hash: bytes, locktime: int
) -> CScript:
    return ScriptFactory.create_htlc(
        sender_pubkey, receiver_pubkey, payment_hash, locktime
    )


def build_htlc_fulfill_witness(
    signature: bytes, preimage: bytes, redeem_script: CScript
) -> list[bytes]:
    return ScriptFactory.witness_htlc_fulfill(signature, preimage, redeem_script)


def build_htlc_refund_witness(signature: bytes, redeem_script: CScript) -> list[bytes]:
    return ScriptFactory.witness_htlc_refund(signature, redeem_script)


def build_multisig_witness(
    sig1: bytes, sig2: bytes, redeem_script: CScript
) -> list[bytes]:
    return ScriptFactory.witness_multisig_2of2(sig1, sig2, redeem_script)


def sign_p2wsh_input(
    tx: CMutableTransaction,
    input_idx: int,
    redeem_script: CScript,
    private_key_wif: str,
    amount_sat: int,
) -> bytes:
    """
    Signs a P2WSH SegWit v0 transaction input with ECDSA SIGHASH_ALL per BIP 143.
    """
    from bitcoin.core.script import SIGHASH_ALL, SIGVERSION_WITNESS_V0, SignatureHash
    from bitcoin.wallet import CBitcoinSecret

    from payment_communities.bitcoin.utils import sign_sighash

    secret = CBitcoinSecret(private_key_wif)
    sighash = SignatureHash(
        redeem_script,
        tx,
        input_idx,
        SIGHASH_ALL,
        amount=amount_sat,
        sigversion=SIGVERSION_WITNESS_V0,
    )
    return sign_sighash(secret, sighash)

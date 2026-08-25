"""
Bitcoin Assembly Script Templates for Payment Communities:
- 2-of-2 Multisig Funding Script (P2WSH)
- Hashed Time-Locked Contract (HTLC) Script (P2WSH)
- Witness Stack Builders for Spending HTLCs and Funding Outputs
"""

from typing import List
from bitcoin.core import b2x
from bitcoin.core.script import (
    CScript, OP_0, OP_1, OP_2, OP_CHECKMULTISIG, OP_SHA256, OP_EQUALVERIFY,
    OP_IF, OP_ELSE, OP_ENDIF, OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_CHECKSIG
)
from bitcoin_utils import sha256

def create_2of2_multisig_script(pubkey1: bytes, pubkey2: bytes) -> CScript:
    """
    Creates a 2-of-2 multisig redeem script.
    RedeemScript: 2 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG
    """
    # Sort public keys lexicographically for deterministic multisig construction
    sorted_keys = sorted([pubkey1, pubkey2])
    return CScript([OP_2, sorted_keys[0], sorted_keys[1], OP_2, OP_CHECKMULTISIG])

def create_p2wsh_scriptPubKey(redeem_script: CScript) -> CScript:
    """
    Creates a SegWit v0 P2WSH scriptPubKey.
    Format: OP_0 <32-byte-SHA256(redeem_script)>
    """
    script_hash = sha256(redeem_script)
    return CScript([OP_0, script_hash])

def create_htlc_script(
    sender_pubkey: bytes,
    receiver_pubkey: bytes,
    payment_hash: bytes,
    locktime: int
) -> CScript:
    """
    Creates an HTLC redeem script.
    
    Redeem Script Logic:
    OP_IF
        OP_SHA256 <payment_hash> OP_EQUALVERIFY <receiver_pubkey> OP_CHECKSIG
    OP_ELSE
        <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <sender_pubkey> OP_CHECKSIG
    OP_ENDIF
    """
    return CScript([
        OP_IF,
            OP_SHA256, payment_hash, OP_EQUALVERIFY, receiver_pubkey, OP_CHECKSIG,
        OP_ELSE,
            locktime, OP_CHECKLOCKTIMEVERIFY, OP_DROP, sender_pubkey, OP_CHECKSIG,
        OP_ENDIF
    ])

def build_htlc_fulfill_witness(signature: bytes, preimage: bytes, redeem_script: CScript) -> List[bytes]:
    """
    Constructs witness stack for redeeming HTLC with secret preimage (Success Branch).
    Witness Stack: [<receiver_sig>, <preimage>, b"\x01", <redeem_script>]
    """
    return [signature, preimage, b"\x01", bytes(redeem_script)]

def build_htlc_refund_witness(signature: bytes, redeem_script: CScript) -> List[bytes]:
    """
    Constructs witness stack for reclaiming HTLC after locktime expiry (Timeout Branch).
    Witness Stack: [<sender_sig>, b"", <redeem_script>]
    """
    return [signature, b"", bytes(redeem_script)]

def build_multisig_witness(sig1: bytes, sig2: bytes, redeem_script: CScript) -> List[bytes]:
    """
    Constructs witness stack for spending a 2-of-2 multisig P2WSH output.
    Witness Stack: [b"", <sig1>, <sig2>, <redeem_script>] (b"" is required for CHECKMULTISIG bug off-by-one)
    """
    return [b"", sig1, sig2, bytes(redeem_script)]

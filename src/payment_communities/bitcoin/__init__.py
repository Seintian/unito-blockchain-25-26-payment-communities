"""
Bitcoin Layer 1 Primitives & Script Engine.
"""

from payment_communities.bitcoin.contracts import (
    ScriptFactory,
    build_htlc_fulfill_witness,
    build_htlc_refund_witness,
    build_multisig_witness,
    create_2of2_multisig_script,
    create_htlc_script,
    create_p2wsh_scriptPubKey,
)
from payment_communities.bitcoin.transaction import (
    TransactionBuilder,
    create_commitment_transaction,
    create_cooperative_close_transaction,
    create_funding_transaction,
    create_htlc_claim_transaction,
    create_htlc_refund_transaction,
    verify_transaction_witness,
)
from payment_communities.bitcoin.utils import (
    bytes_to_hex,
    generate_keypair,
    generate_secret,
    hash160,
    hash256,
    hex_to_bytes,
    pubkey_to_p2pkh_address,
    pubkey_to_p2wpkh_address,
    script_to_p2wsh_address,
    sha256,
)

__all__ = [
    "ScriptFactory",
    "TransactionBuilder",
    "build_htlc_fulfill_witness",
    "build_htlc_refund_witness",
    "build_multisig_witness",
    "bytes_to_hex",
    "create_2of2_multisig_script",
    "create_commitment_transaction",
    "create_cooperative_close_transaction",
    "create_funding_transaction",
    "create_htlc_claim_transaction",
    "create_htlc_refund_transaction",
    "create_htlc_script",
    "create_p2wsh_scriptPubKey",
    "generate_keypair",
    "generate_secret",
    "hash160",
    "hash256",
    "hex_to_bytes",
    "pubkey_to_p2pkh_address",
    "pubkey_to_p2wpkh_address",
    "script_to_p2wsh_address",
    "sha256",
    "verify_transaction_witness",
]

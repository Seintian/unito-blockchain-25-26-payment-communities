"""
Configuration & Protocol Specification Constants for Payment Communities.
Defines network settings, environment variables, and Bitcoin protocol constants.
"""

import os
from typing import Literal, cast

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()

# ==============================================================================
# BITCOIN CONSENSUS & LIGHTNING PROTOCOL CONSTANTS
# ==============================================================================

BITCOIN_DUST_LIMIT_SAT: int = 546
"""
Bitcoin Core Standardness Dust Threshold (in Satoshis).
Any UTXO output below this value is considered unspendable 'dust' because the transaction fee
required to spend it exceeds the output's value under standard relay policy (BIP 141).
In payment channel specifications (BOLT #3), outputs below this limit are omitted from
commitment transactions to prevent relay rejection by Bitcoin nodes.
"""

BITCOIN_ANCHOR_OUTPUT_SAT: int = 330
"""
Standard Anchor Output value in Satoshis (BOLT #3).
330 sat is the exact dust threshold for P2WSH anchor script outputs under standard
Bitcoin Core relay policy, allowing anchor outputs to be spent via Child-Pays-For-Parent (CPFP).
"""

SECRET_KEY_SIZE_BYTES: int = 32
"""
Cryptographic Secret Size (in Bytes).
Standard 256-bit entropy size for private keys, HTLC preimages, and Poon-Dryja revocation secrets.
"""

DEFAULT_TO_SELF_DELAY_BLOCKS: int = 144
"""
Poon-Dryja Relative Timelock Delay (in Block Height Units).
The number of blocks (~24 hours at 10 minutes per block) a channel party must wait before spending
their un-breached balance output via OP_CHECKSEQUENCEVERIFY. This window gives the non-breaching
counterparty sufficient time to detect a cheat attempt and broadcast a Breach Remedy transaction.
"""

DEFAULT_CLTV_DELTA_BLOCKS: int = 40
"""
Multi-Hop HTLC Timelock Staggering Delta (in Block Height Units).
The minimum block height safety margin subtracted per routing hop (T1 > T2 > ... > Tn) to ensure
intermediate nodes have enough time to claim incoming HTLC payments before outgoing HTLC timelocks expire.
"""

MIN_CHANNEL_CAPACITY_SAT: int = 10_000
"""
Minimum Allowed Channel Capacity (10,000 Satoshis).
Enforces economic viability to prevent anti-spam micro-channels whose balances could fall below fee thresholds.
"""

MAX_CHANNEL_CAPACITY_SAT: int = 16_777_216
"""
Maximum Allowed Channel Capacity (2^24 = 16,777,216 Satoshis / ~0.1678 BTC).
Original BOLT #2 specification 'wumbo' channel boundary limit.
"""

ELTOO_BASE_LOCKTIME: int = 500_000_000
"""
Eltoo (LN-Symmetric) Sequence Update Base Locktime Parameter (500,000,000).
Locktime values at or above 500,000,000 represent UNIX timestamps rather than block heights
in Bitcoin transaction header nLockTime field.
"""

SECP256K1_ORDER: int = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)
"""
secp256k1 Elliptic Curve Generator Point Prime Order N.
256-bit prime scalar used for modular arithmetic operations in Schnorr Adaptor Signatures.
"""

WATCHTOWER_HINT_BYTES: int = 16
"""
Watchtower Locator Hint Size (in Bytes).
128-bit / 16-byte hint derived from the first 16 bytes of SHA256(revoked_txid), enabling
watchtowers to index justice blobs without knowing full txids in advance.
"""

AES_GCM_NONCE_BYTES: int = 12
"""Standard AES-256-GCM Initialization Vector / Nonce length (96 bits / 12 bytes)."""

AES_GCM_TAG_BYTES: int = 16
"""Standard AES-256-GCM Authentication Tag length (128 bits / 16 bytes)."""

SPHINX_HEADER_BYTES: int = 32
"""Sphinx Onion Packet Header HMAC Digest Size (in Bytes)."""

DEFAULT_ROUTING_BASE_FEE_SAT: int = 1
"""
Base Routing Fee (in Satoshis).
Fixed fee charged by a routing node per forwarded HTLC regardless of payment size.
"""

DEFAULT_ROUTING_FEE_RATE_PPM: int = 1000
"""
Proportional Routing Fee Rate (in Parts-Per-Million / PPM).
Liquidity fee rate charged per forwarded HTLC (1,000 PPM = 0.10% of payment amount).
"""

PPM_DENOMINATOR: int = 1_000_000
"""
Parts-Per-Million (PPM) Scaling Denominator.
Used to convert PPM fee rates to exact integer satoshi amounts: fee = amount * ppm // 1,000,000.
"""

ESPLORA_DEFAULT_TIMEOUT_SECONDS: float = 5.0
"""HTTP request timeout (in seconds) for standard Esplora API queries."""

ESPLORA_BROADCAST_TIMEOUT_SECONDS: float = 10.0
"""HTTP request timeout (in seconds) for broadcasting raw transaction hexes."""

ESPLORA_FALLBACK_BLOCK_HEIGHT: int = 100_000
"""Fallback simulated block height used when Esplora REST API endpoint is offline or unreachable."""

SEQUENCE_CLTV_ENABLE_MASK: int = 0xFFFFFFFE
"""nSequence transaction input flag enabling OP_CHECKLOCKTIMEVERIFY without activating CSV relative timelocks."""


# ==============================================================================
# DEMO & SIMULATION CONSTANTS
# ==============================================================================

MOCK_UTXO_TXID_ALICE: str = "00" * 32
"""Deterministic simulated funding UTXO transaction ID for Alice."""

MOCK_UTXO_TXID_BOB: str = "11" * 32
"""Deterministic simulated funding UTXO transaction ID for Bob."""

MOCK_UTXO_TXID_REVOKED: str = "aa" * 32
"""Deterministic simulated revoked commitment transaction ID for breach testing."""

MOCK_UTXO_TXID_WATCHTOWER: str = "cc" * 32
"""Deterministic simulated watchtower monitoring transaction ID."""

MOCK_JUSTICE_SIGNATURE: bytes = b"\x30\x44" + b"\x00" * 68
"""Dummy DER-encoded ECDSA signature used for simulated justice sweep verification."""

DEFAULT_SIMULATION_CAPACITY_SAT: int = 100_000
"""Default channel funding capacity in satoshis for interactive demos (100k sat)."""

DEFAULT_SIMULATION_PAYMENT_SAT: int = 25_000
"""Default multi-hop payment routing amount in satoshis (25k sat)."""

DEFAULT_HTLC_LOCKTIME_T1_DELTA: int = 144
"""Primary HTLC timelock block delta (~24 hours)."""

DEFAULT_HTLC_LOCKTIME_T2_DELTA: int = 100
"""Secondary hop HTLC timelock block delta (~16.6 hours)."""

DEFAULT_LEASE_FEE_BASE_SAT: int = 500
"""Base fee in satoshis for leasing inbound channel capacity (BOLT #7 Liquidity Ads)."""

DEFAULT_LEASE_FEE_BASIS_PPM: int = 2000
"""Proportional fee rate in PPM (2,000 PPM = 0.20%) for inbound capacity leasing."""

DEFAULT_LEASE_MAX_CAPACITY_SAT: int = 10_000_000
"""Maximum allowed leased channel capacity in satoshis (0.10 BTC)."""

DEFAULT_FUNDING_WEIGHT: int = 252
"""Standard SegWit 2-of-2 multisig funding output transaction weight in Virtual Bytes (vB)."""


# ==============================================================================
# ENVIRONMENT & NETWORK SETTINGS
# ==============================================================================

NetworkType = Literal["testnet", "signet", "regtest", "mainnet"]


def _get_network() -> NetworkType:
    val = os.getenv("BITCOIN_NETWORK", "signet").lower()
    if val in ("testnet", "signet", "regtest", "mainnet"):
        return cast(NetworkType, val)
    return "signet"


class Settings(BaseModel):
    network: NetworkType = Field(default_factory=_get_network)
    esplora_api_url: str = Field(
        default_factory=lambda: os.getenv(
            "ESPLORA_API_URL", "https://mempool.space/signet/api"
        )
    )
    alice_key: str = Field(default_factory=lambda: os.getenv("ALICE_PRIVATE_KEY", ""))
    bob_key: str = Field(default_factory=lambda: os.getenv("BOB_PRIVATE_KEY", ""))
    dave_key: str = Field(default_factory=lambda: os.getenv("DAVE_PRIVATE_KEY", ""))


settings = Settings()


def init_bitcoin_network():
    """Selects the bitcoinlib network parameters according to configuration."""
    import bitcoin

    net = settings.network.lower()
    if net in ("testnet", "signet"):
        bitcoin.SelectParams("testnet")
    elif net == "regtest":
        bitcoin.SelectParams("regtest")
    elif net == "mainnet":
        bitcoin.SelectParams("mainnet")
    else:
        bitcoin.SelectParams("testnet")

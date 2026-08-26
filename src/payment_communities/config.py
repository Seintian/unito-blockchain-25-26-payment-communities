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

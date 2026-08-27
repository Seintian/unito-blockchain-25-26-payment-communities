"""
Bitcoin Network API Client for Esplora (Mempool.space API).
Provides methods for querying UTXOs, fetching block height, and broadcasting transactions with retry resilience.
"""

from typing import Any

import httpx

from payment_communities.config import (
    ESPLORA_BROADCAST_TIMEOUT_SECONDS,
    ESPLORA_DEFAULT_TIMEOUT_SECONDS,
    settings,
)
from payment_communities.domain.core.decorators import retry
from payment_communities.exceptions import NetworkError


class EsploraClient:
    """HTTP client interacting with Esplora REST API endpoint for Bitcoin Signet/Testnet."""

    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or settings.esplora_api_url).rstrip("/")

    @retry(max_attempts=2, delay_seconds=0.1, exceptions=(httpx.HTTPError,))
    def get_block_height(self) -> int:
        """Fetches current tip block height from network API."""
        endpoint = f"{self.base_url}/blocks/tip/height"
        try:
            with httpx.Client(timeout=ESPLORA_DEFAULT_TIMEOUT_SECONDS) as client:
                res = client.get(endpoint)
                res.raise_for_status()
                return int(res.text.strip())
        except (httpx.HTTPError, httpx.RequestError, ValueError) as e:
            raise NetworkError(
                f"Failed to fetch block height from {endpoint}: {e}",
                context={"endpoint": endpoint, "error": str(e)},
            ) from e

    @retry(max_attempts=2, delay_seconds=0.1, exceptions=(httpx.HTTPError,))
    def get_address_utxos(self, address: str) -> list[dict[str, Any]]:
        """Fetches unspent outputs (UTXOs) for a Bitcoin address."""
        endpoint = f"{self.base_url}/address/{address}/utxo"
        try:
            with httpx.Client(timeout=ESPLORA_DEFAULT_TIMEOUT_SECONDS) as client:
                res = client.get(endpoint)
                res.raise_for_status()
                return res.json()
        except (httpx.HTTPError, httpx.RequestError, ValueError) as e:
            raise NetworkError(
                f"Failed to fetch UTXOs for address {address} from {endpoint}: {e}",
                context={"address": address, "endpoint": endpoint, "error": str(e)},
            ) from e

    @retry(max_attempts=2, delay_seconds=0.1, exceptions=(httpx.HTTPError,))
    def broadcast_tx(self, raw_tx_hex: str) -> str:
        """
        Broadcasting signed raw transaction hex to the Bitcoin network.
        Returns TXID if successful, or raises NetworkError on failure.
        """
        endpoint = f"{self.base_url}/tx"
        try:
            with httpx.Client(timeout=ESPLORA_BROADCAST_TIMEOUT_SECONDS) as client:
                res = client.post(endpoint, content=raw_tx_hex)
                res.raise_for_status()
                return res.text.strip()
        except (httpx.HTTPError, httpx.RequestError, ValueError) as e:
            raise NetworkError(
                f"Failed to broadcast transaction to {endpoint}: {e}",
                context={"endpoint": endpoint, "error": str(e)},
            ) from e

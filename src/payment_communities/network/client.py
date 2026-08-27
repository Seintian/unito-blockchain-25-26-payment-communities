"""
Bitcoin Network API Client for Esplora (Mempool.space API).
Provides methods for querying UTXOs, fetching block height and tip hash, estimating fees,
querying address stats/balances, inspecting transactions, and broadcasting transactions with retry resilience.
"""

from typing import Any

import httpx

from payment_communities.config import (
    DEFAULT_FEE_RATE_SAT_VB,
    ESPLORA_ADDRESS_ENDPOINT,
    ESPLORA_BROADCAST_TIMEOUT_SECONDS,
    ESPLORA_DEFAULT_TIMEOUT_SECONDS,
    ESPLORA_FEE_ESTIMATES_ENDPOINT,
    ESPLORA_TIP_HASH_ENDPOINT,
    ESPLORA_TIP_HEIGHT_ENDPOINT,
    ESPLORA_TX_ENDPOINT,
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
        endpoint = f"{self.base_url}{ESPLORA_TIP_HEIGHT_ENDPOINT}"
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
    def get_tip_hash(self) -> str:
        """Fetches current tip block hash from network API."""
        endpoint = f"{self.base_url}{ESPLORA_TIP_HASH_ENDPOINT}"
        try:
            with httpx.Client(timeout=ESPLORA_DEFAULT_TIMEOUT_SECONDS) as client:
                res = client.get(endpoint)
                res.raise_for_status()
                return res.text.strip()
        except (httpx.HTTPError, httpx.RequestError, ValueError) as e:
            raise NetworkError(
                f"Failed to fetch tip block hash from {endpoint}: {e}",
                context={"endpoint": endpoint, "error": str(e)},
            ) from e

    @retry(max_attempts=2, delay_seconds=0.1, exceptions=(httpx.HTTPError,))
    def get_fee_estimates(self) -> dict[str, float]:
        """
        Fetches current mempool recommended fee estimates by target confirmation blocks.
        Returns a dictionary mapping block targets (e.g. '1', '2', '3', '6') to fee rates in sat/vB.
        """
        endpoint = f"{self.base_url}{ESPLORA_FEE_ESTIMATES_ENDPOINT}"
        try:
            with httpx.Client(timeout=ESPLORA_DEFAULT_TIMEOUT_SECONDS) as client:
                res = client.get(endpoint)
                res.raise_for_status()
                return res.json()
        except (httpx.HTTPError, httpx.RequestError, ValueError) as e:
            raise NetworkError(
                f"Failed to fetch fee estimates from {endpoint}: {e}",
                context={"endpoint": endpoint, "error": str(e)},
            ) from e

    def get_recommended_fee_rate(self, target_blocks: int = 1) -> float:
        """
        Gets recommended fee rate (sat/vB) for a target confirmation block time,
        falling back to default_fee_rate_sat_vb if estimates are unavailable.
        """
        try:
            estimates = self.get_fee_estimates()
            key = str(target_blocks)
            if key in estimates:
                return float(estimates[key])
            # Check closest target key
            int_keys = sorted([int(k) for k in estimates])
            for k in int_keys:
                if k >= target_blocks:
                    return float(estimates[str(k)])
            if int_keys:
                return float(estimates[str(int_keys[-1])])
        except NetworkError, httpx.HTTPError, ValueError, KeyError:
            pass
        return float(settings.default_fee_rate_sat_vb or DEFAULT_FEE_RATE_SAT_VB)

    @retry(max_attempts=2, delay_seconds=0.1, exceptions=(httpx.HTTPError,))
    def get_address_stats(self, address: str) -> dict[str, Any]:
        """Fetches address information including on-chain funded/spent amounts and mempool stats."""
        endpoint = f"{self.base_url}{ESPLORA_ADDRESS_ENDPOINT}/{address}"
        try:
            with httpx.Client(timeout=ESPLORA_DEFAULT_TIMEOUT_SECONDS) as client:
                res = client.get(endpoint)
                res.raise_for_status()
                return res.json()
        except (httpx.HTTPError, httpx.RequestError, ValueError) as e:
            raise NetworkError(
                f"Failed to fetch address stats for {address} from {endpoint}: {e}",
                context={"address": address, "endpoint": endpoint, "error": str(e)},
            ) from e

    def get_address_balance(self, address: str) -> tuple[int, int]:
        """
        Calculates confirmed balance and pending unconfirmed mempool delta for a Bitcoin address.
        Returns:
            (confirmed_balance_sat, unconfirmed_delta_sat)
        """
        data = self.get_address_stats(address)
        chain = data.get("chain_stats", {})
        mempool = data.get("mempool_stats", {})

        confirmed = int(chain.get("funded_txo_sum", 0)) - int(
            chain.get("spent_txo_sum", 0)
        )
        unconfirmed = int(mempool.get("funded_txo_sum", 0)) - int(
            mempool.get("spent_txo_sum", 0)
        )
        return confirmed, unconfirmed

    @retry(max_attempts=2, delay_seconds=0.1, exceptions=(httpx.HTTPError,))
    def get_address_utxos(self, address: str) -> list[dict[str, Any]]:
        """Fetches unspent outputs (UTXOs) for a Bitcoin address."""
        endpoint = f"{self.base_url}{ESPLORA_ADDRESS_ENDPOINT}/{address}/utxo"
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

    def get_utxo_for_node(self, pubkey_bytes: bytes, address: str) -> tuple[str, int]:
        """
        Retrieves a live UTXO for node address from Esplora API if funded on Signet.
        If no live UTXOs exist, derives a deterministic 32-byte TXID from the node's
        compressed public key and the live network tip block hash.
        """
        try:
            utxos = self.get_address_utxos(address)
            if utxos and isinstance(utxos, list) and len(utxos) > 0:
                return str(utxos[0]["txid"]), int(utxos[0].get("vout", 0))
        except NetworkError:
            pass

        try:
            tip_hash_hex = self.get_tip_hash()
            tip_bytes = bytes.fromhex(tip_hash_hex)
        except NetworkError:
            tip_bytes = b"\x00" * 32

        from payment_communities.bitcoin.utils import bytes_to_hex, hash256

        derived_txid_bytes = hash256(pubkey_bytes + tip_bytes)
        return bytes_to_hex(derived_txid_bytes), 0

    @retry(max_attempts=2, delay_seconds=0.1, exceptions=(httpx.HTTPError,))
    def get_tx(self, txid: str) -> dict[str, Any]:
        """Fetches parsed transaction details from the Esplora API."""
        endpoint = f"{self.base_url}{ESPLORA_TX_ENDPOINT}/{txid}"
        try:
            with httpx.Client(timeout=ESPLORA_DEFAULT_TIMEOUT_SECONDS) as client:
                res = client.get(endpoint)
                res.raise_for_status()
                return res.json()
        except (httpx.HTTPError, httpx.RequestError, ValueError) as e:
            raise NetworkError(
                f"Failed to fetch transaction {txid} from {endpoint}: {e}",
                context={"txid": txid, "endpoint": endpoint, "error": str(e)},
            ) from e

    @retry(max_attempts=2, delay_seconds=0.1, exceptions=(httpx.HTTPError,))
    def get_tx_status(self, txid: str) -> dict[str, Any]:
        """Fetches transaction confirmation status (confirmed, block height, block time)."""
        endpoint = f"{self.base_url}{ESPLORA_TX_ENDPOINT}/{txid}/status"
        try:
            with httpx.Client(timeout=ESPLORA_DEFAULT_TIMEOUT_SECONDS) as client:
                res = client.get(endpoint)
                res.raise_for_status()
                return res.json()
        except (httpx.HTTPError, httpx.RequestError, ValueError) as e:
            raise NetworkError(
                f"Failed to fetch transaction status for {txid} from {endpoint}: {e}",
                context={"txid": txid, "endpoint": endpoint, "error": str(e)},
            ) from e

    def is_tx_confirmed(self, txid: str) -> bool:
        """Returns True if the transaction has been confirmed on-chain."""
        status = self.get_tx_status(txid)
        return bool(status.get("confirmed", False))

    @retry(max_attempts=2, delay_seconds=0.1, exceptions=(httpx.HTTPError,))
    def broadcast_tx(self, raw_tx_hex: str) -> str:
        """
        Broadcasting signed raw transaction hex to the Bitcoin network.
        Returns TXID if successful, or raises NetworkError on failure.
        """
        endpoint = f"{self.base_url}{ESPLORA_TX_ENDPOINT}"
        try:
            with httpx.Client(timeout=ESPLORA_BROADCAST_TIMEOUT_SECONDS) as client:
                res = client.post(endpoint, content=raw_tx_hex)
                res.raise_for_status()
                return res.text.strip()
        except (httpx.HTTPError, httpx.RequestError, ValueError) as e:
            err_body = ""
            if isinstance(e, httpx.HTTPStatusError) and e.response is not None:
                err_body = f" - Server details: {e.response.text}"
            raise NetworkError(
                f"Failed to broadcast transaction to {endpoint}: {e}{err_body}",
                context={"endpoint": endpoint, "error": f"{e}{err_body}"},
            ) from e

    def fund_channel_on_chain(
        self,
        funder_secret: Any,
        counterparty_pubkey: bytes,
        capacity_sat: int,
        fee_rate_sat_vb: float = 2.0,
    ) -> tuple[str, int, Any]:
        """
        Queries live UTXOs for funder_secret, constructs a P2WPKH -> 2-of-2 Multisig P2WSH funding transaction,
        signs it with real private keys, broadcasts it via Esplora REST API, and returns (txid_hex, vout, redeem_script).
        """
        from bitcoin.core.script import (
            SIGHASH_ALL,
            SIGVERSION_WITNESS_V0,
            SignatureHash,
        )

        from payment_communities.bitcoin.contracts import ScriptFactory
        from payment_communities.bitcoin.transaction import TransactionBuilder
        from payment_communities.bitcoin.utils import (
            bytes_to_hex,
            pubkey_to_p2wpkh_address,
            sign_sighash,
        )
        from payment_communities.config import (
            BITCOIN_DUST_LIMIT_SAT,
            DEFAULT_FUNDING_TX_VBYTES,
        )

        funder_pubkey = funder_secret.pub
        funder_addr = str(pubkey_to_p2wpkh_address(funder_pubkey))
        utxos = self.get_address_utxos(funder_addr)

        if not utxos:
            raise NetworkError(f"No UTXOs available for funding address {funder_addr}.")

        confirmed_utxos = [
            u for u in utxos if u.get("status", {}).get("confirmed", False)
        ]
        if not confirmed_utxos:
            confirmed_utxos = utxos

        estimated_fee_sat = int(DEFAULT_FUNDING_TX_VBYTES * fee_rate_sat_vb)

        selected_utxos = []
        accumulated = 0
        for utxo in confirmed_utxos:
            selected_utxos.append(utxo)
            accumulated += utxo.get("value", 0)
            if accumulated >= capacity_sat + estimated_fee_sat:
                break

        if accumulated < estimated_fee_sat + BITCOIN_DUST_LIMIT_SAT:
            raise NetworkError(
                f"Insufficient funds on-chain for {funder_addr}: "
                f"Available {accumulated:,} sat, minimum required {estimated_fee_sat + BITCOIN_DUST_LIMIT_SAT:,} sat."
            )

        if capacity_sat > accumulated - estimated_fee_sat:
            capacity_sat = max(BITCOIN_DUST_LIMIT_SAT, accumulated - estimated_fee_sat)

        redeem_script = ScriptFactory.create_multisig_2of2(
            funder_pubkey, counterparty_pubkey
        )
        unsigned_builder = TransactionBuilder()

        for utxo in selected_utxos:
            unsigned_builder.add_input(utxo["txid"], utxo["vout"])

        unsigned_builder.add_p2wsh_output(capacity_sat, redeem_script)

        change_sat = accumulated - capacity_sat - estimated_fee_sat
        if change_sat >= BITCOIN_DUST_LIMIT_SAT:
            unsigned_builder.add_p2wpkh_output(change_sat, funder_pubkey)

        unsigned_tx = unsigned_builder.build()

        p2wpkh_script_code = ScriptFactory.create_p2wpkh_scriptCode(funder_pubkey)
        signed_builder = TransactionBuilder()
        for utxo in selected_utxos:
            signed_builder.add_input(utxo["txid"], utxo["vout"])

        signed_builder.add_p2wsh_output(capacity_sat, redeem_script)
        if change_sat >= BITCOIN_DUST_LIMIT_SAT:
            signed_builder.add_p2wpkh_output(change_sat, funder_pubkey)

        for i, utxo in enumerate(selected_utxos):
            input_val = utxo.get("value", 0)
            sighash = SignatureHash(
                p2wpkh_script_code,
                unsigned_tx,
                i,
                SIGHASH_ALL,
                amount=input_val,
                sigversion=SIGVERSION_WITNESS_V0,
            )
            sig = sign_sighash(funder_secret, sighash)
            signed_builder.add_witness_stack([sig, funder_pubkey])

        signed_tx = signed_builder.build()
        raw_hex = bytes_to_hex(signed_tx.serialize())
        txid = self.broadcast_tx(raw_hex)
        return txid, 0, redeem_script

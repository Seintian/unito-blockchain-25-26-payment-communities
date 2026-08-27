import httpx
import pytest

from payment_communities.exceptions import NetworkError
from payment_communities.network.client import EsploraClient


@pytest.fixture
def esplora_client():
    return EsploraClient(base_url="https://mempool.space/signet/api")


def test_esplora_block_height_mocked(monkeypatch, esplora_client):
    req = httpx.Request("GET", "https://mempool.space/signet/api/blocks/tip/height")

    def mock_get(*args, **kwargs):
        return httpx.Response(200, text="319300", request=req)

    monkeypatch.setattr(httpx.Client, "get", mock_get)

    block_height = esplora_client.get_block_height()
    assert block_height == 319300, "Block height returned from mocked API mismatch"


def test_esplora_utxo_fetch_mocked(monkeypatch, esplora_client):
    req = httpx.Request(
        "GET", "https://mempool.space/signet/api/address/tb1qtestaddress/utxo"
    )
    mock_utxos = [{"txid": "00" * 32, "vout": 0, "value": 50000}]

    def mock_get(*args, **kwargs):
        return httpx.Response(200, json=mock_utxos, request=req)

    monkeypatch.setattr(httpx.Client, "get", mock_get)

    utxos = esplora_client.get_address_utxos("tb1qtestaddress")
    assert utxos == mock_utxos, "UTXO response from mocked API mismatch"


def test_esplora_tx_broadcast_mocked(monkeypatch, esplora_client):
    req = httpx.Request("POST", "https://mempool.space/signet/api/tx")
    expected_txid = "a" * 64

    def mock_post(*args, **kwargs):
        return httpx.Response(200, text=expected_txid, request=req)

    monkeypatch.setattr(httpx.Client, "post", mock_post)

    txid = esplora_client.broadcast_tx("0200000001...")
    assert txid == expected_txid, "Broadcast TXID from mocked API mismatch"


def test_esplora_block_height_error_raises_network_error():
    client = EsploraClient(base_url="https://invalid-api-url.example.com")
    with pytest.raises(NetworkError, match="Failed to fetch block height"):
        client.get_block_height()


def test_esplora_utxo_fetch_error_raises_network_error():
    client = EsploraClient(base_url="https://invalid-api-url.example.com")
    with pytest.raises(NetworkError, match="Failed to fetch UTXOs"):
        client.get_address_utxos("tb1qtestaddress")


def test_esplora_tx_broadcast_error_raises_network_error():
    client = EsploraClient(base_url="https://invalid-api-url.example.com")
    raw_tx_hex = "0200000001..."
    with pytest.raises(NetworkError, match="Failed to broadcast transaction"):
        client.broadcast_tx(raw_tx_hex)


def test_esplora_http_status_error(monkeypatch, esplora_client):
    req = httpx.Request("GET", "https://mempool.space/signet/api/blocks/tip/height")

    def mock_get(*args, **kwargs):
        return httpx.Response(500, text="Internal Server Error", request=req)

    monkeypatch.setattr(httpx.Client, "get", mock_get)

    with pytest.raises(NetworkError, match="Failed to fetch block height"):
        esplora_client.get_block_height()


def test_esplora_tip_hash_mocked(monkeypatch, esplora_client):
    req = httpx.Request("GET", "https://mempool.space/signet/api/blocks/tip/hash")
    expected_hash = "000000014f424905931a5bdd2885387f5f3b245182ea3496cdba0d18fb6d23c2"

    def mock_get(*args, **kwargs):
        return httpx.Response(200, text=expected_hash, request=req)

    monkeypatch.setattr(httpx.Client, "get", mock_get)
    tip_hash = esplora_client.get_tip_hash()
    assert tip_hash == expected_hash


def test_esplora_fee_estimates_mocked(monkeypatch, esplora_client):
    req = httpx.Request("GET", "https://mempool.space/signet/api/fee-estimates")
    mock_fees = {"1": 2.5, "2": 2.0, "3": 1.5, "6": 1.0}

    def mock_get(*args, **kwargs):
        return httpx.Response(200, json=mock_fees, request=req)

    monkeypatch.setattr(httpx.Client, "get", mock_get)
    fees = esplora_client.get_fee_estimates()
    assert fees == mock_fees
    assert esplora_client.get_recommended_fee_rate(target_blocks=1) == 2.5
    assert esplora_client.get_recommended_fee_rate(target_blocks=2) == 2.0


def test_esplora_address_stats_and_balance_mocked(monkeypatch, esplora_client):
    req = httpx.Request("GET", "https://mempool.space/signet/api/address/tb1qtest")
    mock_stats = {
        "address": "tb1qtest",
        "chain_stats": {"funded_txo_sum": 100000, "spent_txo_sum": 30000},
        "mempool_stats": {"funded_txo_sum": 5000, "spent_txo_sum": 0},
    }

    def mock_get(*args, **kwargs):
        return httpx.Response(200, json=mock_stats, request=req)

    monkeypatch.setattr(httpx.Client, "get", mock_get)
    stats = esplora_client.get_address_stats("tb1qtest")
    assert stats == mock_stats

    confirmed, unconfirmed = esplora_client.get_address_balance("tb1qtest")
    assert confirmed == 70000
    assert unconfirmed == 5000


def test_esplora_tx_lookup_and_status_mocked(monkeypatch, esplora_client):
    txid = "b" * 64
    mock_tx = {"txid": txid, "version": 2, "size": 220}
    mock_status = {"confirmed": True, "block_height": 319500}

    def mock_get(self, url, *args, **kwargs):
        if url.endswith("/status"):
            req = httpx.Request("GET", url)
            return httpx.Response(200, json=mock_status, request=req)
        req = httpx.Request("GET", url)
        return httpx.Response(200, json=mock_tx, request=req)

    monkeypatch.setattr(httpx.Client, "get", mock_get)
    tx = esplora_client.get_tx(txid)
    assert tx == mock_tx
    status = esplora_client.get_tx_status(txid)
    assert status == mock_status
    assert esplora_client.is_tx_confirmed(txid) is True


def test_settings_node_helpers():
    from payment_communities.config import Settings

    custom_settings = Settings(
        alice_key="key_alice",
        bob_key="key_bob",
        dave_key="key_dave",
        alice_address="addr_alice",
        bob_address="addr_bob",
        dave_address="addr_dave",
        alice_pubkey="pub_alice",
        bob_pubkey="pub_bob",
        dave_pubkey="pub_dave",
    )
    assert custom_settings.get_key("Alice") == "key_alice"
    assert custom_settings.get_key("Bob") == "key_bob"
    assert custom_settings.get_address("Dave") == "addr_dave"
    assert custom_settings.get_pubkey("Alice") == "pub_alice"
    assert custom_settings.is_live_configured is True

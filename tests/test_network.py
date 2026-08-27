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

import httpx
import pytest

from payment_communities.network import EsploraClient


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


def test_esplora_block_height_fallback():
    client = EsploraClient(base_url="https://invalid-api-url.example.com")
    height = client.get_block_height()
    assert height == 100_000, "Unreachable API must fallback to default height 100,000"


def test_esplora_utxo_fetch_fallback():
    client = EsploraClient(base_url="https://invalid-api-url.example.com")
    utxos = client.get_address_utxos("tb1qtestaddress")
    assert utxos == [], "Unreachable API must fallback to empty list"


def test_esplora_tx_broadcast_fallback():
    client = EsploraClient(base_url="https://invalid-api-url.example.com")
    raw_tx_hex = "0200000001..."
    txid = client.broadcast_tx(raw_tx_hex)
    assert len(txid) == 64, "Fallback pseudo-TXID must be a 64-char SHA256 hex digest"

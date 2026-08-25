from network import EsploraClient


def test_esplora_block_height_fallback():
    client = EsploraClient(base_url="https://invalid-api-url.example.com")
    height = client.get_block_height()
    assert height > 0


def test_esplora_utxo_fetch_fallback():
    client = EsploraClient(base_url="https://invalid-api-url.example.com")
    utxos = client.get_address_utxos("tb1qtestaddress")
    assert isinstance(utxos, list)


def test_esplora_tx_broadcast_fallback():
    client = EsploraClient(base_url="https://invalid-api-url.example.com")
    txid = client.broadcast_tx("0200000001...")
    assert len(txid) == 64

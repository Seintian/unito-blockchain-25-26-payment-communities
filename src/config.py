import os
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()

class Settings(BaseModel):
    network: Literal["testnet", "signet", "regtest", "mainnet"] = Field(
        default_factory=lambda: os.getenv("BITCOIN_NETWORK", "signet")  # type: ignore
    )
    esplora_api_url: str = Field(
        default_factory=lambda: os.getenv("ESPLORA_API_URL", "https://mempool.space/signet/api")
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

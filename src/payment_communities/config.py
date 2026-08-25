import os
from typing import Literal, cast

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()

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

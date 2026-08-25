"""
Persistence Engine for Payment Communities.
Saves and loads node keys, active channels, balances, HTLC contracts,
known preimages, and Poon-Dryja revocation history across CLI sessions.
"""

import json
from pathlib import Path

from pydantic import BaseModel

from payment_communities.channel import Channel


class NetworkState(BaseModel):
    channels: dict[str, Channel] = {}
    known_preimages: dict[str, str] = {}


class StorageEngine:
    """JSON-based persistent state storage engine."""

    def __init__(self, data_dir: str = ".data", filename: str = "network_state.json"):
        self.data_dir = Path(data_dir)
        self.file_path = self.data_dir / filename
        self._ensure_storage_directory()

    def _ensure_storage_directory(self) -> None:
        """Creates data directory if it does not exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def save_state(
        self, channels: dict[str, Channel], known_preimages: dict[str, str]
    ) -> None:
        """Serializes network channels and preimages to persistent JSON storage."""
        state = NetworkState(channels=channels, known_preimages=known_preimages)
        with open(self.file_path, "w", encoding="utf-8") as f:
            f.write(state.model_dump_json(indent=2))

    def load_state(self) -> NetworkState:
        """Loads and deserializes network channels and preimages from persistent storage."""
        if not self.file_path.exists():
            return NetworkState()

        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return NetworkState.model_validate(data)
        except json.JSONDecodeError, ValueError:
            return NetworkState()

    def clear_state(self) -> None:
        """Clears persistent state storage."""
        if self.file_path.exists():
            self.file_path.unlink()

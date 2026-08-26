"""
Persistence Engine for Payment Communities.
Saves and loads node keys, active channels, balances, HTLC contracts,
known preimages, and Poon-Dryja revocation history across CLI sessions using atomic operations.
"""

import json
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from pydantic import BaseModel

from payment_communities.domain.channel import Channel
from payment_communities.domain.core.result import Err, Ok, Result


class NetworkState(BaseModel):
    channels: dict[str, Channel] = {}
    known_preimages: dict[str, str] = {}


class StorageEngine:
    """JSON-based persistent state storage engine with atomic transactional writing."""

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
        """Serializes network channels and preimages to persistent JSON storage atomically."""
        state = NetworkState(channels=channels, known_preimages=known_preimages)
        temp_path = self.file_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(state.model_dump_json(indent=2))
        temp_path.replace(self.file_path)

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

    def load_state_safe(self) -> Result[NetworkState, Exception]:
        """Loads network state safely returning a Result monad."""
        try:
            return Ok(self.load_state())
        except Exception as e:  # noqa: BLE001
            return Err(e)

    def clear_state(self) -> None:
        """Clears persistent state storage."""
        if self.file_path.exists():
            self.file_path.unlink()

    @contextmanager
    def session(
        self, channels: dict[str, Channel], known_preimages: dict[str, str]
    ) -> Generator[NetworkState]:
        """Context manager yielding current state and automatically saving changes on exit."""
        state = NetworkState(channels=channels, known_preimages=known_preimages)
        try:
            yield state
        finally:
            self.save_state(state.channels, state.known_preimages)

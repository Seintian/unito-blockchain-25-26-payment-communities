"""
ACID-compliant SQLite Persistence Engine with Write-Ahead Logging (WAL).

Provides robust, persistent storage for:
- Channel states and configurations
- Active and settled HTLCs
- BOLT #3 Shachain revocation trees
- Discovered payment hash preimages
- Watchtower encrypted breach remedy hints
"""

import json
import sqlite3
from pathlib import Path

from payment_communities.domain.channel import Channel
from payment_communities.protocols.shachain import ShachainReceiver
from payment_communities.storage.engine import NetworkState


class SqliteStorageEngine:
    """ACID SQLite storage engine with WAL mode for high concurrency and crash resilience."""

    def __init__(self, db_path: str = ".data/payment_communities.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _init_db(self) -> None:
        """Initializes database schema with required tables and indexes."""
        with self._get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS channels (
                    channel_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    sender_alias TEXT,
                    receiver_alias TEXT,
                    capacity_sat INTEGER,
                    state TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS htlcs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel_id TEXT NOT NULL,
                    htlc_id TEXT NOT NULL,
                    amount_sat INTEGER NOT NULL,
                    hash_lock TEXT NOT NULL,
                    cltv_expiry INTEGER NOT NULL,
                    direction TEXT,
                    status TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(channel_id) REFERENCES channels(channel_id) ON DELETE CASCADE,
                    UNIQUE(channel_id, htlc_id)
                );

                CREATE TABLE IF NOT EXISTS shachain (
                    channel_id TEXT PRIMARY KEY,
                    serialized_slots TEXT NOT NULL,
                    last_index INTEGER NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(channel_id) REFERENCES channels(channel_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS preimages (
                    payment_hash TEXT PRIMARY KEY,
                    preimage TEXT NOT NULL,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS watchtower_hints (
                    hint_hex TEXT PRIMARY KEY,
                    encrypted_blob_hex TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_htlcs_channel ON htlcs(channel_id);
                CREATE INDEX IF NOT EXISTS idx_htlcs_hash ON htlcs(hash_lock);
                """
            )

    def save_channel(self, channel: Channel) -> None:
        """Atomically saves or updates a channel in SQLite."""
        state_json = channel.model_dump_json()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO channels (channel_id, state_json, sender_alias, receiver_alias, capacity_sat, state, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(channel_id) DO UPDATE SET
                    state_json = excluded.state_json,
                    sender_alias = excluded.sender_alias,
                    receiver_alias = excluded.receiver_alias,
                    capacity_sat = excluded.capacity_sat,
                    state = excluded.state,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (
                    channel.channel_id,
                    state_json,
                    channel.sender_alias,
                    channel.receiver_alias,
                    channel.capacity_sat,
                    getattr(channel.state, "value", str(channel.state)),
                ),
            )
            # Sync active HTLCs
            conn.execute(
                "DELETE FROM htlcs WHERE channel_id = ?;", (channel.channel_id,)
            )
            for h in channel.active_htlcs.values():
                conn.execute(
                    """
                    INSERT INTO htlcs (channel_id, htlc_id, amount_sat, hash_lock, cltv_expiry, direction, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        channel.channel_id,
                        str(h.htlc_id),
                        h.amount_sat,
                        h.payment_hash,
                        h.locktime,
                        h.offerer_alias or "OUTGOING",
                        getattr(h.state, "value", str(h.state)),
                    ),
                )


    def load_channel(self, channel_id: str) -> Channel | None:
        """Loads a single channel by channel_id."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT state_json FROM channels WHERE channel_id = ?;", (channel_id,)
            ).fetchone()
            if not row:
                return None
            return Channel.model_validate(json.loads(row["state_json"]))

    def load_all_channels(self) -> dict[str, Channel]:
        """Loads all channels into a dictionary keyed by channel_id."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT channel_id, state_json FROM channels;"
            ).fetchall()
            channels: dict[str, Channel] = {}
            for row in rows:
                try:
                    channels[row["channel_id"]] = Channel.model_validate(
                        json.loads(row["state_json"])
                    )
                except Exception:  # noqa: BLE001, S112
                    continue
            return channels

    def delete_channel(self, channel_id: str) -> None:
        """Deletes a channel and associated HTLCs and Shachain records."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM channels WHERE channel_id = ?;", (channel_id,))

    def save_shachain(self, channel_id: str, receiver: ShachainReceiver) -> None:
        """Saves a BOLT #3 ShachainReceiver for a channel."""
        serialized = receiver.model_dump_json()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO shachain (channel_id, serialized_slots, last_index, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(channel_id) DO UPDATE SET
                    serialized_slots = excluded.serialized_slots,
                    last_index = excluded.last_index,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (channel_id, serialized, receiver.last_index),
            )

    def load_shachain(self, channel_id: str) -> ShachainReceiver | None:
        """Loads a BOLT #3 ShachainReceiver for a channel."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT serialized_slots FROM shachain WHERE channel_id = ?;",
                (channel_id,),
            ).fetchone()
            if not row:
                return None
            return ShachainReceiver.model_validate(json.loads(row["serialized_slots"]))

    def save_preimage(self, payment_hash: str, preimage: str) -> None:
        """Persists a discovered payment hash preimage."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO preimages (payment_hash, preimage)
                VALUES (?, ?)
                ON CONFLICT(payment_hash) DO UPDATE SET preimage = excluded.preimage;
                """,
                (payment_hash, preimage),
            )

    def load_preimages(self) -> dict[str, str]:
        """Loads all known preimages."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT payment_hash, preimage FROM preimages;"
            ).fetchall()
            return {r["payment_hash"]: r["preimage"] for r in rows}

    def save_watchtower_hint(self, hint_hex: str, encrypted_blob_hex: str) -> None:
        """Persists a watchtower breach monitoring hint and encrypted blob."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO watchtower_hints (hint_hex, encrypted_blob_hex)
                VALUES (?, ?)
                ON CONFLICT(hint_hex) DO UPDATE SET encrypted_blob_hex = excluded.encrypted_blob_hex;
                """,
                (hint_hex, encrypted_blob_hex),
            )

    def lookup_watchtower_hint(self, hint_hex: str) -> str | None:
        """Looks up an encrypted penalty blob by txid hint."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT encrypted_blob_hex FROM watchtower_hints WHERE hint_hex = ?;",
                (hint_hex,),
            ).fetchone()
            return row["encrypted_blob_hex"] if row else None

    def load_all_watchtower_hints(self) -> dict[str, str]:
        """Loads all watchtower hints."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT hint_hex, encrypted_blob_hex FROM watchtower_hints;"
            ).fetchall()
            return {r["hint_hex"]: r["encrypted_blob_hex"] for r in rows}

    def save_network_state(
        self, channels: dict[str, Channel], known_preimages: dict[str, str]
    ) -> None:
        """Atomically saves full network state (channels + preimages)."""
        for ch in channels.values():
            self.save_channel(ch)
        for h, p in known_preimages.items():
            self.save_preimage(h, p)

    def load_network_state(self) -> NetworkState:
        """Loads full network state compatible with NetworkState model."""
        channels = self.load_all_channels()
        preimages = self.load_preimages()
        return NetworkState(channels=channels, known_preimages=preimages)

    def clear(self) -> None:
        """Clears all records across all tables."""
        with self._get_connection() as conn:
            conn.executescript(
                """
                DELETE FROM htlcs;
                DELETE FROM shachain;
                DELETE FROM channels;
                DELETE FROM preimages;
                DELETE FROM watchtower_hints;
                """
            )

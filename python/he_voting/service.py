from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .crypto_cli import CryptoCli
from .settings import Settings


EMPTY_CHAIN_HASH = "0" * 64
MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class Receipt:
    receipt: str
    status: str
    sequence: int
    chain_hash: str


class VotingService:
    """Ordered ballot processor.

    The service never receives an employee ID or plaintext choice. A random
    voter token is hashed to locate that voter's encrypted has_voted flag.
    """

    def __init__(self, settings: Settings):
        settings.validate()
        self.settings = settings
        self.crypto = CryptoCli(settings.crypto_bin)
        self._lock = threading.Lock()

        settings.ballots_dir.mkdir(parents=True, exist_ok=True)
        (settings.runtime_dir / "tmp").mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.settings.database_path,
            timeout=30,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS eligible_tokens (
                    token_hash TEXT PRIMARY KEY
                );

                CREATE TABLE IF NOT EXISTS ballots (
                    receipt TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL,
                    ballot_hash TEXT NOT NULL,
                    sequence INTEGER NOT NULL UNIQUE,
                    chain_hash TEXT NOT NULL,
                    ciphertext_path TEXT NOT NULL,
                    internal_status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                INSERT OR IGNORE INTO metadata(key, value)
                VALUES ('sequence', '0');

                INSERT OR IGNORE INTO metadata(key, value)
                VALUES ('chain_hash', '0000000000000000000000000000000000000000000000000000000000000000');
                """
            )

    @staticmethod
    def token_hash(voter_token: str) -> str:
        normalized = voter_token.strip().lower()
        if len(normalized) != 64:
            raise ValueError("voter token must contain 64 hexadecimal characters")
        try:
            bytes.fromhex(normalized)
        except ValueError as error:
            raise ValueError(
                "voter token must contain 64 hexadecimal characters"
            ) from error
        return hashlib.sha256(normalized.encode("ascii")).hexdigest()

    def register_tokens(self, voter_tokens: Iterable[str]) -> int:
        rows = [(self.token_hash(token),) for token in voter_tokens]
        with self._connect() as connection:
            connection.executemany(
                "INSERT OR IGNORE INTO eligible_tokens(token_hash) VALUES (?)",
                rows,
            )
        return len(rows)

    @staticmethod
    def _validate_ciphertext(ciphertext: bytes) -> None:
        if not ciphertext:
            raise ValueError("encrypted choice must not be empty")
        if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
            raise ValueError(
                f"encrypted choice exceeds {MAX_CIPHERTEXT_BYTES} bytes"
            )

    def _next_chain_values(
        self,
        connection: sqlite3.Connection,
        ballot_hash: str,
    ) -> tuple[int, str]:
        sequence = int(
            connection.execute(
                "SELECT value FROM metadata WHERE key = 'sequence'"
            ).fetchone()["value"]
        )
        previous_chain = connection.execute(
            "SELECT value FROM metadata WHERE key = 'chain_hash'"
        ).fetchone()["value"]

        next_sequence = sequence + 1
        chain_material = (
            previous_chain
            + ":"
            + str(next_sequence)
            + ":"
            + ballot_hash
        ).encode("ascii")
        return next_sequence, hashlib.sha256(chain_material).hexdigest()

    def submit(self, voter_token: str, encrypted_choice: bytes) -> Receipt:
        self._validate_ciphertext(encrypted_choice)
        token_hash = self.token_hash(voter_token)
        ballot_hash = hashlib.sha256(
            token_hash.encode("ascii") + encrypted_choice
        ).hexdigest()
        receipt_id = ballot_hash

        with self._lock:
            with self._connect() as connection:
                existing = connection.execute(
                    """
                    SELECT receipt, sequence, chain_hash
                    FROM ballots
                    WHERE receipt = ?
                    """,
                    (receipt_id,),
                ).fetchone()
                if existing is not None:
                    return Receipt(
                        receipt=existing["receipt"],
                        status="recorded",
                        sequence=int(existing["sequence"]),
                        chain_hash=existing["chain_hash"],
                    )

                eligible = (
                    connection.execute(
                        """
                        SELECT 1 FROM eligible_tokens WHERE token_hash = ?
                        """,
                        (token_hash,),
                    ).fetchone()
                    is not None
                )

                sequence, chain_hash = self._next_chain_values(
                    connection, ballot_hash
                )
                ballot_path = (
                    self.settings.ballots_dir
                    / f"{sequence:012d}-{receipt_id}.ct"
                )
                ballot_temp = ballot_path.with_suffix(".ct.tmp")
                ballot_temp.write_bytes(encrypted_choice)
                os.replace(ballot_temp, ballot_path)

                internal_status = "ignored_unknown_token"
                if eligible:
                    self._apply_encrypted_vote(
                        token_hash=token_hash,
                        ballot_path=ballot_path,
                    )
                    internal_status = "evaluated"

                connection.execute(
                    """
                    INSERT INTO ballots(
                        receipt,
                        token_hash,
                        ballot_hash,
                        sequence,
                        chain_hash,
                        ciphertext_path,
                        internal_status,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt_id,
                        token_hash,
                        ballot_hash,
                        sequence,
                        chain_hash,
                        str(ballot_path.relative_to(self.settings.runtime_dir)),
                        internal_status,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                connection.execute(
                    "UPDATE metadata SET value = ? WHERE key = 'sequence'",
                    (str(sequence),),
                )
                connection.execute(
                    "UPDATE metadata SET value = ? WHERE key = 'chain_hash'",
                    (chain_hash,),
                )

                return Receipt(
                    receipt=receipt_id,
                    status="recorded",
                    sequence=sequence,
                    chain_hash=chain_hash,
                )

    def _apply_encrypted_vote(
        self,
        token_hash: str,
        ballot_path: Path,
    ) -> None:
        flag_path = self.settings.flags_dir / f"{token_hash}.ct"
        tally_path = self.settings.state_dir / "tally.ct"
        if not flag_path.is_file():
            raise FileNotFoundError(
                "eligible token has no encrypted has_voted state"
            )

        with tempfile.TemporaryDirectory(
            prefix="evaluate-",
            dir=self.settings.runtime_dir / "tmp",
        ) as temporary_directory:
            temporary = Path(temporary_directory)
            next_flag = temporary / "flag.ct"
            next_tally = temporary / "tally.ct"
            previous_flag = temporary / "flag.previous.ct"
            previous_tally = temporary / "tally.previous.ct"
            shutil.copy2(flag_path, previous_flag)
            shutil.copy2(tally_path, previous_tally)

            self.crypto.evaluate(
                public_dir=self.settings.public_dir,
                flag_input=flag_path,
                tally_input=tally_path,
                ballot_input=ballot_path,
                flag_output=next_flag,
                tally_output=next_tally,
                evaluator=self.settings.evaluator,
            )

            try:
                os.replace(next_flag, flag_path)
                os.replace(next_tally, tally_path)
            except Exception:
                os.replace(previous_flag, flag_path)
                os.replace(previous_tally, tally_path)
                raise

    def get_receipt(self, receipt_id: str) -> Receipt | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT receipt, sequence, chain_hash
                FROM ballots
                WHERE receipt = ?
                """,
                (receipt_id,),
            ).fetchone()
        if row is None:
            return None
        return Receipt(
            receipt=row["receipt"],
            status="recorded",
            sequence=int(row["sequence"]),
            chain_hash=row["chain_hash"],
        )

    def bulletin_board(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT receipt, ballot_hash, sequence, chain_hash, created_at
                FROM ballots
                ORDER BY sequence
                """
            ).fetchall()
        return [
            {
                "receipt": row["receipt"],
                "ballot_hash": row["ballot_hash"],
                "sequence": int(row["sequence"]),
                "chain_hash": row["chain_hash"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]


"""Ballot validation, ordering, persistence, and encrypted tally updates.

The service connects the privacy-preserving OpenFHE layer to ordinary
application state. SQLite stores employee and participation metadata, while
ballot choices and running A/B/C totals remain serialized ciphertext files.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from he_voting.openfhe_backend import OpenFHEBackend
from .settings import Settings


# Initial value for the public ballot hash chain before the first submission.
EMPTY_CHAIN_HASH = "0" * 64

# Limit each uploaded component before writing it to disk or passing it to the
# native OpenFHE deserializer.
MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024
CHOICE_NAMES = ("a", "b", "c")


class UnknownEmployeeError(ValueError):
    """The submitted employee ID is not part of this election."""


class AlreadyVotedError(ValueError):
    """The submitted employee already has one accepted ballot."""


@dataclass(frozen=True)
class Receipt:
    """Public proof that the service recorded a submission in a given order."""

    receipt: str
    status: str
    sequence: int
    chain_hash: str
    processing_ms: float


class VotingService:
    """Ordered ballot processor.

    The encrypted API receives an employee ID plus three ciphertexts. SQLite
    records which prepared employee submitted, but never stores their choice.
    A plaintext ``has_voted`` flag ensures each prepared employee can affect
    the encrypted tally exactly once.
    """

    def __init__(self, settings: Settings):
        # Refuse to start until public material and all encrypted tallies exist.
        settings.validate()
        self.settings = settings
        self.crypto = OpenFHEBackend(settings.public_dir)
        # This lock orders file and database updates within one Python process.
        # It is why the API must run with exactly one worker.
        self._lock = threading.Lock()

        # setup_election creates these normally, but mkdir keeps service startup
        # tolerant of missing empty storage directories.
        settings.ballots_dir.mkdir(parents=True, exist_ok=True)
        (settings.runtime_dir / "tmp").mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        """Open a durable SQLite connection for one short transaction."""
        connection = sqlite3.connect(
            self.settings.database_path,
            timeout=30,
        )
        connection.row_factory = sqlite3.Row
        # WAL improves reader/writer behavior; FULL asks SQLite to sync commits
        # before reporting success.
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize_database(self) -> None:
        """Create the metadata schema and migrate older timing-less runtimes."""
        with self._connect() as connection:
            existing_ballot_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(ballots)"
                ).fetchall()
            }
            if (
                existing_ballot_columns
                and "employee_id" not in existing_ballot_columns
            ):
                raise RuntimeError(
                    "legacy voter-token runtime detected; prepare a fresh "
                    "election runtime for the employee-ID app"
                )
            connection.executescript(
                """
                -- Prepared employees populate the UI dropdown.
                CREATE TABLE IF NOT EXISTS employees (
                    employee_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    has_voted INTEGER NOT NULL DEFAULT 0
                );

                -- The choice itself lives at ciphertext_path, never in SQLite.
                CREATE TABLE IF NOT EXISTS ballots (
                    receipt TEXT PRIMARY KEY,
                    employee_id TEXT NOT NULL,
                    ballot_hash TEXT NOT NULL,
                    sequence INTEGER NOT NULL UNIQUE,
                    chain_hash TEXT NOT NULL,
                    ciphertext_path TEXT NOT NULL,
                    internal_status TEXT NOT NULL,
                    processing_ms REAL NOT NULL DEFAULT 0,
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
            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(ballots)"
                ).fetchall()
            }
            if "processing_ms" not in columns:
                connection.execute(
                    """
                    ALTER TABLE ballots
                    ADD COLUMN processing_ms REAL NOT NULL DEFAULT 0
                    """
                )
            employee_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(employees)"
                ).fetchall()
            }
            if "has_voted" not in employee_columns:
                connection.execute(
                    """
                    ALTER TABLE employees
                    ADD COLUMN has_voted INTEGER NOT NULL DEFAULT 0
                    """
                )

            duplicate = connection.execute(
                """
                SELECT employee_id, COUNT(*) AS ballot_count
                FROM ballots
                WHERE internal_status IN ('accepted', 'evaluated')
                GROUP BY employee_id
                HAVING COUNT(*) > 1
                LIMIT 1
                """
            ).fetchone()
            if duplicate is not None:
                raise RuntimeError(
                    "existing runtime already contains multiple accepted "
                    f"ballots for employee {duplicate['employee_id']}; "
                    "prepare a fresh election because encrypted historical "
                    "totals cannot be corrected without rebuilding them"
                )

            # Migrate existing one-ballot runtimes without changing their
            # ciphertexts or tallies.
            connection.execute(
                """
                UPDATE employees
                SET has_voted = CASE
                    WHEN EXISTS (
                        SELECT 1
                        FROM ballots
                        WHERE ballots.employee_id = employees.employee_id
                          AND internal_status IN ('accepted', 'evaluated')
                    )
                    THEN 1
                    ELSE 0
                END
                """
            )
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS
                    one_accepted_ballot_per_employee
                ON ballots(employee_id)
                WHERE internal_status IN ('accepted', 'evaluated')
                """
            )

    @staticmethod
    def _receipt_status(internal_status: str) -> str:
        """Map internal/legacy database states to the small public API vocabulary."""
        return {
            "accepted": "accepted",
            "rejected_unknown_employee": "rejected",
            # Compatibility with runtimes created by the older encrypted-flag
            # implementation.
            "evaluated": "accepted",
            "ignored_unknown_token": "rejected",
        }.get(internal_status, "recorded")

    @staticmethod
    def normalize_employee_id(employee_id: str) -> str:
        """Validate the visible employee identifier used by the demo app."""
        normalized = employee_id.strip()
        if not normalized:
            raise ValueError("employee ID must not be empty")
        if len(normalized) > 128:
            raise ValueError("employee ID must not exceed 128 characters")
        return normalized

    def register_employees(
        self,
        employees: Iterable[tuple[str, str]],
    ) -> int:
        """Store the prepared employee IDs and display names."""
        rows = []
        for employee_id, display_name in employees:
            normalized_id = self.normalize_employee_id(employee_id)
            normalized_name = display_name.strip() or normalized_id
            rows.append((normalized_id, normalized_name))
        if len({employee_id for employee_id, _ in rows}) != len(rows):
            raise ValueError("employee IDs must be unique")
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO employees(employee_id, display_name)
                VALUES (?, ?)
                """,
                rows,
            )
        return len(rows)

    @staticmethod
    def _validate_ciphertexts(
        encrypted_choice: dict[str, bytes],
    ) -> None:
        """Perform transport-level validation before native deserialization.

        Because the values are encrypted, this method cannot prove they contain
        a valid one-hot 0/1 ballot. The MVP trusts its supplied client to create
        valid A/B/C ciphertexts.
        """
        if set(encrypted_choice) != set(CHOICE_NAMES):
            raise ValueError(
                "encrypted choice must contain separate A, B, and C ciphertexts"
            )
        for choice_name in CHOICE_NAMES:
            ciphertext = encrypted_choice[choice_name]
            if not ciphertext:
                raise ValueError(
                    f"encrypted choice {choice_name.upper()} must not be empty"
                )
            if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
                raise ValueError(
                    f"encrypted choice {choice_name.upper()} exceeds "
                    f"{MAX_CIPHERTEXT_BYTES} bytes"
                )

    def _next_chain_values(
        self,
        connection: sqlite3.Connection,
        ballot_hash: str,
    ) -> tuple[int, str]:
        """Return the next sequence number and tamper-evident chain hash.

        The hash chain exposes deletion, insertion, or reordering after
        publication. It is not a digital signature by itself.
        """
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

    def submit(
        self,
        employee_id: str,
        encrypted_choice: dict[str, bytes],
    ) -> Receipt:
        """Record one row and add it when the employee ID was prepared."""
        processing_started = time.perf_counter()
        self._validate_ciphertexts(encrypted_choice)
        normalized_employee_id = self.normalize_employee_id(employee_id)
        # Bind the metadata receipt to the employee ID and the exact
        # three ciphertext byte strings without revealing their plaintexts.
        ballot_digest = hashlib.sha256(
            normalized_employee_id.encode("utf-8")
        )
        for choice_name in CHOICE_NAMES:
            ballot_digest.update(choice_name.encode("ascii"))
            ballot_digest.update(encrypted_choice[choice_name])
        ballot_hash = ballot_digest.hexdigest()

        # Keep sequence allocation, ciphertext file replacement, and SQLite
        # metadata updates ordered relative to other submissions in this worker.
        with self._lock:
            with self._connect() as connection:
                # Lock the plaintext employee state before checking it. This
                # protects the rule even if a second app process is started.
                connection.execute("BEGIN IMMEDIATE")
                employee = connection.execute(
                    """
                    SELECT has_voted
                    FROM employees
                    WHERE employee_id = ?
                    """,
                    (normalized_employee_id,),
                ).fetchone()
                if employee is None:
                    raise UnknownEmployeeError(
                        f"employee ID is not prepared: {normalized_employee_id}"
                    )
                if bool(employee["has_voted"]):
                    raise AlreadyVotedError(
                        f"employee {normalized_employee_id} has already voted"
                    )

                sequence, chain_hash = self._next_chain_values(
                    connection, ballot_hash
                )
                receipt_id = hashlib.sha256(
                    f"{sequence}:{ballot_hash}".encode("ascii")
                ).hexdigest()
                ballot_directory = (
                    self.settings.ballots_dir
                    / f"{sequence:012d}-{receipt_id}"
                )
                ballot_directory.mkdir(parents=True, exist_ok=False)
                # Write to a temporary name and atomically rename each complete
                # ciphertext so readers never observe a partially written file.
                for choice_name in CHOICE_NAMES:
                    ballot_path = (
                        ballot_directory / f"choice_{choice_name}.ct"
                    )
                    ballot_temp = ballot_path.with_suffix(".ct.tmp")
                    ballot_temp.write_bytes(encrypted_choice[choice_name])
                    os.replace(ballot_temp, ballot_path)

                submitted_at = datetime.now(timezone.utc).isoformat()
                # The plaintext has_voted check is complete. Only the three
                # encrypted choice values enter the homomorphic calculation.
                self._apply_encrypted_vote(
                    ballot_directory=ballot_directory,
                )
                internal_status = "accepted"

                processing_ms = (
                    time.perf_counter() - processing_started
                ) * 1000.0
                connection.execute(
                    """
                    INSERT INTO ballots(
                        receipt,
                        employee_id,
                        ballot_hash,
                        sequence,
                        chain_hash,
                        ciphertext_path,
                        internal_status,
                        processing_ms,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt_id,
                        normalized_employee_id,
                        ballot_hash,
                        sequence,
                        chain_hash,
                        str(
                            ballot_directory.relative_to(
                                self.settings.runtime_dir
                            )
                        ),
                        internal_status,
                        processing_ms,
                        submitted_at,
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
                connection.execute(
                    """
                    UPDATE employees
                    SET has_voted = 1
                    WHERE employee_id = ? AND has_voted = 0
                    """,
                    (normalized_employee_id,),
                )

                # Exiting the connection context commits the SQLite transaction.
                return Receipt(
                    receipt=receipt_id,
                    status=self._receipt_status(internal_status),
                    sequence=sequence,
                    chain_hash=chain_hash,
                    processing_ms=processing_ms,
                )

    def _apply_encrypted_vote(
        self,
        ballot_directory: Path,
    ) -> None:
        """Calculate and install the next encrypted A/B/C tally files."""
        with tempfile.TemporaryDirectory(
            prefix="evaluate-",
            dir=self.settings.runtime_dir / "tmp",
        ) as temporary_directory:
            temporary = Path(temporary_directory)
            next_tally_directory = temporary / "next_tally"
            previous_tally_directory = temporary / "previous_tally"
            next_tally_directory.mkdir()
            previous_tally_directory.mkdir()
            # Preserve all three old totals so a failed replacement attempt can
            # restore a consistent previous state.
            for choice_name in CHOICE_NAMES:
                shutil.copy2(
                    self.settings.state_dir / f"tally_{choice_name}.ct",
                    previous_tally_directory / f"tally_{choice_name}.ct",
                )

            self.crypto.evaluate(
                public_dir=self.settings.public_dir,
                tally_input_directory=self.settings.state_dir,
                ballot_directory=ballot_directory,
                tally_output_directory=next_tally_directory,
            )

            try:
                # Replace the live tallies only after all next totals have been
                # calculated and serialized successfully.
                for choice_name in CHOICE_NAMES:
                    os.replace(
                        next_tally_directory / f"tally_{choice_name}.ct",
                        self.settings.state_dir
                        / f"tally_{choice_name}.ct",
                    )
            except Exception:
                # Best-effort rollback if installing any of A/B/C fails.
                for choice_name in CHOICE_NAMES:
                    os.replace(
                        previous_tally_directory
                        / f"tally_{choice_name}.ct",
                        self.settings.state_dir
                        / f"tally_{choice_name}.ct",
                    )
                raise

    def get_receipt(self, receipt_id: str) -> Receipt | None:
        """Look up the public status and chain position of one receipt."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT receipt, sequence, chain_hash, processing_ms,
                       internal_status
                FROM ballots
                WHERE receipt = ?
                """,
                (receipt_id,),
            ).fetchone()
        if row is None:
            return None
        return Receipt(
            receipt=row["receipt"],
            status=self._receipt_status(row["internal_status"]),
            sequence=int(row["sequence"]),
            chain_hash=row["chain_hash"],
            processing_ms=float(row["processing_ms"]),
        )

    def participation_records(self) -> dict[str, str]:
        """Return accepted-submission times by employee ID, without choices."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT employee_id, MIN(created_at) AS submitted_at
                FROM ballots
                WHERE internal_status IN ('accepted', 'evaluated')
                GROUP BY employee_id
                ORDER BY submitted_at
                """
            ).fetchall()
        return {
            row["employee_id"]: row["submitted_at"]
            for row in rows
        }

    def employees(self) -> list[dict[str, str | None]]:
        """Return prepared employees and whether each has submitted."""
        participation = self.participation_records()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT employee_id, display_name
                FROM employees
                ORDER BY employee_id
                """
            ).fetchall()
        return [
            {
                "employee_id": row["employee_id"],
                "display_name": row["display_name"],
                "submitted_at": participation.get(row["employee_id"]),
            }
            for row in rows
        ]

    def progress(self) -> dict[str, int | str | None]:
        """Return non-secret operational counts for the admin page."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM employees) AS eligible_employees,
                    COUNT(*) AS recorded_submissions,
                    SUM(CASE WHEN internal_status = 'accepted' THEN 1 ELSE 0 END)
                        AS encrypted_ballots,
                    COUNT(DISTINCT CASE
                        WHEN internal_status = 'accepted' THEN employee_id
                    END) AS participating_employees,
                    MAX(created_at) AS latest_submission
                FROM ballots
                """
            ).fetchone()
        return {
            "eligible_employees": int(row["eligible_employees"] or 0),
            "recorded_submissions": int(row["recorded_submissions"] or 0),
            "encrypted_ballots": int(row["encrypted_ballots"] or 0),
            "participating_employees": int(
                row["participating_employees"] or 0
            ),
            "latest_submission": row["latest_submission"],
        }

    def bulletin_board(self) -> list[dict[str, object]]:
        """Return ordered public receipt hashes without IDs or vote choices."""
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

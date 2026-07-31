"""Resolve and validate the on-disk election runtime layout.

Expected layout::

    runtime/
      public/crypto_context.bin
      public/public_key.bin
      state/tally_a.ct
      state/tally_b.ct
      state/tally_c.ct
      ballots/
      voting.sqlite3

The trustee secret key intentionally lives outside this runtime directory.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Filesystem locations used by one election service instance."""

    runtime_dir: Path

    @classmethod
    def from_environment(cls) -> "Settings":
        """Use HE_VOTING_RUNTIME, falling back to ``<project>/runtime``."""
        project_dir = Path(__file__).resolve().parents[1]
        return cls(
            runtime_dir=Path(
                os.environ.get(
                    "HE_VOTING_RUNTIME",
                    project_dir / "runtime",
                )
            ).resolve(),
        )

    @property
    def public_dir(self) -> Path:
        """Directory containing the distributable context and public key."""
        return self.runtime_dir / "public"

    @property
    def state_dir(self) -> Path:
        """Directory containing the live encrypted A/B/C totals."""
        return self.runtime_dir / "state"

    @property
    def ballots_dir(self) -> Path:
        """Directory retaining each submitted three-ciphertext ballot."""
        return self.runtime_dir / "ballots"

    @property
    def database_path(self) -> Path:
        """SQLite database for employees, receipts, and participation."""
        return self.runtime_dir / "voting.sqlite3"

    @property
    def context_id(self) -> str:
        """Short fingerprint proving which serialized HE context is mounted."""
        context_path = self.public_dir / "crypto_context.bin"
        return hashlib.sha256(context_path.read_bytes()).hexdigest()[:16]

    def validate(self) -> None:
        """Reject incompatible or incomplete election runtime directories."""
        # Older runtimes used encrypted participation flags. Mixing that layout
        # with the current metadata design could count participants incorrectly.
        legacy_flags = self.runtime_dir / "flags"
        if legacy_flags.is_dir() and any(legacy_flags.glob("*.ct")):
            raise RuntimeError(
                "legacy encrypted-flag runtime detected; create a fresh "
                "election runtime so participation cannot be counted twice"
            )
        # The service can evaluate additions using only public material and the
        # three current ciphertexts. It must never require the trustee key.
        required_files = [
            self.public_dir / "crypto_context.bin",
            self.public_dir / "public_key.bin",
            self.state_dir / "tally_a.ct",
            self.state_dir / "tally_b.ct",
            self.state_dir / "tally_c.ct",
        ]
        missing = [str(path) for path in required_files if not path.is_file()]
        if missing:
            raise FileNotFoundError(
                "election runtime is incomplete; missing: " + ", ".join(missing)
            )

        manifest_path = self.runtime_dir / "election.json"
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            checks = {
                "crypto_context.bin": (
                    self.public_dir / "crypto_context.bin",
                    manifest.get("context_sha256"),
                ),
                "public_key.bin": (
                    self.public_dir / "public_key.bin",
                    manifest.get("public_key_sha256"),
                ),
            }
            for material_name, (path, expected_hash) in checks.items():
                if not expected_hash:
                    continue
                actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual_hash != expected_hash:
                    raise RuntimeError(
                        f"{material_name} does not match election.json; "
                        "refusing to mix OpenFHE election material"
                    )

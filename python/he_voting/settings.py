from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    runtime_dir: Path

    @classmethod
    def from_environment(cls) -> "Settings":
        project_dir = Path(__file__).resolve().parents[2]
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
        return self.runtime_dir / "public"

    @property
    def state_dir(self) -> Path:
        return self.runtime_dir / "state"

    @property
    def ballots_dir(self) -> Path:
        return self.runtime_dir / "ballots"

    @property
    def database_path(self) -> Path:
        return self.runtime_dir / "voting.sqlite3"

    def validate(self) -> None:
        legacy_flags = self.runtime_dir / "flags"
        if legacy_flags.is_dir() and any(legacy_flags.glob("*.ct")):
            raise RuntimeError(
                "legacy encrypted-flag runtime detected; create a fresh "
                "election runtime so participation cannot be counted twice"
            )
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

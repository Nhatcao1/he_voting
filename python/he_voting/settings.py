from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    runtime_dir: Path
    crypto_bin: Path
    evaluator: str = "openfhe"

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
            crypto_bin=Path(
                os.environ.get(
                    "HE_VOTING_CRYPTO_BIN",
                    project_dir / "build" / "he_voting_crypto",
                )
            ).resolve(),
            evaluator=os.environ.get("HE_EVALUATOR", "openfhe"),
        )

    @property
    def public_dir(self) -> Path:
        return self.runtime_dir / "public"

    @property
    def state_dir(self) -> Path:
        return self.runtime_dir / "state"

    @property
    def flags_dir(self) -> Path:
        return self.runtime_dir / "flags"

    @property
    def ballots_dir(self) -> Path:
        return self.runtime_dir / "ballots"

    @property
    def database_path(self) -> Path:
        return self.runtime_dir / "voting.sqlite3"

    def validate(self) -> None:
        if self.evaluator not in {"openfhe", "heir-openfhe"}:
            raise ValueError(f"unsupported HE evaluator: {self.evaluator}")
        required_files = [
            self.crypto_bin,
            self.public_dir / "crypto_context.bin",
            self.public_dir / "public_key.bin",
            self.public_dir / "eval_mult_keys.bin",
            self.public_dir / "encrypted_one.ct",
            self.state_dir / "tally.ct",
        ]
        missing = [str(path) for path in required_files if not path.is_file()]
        if missing:
            raise FileNotFoundError(
                "election runtime is incomplete; missing: " + ", ".join(missing)
            )


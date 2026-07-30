#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "python"))

from he_voting.openfhe_backend import OpenFHEBackend  # noqa: E402
from he_voting.service import VotingService  # noqa: E402
from he_voting.settings import Settings  # noqa: E402


def read_tokens(roster_path: Path) -> list[str]:
    with roster_path.open(encoding="utf-8", newline="") as input_file:
        rows = list(csv.DictReader(input_file))
    if not rows:
        raise ValueError("roster must contain at least one employee")

    tokens: list[str] = []
    for row in rows:
        token = row.get("voter_token", "").strip().lower()
        if len(token) != 64:
            raise ValueError(
                f"employee {row.get('employee_id')} has an invalid voter token"
            )
        bytes.fromhex(token)
        tokens.append(token)
    if len(tokens) != len(set(tokens)):
        raise ValueError("voter tokens must be unique")
    return tokens


def setup_election(
    roster_path: Path,
    runtime_dir: Path,
    trustee_dir: Path,
) -> dict[str, object]:
    if runtime_dir.exists() and any(runtime_dir.iterdir()):
        raise FileExistsError(
            f"runtime directory is not empty: {runtime_dir}"
        )
    if trustee_dir.exists() and any(trustee_dir.iterdir()):
        raise FileExistsError(
            f"trustee directory is not empty: {trustee_dir}"
        )

    crypto = OpenFHEBackend()
    runtime_dir.mkdir(parents=True, exist_ok=True)
    trustee_dir.mkdir(parents=True, exist_ok=True)
    public_dir = runtime_dir / "public"
    state_dir = runtime_dir / "state"
    flags_dir = runtime_dir / "flags"
    ballots_dir = runtime_dir / "ballots"
    ballots_dir.mkdir(parents=True, exist_ok=True)

    tokens = read_tokens(roster_path)
    token_hashes = [
        hashlib.sha256(token.encode("ascii")).hexdigest()
        for token in tokens
    ]
    crypto_parameters = crypto.setup(
        public_dir=public_dir,
        trustee_dir=trustee_dir,
        state_dir=state_dir,
    )
    crypto.initialize_flags(
        token_hashes=token_hashes,
        flags_dir=flags_dir,
    )

    settings = Settings(runtime_dir=runtime_dir)
    service = VotingService(settings)
    service.register_tokens(tokens)

    manifest = {
        "employee_count": len(tokens),
        "crypto": crypto_parameters,
    }
    (runtime_dir / "election.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Initialize encrypted flags, tally, and API runtime."
    )
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--trustee-dir", type=Path, required=True)
    parser.add_argument(
        "--force",
        action="store_true",
        help="Remove only the explicitly supplied runtime and trustee directories.",
    )
    arguments = parser.parse_args()

    runtime_dir = arguments.runtime_dir.resolve()
    trustee_dir = arguments.trustee_dir.resolve()
    if arguments.force:
        for path in (runtime_dir, trustee_dir):
            if path.exists():
                shutil.rmtree(path)

    manifest = setup_election(
        roster_path=arguments.roster.resolve(),
        runtime_dir=runtime_dir,
        trustee_dir=trustee_dir,
    )
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()

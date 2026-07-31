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
sys.path.insert(0, str(PROJECT_DIR))
sys.path.insert(0, str(PROJECT_DIR / "python"))

from app.settings import Settings  # noqa: E402
from app.voting_service import VotingService  # noqa: E402
from he_voting.openfhe_backend import OpenFHEBackend  # noqa: E402


def read_employees(employees_path: Path) -> list[tuple[str, str]]:
    with employees_path.open(encoding="utf-8", newline="") as input_file:
        rows = list(csv.DictReader(input_file))
    if not rows:
        raise ValueError("employees CSV must contain at least one employee")

    employees: list[tuple[str, str]] = []
    for row in rows:
        employee_id = row.get("employee_id", "").strip()
        display_name = row.get("display_name", "").strip()
        if not employee_id:
            raise ValueError("every employee row needs employee_id")
        employees.append((employee_id, display_name or employee_id))
    if len({employee_id for employee_id, _ in employees}) != len(employees):
        raise ValueError("employee IDs must be unique")
    return employees


def setup_election(
    employees_path: Path,
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
    ballots_dir = runtime_dir / "ballots"
    ballots_dir.mkdir(parents=True, exist_ok=True)

    employees = read_employees(employees_path)
    crypto_parameters = crypto.setup(
        public_dir=public_dir,
        trustee_dir=trustee_dir,
        state_dir=state_dir,
    )

    settings = Settings(runtime_dir=runtime_dir)
    service = VotingService(settings)
    service.register_employees(employees)

    context_sha256 = hashlib.sha256(
        (public_dir / "crypto_context.bin").read_bytes()
    ).hexdigest()
    public_key_sha256 = hashlib.sha256(
        (public_dir / "public_key.bin").read_bytes()
    ).hexdigest()
    secret_key_sha256 = hashlib.sha256(
        (trustee_dir / "secret_key.bin").read_bytes()
    ).hexdigest()
    manifest = {
        "runtime_version": 4,
        "employee_count": len(employees),
        "participation_tracking": "ballot-metadata",
        "context_sha256": context_sha256,
        "context_id": context_sha256[:16],
        "public_key_sha256": public_key_sha256,
        "crypto": crypto_parameters,
    }
    (runtime_dir / "election.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    (trustee_dir / "election-key.json").write_text(
        json.dumps(
            {
                "context_sha256": context_sha256,
                "context_id": context_sha256[:16],
                "public_key_sha256": public_key_sha256,
                "secret_key_sha256": secret_key_sha256,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Initialize encrypted tallies and the voting API runtime."
    )
    parser.add_argument("--employees", type=Path, required=True)
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
        employees_path=arguments.employees.resolve(),
        runtime_dir=runtime_dir,
        trustee_dir=trustee_dir,
    )
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()

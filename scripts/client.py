#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "python"))

from he_voting.openfhe_backend import OpenFHEBackend  # noqa: E402


def find_voter_token(roster_path: Path, employee_id: str) -> str:
    with roster_path.open(encoding="utf-8", newline="") as input_file:
        for row in csv.DictReader(input_file):
            if row["employee_id"] == employee_id:
                return row["voter_token"]
    raise ValueError(f"employee ID not found in local roster: {employee_id}")


class VoteEncryptor:
    """Loads public election material once and encrypts rows separately."""

    def __init__(self, public_directory: Path):
        self.backend = OpenFHEBackend(public_directory.resolve())

    def encrypt_choice(self, choice: str) -> dict[str, bytes]:
        return self.backend.encrypt_choice(choice)


def encrypt_choice(
    public_directory: Path,
    choice: str,
) -> dict[str, bytes]:
    return VoteEncryptor(public_directory).encrypt_choice(choice)


def submit_vote(
    api_url: str,
    voter_token: str,
    encrypted_choice: dict[str, bytes],
) -> dict[str, object]:
    payload = json.dumps(
        {
            "voter_token": voter_token,
            "encrypted_choice_a": base64.b64encode(
                encrypted_choice["a"]
            ).decode("ascii"),
            "encrypted_choice_b": base64.b64encode(
                encrypted_choice["b"]
            ).decode("ascii"),
            "encrypted_choice_c": base64.b64encode(
                encrypted_choice["c"]
            ).decode("ascii"),
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        api_url.rstrip("/") + "/election/vote",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"vote API returned HTTP {error.code}: {detail}"
        ) from error


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Encrypt one A/B/C choice locally and submit it with the employee's "
            "random voter token. The employee ID is never sent to the API."
        )
    )
    parser.add_argument("--employee-id", required=True)
    parser.add_argument("--choice", choices=["A", "B", "C"], required=True)
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    arguments = parser.parse_args()

    voter_token = find_voter_token(
        arguments.roster.resolve(),
        arguments.employee_id,
    )
    ciphertext = encrypt_choice(
        arguments.public_dir.resolve(),
        arguments.choice,
    )
    response = submit_vote(
        arguments.api_url,
        voter_token,
        ciphertext,
    )
    print(json.dumps(response))


if __name__ == "__main__":
    main()

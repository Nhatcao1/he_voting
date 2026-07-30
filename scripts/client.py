#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import json
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "python"))

from he_voting.crypto_cli import CryptoCli  # noqa: E402


def find_voter_token(roster_path: Path, employee_id: str) -> str:
    with roster_path.open(encoding="utf-8", newline="") as input_file:
        for row in csv.DictReader(input_file):
            if row["employee_id"] == employee_id:
                return row["voter_token"]
    raise ValueError(f"employee ID not found in local roster: {employee_id}")


def encrypt_choice(
    crypto_binary: Path,
    public_directory: Path,
    choice: str,
) -> bytes:
    with tempfile.TemporaryDirectory(prefix="he-vote-client-") as temporary:
        output_path = Path(temporary) / "choice.ct"
        CryptoCli(crypto_binary).encrypt_choice(
            public_dir=public_directory,
            choice=choice,
            output=output_path,
        )
        return output_path.read_bytes()


def submit_vote(
    api_url: str,
    voter_token: str,
    encrypted_choice: bytes,
) -> dict[str, object]:
    payload = json.dumps(
        {
            "voter_token": voter_token,
            "encrypted_choice": base64.b64encode(
                encrypted_choice
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
    parser.add_argument(
        "--crypto-bin",
        type=Path,
        default=PROJECT_DIR / "build" / "he_voting_crypto",
    )
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    arguments = parser.parse_args()

    voter_token = find_voter_token(
        arguments.roster.resolve(),
        arguments.employee_id,
    )
    ciphertext = encrypt_choice(
        arguments.crypto_bin.resolve(),
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


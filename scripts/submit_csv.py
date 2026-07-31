#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "scripts"))

from client import VoteEncryptor, submit_vote  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Encrypt and submit a two-column employee_id,choice CSV."
    )
    parser.add_argument("--votes", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    arguments = parser.parse_args()

    with arguments.votes.resolve().open(
        encoding="utf-8", newline=""
    ) as input_file:
        rows = list(csv.DictReader(input_file))

    encryptor = VoteEncryptor(arguments.public_dir.resolve())
    receipts: list[dict[str, object]] = []
    for index, row in enumerate(rows, start=1):
        employee_id = row["employee_id"]
        choice = row["choice"]
        ciphertext = encryptor.encrypt_choice(choice)
        receipt = submit_vote(
            arguments.api_url,
            employee_id,
            ciphertext,
        )
        receipts.append(receipt)
        print(
            json.dumps(
                {
                    "row": index,
                    "receipt": receipt["receipt"],
                    "status": receipt["status"],
                }
            )
        )

    print(json.dumps({"submitted": len(receipts)}))


if __name__ == "__main__":
    main()

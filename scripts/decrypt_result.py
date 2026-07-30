#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "python"))

from he_voting.crypto_cli import CryptoCli  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Trustee-side decryption of only the aggregate A/B/C tally."
    )
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--trustee-dir", type=Path, required=True)
    parser.add_argument(
        "--crypto-bin",
        type=Path,
        default=PROJECT_DIR / "build" / "he_voting_crypto",
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Write the decrypted aggregate to runtime/published_result.json.",
    )
    arguments = parser.parse_args()

    runtime_dir = arguments.runtime_dir.resolve()
    result = CryptoCli(arguments.crypto_bin.resolve()).decrypt_result(
        public_dir=runtime_dir / "public",
        trustee_dir=arguments.trustee_dir.resolve(),
        tally=runtime_dir / "state" / "tally.ct",
    )
    if arguments.publish:
        (runtime_dir / "published_result.json").write_text(
            json.dumps(result, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(result))


if __name__ == "__main__":
    main()


#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "scripts"))

from generate_data import generate  # noqa: E402


DEFAULT_QUOTAS = (100, 1_000, 10_000)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Generate 100, 1,000, and 10,000-row voting benchmark fixtures "
            "with a chosen duplicate percentage."
        )
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--duplicate-percent",
        type=int,
        choices=[10, 20],
        default=10,
    )
    parser.add_argument(
        "--quotas",
        type=int,
        nargs="+",
        default=list(DEFAULT_QUOTAS),
    )
    parser.add_argument("--seed", type=int, default=20260730)
    arguments = parser.parse_args()

    root = arguments.out_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    fixtures: list[dict[str, object]] = []

    for quota in arguments.quotas:
        if quota < 2:
            raise ValueError("each quota must be at least 2")
        duplicate_count = round(
            quota * arguments.duplicate_percent / 100
        )
        unique_count = quota - duplicate_count
        fixture_dir = root / (
            f"votes_{quota}_dup{arguments.duplicate_percent}"
        )
        expected = generate(
            output_directory=fixture_dir,
            employee_count=unique_count,
            vote_count=quota,
            duplicate_count=duplicate_count,
            seed=arguments.seed + quota,
        )
        fixtures.append(
            {
                "quota": quota,
                "unique_employees": unique_count,
                "duplicate_votes": duplicate_count,
                "duplicate_percent": arguments.duplicate_percent,
                "directory": str(fixture_dir),
                "expected_result": expected,
            }
        )

    manifest = {
        "duplicate_percent": arguments.duplicate_percent,
        "fixtures": fixtures,
    }
    (root / "benchmark_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()


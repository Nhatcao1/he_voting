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
            "Generate 100, 1,000, and 10,000-row voting benchmark fixtures."
        )
    )
    parser.add_argument("--out-dir", type=Path, required=True)
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
        fixture_dir = root / f"votes_{quota}"
        expected = generate(
            output_directory=fixture_dir,
            employee_count=quota,
            vote_count=quota,
            seed=arguments.seed + quota,
        )
        fixtures.append(
            {
                "quota": quota,
                "employees": quota,
                "directory": str(fixture_dir),
                "expected_result": expected,
            }
        )

    manifest = {"fixtures": fixtures}
    (root / "benchmark_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()

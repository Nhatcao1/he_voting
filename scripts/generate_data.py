#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


CHOICES = ("A", "B", "C")


def deterministic_token(seed: int, employee_id: str) -> str:
    material = f"he-voting:{seed}:{employee_id}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def generate(
    output_directory: Path,
    employee_count: int,
    vote_count: int,
    seed: int,
) -> dict[str, int]:
    if employee_count < 1:
        raise ValueError("employee_count must be positive")
    if vote_count < 1:
        raise ValueError("vote_count must be positive")
    if vote_count > employee_count:
        raise ValueError(
            "vote count cannot exceed the employee count; increase --employees"
        )

    output_directory.mkdir(parents=True, exist_ok=True)

    roster: list[dict[str, str | int]] = []
    for index in range(employee_count):
        employee_id = str(100001 + index)
        roster.append(
            {
                "employee_id": employee_id,
                "display_name": f"Employee {index + 1:05d}",
                "voter_token": deterministic_token(seed, employee_id),
            }
        )

    votes: list[dict[str, str]] = []
    for index in range(vote_count):
        votes.append(
            {
                "employee_id": str(roster[index]["employee_id"]),
                "choice": CHOICES[index % len(CHOICES)],
            }
        )

    roster_path = output_directory / "roster.csv"
    with roster_path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=["employee_id", "display_name", "voter_token"],
        )
        writer.writeheader()
        writer.writerows(roster)

    votes_path = output_directory / "votes.csv"
    with votes_path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=["employee_id", "choice"],
        )
        writer.writeheader()
        writer.writerows(votes)

    expected = {"A": 0, "B": 0, "C": 0}
    for row in votes:
        expected[row["choice"]] += 1

    (output_directory / "expected_result.json").write_text(
        json.dumps(expected, indent=2) + "\n",
        encoding="utf-8",
    )
    return expected


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a local employee roster and a two-column A/B/C vote fixture."
        )
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--employees", type=int, default=16)
    parser.add_argument("--votes", type=int, default=4)
    parser.add_argument("--seed", type=int, default=20260729)
    arguments = parser.parse_args()

    expected = generate(
        output_directory=arguments.out_dir.resolve(),
        employee_count=arguments.employees,
        vote_count=arguments.votes,
        seed=arguments.seed,
    )
    print(
        json.dumps(
            {
                "roster": str((arguments.out_dir / "roster.csv").resolve()),
                "votes": str((arguments.out_dir / "votes.csv").resolve()),
                "expected": expected,
            }
        )
    )


if __name__ == "__main__":
    main()

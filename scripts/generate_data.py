#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from pathlib import Path


CHOICES = ("A", "B", "C")


def deterministic_token(seed: int, employee_id: str) -> str:
    material = f"he-voting:{seed}:{employee_id}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def generate(
    output_directory: Path,
    employee_count: int,
    vote_count: int,
    duplicate_count: int,
    seed: int,
) -> dict[str, int]:
    if employee_count < 1:
        raise ValueError("employee_count must be positive")
    if vote_count < 1:
        raise ValueError("vote_count must be positive")
    if duplicate_count < 0 or duplicate_count >= vote_count:
        raise ValueError("duplicate_count must be between 0 and vote_count - 1")

    unique_vote_count = vote_count - duplicate_count
    if unique_vote_count > employee_count:
        raise ValueError(
            "unique vote count cannot exceed the employee count; "
            "increase --employees or --duplicates"
        )

    output_directory.mkdir(parents=True, exist_ok=True)
    randomizer = random.Random(seed)

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

    first_votes: list[dict[str, str]] = []
    for index in range(unique_vote_count):
        first_votes.append(
            {
                "employee_id": str(roster[index]["employee_id"]),
                "choice": CHOICES[index % len(CHOICES)],
            }
        )

    duplicate_votes: list[dict[str, str]] = []
    for index in range(duplicate_count):
        original = first_votes[index % len(first_votes)]
        original_choice_index = CHOICES.index(original["choice"])
        duplicate_votes.append(
            {
                "employee_id": original["employee_id"],
                "choice": CHOICES[(original_choice_index + 1) % len(CHOICES)],
            }
        )
    randomizer.shuffle(duplicate_votes)
    votes = first_votes + duplicate_votes

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

    seen: set[str] = set()
    expected = {"A": 0, "B": 0, "C": 0}
    for row in votes:
        if row["employee_id"] in seen:
            continue
        seen.add(row["employee_id"])
        expected[row["choice"]] += 1

    (output_directory / "expected_result.json").write_text(
        json.dumps(expected, indent=2) + "\n",
        encoding="utf-8",
    )
    return expected


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a local employee roster and a two-column A/B/C vote "
            "fixture with deliberate duplicate employees."
        )
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--employees", type=int, default=16)
    parser.add_argument("--votes", type=int, default=4)
    parser.add_argument("--duplicates", type=int, default=1)
    parser.add_argument("--seed", type=int, default=20260729)
    arguments = parser.parse_args()

    expected = generate(
        output_directory=arguments.out_dir.resolve(),
        employee_count=arguments.employees,
        vote_count=arguments.votes,
        duplicate_count=arguments.duplicates,
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


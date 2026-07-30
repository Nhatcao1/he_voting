#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
import time
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "scripts"))

from client import encrypt_choice, submit_vote  # noqa: E402


def read_roster_tokens(path: Path) -> dict[str, str]:
    with path.open(encoding="utf-8", newline="") as input_file:
        rows = list(csv.DictReader(input_file))
    return {
        row["employee_id"]: row["voter_token"]
        for row in rows
    }


def read_votes(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as input_file:
        rows = list(csv.DictReader(input_file))
    if not rows:
        raise ValueError("vote benchmark CSV is empty")
    for row in rows:
        if row["choice"] not in {"A", "B", "C"}:
            raise ValueError(
                f"invalid choice for employee {row['employee_id']}"
            )
    return rows


def percentile95(values: list[float]) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[min(index, len(ordered) - 1)]


def metric_summary(values: list[float]) -> dict[str, float]:
    return {
        "average": round(statistics.fmean(values), 3),
        "median": round(statistics.median(values), 3),
        "p95": round(percentile95(values), 3),
        "minimum": round(min(values), 3),
        "maximum": round(max(values), 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Submit every benchmark row individually through the real HTTP API "
            "and record per-vote and overall processing time."
        )
    )
    parser.add_argument("--votes", type=Path, required=True)
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument(
        "--crypto-bin",
        type=Path,
        default=PROJECT_DIR / "build" / "he_voting_crypto",
    )
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--progress-every", type=int, default=100)
    arguments = parser.parse_args()

    votes = read_votes(arguments.votes.resolve())
    token_by_employee = read_roster_tokens(arguments.roster.resolve())
    output_directory = arguments.out_dir.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    per_vote_path = output_directory / "per_vote_times.csv"

    encryption_times: list[float] = []
    http_times: list[float] = []
    server_times: list[float] = []
    end_to_end_times: list[float] = []
    seen_employees: set[str] = set()
    duplicate_count = 0

    overall_started = time.perf_counter()
    with per_vote_path.open(
        "w", encoding="utf-8", newline=""
    ) as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=[
                "row",
                "is_duplicate",
                "encrypt_ms",
                "http_round_trip_ms",
                "server_processing_ms",
                "end_to_end_ms",
                "receipt",
            ],
        )
        writer.writeheader()

        for row_number, row in enumerate(votes, start=1):
            employee_id = row["employee_id"]
            voter_token = token_by_employee.get(employee_id)
            if voter_token is None:
                raise ValueError(
                    f"employee {employee_id} is missing from the roster"
                )

            is_duplicate = employee_id in seen_employees
            if is_duplicate:
                duplicate_count += 1
            else:
                seen_employees.add(employee_id)

            vote_started = time.perf_counter()
            encryption_started = time.perf_counter()
            ciphertexts = encrypt_choice(
                arguments.crypto_bin.resolve(),
                arguments.public_dir.resolve(),
                row["choice"],
            )
            encryption_ms = (
                time.perf_counter() - encryption_started
            ) * 1000.0

            http_started = time.perf_counter()
            response = submit_vote(
                arguments.api_url,
                voter_token,
                ciphertexts,
            )
            http_ms = (time.perf_counter() - http_started) * 1000.0
            end_to_end_ms = (
                time.perf_counter() - vote_started
            ) * 1000.0
            server_ms = float(response["processing_ms"])

            encryption_times.append(encryption_ms)
            http_times.append(http_ms)
            server_times.append(server_ms)
            end_to_end_times.append(end_to_end_ms)
            writer.writerow(
                {
                    "row": row_number,
                    "is_duplicate": str(is_duplicate).lower(),
                    "encrypt_ms": f"{encryption_ms:.3f}",
                    "http_round_trip_ms": f"{http_ms:.3f}",
                    "server_processing_ms": f"{server_ms:.3f}",
                    "end_to_end_ms": f"{end_to_end_ms:.3f}",
                    "receipt": response["receipt"],
                }
            )
            output_file.flush()

            if (
                arguments.progress_every > 0
                and (
                    row_number % arguments.progress_every == 0
                    or row_number == len(votes)
                )
            ):
                print(
                    json.dumps(
                        {
                            "processed": row_number,
                            "total": len(votes),
                            "latest_server_ms": round(server_ms, 3),
                        }
                    ),
                    flush=True,
                )

    total_seconds = time.perf_counter() - overall_started
    summary = {
        "votes_submitted": len(votes),
        "unique_employees": len(seen_employees),
        "duplicate_votes": duplicate_count,
        "duplicate_percent": round(
            duplicate_count * 100.0 / len(votes), 2
        ),
        "total_wall_seconds": round(total_seconds, 3),
        "throughput_votes_per_second": round(
            len(votes) / total_seconds, 3
        ),
        "per_vote_ms": {
            "encryption": metric_summary(encryption_times),
            "http_round_trip": metric_summary(http_times),
            "server_processing": metric_summary(server_times),
            "end_to_end": metric_summary(end_to_end_times),
        },
        "per_vote_csv": str(per_vote_path),
    }
    summary_path = output_directory / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary))


if __name__ == "__main__":
    main()

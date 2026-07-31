#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import math
import shutil
import statistics
import sys
import time
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))
sys.path.insert(0, str(PROJECT_DIR / "scripts"))
sys.path.insert(0, str(PROJECT_DIR / "python"))

from app.settings import Settings  # noqa: E402
from app.voting_service import VotingService  # noqa: E402
from client import VoteEncryptor  # noqa: E402
from he_voting.openfhe_backend import OpenFHEBackend  # noqa: E402


CHOICE_NAMES = ("a", "b", "c")
ENCODINGS = {
    "A": (1, 0, 0),
    "B": (0, 1, 0),
    "C": (0, 0, 1),
}


def read_employees(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as input_file:
        rows = list(csv.DictReader(input_file))
    if not rows:
        raise ValueError("employees CSV is empty")
    return rows


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


def ciphertext_evidence(
    *,
    value: bytes,
    path: Path,
    output_directory: Path,
) -> dict[str, str | int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return {
        "file": str(path.relative_to(output_directory)),
        "bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "preview_base64": base64.b64encode(value[:48]).decode("ascii"),
    }


def expected_from_rows(votes: list[dict[str, str]]) -> dict[str, int]:
    result = {"A": 0, "B": 0, "C": 0}
    for row in votes:
        result[row["choice"]] += 1
    return result


def copy_key_bundle(
    *,
    public_directory: Path,
    trustee_directory: Path,
    output_directory: Path,
) -> tuple[Path, list[tuple[str, str]]]:
    """Copy all material needed to reproduce and decrypt this benchmark.

    This voting workload performs ciphertext addition only, so OpenFHE does
    not generate multiplication, rotation, or other evaluation keys.
    """
    key_bundle_directory = output_directory / "key_bundle"
    public_bundle_directory = key_bundle_directory / "public"
    evaluation_bundle_directory = (
        public_bundle_directory / "evaluation_keys"
    )
    private_bundle_directory = key_bundle_directory / "private"
    public_bundle_directory.mkdir(parents=True, exist_ok=True)
    evaluation_bundle_directory.mkdir(parents=True, exist_ok=True)
    private_bundle_directory.mkdir(parents=True, exist_ok=True)

    required_files = (
        (
            public_directory / "crypto_context.bin",
            public_bundle_directory / "crypto_context.bin",
            "crypto_context",
        ),
        (
            public_directory / "public_key.bin",
            public_bundle_directory / "public_key.bin",
            "public_key",
        ),
        (
            trustee_directory / "secret_key.bin",
            private_bundle_directory / "secret_key.bin",
            "secret_key",
        ),
    )
    copied_files: dict[str, str] = {}
    checksum_rows: list[tuple[str, str]] = []
    for source, destination, material_name in required_files:
        if not source.is_file():
            raise FileNotFoundError(
                f"cannot create benchmark key bundle; missing {source}"
            )
        shutil.copy2(source, destination)
        if material_name == "secret_key":
            destination.chmod(0o600)
        relative_path = str(destination.relative_to(output_directory))
        copied_files[material_name] = relative_path
        checksum_rows.append(
            (hashlib.sha256(destination.read_bytes()).hexdigest(), relative_path)
        )

    evaluation_key_sources = sorted(
        path
        for path in public_directory.iterdir()
        if path.is_file()
        and (
            "eval" in path.name.lower()
            or "rotation" in path.name.lower()
            or "automorphism" in path.name.lower()
            or "relinear" in path.name.lower()
        )
    )
    evaluation_key_files: list[str] = []
    for source in evaluation_key_sources:
        destination = evaluation_bundle_directory / source.name
        shutil.copy2(source, destination)
        relative_path = str(destination.relative_to(output_directory))
        evaluation_key_files.append(relative_path)
        checksum_rows.append(
            (hashlib.sha256(destination.read_bytes()).hexdigest(), relative_path)
        )

    manifest_path = key_bundle_directory / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "warning": (
                    "PRIVATE: this bundle contains the election secret key and "
                    "can decrypt the retained benchmark tally."
                ),
                "public_material": {
                    "crypto_context": copied_files["crypto_context"],
                    "public_key": copied_files["public_key"],
                },
                "private_material": {
                    "secret_key": copied_files["secret_key"],
                },
                "evaluation_keys": {
                    "generated": bool(evaluation_key_files),
                    "files": evaluation_key_files,
                    "reason": (
                        "Serialized evaluation keys found in the election "
                        "public directory were copied."
                        if evaluation_key_files
                        else (
                            "The ballot tally uses ciphertext EvalAdd only; "
                            "multiplication and rotation evaluation keys are "
                            "not required or generated."
                        )
                    ),
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest_relative_path = str(manifest_path.relative_to(output_directory))
    checksum_rows.append(
        (
            hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            manifest_relative_path,
        )
    )
    return key_bundle_directory, checksum_rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Encrypt and process every benchmark row synchronously, one at a "
            "time, and record per-vote and overall timing."
        )
    )
    parser.add_argument("--votes", type=Path, required=True)
    parser.add_argument("--employees", type=Path, required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--trustee-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--progress-every", type=int, default=100)
    arguments = parser.parse_args()

    votes = read_votes(arguments.votes.resolve())
    employee_rows = read_employees(arguments.employees.resolve())
    prepared_employee_ids = {
        row["employee_id"] for row in employee_rows
    }
    settings = Settings(runtime_dir=arguments.runtime_dir.resolve())
    encryptor = VoteEncryptor(settings.public_dir)
    service = VotingService(settings)
    output_directory = arguments.out_dir.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    per_vote_path = output_directory / "per_vote_times.csv"
    evidence_path = output_directory / "vote_evidence.csv"
    ciphertext_root = output_directory / "ciphertexts"
    final_tally_directory = ciphertext_root / "final_tally"
    shutil.copy2(arguments.votes.resolve(), output_directory / "input_votes.csv")

    encryption_times: list[float] = []
    processing_times: list[float] = []
    end_to_end_times: list[float] = []
    expected_result = expected_from_rows(votes)
    checksum_rows: list[tuple[str, str]] = []
    key_bundle_directory, key_bundle_checksums = copy_key_bundle(
        public_directory=settings.public_dir,
        trustee_directory=arguments.trustee_dir.resolve(),
        output_directory=output_directory,
    )
    checksum_rows.extend(key_bundle_checksums)

    overall_started = time.perf_counter()
    with (
        per_vote_path.open("w", encoding="utf-8", newline="") as timing_file,
        evidence_path.open("w", encoding="utf-8", newline="") as evidence_file,
    ):
        timing_writer = csv.DictWriter(
            timing_file,
            fieldnames=[
                "row",
                "encrypt_ms",
                "server_processing_ms",
                "end_to_end_ms",
                "status",
                "receipt",
            ],
        )
        evidence_fields = [
            "row",
            "employee_id",
            "input_choice",
            "encoded_a",
            "encoded_b",
            "encoded_c",
            "server_status",
            "choice_a_file",
            "choice_a_bytes",
            "choice_a_sha256",
            "choice_a_preview_base64",
            "choice_b_file",
            "choice_b_bytes",
            "choice_b_sha256",
            "choice_b_preview_base64",
            "choice_c_file",
            "choice_c_bytes",
            "choice_c_sha256",
            "choice_c_preview_base64",
        ]
        evidence_writer = csv.DictWriter(
            evidence_file,
            fieldnames=evidence_fields,
        )
        timing_writer.writeheader()
        evidence_writer.writeheader()

        for row_number, row in enumerate(votes, start=1):
            employee_id = row["employee_id"]
            if employee_id not in prepared_employee_ids:
                raise ValueError(
                    f"employee {employee_id} is missing from employees.csv"
                )

            vote_started = time.perf_counter()
            encryption_started = time.perf_counter()
            ciphertexts = encryptor.encrypt_choice(row["choice"])
            encryption_ms = (
                time.perf_counter() - encryption_started
            ) * 1000.0

            processing_started = time.perf_counter()
            receipt = service.submit(
                employee_id,
                ciphertexts,
            )
            processing_ms = (
                time.perf_counter() - processing_started
            ) * 1000.0
            end_to_end_ms = (
                time.perf_counter() - vote_started
            ) * 1000.0

            # Evidence copying is intentionally outside the measured vote path.
            ballot_evidence: dict[str, dict[str, str | int]] = {}
            for choice_name in CHOICE_NAMES:
                metadata = ciphertext_evidence(
                    value=ciphertexts[choice_name],
                    path=(
                        ciphertext_root
                        / "ballots"
                        / f"row_{row_number:06d}"
                        / f"choice_{choice_name}.ct"
                    ),
                    output_directory=output_directory,
                )
                ballot_evidence[choice_name] = metadata
                checksum_rows.append(
                    (str(metadata["sha256"]), str(metadata["file"]))
                )

            encryption_times.append(encryption_ms)
            processing_times.append(processing_ms)
            end_to_end_times.append(end_to_end_ms)
            timing_writer.writerow(
                {
                    "row": row_number,
                    "encrypt_ms": f"{encryption_ms:.3f}",
                    "server_processing_ms": f"{processing_ms:.3f}",
                    "end_to_end_ms": f"{end_to_end_ms:.3f}",
                    "status": receipt.status,
                    "receipt": receipt.receipt,
                }
            )
            encoding = ENCODINGS[row["choice"]]
            evidence_row: dict[str, object] = {
                "row": row_number,
                "employee_id": employee_id,
                "input_choice": row["choice"],
                "encoded_a": encoding[0],
                "encoded_b": encoding[1],
                "encoded_c": encoding[2],
                "server_status": receipt.status,
            }
            for choice_name in CHOICE_NAMES:
                metadata = ballot_evidence[choice_name]
                for property_name in (
                    "file",
                    "bytes",
                    "sha256",
                    "preview_base64",
                ):
                    evidence_row[
                        f"choice_{choice_name}_{property_name}"
                    ] = metadata[property_name]
            evidence_writer.writerow(evidence_row)
            timing_file.flush()
            evidence_file.flush()

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
                            "latest_status": receipt.status,
                            "latest_encrypt_ms": round(encryption_ms, 3),
                            "latest_server_processing_ms": round(
                                processing_ms, 3
                            ),
                        }
                    ),
                    flush=True,
                )

    benchmark_loop_seconds = time.perf_counter() - overall_started
    vote_path_seconds = sum(end_to_end_times) / 1000.0
    evidence_overhead_seconds = max(
        0.0,
        benchmark_loop_seconds - vote_path_seconds,
    )
    final_tally_directory.mkdir(parents=True, exist_ok=True)
    final_tally_evidence: dict[str, dict[str, str | int]] = {}
    for choice_name in CHOICE_NAMES:
        source = settings.state_dir / f"tally_{choice_name}.ct"
        destination = final_tally_directory / f"tally_{choice_name}.ct"
        value = source.read_bytes()
        metadata = ciphertext_evidence(
            value=value,
            path=destination,
            output_directory=output_directory,
        )
        final_tally_evidence[choice_name] = metadata
        checksum_rows.append(
            (str(metadata["sha256"]), str(metadata["file"]))
        )

    decrypted_result = OpenFHEBackend(
        settings.public_dir
    ).decrypt_result(
        trustee_dir=arguments.trustee_dir.resolve(),
        tally_directory=settings.state_dir,
    )
    decrypted_total = sum(decrypted_result.values())
    participation_records = service.participation_records()
    result_matches = (
        decrypted_result == expected_result
        and decrypted_total == len(votes)
    )

    expected_path = output_directory / "expected_result.json"
    expected_path.write_text(
        json.dumps(
            {
                "choice_totals": expected_result,
                "total_votes": len(votes),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    decrypted_path = output_directory / "decrypted_result.json"
    decrypted_path.write_text(
        json.dumps(
            {
                "choice_totals": decrypted_result,
                "total": decrypted_total,
                "matches_expected": result_matches,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    participation_path = output_directory / "participation.csv"
    with participation_path.open(
        "w", encoding="utf-8", newline=""
    ) as participation_file:
        participation_writer = csv.DictWriter(
            participation_file,
            fieldnames=[
                "employee_id",
                "display_name",
                "submitted",
                "submitted_at",
            ],
        )
        participation_writer.writeheader()
        for employee_row in employee_rows:
            record = participation_records.get(employee_row["employee_id"])
            participation_writer.writerow(
                {
                    "employee_id": employee_row["employee_id"],
                    "display_name": employee_row.get("display_name", ""),
                    "submitted": str(record is not None).lower(),
                    "submitted_at": "" if record is None else record,
                }
            )

    final_result_path = output_directory / "final_result.csv"
    with final_result_path.open(
        "w", encoding="utf-8", newline=""
    ) as result_file:
        result_writer = csv.DictWriter(
            result_file,
            fieldnames=[
                "choice",
                "expected_count",
                "decrypted_count",
                "matches",
                "encrypted_tally_file",
                "ciphertext_bytes",
                "ciphertext_sha256",
                "ciphertext_preview_base64",
            ],
        )
        result_writer.writeheader()
        for choice_name in CHOICE_NAMES:
            choice = choice_name.upper()
            metadata = final_tally_evidence[choice_name]
            result_writer.writerow(
                {
                    "choice": choice,
                    "expected_count": expected_result[choice],
                    "decrypted_count": decrypted_result[choice],
                    "matches": str(
                        expected_result[choice] == decrypted_result[choice]
                    ).lower(),
                    "encrypted_tally_file": metadata["file"],
                    "ciphertext_bytes": metadata["bytes"],
                    "ciphertext_sha256": metadata["sha256"],
                    "ciphertext_preview_base64": metadata[
                        "preview_base64"
                    ],
                }
            )

    checksums_path = output_directory / "checksums.sha256"
    checksums_path.write_text(
        "".join(
            f"{digest}  {relative_path}\n"
            for digest, relative_path in checksum_rows
        ),
        encoding="utf-8",
    )

    summary = {
        "votes_submitted": len(votes),
        "eligible_employees": len(employee_rows),
        "participating_employees": len(participation_records),
        "total_vote_path_seconds": round(vote_path_seconds, 3),
        "benchmark_loop_seconds_including_evidence": round(
            benchmark_loop_seconds, 3
        ),
        "evidence_capture_overhead_seconds": round(
            evidence_overhead_seconds, 3
        ),
        "throughput_votes_per_second": round(
            len(votes) / vote_path_seconds, 3
        ),
        "expected_result": expected_result,
        "decrypted_result": decrypted_result,
        "decrypted_total": decrypted_total,
        "result_matches_expected": result_matches,
        "per_vote_ms": {
            "encryption": metric_summary(encryption_times),
            "encrypted_tally_processing": metric_summary(processing_times),
            "end_to_end": metric_summary(end_to_end_times),
        },
        "artifacts": {
            "input_votes_csv": str(output_directory / "input_votes.csv"),
            "per_vote_times_csv": str(per_vote_path),
            "vote_evidence_csv": str(evidence_path),
            "participation_csv": str(participation_path),
            "final_result_csv": str(final_result_path),
            "expected_result_json": str(expected_path),
            "decrypted_result_json": str(decrypted_path),
            "ciphertext_directory": str(ciphertext_root),
            "key_bundle_directory": str(key_bundle_directory),
            "key_bundle_manifest": str(
                key_bundle_directory / "manifest.json"
            ),
            "checksums_sha256": str(checksums_path),
        },
    }
    summary_path = output_directory / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary))


if __name__ == "__main__":
    main()

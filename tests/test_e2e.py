from __future__ import annotations

import base64
import csv
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.settings import Settings
from app.voting_service import AlreadyVotedError, VotingService
from client import encrypt_choice
from generate_data import generate
from he_voting.openfhe_backend import OpenFHEBackend
from setup_election import setup_election


@pytest.fixture()
def election(tmp_path: Path) -> dict[str, Path | Settings]:
    pytest.importorskip("openfhe")

    generated = tmp_path / "generated"
    runtime = tmp_path / "runtime"
    trustee = tmp_path / "trustee"
    expected = generate(
        output_directory=generated,
        employee_count=4,
        vote_count=4,
    )
    assert expected == {"A": 2, "B": 1, "C": 1}

    setup_election(
        employees_path=generated / "employees.csv",
        runtime_dir=runtime,
        trustee_dir=trustee,
    )
    settings = Settings(runtime_dir=runtime)
    return {
        "generated": generated,
        "runtime": runtime,
        "trustee": trustee,
        "settings": settings,
    }


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as input_file:
        return list(csv.DictReader(input_file))


def test_generated_vote_fixture_has_only_two_columns(
    election: dict[str, Path | Settings],
) -> None:
    generated = election["generated"]
    assert isinstance(generated, Path)
    rows = read_rows(generated / "votes.csv")
    employees = read_rows(generated / "employees.csv")
    assert list(employees[0]) == ["employee_id", "display_name"]
    assert list(rows[0]) == ["employee_id", "choice"]
    assert rows == [
        {"employee_id": "100001", "choice": "A"},
        {"employee_id": "100002", "choice": "B"},
        {"employee_id": "100003", "choice": "C"},
        {"employee_id": "100004", "choice": "A"},
    ]


def test_every_generated_row_is_added_to_encrypted_tally(
    election: dict[str, Path | Settings],
) -> None:
    generated = election["generated"]
    runtime = election["runtime"]
    trustee = election["trustee"]
    settings = election["settings"]
    assert isinstance(generated, Path)
    assert isinstance(runtime, Path)
    assert isinstance(trustee, Path)
    assert isinstance(settings, Settings)

    service = VotingService(settings)
    rows = read_rows(generated / "votes.csv")
    receipts = []
    for row in rows:
        ciphertext = encrypt_choice(
            runtime / "public",
            row["choice"],
        )
        receipts.append(service.submit(row["employee_id"], ciphertext))

    assert [receipt.sequence for receipt in receipts] == [1, 2, 3, 4]
    assert [receipt.status for receipt in receipts] == [
        "accepted",
        "accepted",
        "accepted",
        "accepted",
    ]
    assert all(receipt.processing_ms > 0 for receipt in receipts)
    assert len(service.bulletin_board()) == 4

    crypto = OpenFHEBackend(runtime / "public")
    result = crypto.decrypt_result(
        trustee_dir=trustee,
        tally_directory=runtime / "state",
    )
    assert result == {"A": 2, "B": 1, "C": 1}

    assert not (runtime / "secret_key.bin").exists()
    assert not (runtime / "public" / "secret_key.bin").exists()
    assert (trustee / "secret_key.bin").is_file()
    assert not (runtime / "flags").exists()
    assert not (runtime / "public" / "eval_mult_keys.bin").exists()
    assert not (runtime / "public" / "encrypted_one.ct").exists()
    assert all(
        len(list(ballot_directory.glob("choice_*.ct"))) == 3
        for ballot_directory in (runtime / "ballots").iterdir()
    )


def test_api_rejects_a_second_submission_for_the_same_employee(
    election: dict[str, Path | Settings],
) -> None:
    generated = election["generated"]
    runtime = election["runtime"]
    settings = election["settings"]
    assert isinstance(generated, Path)
    assert isinstance(runtime, Path)
    assert isinstance(settings, Settings)

    app = create_app(settings)
    with TestClient(app) as client:
        responses = []
        for choice in ("A", "C"):
            ciphertext = encrypt_choice(
                runtime / "public",
                choice,
            )
            response = client.post(
                "/election/vote",
                json={
                    "employee_id": "100001",
                    "encrypted_choice_a": base64.b64encode(
                        ciphertext["a"]
                    ).decode("ascii"),
                    "encrypted_choice_b": base64.b64encode(
                        ciphertext["b"]
                    ).decode("ascii"),
                    "encrypted_choice_c": base64.b64encode(
                        ciphertext["c"]
                    ).decode("ascii"),
                },
            )
            responses.append(response)

        assert responses[0].status_code == 202
        assert responses[1].status_code == 409
        assert responses[0].json()["status"] == "accepted"
        assert responses[0].json()["processing_ms"] > 0
        assert responses[1].json()["detail"] == (
            "employee 100001 has already voted"
        )
        assert (
            client.get("/health").json()["backend"]
            == "openfhe-python"
        )
        assert client.get("/vote").status_code == 200
        assert client.get("/storage").status_code == 200
        assert len(client.get("/demo/employees").json()) == 4
        assert len(client.get("/election/bulletin-board").json()) == 1


def test_concurrent_submissions_accept_only_one(
    election: dict[str, Path | Settings],
) -> None:
    generated = election["generated"]
    runtime = election["runtime"]
    trustee = election["trustee"]
    settings = election["settings"]
    assert isinstance(generated, Path)
    assert isinstance(runtime, Path)
    assert isinstance(trustee, Path)
    assert isinstance(settings, Settings)

    service = VotingService(settings)
    encrypted_a = encrypt_choice(
        runtime / "public",
        "A",
    )
    encrypted_b = encrypt_choice(
        runtime / "public",
        "B",
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(service.submit, "100001", ciphertext)
            for ciphertext in (encrypted_a, encrypted_b)
        ]
    receipts = []
    errors = []
    for future in futures:
        try:
            receipts.append(future.result())
        except AlreadyVotedError as error:
            errors.append(error)
    assert len(receipts) == 1
    assert receipts[0].sequence == 1
    assert receipts[0].status == "accepted"
    assert len(errors) == 1

    result = OpenFHEBackend(runtime / "public").decrypt_result(
        trustee_dir=trustee,
        tally_directory=runtime / "state",
    )
    assert sum(result.values()) == 1


def test_same_choice_encrypts_to_different_ciphertexts(
    election: dict[str, Path | Settings],
) -> None:
    runtime = election["runtime"]
    assert isinstance(runtime, Path)
    first = encrypt_choice(runtime / "public", "A")
    second = encrypt_choice(runtime / "public", "A")
    assert first != second
    assert set(first) == {"a", "b", "c"}
    assert all(first[name] != second[name] for name in ("a", "b", "c"))

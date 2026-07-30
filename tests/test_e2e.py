from __future__ import annotations

import base64
import csv
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from client import encrypt_choice, find_voter_token
from generate_data import generate
from he_voting.api import create_app
from he_voting.crypto_cli import CryptoCli
from he_voting.service import VotingService
from he_voting.settings import Settings
from setup_election import setup_election


PROJECT_DIR = Path(__file__).resolve().parents[1]
CRYPTO_BINARY = PROJECT_DIR / "build" / "he_voting_crypto"


@pytest.fixture()
def election(tmp_path: Path) -> dict[str, Path | Settings]:
    if not CRYPTO_BINARY.is_file():
        pytest.fail(
            "native crypto binary is missing; build it with cmake before tests"
        )

    generated = tmp_path / "generated"
    runtime = tmp_path / "runtime"
    trustee = tmp_path / "trustee"
    expected = generate(
        output_directory=generated,
        employee_count=3,
        vote_count=4,
        duplicate_count=1,
        seed=7,
    )
    assert expected == {"A": 1, "B": 1, "C": 1}

    setup_election(
        roster_path=generated / "roster.csv",
        runtime_dir=runtime,
        trustee_dir=trustee,
        crypto_binary=CRYPTO_BINARY,
        evaluator="openfhe",
    )
    settings = Settings(
        runtime_dir=runtime,
        crypto_bin=CRYPTO_BINARY,
        evaluator="openfhe",
    )
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
    assert list(rows[0]) == ["employee_id", "choice"]
    assert rows == [
        {"employee_id": "100001", "choice": "A"},
        {"employee_id": "100002", "choice": "B"},
        {"employee_id": "100003", "choice": "C"},
        {"employee_id": "100001", "choice": "B"},
    ]


def test_encrypted_duplicate_is_not_counted(
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
        token = find_voter_token(
            generated / "roster.csv",
            row["employee_id"],
        )
        ciphertext = encrypt_choice(
            CRYPTO_BINARY,
            runtime / "public",
            row["choice"],
        )
        receipts.append(service.submit(token, ciphertext))

    assert [receipt.sequence for receipt in receipts] == [1, 2, 3, 4]
    assert {receipt.status for receipt in receipts} == {"recorded"}
    assert len(service.bulletin_board()) == 4

    crypto = CryptoCli(CRYPTO_BINARY)
    result = crypto.decrypt_result(
        public_dir=runtime / "public",
        trustee_dir=trustee,
        tally=runtime / "state" / "tally.ct",
    )
    assert result == {"A": 1, "B": 1, "C": 1}

    first_token = find_voter_token(
        generated / "roster.csv",
        "100001",
    )
    first_token_hash = service.token_hash(first_token)
    assert (
        crypto.decrypt_flag(
            public_dir=runtime / "public",
            trustee_dir=trustee,
            flag=runtime / "flags" / f"{first_token_hash}.ct",
        )
        == 1
    )

    assert not (runtime / "secret_key.bin").exists()
    assert not (runtime / "public" / "secret_key.bin").exists()
    assert (trustee / "secret_key.bin").is_file()


def test_api_accepts_ciphertext_and_returns_same_shape_for_duplicate(
    election: dict[str, Path | Settings],
) -> None:
    generated = election["generated"]
    runtime = election["runtime"]
    settings = election["settings"]
    assert isinstance(generated, Path)
    assert isinstance(runtime, Path)
    assert isinstance(settings, Settings)

    token = find_voter_token(generated / "roster.csv", "100001")
    app = create_app(settings)
    with TestClient(app) as client:
        responses = []
        for choice in ("A", "C"):
            ciphertext = encrypt_choice(
                CRYPTO_BINARY,
                runtime / "public",
                choice,
            )
            response = client.post(
                "/election/vote",
                json={
                    "voter_token": token,
                    "encrypted_choice": base64.b64encode(
                        ciphertext
                    ).decode("ascii"),
                },
            )
            assert response.status_code == 202
            responses.append(response.json())

        assert set(responses[0]) == set(responses[1])
        assert responses[0]["status"] == "recorded"
        assert responses[1]["status"] == "recorded"
        assert client.get("/health").json()["evaluator"] == "openfhe"
        assert len(client.get("/election/bulletin-board").json()) == 2


def test_concurrent_duplicate_requests_count_at_most_once(
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

    token = find_voter_token(generated / "roster.csv", "100001")
    service = VotingService(settings)
    encrypted_a = encrypt_choice(
        CRYPTO_BINARY,
        runtime / "public",
        "A",
    )
    encrypted_b = encrypt_choice(
        CRYPTO_BINARY,
        runtime / "public",
        "B",
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        receipts = list(
            executor.map(
                lambda ciphertext: service.submit(token, ciphertext),
                (encrypted_a, encrypted_b),
            )
        )
    assert sorted(receipt.sequence for receipt in receipts) == [1, 2]

    result = CryptoCli(CRYPTO_BINARY).decrypt_result(
        public_dir=runtime / "public",
        trustee_dir=trustee,
        tally=runtime / "state" / "tally.ct",
    )
    assert sum(result.values()) == 1
    assert result in (
        {"A": 1, "B": 0, "C": 0},
        {"A": 0, "B": 1, "C": 0},
    )


def test_same_choice_encrypts_to_different_ciphertexts(
    election: dict[str, Path | Settings],
) -> None:
    runtime = election["runtime"]
    assert isinstance(runtime, Path)
    first = encrypt_choice(CRYPTO_BINARY, runtime / "public", "A")
    second = encrypt_choice(CRYPTO_BINARY, runtime / "public", "A")
    assert first != second


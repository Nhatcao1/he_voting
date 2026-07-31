from __future__ import annotations

import csv
import json
import pickle
import sys
import types
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.api import create_app
from app.settings import Settings
from app.voting_service import VotingService
from benchmark_votes import main as benchmark_main
from client import VoteEncryptor
from generate_data import generate
from he_voting.openfhe_backend import OpenFHEBackend
from setup_election import setup_election


@dataclass
class FakePlaintext:
    values: list[int]

    def SetLength(self, length: int) -> None:
        self.values = self.values[:length]

    def GetCoefPackedValue(self) -> list[int]:
        return self.values


@dataclass
class FakeCiphertext:
    value: int
    nonce: str


@dataclass
class FakeKeyPair:
    publicKey: str = "public"
    secretKey: str = "secret"


class FakeParameters:
    def SetPlaintextModulus(self, value: int) -> None:
        self.plaintext_modulus = value

    def SetMultiplicativeDepth(self, value: int) -> None:
        self.depth = value

    def SetSecurityLevel(self, value: Any) -> None:
        self.security = value


class FakeContext:
    def Enable(self, feature: Any) -> None:
        pass

    def KeyGen(self) -> FakeKeyPair:
        return FakeKeyPair()

    def MakeCoefPackedPlaintext(self, values: list[int]) -> FakePlaintext:
        return FakePlaintext(values)

    def Encrypt(
        self,
        public_key: str,
        plaintext: FakePlaintext,
    ) -> FakeCiphertext:
        return FakeCiphertext(plaintext.values[0], uuid.uuid4().hex)

    def EvalAdd(
        self,
        left: FakeCiphertext,
        right: FakeCiphertext,
    ) -> FakeCiphertext:
        return FakeCiphertext(left.value + right.value, uuid.uuid4().hex)

    def Decrypt(
        self,
        secret_key: str,
        ciphertext: FakeCiphertext,
    ) -> FakePlaintext:
        return FakePlaintext([ciphertext.value])


def fake_openfhe_module() -> types.ModuleType:
    module = types.ModuleType("openfhe")
    module.BINARY = object()
    module.CCParamsBFVRNS = FakeParameters
    module.GenCryptoContext = lambda parameters: FakeContext()
    module.PKESchemeFeature = types.SimpleNamespace(
        PKE="PKE",
        KEYSWITCH="KEYSWITCH",
        LEVELEDSHE="LEVELEDSHE",
    )
    module.SecurityLevel = types.SimpleNamespace(
        HEStd_128_classic="HEStd_128_classic"
    )

    def serialize(path: str, value: Any, serialization: Any) -> bool:
        with Path(path).open("wb") as output_file:
            pickle.dump(value, output_file)
        return True

    def deserialize(path: str, serialization: Any) -> tuple[Any, bool]:
        with Path(path).open("rb") as input_file:
            return pickle.load(input_file), True

    module.SerializeToFile = serialize
    module.DeserializeCryptoContext = deserialize
    module.DeserializePublicKey = deserialize
    module.DeserializePrivateKey = deserialize
    module.DeserializeCiphertext = deserialize
    return module


def write_ballot(directory: Path, ciphertexts: dict[str, bytes]) -> None:
    directory.mkdir()
    for name, value in ciphertexts.items():
        (directory / f"choice_{name}.ct").write_bytes(value)


def evaluate_vote(
    backend: OpenFHEBackend,
    runtime: Path,
    ballot_directory: Path,
    output_directory: Path,
) -> None:
    output_directory.mkdir()
    backend.evaluate(
        public_dir=runtime / "public",
        tally_input_directory=runtime / "state",
        ballot_directory=ballot_directory,
        tally_output_directory=output_directory,
    )
    for name in ("a", "b", "c"):
        (output_directory / f"tally_{name}.ct").replace(
            runtime / "state" / f"tally_{name}.ct"
        )


def test_python_backend_adds_each_encrypted_choice_to_tally(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setitem(sys.modules, "openfhe", fake_openfhe_module())
    runtime = tmp_path / "runtime"
    trustee = tmp_path / "trustee"
    setup = OpenFHEBackend()
    setup.setup(runtime / "public", trustee, runtime / "state")

    encryptor = OpenFHEBackend(runtime / "public")
    first = encryptor.encrypt_choice("A")
    second = encryptor.encrypt_choice("B")
    assert first != second

    first_ballot = tmp_path / "first"
    second_ballot = tmp_path / "second"
    write_ballot(first_ballot, first)
    write_ballot(second_ballot, second)

    evaluator = OpenFHEBackend(runtime / "public")
    evaluate_vote(
        evaluator,
        runtime,
        first_ballot,
        tmp_path / "first-output",
    )
    evaluate_vote(
        evaluator,
        runtime,
        second_ballot,
        tmp_path / "second-output",
    )

    result = OpenFHEBackend(runtime / "public").decrypt_result(
        trustee_dir=trustee,
        tally_directory=runtime / "state",
    )
    assert result == {"A": 1, "B": 1, "C": 0}
    assert not (runtime / "flags").exists()
    assert not (runtime / "public" / "eval_mult_keys.bin").exists()
    assert not (runtime / "public" / "encrypted_one.ct").exists()


def test_python_setup_client_and_service_contract(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setitem(sys.modules, "openfhe", fake_openfhe_module())
    generated = tmp_path / "generated"
    runtime = tmp_path / "runtime"
    trustee = tmp_path / "trustee"
    expected = generate(
        output_directory=generated,
        employee_count=4,
        vote_count=4,
    )
    setup_election(
        employees_path=generated / "employees.csv",
        runtime_dir=runtime,
        trustee_dir=trustee,
    )

    settings = Settings(runtime_dir=runtime)
    service = VotingService(settings)
    encryptor = VoteEncryptor(runtime / "public")
    vote_rows = [
        ("100001", "A"),
        ("100002", "B"),
        ("100003", "C"),
        ("100004", "A"),
    ]
    statuses = []
    for employee_id, choice in vote_rows:
        receipt = service.submit(
            employee_id,
            encryptor.encrypt_choice(choice),
        )
        statuses.append(receipt.status)

    assert statuses == ["accepted", "accepted", "accepted", "accepted"]
    result = OpenFHEBackend(runtime / "public").decrypt_result(
        trustee_dir=trustee,
        tally_directory=runtime / "state",
    )
    assert result == expected == {"A": 2, "B": 1, "C": 1}
    assert len(service.participation_records()) == 4
    assert settings.context_id == json.loads(
        (runtime / "election.json").read_text()
    )["context_id"]

    app = create_app(settings)
    with TestClient(app) as client:
        assert client.get("/vote").status_code == 200
        assert client.get("/storage").status_code == 200
        employees = client.get("/demo/employees").json()
        assert employees[0]["employee_id"] == "100001"
        assert employees[0]["submitted_at"] is not None
        duplicate = client.post(
            "/demo/vote",
            json={"employee_id": "100001", "choice": "B"},
        )
        assert duplicate.status_code == 409
        assert duplicate.json()["detail"] == "employee 100001 has already voted"
        progress = client.get("/demo/progress").json()
        assert progress["encrypted_ballots"] == 4
        assert progress["context_id"] == settings.context_id
        storage = client.get("/demo/storage").json()
        assert storage["summary"]["tally_files"] == 3
        assert storage["summary"]["ballot_files"] == 12
        assert storage["summary"]["total_files"] == 15
        assert len(storage["files"]) == 15
        assert all(
            set(file_record)
            == {
                "category",
                "path",
                "bytes",
                "sha256",
                "preview_base64",
                "modified_at",
            }
            for file_record in storage["files"]
        )


def test_benchmark_writes_client_evidence_bundle(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setitem(sys.modules, "openfhe", fake_openfhe_module())
    generated = tmp_path / "generated"
    runtime = tmp_path / "runtime"
    trustee = tmp_path / "trustee"
    output = tmp_path / "benchmark"
    generate(
        output_directory=generated,
        employee_count=5,
        vote_count=4,
    )
    setup_election(
        employees_path=generated / "employees.csv",
        runtime_dir=runtime,
        trustee_dir=trustee,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "benchmark_votes.py",
            "--votes",
            str(generated / "votes.csv"),
            "--employees",
            str(generated / "employees.csv"),
            "--runtime-dir",
            str(runtime),
            "--trustee-dir",
            str(trustee),
            "--out-dir",
            str(output),
            "--progress-every",
            "0",
        ],
    )

    benchmark_main()

    summary = json.loads((output / "summary.json").read_text())
    assert summary["expected_result"] == {"A": 2, "B": 1, "C": 1}
    assert summary["decrypted_result"] == {"A": 2, "B": 1, "C": 1}
    assert summary["decrypted_total"] == 4
    assert summary["participating_employees"] == 4
    assert summary["result_matches_expected"] is True
    with (output / "vote_evidence.csv").open(newline="") as evidence_file:
        evidence = list(csv.DictReader(evidence_file))
    assert [row["server_status"] for row in evidence] == [
        "accepted",
        "accepted",
        "accepted",
        "accepted",
    ]
    assert evidence[0]["input_choice"] == "A"
    assert (
        evidence[0]["encoded_a"],
        evidence[0]["encoded_b"],
        evidence[0]["encoded_c"],
    ) == ("1", "0", "0")
    assert len(list((output / "ciphertexts" / "ballots").rglob("*.ct"))) == 12
    assert len(list((output / "ciphertexts" / "final_tally").glob("*.ct"))) == 3
    key_bundle = output / "key_bundle"
    assert (
        key_bundle / "public" / "crypto_context.bin"
    ).read_bytes() == (runtime / "public" / "crypto_context.bin").read_bytes()
    assert (
        key_bundle / "public" / "public_key.bin"
    ).read_bytes() == (runtime / "public" / "public_key.bin").read_bytes()
    assert (
        key_bundle / "private" / "secret_key.bin"
    ).read_bytes() == (trustee / "secret_key.bin").read_bytes()
    key_manifest = json.loads((key_bundle / "manifest.json").read_text())
    assert key_manifest["evaluation_keys"] == {
        "generated": False,
        "files": [],
        "reason": (
            "The ballot tally uses ciphertext EvalAdd only; multiplication "
            "and rotation evaluation keys are not required or generated."
        ),
    }
    assert summary["artifacts"]["key_bundle_directory"] == str(key_bundle)
    with (output / "participation.csv").open(newline="") as participation_file:
        participation = list(csv.DictReader(participation_file))
    assert [row["submitted"] for row in participation] == [
        "true",
        "true",
        "true",
        "true",
        "false",
    ]

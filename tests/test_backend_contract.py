from __future__ import annotations

import pickle
import sys
import types
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from client import VoteEncryptor, find_voter_token
from generate_data import generate
from he_voting.openfhe_backend import OpenFHEBackend
from he_voting.service import VotingService
from he_voting.settings import Settings
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

    def EvalMultKeyGen(self, secret_key: str) -> None:
        pass

    def SerializeEvalMultKey(self, path: str, serialization: Any) -> bool:
        Path(path).write_bytes(b"fake-eval-key")
        return True

    def DeserializeEvalMultKey(
        self,
        path: str,
        serialization: Any,
    ) -> bool:
        return Path(path).read_bytes() == b"fake-eval-key"

    def MakeCoefPackedPlaintext(self, values: list[int]) -> FakePlaintext:
        return FakePlaintext(values)

    def Encrypt(
        self,
        public_key: str,
        plaintext: FakePlaintext,
    ) -> FakeCiphertext:
        return FakeCiphertext(plaintext.values[0], uuid.uuid4().hex)

    def EvalSub(
        self,
        left: FakeCiphertext,
        right: FakeCiphertext,
    ) -> FakeCiphertext:
        return FakeCiphertext(left.value - right.value, uuid.uuid4().hex)

    def EvalMult(
        self,
        left: FakeCiphertext,
        right: FakeCiphertext,
    ) -> FakeCiphertext:
        return FakeCiphertext(left.value * right.value, uuid.uuid4().hex)

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
    token_hash: str,
    ballot_directory: Path,
    output_directory: Path,
) -> None:
    output_directory.mkdir()
    backend.evaluate(
        public_dir=runtime / "public",
        flag_input=runtime / "flags" / f"{token_hash}.ct",
        tally_input_directory=runtime / "state",
        ballot_directory=ballot_directory,
        flag_output=output_directory / "flag.ct",
        tally_output_directory=output_directory,
    )
    (output_directory / "flag.ct").replace(
        runtime / "flags" / f"{token_hash}.ct"
    )
    for name in ("a", "b", "c"):
        (output_directory / f"tally_{name}.ct").replace(
            runtime / "state" / f"tally_{name}.ct"
        )


def test_python_backend_preserves_encrypted_duplicate_logic(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setitem(sys.modules, "openfhe", fake_openfhe_module())
    runtime = tmp_path / "runtime"
    trustee = tmp_path / "trustee"
    token_hash = "a" * 64

    setup = OpenFHEBackend()
    setup.setup(runtime / "public", trustee, runtime / "state")
    setup.initialize_flags([token_hash], runtime / "flags")

    encryptor = OpenFHEBackend(runtime / "public")
    first = encryptor.encrypt_choice("A")
    duplicate = encryptor.encrypt_choice("B")
    assert first != duplicate

    first_ballot = tmp_path / "first"
    duplicate_ballot = tmp_path / "duplicate"
    write_ballot(first_ballot, first)
    write_ballot(duplicate_ballot, duplicate)

    evaluator = OpenFHEBackend(
        runtime / "public",
        load_evaluation_keys=True,
    )
    evaluate_vote(
        evaluator,
        runtime,
        token_hash,
        first_ballot,
        tmp_path / "first-output",
    )
    evaluate_vote(
        evaluator,
        runtime,
        token_hash,
        duplicate_ballot,
        tmp_path / "duplicate-output",
    )

    result = OpenFHEBackend(runtime / "public").decrypt_result(
        trustee_dir=trustee,
        tally_directory=runtime / "state",
    )
    assert result == {"A": 1, "B": 0, "C": 0}


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
        employee_count=3,
        vote_count=4,
        duplicate_count=1,
        seed=7,
    )
    setup_election(
        roster_path=generated / "roster.csv",
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
        ("100001", "B"),
    ]
    for employee_id, choice in vote_rows:
        token = find_voter_token(
            generated / "roster.csv",
            employee_id,
        )
        receipt = service.submit(
            token,
            encryptor.encrypt_choice(choice),
        )
        assert receipt.status == "recorded"

    result = OpenFHEBackend(runtime / "public").decrypt_result(
        trustee_dir=trustee,
        tally_directory=runtime / "state",
    )
    assert result == expected == {"A": 1, "B": 1, "C": 1}

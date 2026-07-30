from __future__ import annotations

import importlib
import tempfile
from pathlib import Path
from typing import Any, Iterable


PLAINTEXT_MODULUS = 65537
CHOICE_NAMES = ("a", "b", "c")


class OpenFHEBackendError(RuntimeError):
    pass


def _load_openfhe() -> Any:
    try:
        return importlib.import_module("openfhe")
    except ImportError as error:
        raise OpenFHEBackendError(
            "the official openfhe Python package could not be loaded; "
            "install requirements.txt or build a version-matched "
            "openfhe-python against /usr/local/lib/OpenFHE. "
            f"Original import error: {error}"
        ) from error


class OpenFHEBackend:
    """Persistent BFV backend implemented with the official Python bindings."""

    def __init__(
        self,
        public_dir: Path | None = None,
        *,
        load_evaluation_keys: bool = False,
    ):
        self.fhe = _load_openfhe()
        self.context: Any | None = None
        self.public_key: Any | None = None
        if public_dir is not None:
            self.load_public_material(
                public_dir,
                load_evaluation_keys=load_evaluation_keys,
            )

    @property
    def binary_serialization(self) -> Any:
        return self.fhe.BINARY

    @staticmethod
    def _require(success: bool, message: str) -> None:
        if not success:
            raise OpenFHEBackendError(message)

    def _serialize(self, path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._require(
            bool(
                self.fhe.SerializeToFile(
                    str(path),
                    value,
                    self.binary_serialization,
                )
            ),
            f"could not serialize OpenFHE object to {path}",
        )

    def _deserialize(
        self,
        loader_name: str,
        path: Path,
    ) -> Any:
        loader = getattr(self.fhe, loader_name)
        value, success = loader(str(path), self.binary_serialization)
        self._require(
            bool(success),
            f"could not deserialize OpenFHE object from {path}",
        )
        return value

    def load_public_material(
        self,
        public_dir: Path,
        *,
        load_evaluation_keys: bool = False,
    ) -> None:
        public_dir = public_dir.resolve()
        self.context = self._deserialize(
            "DeserializeCryptoContext",
            public_dir / "crypto_context.bin",
        )
        self.public_key = self._deserialize(
            "DeserializePublicKey",
            public_dir / "public_key.bin",
        )
        if load_evaluation_keys:
            self._require(
                bool(
                    self.context.DeserializeEvalMultKey(
                        str(public_dir / "eval_mult_keys.bin"),
                        self.binary_serialization,
                    )
                ),
                "could not deserialize OpenFHE multiplication keys",
            )

    def _require_public_context(self) -> tuple[Any, Any]:
        if self.context is None or self.public_key is None:
            raise OpenFHEBackendError("OpenFHE public material is not loaded")
        return self.context, self.public_key

    def _encrypt_scalar(self, value: int) -> Any:
        context, public_key = self._require_public_context()
        plaintext = context.MakeCoefPackedPlaintext([int(value)])
        return context.Encrypt(public_key, plaintext)

    def setup(
        self,
        public_dir: Path,
        trustee_dir: Path,
        state_dir: Path,
    ) -> dict[str, object]:
        public_dir.mkdir(parents=True, exist_ok=True)
        trustee_dir.mkdir(parents=True, exist_ok=True)
        state_dir.mkdir(parents=True, exist_ok=True)

        parameters = self.fhe.CCParamsBFVRNS()
        parameters.SetPlaintextModulus(PLAINTEXT_MODULUS)
        parameters.SetMultiplicativeDepth(2)
        parameters.SetSecurityLevel(
            self.fhe.SecurityLevel.HEStd_128_classic
        )

        context = self.fhe.GenCryptoContext(parameters)
        context.Enable(self.fhe.PKESchemeFeature.PKE)
        context.Enable(self.fhe.PKESchemeFeature.KEYSWITCH)
        context.Enable(self.fhe.PKESchemeFeature.LEVELEDSHE)

        key_pair = context.KeyGen()
        context.EvalMultKeyGen(key_pair.secretKey)

        self.context = context
        self.public_key = key_pair.publicKey
        self._serialize(public_dir / "crypto_context.bin", context)
        self._serialize(public_dir / "public_key.bin", key_pair.publicKey)
        self._serialize(
            trustee_dir / "secret_key.bin",
            key_pair.secretKey,
        )
        self._require(
            bool(
                context.SerializeEvalMultKey(
                    str(public_dir / "eval_mult_keys.bin"),
                    self.binary_serialization,
                )
            ),
            "could not serialize OpenFHE multiplication keys",
        )

        for choice_name in CHOICE_NAMES:
            self._serialize(
                state_dir / f"tally_{choice_name}.ct",
                self._encrypt_scalar(0),
            )
        self._serialize(
            public_dir / "encrypted_one.ct",
            self._encrypt_scalar(1),
        )

        return {
            "backend": "openfhe-python",
            "scheme": "BFV-RNS",
            "plaintext_modulus": PLAINTEXT_MODULUS,
            "encoding": "coefficient-scalar",
            "security": "HEStd_128_classic",
        }

    def initialize_flags(
        self,
        token_hashes: Iterable[str],
        flags_dir: Path,
    ) -> int:
        flags_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        for token_hash in token_hashes:
            if len(token_hash) != 64:
                raise ValueError("token hash must have 64 hexadecimal characters")
            bytes.fromhex(token_hash)
            self._serialize(
                flags_dir / f"{token_hash}.ct",
                self._encrypt_scalar(0),
            )
            count += 1
        return count

    def encrypt_choice(self, choice: str) -> dict[str, bytes]:
        normalized = choice.strip().upper()
        if normalized not in {"A", "B", "C"}:
            raise ValueError("choice must be A, B, or C")

        with tempfile.TemporaryDirectory(
            prefix="he-vote-encrypt-"
        ) as temporary_directory:
            temporary = Path(temporary_directory)
            encrypted: dict[str, bytes] = {}
            for choice_name in CHOICE_NAMES:
                path = temporary / f"choice_{choice_name}.ct"
                self._serialize(
                    path,
                    self._encrypt_scalar(
                        1 if normalized == choice_name.upper() else 0
                    ),
                )
                encrypted[choice_name] = path.read_bytes()
            return encrypted

    def evaluate(
        self,
        *,
        public_dir: Path,
        flag_input: Path,
        tally_input_directory: Path,
        ballot_directory: Path,
        flag_output: Path,
        tally_output_directory: Path,
    ) -> None:
        if self.context is None:
            self.load_public_material(
                public_dir,
                load_evaluation_keys=True,
            )
        context = self.context
        if context is None:
            raise OpenFHEBackendError("OpenFHE context is not loaded")

        has_voted = self._deserialize("DeserializeCiphertext", flag_input)
        encrypted_one = self._deserialize(
            "DeserializeCiphertext",
            public_dir / "encrypted_one.ct",
        )
        choices = {
            name: self._deserialize(
                "DeserializeCiphertext",
                ballot_directory / f"choice_{name}.ct",
            )
            for name in CHOICE_NAMES
        }
        tallies = {
            name: self._deserialize(
                "DeserializeCiphertext",
                tally_input_directory / f"tally_{name}.ct",
            )
            for name in CHOICE_NAMES
        }

        # Entire encrypted voting calculation. No value is decrypted here.
        can_vote = context.EvalSub(encrypted_one, has_voted)
        accepted = {
            name: context.EvalMult(can_vote, choices[name])
            for name in CHOICE_NAMES
        }
        next_tallies = {
            name: context.EvalAdd(tallies[name], accepted[name])
            for name in CHOICE_NAMES
        }
        next_flag = context.EvalAdd(has_voted, can_vote)

        self._serialize(flag_output, next_flag)
        for name in CHOICE_NAMES:
            self._serialize(
                tally_output_directory / f"tally_{name}.ct",
                next_tallies[name],
            )

    def decrypt_result(
        self,
        *,
        trustee_dir: Path,
        tally_directory: Path,
    ) -> dict[str, int]:
        if self.context is None:
            raise OpenFHEBackendError("OpenFHE context is not loaded")
        secret_key = self._deserialize(
            "DeserializePrivateKey",
            trustee_dir / "secret_key.bin",
        )
        result: dict[str, int] = {}
        for name in CHOICE_NAMES:
            ciphertext = self._deserialize(
                "DeserializeCiphertext",
                tally_directory / f"tally_{name}.ct",
            )
            plaintext = self.context.Decrypt(secret_key, ciphertext)
            plaintext.SetLength(1)
            result[name.upper()] = int(
                plaintext.GetCoefPackedValue()[0]
            )
        return result

"""OpenFHE operations used by the encrypted A/B/C voting application.

This module is deliberately unaware of employees, voter tokens, HTTP, and
SQLite. It only creates election key material, encrypts scalar choice bits,
adds encrypted ballots to encrypted tallies, and decrypts the final aggregate.
"""

from __future__ import annotations

import importlib
import tempfile
from pathlib import Path
from typing import Any


# BFV performs exact integer arithmetic modulo the plaintext modulus. Election
# totals must remain below this value to avoid modular wraparound.
PLAINTEXT_MODULUS = 65537

# A ballot and the running result are represented by three independent
# ciphertexts rather than one SIMD-packed ciphertext.
CHOICE_NAMES = ("a", "b", "c")


class OpenFHEBackendError(RuntimeError):
    """Raised when the OpenFHE binding or a serialized object cannot be used."""

    pass


def _load_openfhe() -> Any:
    """Import the optional native binding only when the backend is constructed."""
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
    """Persistent BFV backend implemented with the official Python bindings.

    A backend used by a client or service loads only the public crypto context
    and public key. The trustee secret key is loaded only by ``decrypt_result``.
    OpenFHE objects are kept in memory so they do not need to be reloaded for
    every ballot.
    """

    def __init__(
        self,
        public_dir: Path | None = None,
    ):
        # ``fhe`` is the official native OpenFHE Python module.
        self.fhe = _load_openfhe()
        self.context: Any | None = None
        self.public_key: Any | None = None
        if public_dir is not None:
            self.load_public_material(public_dir)

    @property
    def binary_serialization(self) -> Any:
        """Use OpenFHE's compact binary format for contexts, keys, and ciphertexts."""
        return self.fhe.BINARY

    @staticmethod
    def _require(success: bool, message: str) -> None:
        if not success:
            raise OpenFHEBackendError(message)

    def _serialize(self, path: Path, value: Any) -> None:
        """Write one OpenFHE object and turn a false return value into an error."""
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
        """Load an object with the type-specific OpenFHE deserializer."""
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
    ) -> None:
        """Load non-secret material shared by clients and the voting service."""
        public_dir = public_dir.resolve()
        # The context contains scheme parameters, not the election secret key.
        self.context = self._deserialize(
            "DeserializeCryptoContext",
            public_dir / "crypto_context.bin",
        )
        self.public_key = self._deserialize(
            "DeserializePublicKey",
            public_dir / "public_key.bin",
        )

    def _require_public_context(self) -> tuple[Any, Any]:
        if self.context is None or self.public_key is None:
            raise OpenFHEBackendError("OpenFHE public material is not loaded")
        return self.context, self.public_key

    def _encrypt_scalar(self, value: int) -> Any:
        """Encrypt one exact integer in coefficient-packed BFV form."""
        context, public_key = self._require_public_context()
        # Only the first coefficient is used. OpenFHE encryption is randomized,
        # so encrypting the same 0 or 1 twice produces different ciphertexts.
        plaintext = context.MakeCoefPackedPlaintext([int(value)])
        return context.Encrypt(public_key, plaintext)

    def setup(
        self,
        public_dir: Path,
        trustee_dir: Path,
        state_dir: Path,
    ) -> dict[str, object]:
        """Create one election keypair and three encrypted-zero tallies.

        ``public_dir`` is safe to distribute to voter clients and the service.
        ``trustee_dir`` contains the secret key and must remain private.
        ``state_dir`` contains only the encrypted running A/B/C totals.
        """
        public_dir.mkdir(parents=True, exist_ok=True)
        trustee_dir.mkdir(parents=True, exist_ok=True)
        state_dir.mkdir(parents=True, exist_ok=True)

        # BFV-RNS is used because vote counts require exact integer addition.
        parameters = self.fhe.CCParamsBFVRNS()
        parameters.SetPlaintextModulus(PLAINTEXT_MODULUS)
        parameters.SetMultiplicativeDepth(1)
        parameters.SetSecurityLevel(
            self.fhe.SecurityLevel.HEStd_128_classic
        )

        context = self.fhe.GenCryptoContext(parameters)
        # PKE enables public-key encryption. LEVELEDSHE provides EvalAdd.
        context.Enable(self.fhe.PKESchemeFeature.PKE)
        context.Enable(self.fhe.PKESchemeFeature.LEVELEDSHE)

        # A single keypair is generated per election. Every ballot and tally in
        # this runtime must use this public key to remain mutually compatible.
        key_pair = context.KeyGen()

        self.context = context
        self.public_key = key_pair.publicKey
        # Public evaluation material is kept in the API runtime.
        self._serialize(public_dir / "crypto_context.bin", context)
        self._serialize(public_dir / "public_key.bin", key_pair.publicKey)
        # The secret key is deliberately stored outside the API runtime.
        self._serialize(
            trustee_dir / "secret_key.bin",
            key_pair.secretKey,
        )

        # Each candidate starts with a fresh randomized encryption of zero.
        for choice_name in CHOICE_NAMES:
            self._serialize(
                state_dir / f"tally_{choice_name}.ct",
                self._encrypt_scalar(0),
            )

        return {
            "backend": "openfhe-python",
            "scheme": "BFV-RNS",
            "plaintext_modulus": PLAINTEXT_MODULUS,
            "encoding": "coefficient-scalar",
            "security": "HEStd_128_classic",
            "tally_operation": "ciphertext addition only",
        }

    def encrypt_choice(self, choice: str) -> dict[str, bytes]:
        """Encode A, B, or C as three separately encrypted one-hot bits.

        For example, choice B becomes Enc(0), Enc(1), Enc(0). The returned
        bytes can be Base64-encoded by the client and submitted through HTTP.
        """
        normalized = choice.strip().upper()
        if normalized not in {"A", "B", "C"}:
            raise ValueError("choice must be A, B, or C")

        with tempfile.TemporaryDirectory(
            prefix="he-vote-encrypt-"
        ) as temporary_directory:
            # The binding serializes to files, so temporary files bridge its
            # file API to the byte payload expected by the HTTP client.
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
        tally_input_directory: Path,
        ballot_directory: Path,
        tally_output_directory: Path,
    ) -> None:
        """Add one encrypted one-hot ballot to the encrypted running tally."""
        if self.context is None:
            self.load_public_material(public_dir)
        context = self.context
        if context is None:
            raise OpenFHEBackendError("OpenFHE context is not loaded")

        # Deserialize the three ballot components and the three current totals.
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

        # This is the entire homomorphic tally calculation. EvalAdd does not
        # require multiplication, rotation, or other evaluation keys. Neither
        # the ballot choice nor the running totals are decrypted here.
        next_tallies = {
            name: context.EvalAdd(tallies[name], choices[name])
            for name in CHOICE_NAMES
        }

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
        """Trustee-only operation that decrypts the three aggregate totals.

        The method accepts the final tally directory, not individual ballot
        directories, which keeps the supported decryption path aggregate-only.
        """
        if self.context is None:
            raise OpenFHEBackendError("OpenFHE context is not loaded")
        # Loading the private key is intentionally deferred until decryption.
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
            # Only coefficient zero contains the scalar vote count.
            plaintext.SetLength(1)
            result[name.upper()] = int(
                plaintext.GetCoefPackedValue()[0]
            )
        return result

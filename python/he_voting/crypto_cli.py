from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


class CryptoCommandError(RuntimeError):
    pass


class CryptoCli:
    def __init__(self, binary: Path):
        self.binary = binary.resolve()
        if not self.binary.is_file():
            raise FileNotFoundError(f"crypto binary does not exist: {self.binary}")

    def _run(self, command: str, **options: str | Path) -> dict[str, Any]:
        arguments = [str(self.binary), command]
        for key, value in options.items():
            arguments.extend([f"--{key.replace('_', '-')}", str(value)])

        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip()
            raise CryptoCommandError(
                f"{command} failed with exit code {result.returncode}: {message}"
            )

        output = result.stdout.strip().splitlines()
        if not output:
            return {}
        try:
            return json.loads(output[-1])
        except json.JSONDecodeError as error:
            raise CryptoCommandError(
                f"{command} returned invalid JSON: {output[-1]}"
            ) from error

    def setup(
        self,
        public_dir: Path,
        trustee_dir: Path,
        state_dir: Path,
    ) -> dict[str, Any]:
        return self._run(
            "setup",
            public_dir=public_dir,
            trustee_dir=trustee_dir,
            state_dir=state_dir,
        )

    def initialize_flags(
        self,
        public_dir: Path,
        token_keys: Path,
        flags_dir: Path,
    ) -> dict[str, Any]:
        return self._run(
            "init-flags",
            public_dir=public_dir,
            token_keys=token_keys,
            flags_dir=flags_dir,
        )

    def encrypt_choice(
        self,
        public_dir: Path,
        choice: str,
        output: Path,
    ) -> dict[str, Any]:
        return self._run(
            "encrypt-choice",
            public_dir=public_dir,
            choice=choice,
            out=output,
        )

    def evaluate(
        self,
        public_dir: Path,
        flag_input: Path,
        tally_input: Path,
        ballot_input: Path,
        flag_output: Path,
        tally_output: Path,
        evaluator: str,
    ) -> dict[str, Any]:
        return self._run(
            "evaluate",
            public_dir=public_dir,
            flag_in=flag_input,
            tally_in=tally_input,
            ballot_in=ballot_input,
            flag_out=flag_output,
            tally_out=tally_output,
            evaluator=evaluator,
        )

    def decrypt_result(
        self,
        public_dir: Path,
        trustee_dir: Path,
        tally: Path,
    ) -> dict[str, int]:
        result = self._run(
            "decrypt-result",
            public_dir=public_dir,
            trustee_dir=trustee_dir,
            tally=tally,
        )
        return {choice: int(result[choice]) for choice in ("A", "B", "C")}

    def decrypt_flag(
        self,
        public_dir: Path,
        trustee_dir: Path,
        flag: Path,
    ) -> int:
        result = self._run(
            "decrypt-flag",
            public_dir=public_dir,
            trustee_dir=trustee_dir,
            flag=flag,
        )
        return int(result["has_voted"])


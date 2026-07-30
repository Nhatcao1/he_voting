from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from .service import VotingService
from .settings import Settings


class VoteRequest(BaseModel):
    voter_token: str = Field(min_length=64, max_length=64)
    encrypted_choice: str = Field(min_length=1)


class VoteReceiptResponse(BaseModel):
    receipt: str
    status: str
    sequence: int
    chain_hash: str


def _base64_file(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or Settings.from_environment()
    service = VotingService(active_settings)

    app = FastAPI(
        title="HE Employee Voting API",
        version="0.1.0",
        description=(
            "Accepts an anonymous voter token and an OpenFHE BFV encrypted "
            "A/B/C choice. The has_voted flag and tally remain encrypted."
        ),
    )
    app.state.voting_service = service

    @app.get("/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "evaluator": active_settings.evaluator,
        }

    @app.get("/election/public-material")
    def public_material() -> dict[str, str]:
        return {
            "scheme": "BFV-RNS",
            "crypto_context": _base64_file(
                active_settings.public_dir / "crypto_context.bin"
            ),
            "public_key": _base64_file(
                active_settings.public_dir / "public_key.bin"
            ),
        }

    @app.post(
        "/election/vote",
        response_model=VoteReceiptResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def submit_vote(request: VoteRequest) -> VoteReceiptResponse:
        try:
            encrypted_choice = base64.b64decode(
                request.encrypted_choice,
                validate=True,
            )
            receipt = service.submit(
                request.voter_token,
                encrypted_choice,
            )
        except (ValueError, binascii.Error) as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(error),
            ) from error
        return VoteReceiptResponse(**receipt.__dict__)

    @app.get(
        "/election/receipt/{receipt_id}",
        response_model=VoteReceiptResponse,
    )
    def get_receipt(receipt_id: str) -> VoteReceiptResponse:
        receipt = service.get_receipt(receipt_id)
        if receipt is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="receipt not found",
            )
        return VoteReceiptResponse(**receipt.__dict__)

    @app.get("/election/bulletin-board")
    def bulletin_board() -> list[dict[str, object]]:
        return service.bulletin_board()

    @app.get("/election/encrypted-result")
    def encrypted_result() -> dict[str, str]:
        tally_path = active_settings.state_dir / "tally.ct"
        return {
            "scheme": "BFV-RNS",
            "encrypted_tally": _base64_file(tally_path),
        }

    @app.get("/election/result")
    def published_result() -> dict[str, int]:
        result_path = active_settings.runtime_dir / "published_result.json"
        if not result_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="trustees have not published a result",
            )
        value = json.loads(result_path.read_text(encoding="utf-8"))
        return {choice: int(value[choice]) for choice in ("A", "B", "C")}

    return app

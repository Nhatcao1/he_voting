from __future__ import annotations

import base64
import binascii
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .voting_service import (
    AlreadyVotedError,
    UnknownEmployeeError,
    VotingService,
)
from .settings import Settings


class VoteRequest(BaseModel):
    employee_id: str = Field(min_length=1, max_length=128)
    encrypted_choice_a: str = Field(min_length=1)
    encrypted_choice_b: str = Field(min_length=1)
    encrypted_choice_c: str = Field(min_length=1)


class DemoVoteRequest(BaseModel):
    employee_id: str = Field(min_length=1, max_length=128)
    choice: str = Field(pattern="^[ABC]$")


class VoteReceiptResponse(BaseModel):
    receipt: str
    status: str
    sequence: int
    chain_hash: str
    processing_ms: float


def _base64_file(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or Settings.from_environment()
    service = VotingService(active_settings)
    app_directory = Path(__file__).resolve().parent
    templates_directory = app_directory / "templates"
    static_directory = app_directory / "static"

    app = FastAPI(
        title="HE Employee Voting API",
        version="0.2.0",
        description=(
            "Accepts an employee ID and OpenFHE BFV encrypted A/B/C choice. "
            "Employee participation is visible; choices and running totals "
            "remain encrypted."
        ),
    )
    app.state.voting_service = service
    app.mount(
        "/static",
        StaticFiles(directory=static_directory),
        name="static",
    )

    @app.get("/", include_in_schema=False)
    def home() -> RedirectResponse:
        return RedirectResponse("/vote")

    @app.get("/vote", include_in_schema=False)
    def vote_page() -> FileResponse:
        return FileResponse(templates_directory / "vote.html")

    @app.get("/admin", include_in_schema=False)
    def admin_page() -> FileResponse:
        return FileResponse(templates_directory / "admin.html")

    @app.get("/result", include_in_schema=False)
    def result_page() -> FileResponse:
        return FileResponse(templates_directory / "result.html")

    @app.get("/storage", include_in_schema=False)
    def storage_page() -> FileResponse:
        return FileResponse(templates_directory / "storage.html")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "backend": "openfhe-python",
            "context_id": active_settings.context_id,
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
            encrypted_choice = {
                "a": base64.b64decode(
                    request.encrypted_choice_a,
                    validate=True,
                ),
                "b": base64.b64decode(
                    request.encrypted_choice_b,
                    validate=True,
                ),
                "c": base64.b64decode(
                    request.encrypted_choice_c,
                    validate=True,
                ),
            }
            receipt = service.submit(
                request.employee_id,
                encrypted_choice,
            )
        except AlreadyVotedError as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(error),
            ) from error
        except (UnknownEmployeeError, ValueError, binascii.Error) as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(error),
            ) from error
        return VoteReceiptResponse(**receipt.__dict__)

    @app.get("/demo/employees")
    def demo_employees() -> list[dict[str, str | None]]:
        return service.employees()

    @app.post(
        "/demo/vote",
        response_model=VoteReceiptResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def demo_vote(request: DemoVoteRequest) -> VoteReceiptResponse:
        """Demo adapter: encrypt one UI choice, then use the normal service."""
        try:
            encryption_started = time.perf_counter()
            encrypted_choice = service.crypto.encrypt_choice(request.choice)
            encryption_ms = (time.perf_counter() - encryption_started) * 1000
            receipt = service.submit(request.employee_id, encrypted_choice)
        except AlreadyVotedError as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(error),
            ) from error
        except (UnknownEmployeeError, ValueError) as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(error),
            ) from error
        response = receipt.__dict__.copy()
        response["processing_ms"] = (
            float(response["processing_ms"]) + encryption_ms
        )
        return VoteReceiptResponse(**response)

    @app.get("/demo/progress")
    def demo_progress() -> dict[str, object]:
        progress = service.progress()
        ciphertext_files = list(
            active_settings.runtime_dir.rglob("*.ct")
        )
        progress.update(
            {
                "context_id": active_settings.context_id,
                "ciphertext_files": len(ciphertext_files),
                "ciphertext_storage_bytes": sum(
                    path.stat().st_size for path in ciphertext_files
                ),
                "result_published": (
                    active_settings.runtime_dir
                    / "published_result.json"
                ).is_file(),
            }
        )
        return progress

    @app.get("/demo/storage")
    def demo_storage(
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=10, le=200),
    ) -> dict[str, object]:
        """Describe retained ciphertexts without decrypting or downloading them."""
        tally_paths = sorted(active_settings.state_dir.glob("*.ct"))
        ballot_paths = sorted(
            active_settings.ballots_dir.rglob("*.ct"),
            reverse=True,
        )
        ciphertext_paths = tally_paths + ballot_paths
        total_files = len(ciphertext_paths)
        start = (page - 1) * page_size
        selected_paths = ciphertext_paths[start : start + page_size]

        files = []
        for path in selected_paths:
            value = path.read_bytes()
            files.append(
                {
                    "category": (
                        "running tally"
                        if path.parent == active_settings.state_dir
                        else "retained ballot"
                    ),
                    "path": str(
                        path.relative_to(active_settings.runtime_dir)
                    ),
                    "bytes": len(value),
                    "sha256": hashlib.sha256(value).hexdigest(),
                    "preview_base64": base64.b64encode(
                        value[:48]
                    ).decode("ascii"),
                    "modified_at": datetime.fromtimestamp(
                        path.stat().st_mtime,
                        tz=timezone.utc,
                    ).isoformat(),
                }
            )

        tally_bytes = sum(path.stat().st_size for path in tally_paths)
        ballot_bytes = sum(path.stat().st_size for path in ballot_paths)
        return {
            "context_id": active_settings.context_id,
            "summary": {
                "total_files": total_files,
                "total_bytes": tally_bytes + ballot_bytes,
                "tally_files": len(tally_paths),
                "tally_bytes": tally_bytes,
                "ballot_files": len(ballot_paths),
                "ballot_bytes": ballot_bytes,
                "retained_ballots": len(
                    {path.parent for path in ballot_paths}
                ),
            },
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_pages": max(
                    1, (total_files + page_size - 1) // page_size
                ),
            },
            "files": files,
        }

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
    def encrypted_result() -> dict[str, object]:
        return {
            "scheme": "BFV-RNS",
            "encoding": "coefficient-scalar",
            "encrypted_tally": {
                choice.upper(): _base64_file(
                    active_settings.state_dir / f"tally_{choice}.ct"
                )
                for choice in ("a", "b", "c")
            },
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

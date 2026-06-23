from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ELF_MAGIC = b"\x7fELF"


class JobStoreError(Exception):
    """Raised when a job cannot be persisted or loaded."""


class InvalidElfError(JobStoreError):
    """Raised when uploaded content is not an ELF binary."""


@dataclass(frozen=True)
class Job:
    id: str
    filename: str
    status: str
    created_at: str
    size_bytes: int
    binary_path: Path

    def to_dict(self) -> dict[str, str | int]:
        return {
            "id": self.id,
            "filename": self.filename,
            "status": self.status,
            "created_at": self.created_at,
            "size_bytes": self.size_bytes,
            "binary_path": str(self.binary_path),
        }


class JobStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def create_from_upload(self, filename: str, content: bytes) -> Job:
        if not content.startswith(ELF_MAGIC):
            raise InvalidElfError("uploaded file is not an ELF binary")

        job_id = uuid.uuid4().hex
        job_dir = self.root / job_id
        job_dir.mkdir(parents=True, exist_ok=False)
        binary_path = job_dir / "input.elf"
        binary_path.write_bytes(content)

        job = Job(
            id=job_id,
            filename=Path(filename).name or "input.elf",
            status="uploaded",
            created_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            size_bytes=len(content),
            binary_path=binary_path,
        )
        (job_dir / "job.json").write_text(json.dumps(job.to_dict(), indent=2) + "\n", encoding="utf-8")
        return job

    def get(self, job_id: str) -> Job:
        if not job_id or any(part in job_id for part in ("/", "\\", "..")):
            raise JobStoreError(f"invalid job id: {job_id!r}")

        metadata_path = self.root / job_id / "job.json"
        if not metadata_path.exists():
            raise JobStoreError(f"job not found: {job_id}")

        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        return Job(
            id=str(payload["id"]),
            filename=str(payload["filename"]),
            status=str(payload["status"]),
            created_at=str(payload["created_at"]),
            size_bytes=int(payload["size_bytes"]),
            binary_path=Path(str(payload["binary_path"])),
        )

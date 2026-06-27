from __future__ import annotations

import json
import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ELF_MAGIC = b"\x7fELF"


ELF_CLASSES = {
    1: "ELF32",
    2: "ELF64",
}

ELF_DATA_ENCODINGS = {
    1: "little",
    2: "big",
}

ELF_OS_ABIS = {
    0: "System V",
    3: "Linux",
}

ELF_TYPES = {
    1: "relocatable",
    2: "executable",
    3: "shared",
    4: "core",
}

ELF_MACHINES = {
    3: "x86",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}


class JobStoreError(Exception):
    """Raised when a job cannot be persisted or loaded."""


class InvalidElfError(JobStoreError):
    """Raised when uploaded content is not an ELF binary."""


def extract_elf_metadata(content: bytes) -> dict[str, str | int]:
    if len(content) < 16 or not content.startswith(ELF_MAGIC):
        raise InvalidElfError("uploaded file is not an ELF binary")

    elf_class_id = content[4]
    data_encoding_id = content[5]
    if elf_class_id not in ELF_CLASSES:
        raise InvalidElfError(f"unsupported ELF class: {elf_class_id}")
    if data_encoding_id not in ELF_DATA_ENCODINGS:
        raise InvalidElfError(f"unsupported ELF data encoding: {data_encoding_id}")

    is_64_bit = elf_class_id == 2
    header_size = 64 if is_64_bit else 52
    if len(content) < header_size:
        raise InvalidElfError("uploaded ELF header is truncated")

    endian_prefix = "<" if data_encoding_id == 1 else ">"
    if is_64_bit:
        header = struct.unpack_from(f"{endian_prefix}HHIQQQIHHHHHH", content, 16)
    else:
        header = struct.unpack_from(f"{endian_prefix}HHIIIIIHHHHHH", content, 16)

    (
        elf_type,
        machine,
        version,
        entry_point,
        _program_header_offset,
        _section_header_offset,
        _flags,
        elf_header_size,
        _program_header_entry_size,
        program_header_count,
        _section_header_entry_size,
        section_header_count,
        section_name_table_index,
    ) = header

    return {
        "format": ELF_CLASSES[elf_class_id],
        "endianness": ELF_DATA_ENCODINGS[data_encoding_id],
        "elf_version": version,
        "os_abi": ELF_OS_ABIS.get(content[7], f"unknown({content[7]})"),
        "object_type": ELF_TYPES.get(elf_type, f"unknown({elf_type})"),
        "machine": ELF_MACHINES.get(machine, f"unknown({machine})"),
        "entry_point": entry_point,
        "elf_header_size": elf_header_size,
        "program_header_count": program_header_count,
        "section_header_count": section_header_count,
        "section_name_table_index": section_name_table_index,
    }


@dataclass(frozen=True)
class Job:
    id: str
    filename: str
    status: str
    created_at: str
    size_bytes: int
    binary_path: Path
    metadata: dict[str, str | int]

    def to_dict(self) -> dict[str, str | int | dict[str, str | int]]:
        return {
            "id": self.id,
            "filename": self.filename,
            "status": self.status,
            "created_at": self.created_at,
            "size_bytes": self.size_bytes,
            "binary_path": str(self.binary_path),
            "metadata": self.metadata,
        }


class JobStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def create_from_upload(self, filename: str, content: bytes) -> Job:
        metadata = extract_elf_metadata(content)

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
            metadata=metadata,
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
            metadata=dict(payload["metadata"]),
        )

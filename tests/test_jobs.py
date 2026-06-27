from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from decomp_engine.jobs import InvalidElfError, JobStore, extract_elf_metadata


ELF_FIXTURE = (
    b"\x7fELF"
    + bytes([2, 1, 1, 3, 0])
    + (b"\x00" * 7)
    + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 2, 64, 5, 4)
)


def test_extracts_basic_elf_metadata() -> None:
    assert extract_elf_metadata(ELF_FIXTURE) == {
        "format": "ELF64",
        "endianness": "little",
        "elf_version": 1,
        "os_abi": "Linux",
        "object_type": "executable",
        "machine": "x86-64",
        "entry_point": 0x401000,
        "elf_header_size": 64,
        "program_header_count": 2,
        "section_header_count": 5,
        "section_name_table_index": 4,
    }


def test_backend_stores_uploaded_job(tmp_path: Path) -> None:
    store = JobStore(tmp_path)

    job = store.create_from_upload("../fixture.elf", ELF_FIXTURE)

    job_dir = tmp_path / job.id
    assert job.filename == "fixture.elf"
    assert job.status == "uploaded"
    assert job.size_bytes == len(ELF_FIXTURE)
    assert job.binary_path == job_dir / "input.elf"
    assert job.metadata["machine"] == "x86-64"
    assert job.metadata["entry_point"] == 0x401000
    assert job.binary_path.read_bytes() == ELF_FIXTURE

    metadata = json.loads((job_dir / "job.json").read_text(encoding="utf-8"))
    assert metadata == job.to_dict()

    reloaded = store.get(job.id)
    assert reloaded == job


def test_backend_rejects_non_elf_upload(tmp_path: Path) -> None:
    store = JobStore(tmp_path)

    with pytest.raises(InvalidElfError, match="not an ELF"):
        store.create_from_upload("not-elf.bin", b"not an elf")

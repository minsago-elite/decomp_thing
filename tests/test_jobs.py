from __future__ import annotations

import json
from pathlib import Path

import pytest

from decomp_engine.jobs import InvalidElfError, JobStore


ELF_FIXTURE = b"\x7fELF" + b"\x02\x01\x01" + (b"\x00" * 32)


def test_backend_stores_uploaded_job(tmp_path: Path) -> None:
    store = JobStore(tmp_path)

    job = store.create_from_upload("../fixture.elf", ELF_FIXTURE)

    job_dir = tmp_path / job.id
    assert job.filename == "fixture.elf"
    assert job.status == "uploaded"
    assert job.size_bytes == len(ELF_FIXTURE)
    assert job.binary_path == job_dir / "input.elf"
    assert job.binary_path.read_bytes() == ELF_FIXTURE

    metadata = json.loads((job_dir / "job.json").read_text(encoding="utf-8"))
    assert metadata == job.to_dict()

    reloaded = store.get(job.id)
    assert reloaded == job


def test_backend_rejects_non_elf_upload(tmp_path: Path) -> None:
    store = JobStore(tmp_path)

    with pytest.raises(InvalidElfError, match="not an ELF"):
        store.create_from_upload("not-elf.bin", b"not an elf")

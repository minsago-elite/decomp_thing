from __future__ import annotations

import http.client
import json
import struct
import threading
from pathlib import Path

from decomp_engine.web import UploadServer


ELF_FIXTURE = (
    b"\x7fELF"
    + bytes([2, 1, 1, 3, 0])
    + (b"\x00" * 7)
    + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 2, 64, 5, 4)
)


def multipart_body(filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = "----decomp-engine-test-boundary"
    body = b"\r\n".join(
        [
            f"--{boundary}".encode(),
            (
                f'Content-Disposition: form-data; name="binary"; filename="{filename}"\r\n'
                "Content-Type: application/x-elf"
            ).encode(),
            b"",
            content,
            f"--{boundary}--".encode(),
            b"",
        ]
    )
    return body, f"multipart/form-data; boundary={boundary}"


def request(server: UploadServer, method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        return response.status, dict(response.getheaders()), payload
    finally:
        connection.close()


def test_upload_page_has_elf_form(tmp_path: Path) -> None:
    server = UploadServer(("127.0.0.1", 0), tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = request(server, "GET", "/")
    finally:
        server.shutdown()
        server.server_close()

    assert status == 200
    assert b'enctype="multipart/form-data"' in body
    assert b'name="binary"' in body


def test_web_ui_uploads_elf_and_returns_job(tmp_path: Path) -> None:
    server = UploadServer(("127.0.0.1", 0), tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body, content_type = multipart_body("fixture.elf", ELF_FIXTURE)
        status, _, payload = request(
            server,
            "POST",
            "/jobs",
            body,
            {"Content-Type": content_type, "Accept": "application/json"},
        )
    finally:
        server.shutdown()
        server.server_close()

    assert status == 201
    job = json.loads(payload)
    assert job["filename"] == "fixture.elf"
    assert job["status"] == "uploaded"
    assert job["metadata"]["format"] == "ELF64"
    assert job["metadata"]["machine"] == "x86-64"
    assert (tmp_path / job["id"] / "input.elf").read_bytes().startswith(b"\x7fELF")
    assert (tmp_path / job["id"] / "job.json").exists()


def test_job_state_page_shows_status_and_metadata(tmp_path: Path) -> None:
    server = UploadServer(("127.0.0.1", 0), tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body, content_type = multipart_body("fixture.elf", ELF_FIXTURE)
        status, _, payload = request(
            server,
            "POST",
            "/jobs",
            body,
            {"Content-Type": content_type, "Accept": "application/json"},
        )
        assert status == 201
        job = json.loads(payload)

        status, _, page = request(server, "GET", f"/jobs/{job['id']}")
    finally:
        server.shutdown()
        server.server_close()

    assert status == 200
    assert b"uploaded" in page
    assert b"fixture.elf" in page
    assert b"Format" in page
    assert b"ELF64" in page
    assert b"Machine" in page
    assert b"x86-64" in page


def test_upload_rejects_non_elf(tmp_path: Path) -> None:
    server = UploadServer(("127.0.0.1", 0), tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body, content_type = multipart_body("not-elf.bin", b"not an elf")
        status, _, payload = request(server, "POST", "/jobs", body, {"Content-Type": content_type})
    finally:
        server.shutdown()
        server.server_close()

    assert status == 400
    assert b"not an ELF" in payload

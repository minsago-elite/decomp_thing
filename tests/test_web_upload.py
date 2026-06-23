from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path

from decomp_engine.web import UploadServer


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
        body, content_type = multipart_body("fixture.elf", b"\x7fELF" + b"\x02\x01\x01" + (b"\x00" * 32))
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
    assert (tmp_path / job["id"] / "input.elf").read_bytes().startswith(b"\x7fELF")
    assert (tmp_path / job["id"] / "job.json").exists()


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

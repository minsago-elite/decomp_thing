from __future__ import annotations

import argparse
import html
import json
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from decomp_engine.jobs import InvalidElfError, Job, JobStore, JobStoreError


DEFAULT_DATA_DIR = Path(".decomp_engine") / "jobs"


def parse_multipart_upload(body: bytes, content_type: str) -> tuple[str, bytes]:
    if not content_type.startswith("multipart/form-data"):
        raise ValueError("expected multipart/form-data")

    message = BytesParser(policy=default).parsebytes(
        b"Content-Type: " + content_type.encode("ascii", "ignore") + b"\r\n\r\n" + body
    )
    for part in message.iter_parts():
        if part.get_param("name", header="content-disposition") != "binary":
            continue
        filename = part.get_filename() or "input.elf"
        payload = part.get_payload(decode=True)
        if payload is None:
            raise ValueError("uploaded file is empty")
        return filename, payload

    raise ValueError("missing binary upload field")


def render_index() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>decomp_engine</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 3rem auto; max-width: 44rem; line-height: 1.5; }
    form { display: grid; gap: 1rem; padding: 1rem 0; }
    input, button { font: inherit; }
    button { width: max-content; padding: 0.45rem 0.8rem; }
  </style>
</head>
<body>
  <main>
    <h1>decomp_engine</h1>
    <form action="/jobs" method="post" enctype="multipart/form-data">
      <label for="binary">ELF binary</label>
      <input id="binary" name="binary" type="file" accept=".elf,application/x-elf" required>
      <button type="submit">Upload</button>
    </form>
  </main>
</body>
</html>
"""


def render_job(job: Job) -> str:
    metadata_items = "\n".join(
        f"      <dt>{html.escape(key.replace('_', ' ').title())}</dt><dd>{html.escape(str(value))}</dd>"
        for key, value in job.metadata.items()
    )
    repair_history = render_repair_history(job)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Job {html.escape(job.id)}</title>
</head>
<body>
  <main>
    <h1>Job {html.escape(job.id)}</h1>
    <dl>
      <dt>Status</dt><dd>{html.escape(job.status)}</dd>
      <dt>Filename</dt><dd>{html.escape(job.filename)}</dd>
      <dt>Size</dt><dd>{job.size_bytes} bytes</dd>
      <dt>Created</dt><dd>{html.escape(job.created_at)}</dd>
      {metadata_items}
    </dl>
    {repair_history}
  </main>
</body>
</html>
"""


def render_repair_history(job: Job) -> str:
    history_path = job.binary_path.parent / "reports" / "repair_history.json"
    if not history_path.exists():
        return ""

    try:
        payload = json.loads(history_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "<section><h2>Repair History</h2><p>Repair history could not be loaded.</p></section>"

    iterations = payload.get("iterations", [])
    if not isinstance(iterations, list) or not iterations:
        return ""

    items = []
    for iteration in iterations:
        if not isinstance(iteration, dict):
            continue
        index = html.escape(str(iteration.get("index", "?")))
        failure_kind = html.escape(str(iteration.get("failureKind", "unknown")))
        summary = html.escape(str(iteration.get("summary", "")))
        regression_ids = iteration.get("retainedRegressionIds", [])
        if isinstance(regression_ids, list):
            regressions = ", ".join(html.escape(str(item)) for item in regression_ids)
        else:
            regressions = ""
        items.append(
            "<li>"
            f"<strong>Iteration {index}</strong> "
            f"<span>{failure_kind}</span> "
            f"<p>{summary}</p> "
            f"<p>Regressions: {regressions}</p>"
            "</li>"
        )

    if not items:
        return ""
    return "<section><h2>Repair History</h2><ol>" + "".join(items) + "</ol></section>"


class UploadHandler(BaseHTTPRequestHandler):
    server: "UploadServer"

    def do_GET(self) -> None:
        if self.path == "/":
            self.send_html(HTTPStatus.OK, render_index())
            return

        if self.path.startswith("/jobs/"):
            job_id = unquote(self.path.removeprefix("/jobs/"))
            try:
                self.send_html(HTTPStatus.OK, render_job(self.server.store.get(job_id)))
            except JobStoreError as exc:
                self.send_text(HTTPStatus.NOT_FOUND, str(exc))
            return

        self.send_text(HTTPStatus.NOT_FOUND, "not found")

    def do_POST(self) -> None:
        if self.path != "/jobs":
            self.send_text(HTTPStatus.NOT_FOUND, "not found")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            filename, content = parse_multipart_upload(self.rfile.read(length), self.headers.get("Content-Type", ""))
            job = self.server.store.create_from_upload(filename, content)
        except (InvalidElfError, ValueError) as exc:
            self.send_text(HTTPStatus.BAD_REQUEST, str(exc))
            return

        if "application/json" in self.headers.get("Accept", ""):
            self.send_json(HTTPStatus.CREATED, job.to_dict())
            return

        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", f"/jobs/{job.id}")
        self.end_headers()

    def send_html(self, status: HTTPStatus, body: str) -> None:
        self.send_bytes(status, body.encode("utf-8"), "text/html; charset=utf-8")

    def send_text(self, status: HTTPStatus, body: str) -> None:
        self.send_bytes(status, body.encode("utf-8"), "text/plain; charset=utf-8")

    def send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        self.send_bytes(status, json.dumps(payload).encode("utf-8"), "application/json")

    def send_bytes(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class UploadServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], data_dir: Path) -> None:
        super().__init__(server_address, UploadHandler)
        self.store = JobStore(data_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the decomp_engine upload UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.data_dir.mkdir(parents=True, exist_ok=True)
    server = UploadServer((args.host, args.port), args.data_dir)
    print(f"Serving decomp_engine upload UI on http://{args.host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

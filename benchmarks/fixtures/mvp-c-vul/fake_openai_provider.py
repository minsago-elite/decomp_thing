#!/usr/bin/env python3
"""Bounded OpenAI-compatible fixture provider for the Docker MVP acceptance gate."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer


HOST = "0.0.0.0"
PORT = 8080
MODEL = "mvp-c-vul-fixture-v1"
AUTHORIZATION = "Bearer mvp-fixture-not-a-secret-v1"
MAXIMUM_REQUEST_BYTES = 4 * 1024 * 1024

VULNERABLE_SOURCE = """#include <stdio.h>

int main(void) {
    char badge[8];
    const char *message = "[03] Alexandria Stone";
    for (volatile int i = 0; message[i] != '\\0'; i++) {
        badge[i] = message[i];
    }
    puts("[03] Alexandria Stone");
    return badge[0] == 0;
}
"""

PATCHED_SOURCE = """#include <stdio.h>

int main(void) {
    puts("[03] Alexandria Stone");
    return 0;
}
"""

EXPECTED_SEQUENCE = ("binary-reconstruction", "memory-safety")
request_count = 0


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/health":
            self._send(200, b"ok\n", "text/plain; charset=utf-8")
            return
        if self.path == "/v1/models":
            self._send_json(200, {"object": "list", "data": [{"id": MODEL, "object": "model"}]})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.connection.settimeout(5)
        if self.path != "/v1/chat/completions":
            self._send_json(404, {"error": "not found"})
            return
        if self.headers.get("Authorization") != AUTHORIZATION:
            self._send_json(401, {"error": "invalid acceptance authorization sentinel"})
            return
        if self.headers.get("Transfer-Encoding"):
            self._send_json(400, {"error": "transfer encoding is not accepted"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send_json(411, {"error": "a valid content length is required"})
            return
        if length <= 0 or length > MAXIMUM_REQUEST_BYTES:
            self._send_json(413, {"error": "request body exceeds the fixture limit"})
            return
        try:
            request = json.loads(self.rfile.read(length).decode("utf-8", errors="strict"))
            model = request["model"]
            messages = request["messages"]
            user_message = messages[-1]["content"]
        except (KeyError, IndexError, TimeoutError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "invalid OpenAI-compatible request"})
            return
        if model != MODEL or not isinstance(user_message, str):
            self._send_json(422, {"error": "unexpected model or message"})
            return

        failure_kind, relative_path, replacement, summary = self._classify(user_message)
        if failure_kind is None:
            self._send_json(422, {"error": "request is outside the pinned MVP fixture contract"})
            return

        global request_count
        expected_index = request_count
        if expected_index >= len(EXPECTED_SEQUENCE) or failure_kind != EXPECTED_SEQUENCE[expected_index]:
            self._send_json(409, {"error": "unexpected fixture request sequence"})
            return
        request_count += 1
        ordinal = request_count

        content = json.dumps(
            {
                "summary": summary,
                "patches": [{"relativePath": relative_path, "replacement": replacement}],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self._send_json(200, {"choices": [{"message": {"content": content}}]})
        print(f"accepted mvp request {ordinal}: {failure_kind}", flush=True)

    @staticmethod
    def _classify(user_message: str) -> tuple[str | None, str, str, str]:
        if (
            "Failure kind: binary-reconstruction" in user_message
            and "### ghidra_decompiled.c" in user_message
            and "[03] Alexandria Stone" in user_message
        ):
            return (
                "binary-reconstruction",
                "decompiled.c",
                VULNERABLE_SOURCE,
                "Reconstruct the observed copy loop without repairing it before sanitizer validation.",
            )
        if (
            "Failure kind: memory-safety" in user_message
            and "### decompile/decompiled.c" in user_message
            and "Sanitizer evidence:" in user_message
            and "[03] Alexandria Stone" in user_message
        ):
            return (
                "memory-safety",
                "patched.c",
                PATCHED_SOURCE,
                "Remove the overflowing local copy while preserving the observed output.",
            )
        return (None, "", "", "")

    def _send_json(self, status: int, payload: object) -> None:
        self._send(
            status,
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            "application/json",
        )

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    HTTPServer((HOST, PORT), FixtureHandler).serve_forever()

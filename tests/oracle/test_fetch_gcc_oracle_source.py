from __future__ import annotations

import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest
import urllib.error


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FETCHER = runpy.run_path(str(REPOSITORY_ROOT / "scripts/fetch-gcc-oracle-source.py"))
fetch_artifact = FETCHER["fetch_artifact"]
official_candidate_urls = FETCHER["official_candidate_urls"]
VerificationError = FETCHER["VerificationError"]


class FakeResponse:
    def __init__(self, url: str, content: bytes):
        self.url = url
        self.content = content
        self.offset = 0
        self.headers = {"Content-Length": str(len(content))}

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *unused: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, amount: int) -> bytes:
        chunk = self.content[self.offset : self.offset + amount]
        self.offset += len(chunk)
        return chunk


class GccOracleSourceFetchTest(unittest.TestCase):
    payload = b"locked GCC release fixture\n"
    specification = {
        "fileName": "gcc-fixture.tar.xz.sig",
        "url": "https://ftp.gnu.org/gnu/gcc/gcc-16.2.0/gcc-16.2.0.tar.xz.sig",
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }

    def test_primary_failure_uses_verified_official_fallback(self) -> None:
        attempted: list[str] = []

        def opener(request: object, **unused: object) -> FakeResponse:
            url = request.full_url  # type: ignore[attr-defined]
            attempted.append(url)
            if "ftp.gnu.org" in url:
                raise urllib.error.URLError("primary unavailable")
            return FakeResponse(url, self.payload)

        with tempfile.TemporaryDirectory(prefix="gcc-fetch-fallback-") as temporary:
            fetched = fetch_artifact(
                Path(temporary),
                self.specification,
                "fixture signature",
                opener=opener,
                sleeper=lambda unused: None,
            )

            self.assertEqual(self.payload, fetched.read_bytes())
            self.assertEqual(3, len(attempted))
            self.assertIn("gcc.gnu.org", attempted[-1])

    def test_all_endpoint_failures_are_reported_and_leave_no_target(self) -> None:
        def opener(request: object, **unused: object) -> FakeResponse:
            raise urllib.error.URLError(request.full_url)  # type: ignore[attr-defined]

        with tempfile.TemporaryDirectory(prefix="gcc-fetch-failure-") as temporary:
            destination = Path(temporary)
            with self.assertRaisesRegex(VerificationError, "any official endpoint") as failure:
                fetch_artifact(
                    destination,
                    self.specification,
                    "fixture signature",
                    opener=opener,
                    sleeper=lambda unused: None,
                )

            for url in official_candidate_urls(str(self.specification["url"])):
                self.assertIn(url, str(failure.exception))
            self.assertFalse((destination / str(self.specification["fileName"])).exists())

    def test_corrupt_fallback_bytes_are_rejected_without_partial_cache(self) -> None:
        corrupt = b"x" * len(self.payload)

        def opener(request: object, **unused: object) -> FakeResponse:
            return FakeResponse(request.full_url, corrupt)  # type: ignore[attr-defined]

        with tempfile.TemporaryDirectory(prefix="gcc-fetch-corrupt-") as temporary:
            destination = Path(temporary)
            with self.assertRaisesRegex(VerificationError, "SHA-256 mismatch"):
                fetch_artifact(
                    destination,
                    self.specification,
                    "fixture signature",
                    opener=opener,
                    sleeper=lambda unused: None,
                )

            self.assertFalse((destination / str(self.specification["fileName"])).exists())

    def test_verified_existing_artifact_is_reused_without_network(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gcc-fetch-cache-") as temporary:
            destination = Path(temporary)
            target = destination / str(self.specification["fileName"])
            target.write_bytes(self.payload)

            reused = fetch_artifact(
                destination,
                self.specification,
                "fixture signature",
                opener=lambda *args, **kwargs: self.fail("network must not be used"),
            )

            self.assertEqual(target, reused)


if __name__ == "__main__":
    unittest.main()

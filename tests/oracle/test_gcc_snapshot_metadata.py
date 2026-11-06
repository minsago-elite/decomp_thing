"""Exact-source and actual APT verifier controls for #1917 diagnostics."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
DRIVER_PATH = ROOT / "scripts/diagnose-gcc-snapshot-metadata.py"
SPEC = importlib.util.spec_from_file_location("gcc_snapshot_diagnostic", DRIVER_PATH)
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)
GPG_SOCKET_NAMES = (
    "S.gpg-agent", "S.gpg-agent.browser", "S.gpg-agent.extra", "S.gpg-agent.ssh",
)
GPG_SOCKET_PATH_BYTES = 108


def _overlong_gpg_socket_names(home: Path) -> list[str]:
    return [name for name in GPG_SOCKET_NAMES
            if len(os.fsencode(home / name)) >= GPG_SOCKET_PATH_BYTES]


class RecipeAndSanitizerTest(unittest.TestCase):
    def test_gpg_socket_path_bound_covers_browser_socket(self):
        for width in range(1, GPG_SOCKET_PATH_BYTES):
            home = Path("/" + "x" * width)
            lengths = {name: len(os.fsencode(home / name)) for name in GPG_SOCKET_NAMES}
            if (lengths["S.gpg-agent.extra"] < GPG_SOCKET_PATH_BYTES and
                    lengths["S.gpg-agent.browser"] >= GPG_SOCKET_PATH_BYTES):
                self.assertEqual(["S.gpg-agent.browser"], _overlong_gpg_socket_names(home))
                return
        self.fail("no test path distinguished GnuPG's browser socket from extra socket")

    def test_gpg_fixture_setup_failure_runs_registered_class_cleanup(self):
        fixture = ActualAptSignatureControlsTest
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout=b"")

        try:
            with patch.object(subprocess, "run", side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, "fingerprint unavailable"):
                    fixture.setUpClass()
                fixture.doClassCleanups()
        finally:
            fixture.doClassCleanups()
        self.assertTrue(any(command[0] == "gpgconf" for command in calls))
        self.assertFalse(fixture.root.exists())

    def test_gpg_fixture_cleanup_attempts_all_agents_and_temp_after_error(self):
        fixture = ActualAptSignatureControlsTest
        calls = []
        cleanup_calls = []

        class Temp:
            def cleanup(self):
                cleanup_calls.append("temp")

        def fake_run(command, **kwargs):
            calls.append(command)
            if len(calls) == 1:
                raise OSError("first agent cleanup failed")
            return subprocess.CompletedProcess(command, 0)

        with patch.object(fixture, "homes", {
                "trusted": Path("/fixture/t"), "unrelated": Path("/fixture/u")}, create=True), \
             patch.object(fixture, "temp", Temp(), create=True), \
             patch.object(subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "failed to clean 1 GnuPG fixture resources"):
                fixture._cleanup_fixture()
        self.assertEqual(2, len(calls))
        self.assertEqual(["temp"], cleanup_calls)

    def test_derived_recipe_is_exact_locked_metadata_prefix_and_stops_before_download(self):
        dockerfile = diagnostic.DOCKERFILE.read_bytes()
        lock = json.loads(diagnostic.LOCK.read_bytes())
        recipe, observed = diagnostic.derive_diagnostic_recipe(dockerfile, lock)
        self.assertEqual(lock["recipe"]["dockerfileSha256"], observed)
        marker = diagnostic.APT_UPDATE_MARKER
        self.assertIn(dockerfile.split(marker, 1)[0], recipe)
        self.assertIn(b"Acquire::Retries=0", recipe)
        self.assertIn(b"Debug::Acquire::https=true", recipe)
        self.assertIn(b"Debug::Acquire::gpgv=true", recipe)
        self.assertIn(b"Debug::pkgAcquire::Auth=true", recipe)
        self.assertIn(b"KEYRING_META mode=%a size=%s uid=%u gid=%g path=%n", recipe)
        self.assertIn(b"KEYRING_FPR=", recipe)
        self.assertNotIn(b"apt-get download", recipe)
        self.assertNotIn(b"dpkg-deb", recipe)
        self.assertNotIn(b"--extract", recipe)
        self.assertNotIn(b"--load", recipe)
        self.assertEqual(2, recipe.count(b"apt-get "))

    def test_recipe_lock_mismatch_refuses_before_generating_anything(self):
        dockerfile = diagnostic.DOCKERFILE.read_bytes()
        lock = json.loads(diagnostic.LOCK.read_bytes())
        lock["recipe"]["dockerfileSha256"] = "0" * 64
        with self.assertRaisesRegex(diagnostic.Refusal, "does not match"):
            diagnostic.derive_diagnostic_recipe(dockerfile, lock)

    def test_recipe_refuses_ambiguous_update_boundary(self):
        dockerfile = diagnostic.DOCKERFILE.read_bytes()
        lock = json.loads(diagnostic.LOCK.read_bytes())
        lock["recipe"]["dockerfileSha256"] = hashlib.sha256(
            dockerfile + diagnostic.APT_UPDATE_MARKER).hexdigest()
        with self.assertRaisesRegex(diagnostic.Refusal, "exactly one"):
            diagnostic.derive_diagnostic_recipe(dockerfile + diagnostic.APT_UPDATE_MARKER, lock)

    def test_sanitizer_redacts_credentials_headers_queries_and_private_keys(self):
        raw = (b"GET https://user:password@snapshot.example/path?token=secret\n"
               b"Authorization: Bearer abc.def.ghi\nCookie: session=secret\n"
               b"-----BEGIN PRIVATE KEY-----\nprivate bytes\n-----END PRIVATE KEY-----\n"
               b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nsecret packet\n-----END PGP PRIVATE KEY BLOCK-----\n"
               b"Location: /next?token=fixture-secret\nGET /next?token=fixture-secret HTTP/1.1\n"
               b"Location: //alice:hunter2@redirect.example/path?token=protocol-secret\n"
               b"Hit:1 https://snapshot.example/debian/dists/trixie/InRelease\n"
               b"-----BEGIN RSA PRIVATE KEY-----\ntruncated secret bytes\n")
        safe = diagnostic.sanitize_output(raw)
        self.assertNotIn(b"password", safe)
        self.assertNotIn(b"token=secret", safe)
        self.assertNotIn(b"abc.def.ghi", safe)
        self.assertNotIn(b"session=secret", safe)
        self.assertNotIn(b"private bytes", safe)
        self.assertNotIn(b"secret packet", safe)
        self.assertNotIn(b"truncated secret bytes", safe)
        self.assertNotIn(b"fixture-secret", safe)
        self.assertNotIn(b"alice", safe)
        self.assertNotIn(b"hunter2", safe)
        self.assertNotIn(b"protocol-secret", safe)
        self.assertIn(b"snapshot.example/debian/dists/trixie/InRelease", safe)

    def test_protocol_relative_redirect_is_redacted_in_log_and_summary(self):
        raw = b"Location: //alice:hunter2@redirect.example/path?token=protocol-secret\n"
        safe = diagnostic.sanitize_output(raw)
        summary = diagnostic.summarize_apt_transport(safe)
        for retained in (safe, "\n".join(summary["redirectLinesFromAptDebug"]).encode()):
            self.assertNotIn(b"alice", retained)
            self.assertNotIn(b"hunter2", retained)
            self.assertNotIn(b"protocol-secret", retained)
        self.assertIn(b"redirect.example/path", safe)

    def test_buildkit_echoed_command_does_not_make_exact_marker_blocks_ambiguous(self):
        raw = (b"#4 0.001 RUN printf 'DIAG_APT_VERSION_BEGIN\\nDIAG_APT_VERSION_END\\n'\n"
               b"#4 0.002 DIAG_APT_VERSION_BEGIN\n#4 0.003 apt 2.6.1 (amd64)\n"
               b"#4 0.004 DIAG_APT_VERSION_END\n")
        block = diagnostic._block(raw, b"DIAG_APT_VERSION_BEGIN", b"DIAG_APT_VERSION_END")
        self.assertEqual(b"#4 0.003 apt 2.6.1 (amd64)\n", block)

    def test_marker_blocks_require_unique_whole_output_lines(self):
        raw = (b"#1 DIAG_APT_VERSION_BEGIN\n#1 apt 2.6.1\n#1 DIAG_APT_VERSION_END\n"
               b"#2 DIAG_APT_VERSION_BEGIN\n")
        with self.assertRaisesRegex(diagnostic.Refusal, "absent or ambiguous"):
            diagnostic._block(raw, b"DIAG_APT_VERSION_BEGIN", b"DIAG_APT_VERSION_END")

    def test_transport_summary_only_reports_explicit_sanitized_debug_lines(self):
        raw = (b"Answer for: https://snapshot.example/path/InRelease\n"
               b"HTTP/1.1 302 Found\nLocation: https://snapshot.example/final?token=hidden\n"
               b"HTTP/1.1 200 OK\n")
        summary = diagnostic.summarize_apt_transport(diagnostic.sanitize_output(raw))
        self.assertEqual(2, summary["statusLineCountObserved"])
        self.assertEqual(1, summary["redirectLineCountObserved"])
        self.assertIn("302 Found", summary["statusLinesFromAptDebug"][0])
        self.assertNotIn("token=hidden", summary["redirectLinesFromAptDebug"][0])
        self.assertFalse(summary["truncatedAt64"])

    def test_apt_metadata_requires_package_versions_and_bound_keyring_evidence(self):
        keyring_path = "/usr/share/keyrings/archive.gpg"
        keyring_data = b"fixture-keyring-bytes"
        keyring_sha = hashlib.sha256(keyring_data).hexdigest()
        valid = (b"DIAG_APT_VERSION_BEGIN\napt 2.6.1 (amd64)\nDIAG_APT_VERSION_END\n"
                 b"DIAG_GPGV_VERSION_BEGIN\ngpgv 2.2.40\nDIAG_GPGV_VERSION_END\n"
                 b"DIAG_PACKAGE_VERSIONS_BEGIN\napt=2.6.1\ngpgv=2.2.40\n"
                 b"debian-archive-keyring=2023.3\nDIAG_PACKAGE_VERSIONS_END\n"
                 b"DIAG_SOURCE_STANZAS_BEGIN\nURIs: https://snapshot.example/debian\n"
                 b"Signed-By: " + keyring_path.encode() + b"\nDIAG_SOURCE_STANZAS_END\n"
                 b"DIAG_KEYRINGS_BEGIN\nKEYRING_BEGIN=" + keyring_path.encode() + b"\n"
                 b"KEYRING_META mode=644 size=" + str(len(keyring_data)).encode() + b" uid=0 gid=0 path=" +
                 keyring_path.encode() + b"\n" + keyring_sha.encode() + b"  " + keyring_path.encode() + b"\n"
                 b"KEYRING_FPR=0123456789ABCDEF0123456789ABCDEF01234567\nKEYRING_END=" +
                 keyring_path.encode() + b"\nDIAG_KEYRINGS_END\n")
        parsed = diagnostic.parse_apt_metadata(valid)
        self.assertEqual("2.6.1 (amd64)", parsed["aptVersion"])
        self.assertEqual("2.2.40", parsed["gpgvVersion"])
        self.assertEqual("2.2.40", parsed["packageVersions"]["gpgv"])
        self.assertEqual([keyring_path], parsed["sourceSignedByPaths"])
        self.assertEqual(keyring_sha, parsed["keyrings"][0]["sha256"])
        self.assertEqual((0, 0), (parsed["keyrings"][0]["uid"], parsed["keyrings"][0]["gid"]))

        # Trixie's apt 3 may use the sqv method while the base has no gpgv
        # executable/package. Missing gpgv inventory stays explicit UNKNOWN;
        # it cannot be inferred from the separately parsed APT method label.
        trixie = (valid.replace(b"apt 2.6.1 (amd64)", b"apt 3.0.3 (amd64)", 1)
                  .replace(b"apt=2.6.1\n", b"apt=3.0.3\n", 1)
                  .replace(b"debian-archive-keyring=2023.3", b"debian-archive-keyring=2025.1", 1)
                  .replace(b"gpgv 2.2.40", b"/bin/sh: 1: gpgv: not found", 1)
                  .replace(b"gpgv=2.2.40\n", b"gpgv=\n", 1))
        parsed_trixie = diagnostic.parse_apt_metadata(trixie)
        self.assertEqual("3.0.3 (amd64)", parsed_trixie["aptVersion"])
        self.assertEqual("3.0.3", parsed_trixie["packageVersions"]["apt"])
        self.assertEqual("2025.1", parsed_trixie["packageVersions"]["debian-archive-keyring"])
        self.assertEqual("UNKNOWN", parsed_trixie["gpgvVersion"])
        self.assertEqual("UNKNOWN", parsed_trixie["packageVersions"]["gpgv"])
        # Neither the error's digits nor a method URI may be treated as a
        # gpgv version. URI observations are independently summarized below.
        noisy_optional = trixie.replace(
            b"/bin/sh: 1: gpgv: not found", b"/bin/sh: 1: gpgv: not found (exit 127, tried 2.2.40)", 1
        ).replace(b"DIAG_GPGV_VERSION_END", b"gpgv:2.4.7\nDIAG_GPGV_VERSION_END", 1)
        parsed_noisy = diagnostic.parse_apt_metadata(noisy_optional)
        self.assertEqual("UNKNOWN", parsed_noisy["gpgvVersion"])
        self.assertEqual("UNKNOWN", parsed_noisy["packageVersions"]["gpgv"])
        duplicate_optional = trixie.replace(
            b"gpgv=\n", b"gpgv=\ngpgv=2.2.40\n", 1
        )
        self.assertEqual("UNKNOWN", diagnostic.parse_apt_metadata(duplicate_optional)["packageVersions"]["gpgv"])
        unrecognized_optional = trixie.replace(b"gpgv=\n", b"gpgv=not-found\n", 1)
        self.assertEqual("UNKNOWN", diagnostic.parse_apt_metadata(unrecognized_optional)["packageVersions"]["gpgv"])

        observed = (b"#8 1.001 201 URI Done: sqv:/var/lib/apt/lists/a\n"
                    b"#8 1.002 Signature verification succeeded: /var/lib/apt/lists/a\n"
                    b"#8 1.003 201 URI Done: sqv:/var/lib/apt/lists/b\n"
                    b"#8 1.004 Signature verification succeeded: /var/lib/apt/lists/b\n"
                    b"#8 1.005 201 URI Done: gpgv:/var/lib/apt/lists/c\n"
                    b"#8 1.006 Signature verification succeeded: /var/lib/apt/lists/c\n")
        self.assertEqual({
            "verifierUriSchemesObserved": ["gpgv", "sqv"],
            "verifierUriDoneCountObserved": 3,
            "signatureVerificationSuccessCountObserved": 3,
            "verifierObservationTruncated": False,
        }, diagnostic.summarize_verifier_observations(observed))
        self.assertEqual("2.2.40", parsed["gpgvVersion"])
        self.assertEqual("2.2.40", parsed["packageVersions"]["gpgv"])
        sqv_only = diagnostic.summarize_verifier_observations(
            b"#8 1.007 201 URI Done: sqv:/var/lib/apt/lists/installed-gpgv\n"
        )
        self.assertEqual(["sqv"], sqv_only["verifierUriSchemesObserved"])
        self.assertEqual("2.2.40", parsed["gpgvVersion"])
        self.assertEqual("2.2.40", parsed["packageVersions"]["gpgv"])
        gpgv_only = diagnostic.summarize_verifier_observations(
            b"#8 1.008 201 URI Done: gpgv:/var/lib/apt/lists/legacy-method\n"
        )
        self.assertEqual(["gpgv"], gpgv_only["verifierUriSchemesObserved"])
        self.assertEqual([], diagnostic.summarize_verifier_observations(
            b"#8 1.0 mentions sqv: but is not a URI record\n#8 1.1 echo: 201 URI Done: gpgv:/x\n"
        )["verifierUriSchemesObserved"])
        empty_observation = diagnostic.summarize_verifier_observations(b"#8 1.0 no verifier observation\n")
        self.assertEqual([], empty_observation["verifierUriSchemesObserved"])
        self.assertEqual(0, empty_observation["verifierUriDoneCountObserved"])
        self.assertEqual(0, empty_observation["signatureVerificationSuccessCountObserved"])

        many_schemes = b"".join(
            f"#8 1.{i:03d} 201 URI Done: method{i:02d}:/opaque\n".encode()
            for i in range(diagnostic.MAX_VERIFIER_SCHEMES + 1)
        )
        many = diagnostic.summarize_verifier_observations(many_schemes)
        self.assertEqual(diagnostic.MAX_VERIFIER_SCHEMES, len(many["verifierUriSchemesObserved"]))
        self.assertEqual(diagnostic.MAX_VERIFIER_SCHEMES + 1, many["verifierUriDoneCountObserved"])
        self.assertTrue(many["verifierObservationTruncated"])
        self.assertEqual(sorted(many["verifierUriSchemesObserved"]), many["verifierUriSchemesObserved"])

        hostile = (
            valid.replace(b"debian-archive-keyring=2023.3\n", b"", 1),
            valid.replace(b"KEYRING_META mode=644 size=21", b"KEYRING_META mode=666 size=21", 1),
            valid.replace(keyring_sha.encode(), b"g" * 64, 1),
            valid.replace(b"KEYRING_FPR=0123456789ABCDEF0123456789ABCDEF01234567\n", b"", 1),
            valid.replace(keyring_path.encode(), b"/usr/share/keyrings/unrelated.gpg", 1),
            valid.replace(b"DIAG_APT_VERSION_BEGIN", b"DIAG_GPGV_VERSION_BEGIN", 1),
            valid + b"DIAG_APT_VERSION_BEGIN\napt 9.9\nDIAG_APT_VERSION_END\n",
        )
        for payload in hostile:
            with self.subTest(payload=payload[-120:]):
                with self.assertRaises(diagnostic.Refusal):
                    diagnostic.parse_apt_metadata(payload)

    def test_provenance_requires_exact_workflow_checkout_and_run_identity(self):
        provenance = {
            "requestedHead": "a" * 40,
            "workflowSha": "b" * 40,
            "executedCommit": "b" * 40,
            "executedTree": "c" * 40,
            "workflowRunId": "123",
            "workflowRunAttempt": "2",
            "workflowEvent": "pull_request",
            "worktreeClean": True,
        }
        self.assertTrue(diagnostic.provenance_is_complete(provenance, "d" * 64))
        for key, value in (("workflowSha", "e" * 40), ("workflowRunId", None),
                           ("workflowRunAttempt", "0"), ("workflowEvent", None),
                           ("worktreeClean", False)):
            with self.subTest(key=key):
                bad = dict(provenance, **{key: value})
                self.assertFalse(diagnostic.provenance_is_complete(bad, "d" * 64))
        self.assertFalse(diagnostic.provenance_is_complete(provenance, None))

    def test_output_path_rejects_escape_and_existing_destination(self):
        with self.assertRaisesRegex(diagnostic.Refusal, "under build"):
            diagnostic._output_directory("../outside")
        scratch = Path(tempfile.mkdtemp(prefix="gcc-snapshot-diagnostic-path-control-",
                                        dir=ROOT / "build"))
        try:
            relative = str(scratch.relative_to(ROOT))
            with self.assertRaises(FileExistsError):
                diagnostic._output_directory(relative)
        finally:
            scratch.rmdir()

    def test_missing_docker_endpoint_writes_bounded_incomplete_receipt_without_child(self):
        parent = ROOT / "build"
        parent.mkdir(exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="gcc-snapshot-incomplete-", dir=parent))
        shutil.rmtree(scratch)
        relative = str(scratch.relative_to(ROOT))
        status, output = diagnostic.capture(relative, "")
        try:
            self.assertNotEqual(0, status)
            self.assertEqual(scratch, output)
            receipt = json.loads((output / "receipt.json").read_bytes())
            self.assertEqual("incomplete", receipt["status"])
            self.assertIn("unsupported Docker endpoint", receipt["error"])
            self.assertTrue((output / "diagnostic.Dockerfile").is_file())
            self.assertLess(sum(p.stat().st_size for p in output.iterdir() if p.is_file()),
                            diagnostic.EVIDENCE_CAP)
        finally:
            shutil.rmtree(scratch)

    def test_canned_buildkit_transcript_seals_sanitized_complete_diagnostic_receipt(self):
        scratch = Path(tempfile.mkdtemp(prefix="gcc-snapshot-canned-run-", dir=ROOT / "build"))
        try:
            bin_dir = scratch / "bin"
            bin_dir.mkdir()
            docker = bin_dir / "docker"
            transcript = "\n".join([
                "#1 DIAG_APT_EXIT=100",
                "#1 DIAG_APT_VERSION_BEGIN", "#1 apt 2.6.1 (amd64)", "#1 DIAG_APT_VERSION_END",
                "#1 DIAG_GPGV_VERSION_BEGIN", "#1 /bin/sh: 1: gpgv: not found", "#1 DIAG_GPGV_VERSION_END",
                "#1 DIAG_PACKAGE_VERSIONS_BEGIN", "#1 apt=2.6.1", "#1 gpgv=",
                "#1 debian-archive-keyring=2023.3", "#1 DIAG_PACKAGE_VERSIONS_END",
                "#1 DIAG_GPG_TOOL=available",
                "#1 DIAG_SOURCE_STANZAS_BEGIN", "#1 URIs: https://snapshot.example/debian",
                "#1 Signed-By: /usr/share/keyrings/archive.gpg",
                "#1 DIAG_SOURCE_STANZAS_END", "#1 DIAG_KEYRINGS_BEGIN",
                "#1 KEYRING_BEGIN=/usr/share/keyrings/archive.gpg",
                f"#1 KEYRING_META mode=644 size={len(b'fixture-keyring-bytes')} uid=0 gid=0 path=/usr/share/keyrings/archive.gpg",
                f"#1 {hashlib.sha256(b'fixture-keyring-bytes').hexdigest()}  /usr/share/keyrings/archive.gpg",
                "#1 KEYRING_FPR=0123456789ABCDEF0123456789ABCDEF01234567",
                "#1 KEYRING_END=/usr/share/keyrings/archive.gpg",
                "#1 DIAG_KEYRINGS_END", "#1 HTTP/1.1 404 Not Found",
                "#1 1.001 201 URI Done: sqv:/var/lib/apt/lists/a",
                "#1 1.002 Signature verification succeeded: /var/lib/apt/lists/a",
                "#1 1.003 201 URI Done: sqv:/var/lib/apt/lists/b",
                "#1 1.004 Signature verification succeeded: /var/lib/apt/lists/b",
                "#1 1.005 201 URI Done: sqv:/var/lib/apt/lists/c",
                "#1 1.006 Signature verification succeeded: /var/lib/apt/lists/c",
                "#1 Location: https://snapshot.example/final?token=do-not-retain",
                "#1 Authorization: Bearer do-not-retain",
            ]) + "\n"
            expected_recipe = diagnostic.derive_diagnostic_recipe(
                diagnostic.DOCKERFILE.read_bytes(), json.loads(diagnostic.LOCK.read_bytes())
            )[0]
            expected_recipe_sha = diagnostic.sha256(expected_recipe)
            docker.write_text(
                f"#!{sys.executable}\n"
                "import hashlib, pathlib\n"
                "recipe = pathlib.Path('diagnostic.Dockerfile').read_bytes()\n"
                f"if hashlib.sha256(recipe).hexdigest() != {expected_recipe_sha!r}: raise SystemExit(61)\n"
                f"print({transcript!r}, end='')\n"
            )
            docker.chmod(0o755)
            builder = scratch / "builder.txt"
            builder.write_text("test builder identity\n")
            relative = str((scratch / "capture").relative_to(ROOT))
            git_values = {
                ("rev-parse", "HEAD"): "a" * 40,
                ("rev-parse", "HEAD^{tree}"): "b" * 40,
                ("status", "--porcelain"): "",
            }
            with patch.object(diagnostic, "BUILDER_EVIDENCE", builder), \
                 patch.object(diagnostic, "_git_value", side_effect=lambda *args, **kwargs: git_values.get(args)):
                status, output = diagnostic.capture(
                    relative, "unix:///run/docker.sock",
                    environ={"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(scratch),
                             "GCC_REPRODUCTION_HEAD": "a" * 40, "GITHUB_RUN_ID": "123",
                             "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "pull_request",
                             "GITHUB_SHA": "a" * 40},
                )
            self.assertEqual(0, status, (output / "receipt.json").read_text())
            receipt_path = output / "receipt.json"
            receipt = json.loads(receipt_path.read_bytes())
            self.assertEqual("complete", receipt["status"])
            self.assertEqual(2, receipt["schemaVersion"])
            self.assertTrue(receipt["provenance"]["worktreeClean"])
            self.assertEqual(100, receipt["aptObservation"]["updateExitCode"])
            self.assertEqual(1, receipt["aptObservation"]["statusLineCountObserved"])
            self.assertIn("404 Not Found", receipt["aptObservation"]["statusLinesFromAptDebug"][0])
            self.assertEqual("unavailable-from-apt-capture", receipt["aptObservation"]["aptConsumedBodyBytes"])
            self.assertEqual("2.6.1 (amd64)", receipt["aptMetadata"]["aptVersion"])
            self.assertEqual("UNKNOWN", receipt["aptMetadata"]["gpgvVersion"])
            self.assertEqual("UNKNOWN", receipt["aptMetadata"]["packageVersions"]["gpgv"])
            self.assertEqual(["sqv"], receipt["aptObservation"]["verifierUriSchemesObserved"])
            self.assertEqual(3, receipt["aptObservation"]["verifierUriDoneCountObserved"])
            self.assertEqual(3, receipt["aptObservation"]["signatureVerificationSuccessCountObserved"])
            self.assertFalse(receipt["aptObservation"]["verifierObservationTruncated"])
            self.assertIn("apt-diagnostic.log", receipt["evidenceFiles"])
            self.assertIn("diagnostic.Dockerfile", receipt["evidenceFiles"])
            log = (output / "apt-diagnostic.log").read_bytes()
            self.assertNotIn(b"do-not-retain", log)
            self.assertIn(b"[REDACTED_SECRET_FIELD]", log)
            self.assertEqual(diagnostic.sha256(log), receipt["evidenceFiles"]["apt-diagnostic.log"]["sha256"])
            total = sum(p.stat().st_size for p in output.iterdir() if p.is_file())
            self.assertLessEqual(total, diagnostic.EVIDENCE_CAP)

            late_relative = str((scratch / "late-provenance").relative_to(ROOT))
            late_env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(scratch),
                        "GCC_REPRODUCTION_HEAD": "a" * 40, "GITHUB_RUN_ID": "123",
                        "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "pull_request",
                        "GITHUB_SHA": "a" * 40}
            def delayed_git(*args, **kwargs):
                if args == ("rev-parse", "HEAD"):
                    time.sleep(1.0)
                return git_values.get(args)
            with patch.object(diagnostic, "TOTAL_SECONDS", 1.5), \
                 patch.object(diagnostic, "CLEANUP_SECONDS", 0.1), \
                 patch.object(diagnostic, "POSTPROCESS_SECONDS", 0.2), \
                 patch.object(diagnostic, "SEAL_SECONDS", 0.5), \
                 patch.object(diagnostic, "SEAL_CLEANUP_SECONDS", 0.1), \
                 patch.object(diagnostic, "BUILDER_EVIDENCE", builder), \
                 patch.object(diagnostic, "_git_value", side_effect=delayed_git):
                late_status, late_output = diagnostic.capture(late_relative, "unix:///run/docker.sock", environ=late_env)
            late_receipt = json.loads((late_output / "receipt.json").read_bytes())
            self.assertNotEqual(0, late_status)
            self.assertEqual("incomplete", late_receipt["status"])
            self.assertIn("provenance", late_receipt["error"])
        finally:
            shutil.rmtree(scratch)


class ProcessBoundsTest(unittest.TestCase):
    def test_empty_successful_git_status_is_recorded_as_clean(self):
        completed = subprocess.CompletedProcess(["git", "status", "--porcelain"], 0, b"", b"")
        with patch.object(diagnostic.subprocess, "run", return_value=completed):
            self.assertEqual("", diagnostic._git_value("status", "--porcelain", empty_ok=True))
        with patch.object(diagnostic.subprocess, "run", return_value=completed):
            self.assertIsNone(diagnostic._git_value("status", "--porcelain"))

    def test_evidence_sealer_is_killed_and_reaped_at_its_deadline(self):
        scratch = Path(tempfile.mkdtemp(prefix="gcc-snapshot-seal-timeout-", dir=ROOT / "build"))
        original = diagnostic.SEALER_SOURCE
        started = time.monotonic()
        try:
            recipe = b"recipe"
            (scratch / "diagnostic.Dockerfile").write_bytes(recipe)
            diagnostic.SEALER_SOURCE = "import time; time.sleep(30)"
            deadline = time.monotonic() + 0.2
            ok, cleanup_confirmed = diagnostic._seal_files(
                scratch,
                {"apt-diagnostic.log": b"log", "receipt.json": b'{"status":"complete"}'},
                existing_files={"diagnostic.Dockerfile": {"sha256": diagnostic.sha256(recipe),
                                                           "sizeBytes": len(recipe)}},
                deadline=deadline,
                cleanup_deadline=deadline + 0.5,
            )
        finally:
            diagnostic.SEALER_SOURCE = original
        self.assertFalse(ok)
        self.assertTrue(cleanup_confirmed)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertFalse((scratch / "receipt.json").exists())
        self.assertEqual(["diagnostic.Dockerfile"], sorted(p.name for p in scratch.iterdir()))
        (scratch / "diagnostic.Dockerfile").unlink()
        scratch.rmdir()

    def test_sealer_timeout_after_staging_never_publishes_complete_receipt(self):
        scratch = Path(tempfile.mkdtemp(prefix="gcc-snapshot-seal-final-publication-", dir=ROOT / "build"))
        original = diagnostic.SEALER_SOURCE
        recipe = b"locked diagnostic recipe"
        (scratch / "diagnostic.Dockerfile").write_bytes(recipe)
        source = original.replace(
            "os.rename(receipt[1], receipt[2])",
            "time.sleep(30)\nos.rename(receipt[1], receipt[2])",
        )
        self.assertNotEqual(original, source)
        started = time.monotonic()
        try:
            diagnostic.SEALER_SOURCE = source
            deadline = time.monotonic() + 0.5
            ok, cleanup_confirmed = diagnostic._seal_files(
                scratch,
                {"apt-diagnostic.log": b"sanitized diagnostic", "receipt.json": b'{"status":"complete"}'},
                existing_files={"diagnostic.Dockerfile": {"sha256": diagnostic.sha256(recipe),
                                                           "sizeBytes": len(recipe)}},
                deadline=deadline,
                cleanup_deadline=deadline + 0.5,
            )
        finally:
            diagnostic.SEALER_SOURCE = original
        self.assertFalse(ok)
        self.assertTrue(cleanup_confirmed)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertFalse((scratch / "receipt.json").exists())
        shutil.rmtree(scratch)

    def test_output_cap_is_enforced_during_streaming(self):
        old_cap = diagnostic.OUTPUT_CAP
        old_cleanup = diagnostic.CLEANUP_SECONDS
        old_postprocess = diagnostic.POSTPROCESS_SECONDS
        old_seal = diagnostic.SEAL_SECONDS
        diagnostic.OUTPUT_CAP = 1024
        diagnostic.CLEANUP_SECONDS = 0.1
        diagnostic.POSTPROCESS_SECONDS = 0.1
        diagnostic.SEAL_SECONDS = 0.1
        try:
            result = diagnostic._run_docker(
                [os.environ.get("PYTHON", "python3"), "-c", "import sys; sys.stdout.write('x' * 100000)"],
                {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, ROOT,
                time.monotonic() + 15,
            )
        finally:
            diagnostic.OUTPUT_CAP = old_cap
            diagnostic.CLEANUP_SECONDS = old_cleanup
            diagnostic.POSTPROCESS_SECONDS = old_postprocess
            diagnostic.SEAL_SECONDS = old_seal
        self.assertTrue(result["outputOverflow"])
        self.assertFalse(result["complete"])
        self.assertLessEqual(result["rawOutputBytesObservedAtMost"], old_cap)

    def test_timeout_terminates_and_reaps_owned_process_group(self):
        old_total = diagnostic.TOTAL_SECONDS
        old_cleanup = diagnostic.CLEANUP_SECONDS
        old_postprocess = diagnostic.POSTPROCESS_SECONDS
        old_seal = diagnostic.SEAL_SECONDS
        diagnostic.TOTAL_SECONDS = 0.8
        diagnostic.CLEANUP_SECONDS = 0.1
        diagnostic.POSTPROCESS_SECONDS = 0.1
        diagnostic.SEAL_SECONDS = 0.2
        old_seal_cleanup = diagnostic.SEAL_CLEANUP_SECONDS
        diagnostic.SEAL_CLEANUP_SECONDS = 0.1
        start = time.monotonic()
        try:
            result = diagnostic._run_docker(
                [os.environ.get("PYTHON", "python3"), "-c", "import time; time.sleep(5)"],
                {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, ROOT,
                time.monotonic() + 2,
            )
        finally:
            diagnostic.TOTAL_SECONDS = old_total
            diagnostic.CLEANUP_SECONDS = old_cleanup
            diagnostic.POSTPROCESS_SECONDS = old_postprocess
            diagnostic.SEAL_SECONDS = old_seal
            diagnostic.SEAL_CLEANUP_SECONDS = old_seal_cleanup
        self.assertTrue(result["timedOut"])
        self.assertFalse(result["complete"])
        self.assertEqual([], result["cleanup"])
        self.assertTrue(result["groupCleanupConfirmed"])
        self.assertLess(time.monotonic() - start, 2)

    def test_owned_process_group_is_cleaned_after_leader_exits(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("PR_SET_CHILD_SUBREAPER is a Linux process-control facility")
        scratch = Path(tempfile.mkdtemp(prefix="gcc-snapshot-descendant-", dir=ROOT / "build"))
        pid_file = scratch / "descendant.pid"
        reaped_file = scratch / "reaped.json"
        leader_source = (
            "import subprocess,sys,time\n"
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'], "
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "open(sys.argv[1],'w').write(str(p.pid))\n"
            "time.sleep(0.05)\n"
        )
        # Run _run_docker in a separate Linux subreaper. The worker leader and
        # sleeper share the driver's process group; when the leader exits, the
        # subreaper adopts the sleeper and reaps it while the driver performs
        # its SIGTERM/SIGKILL cleanup. This never delegates reaping to PID 1.
        subreaper_source = (
            "import ctypes,importlib.util,json,os,sys,threading,time\n"
            "libc=ctypes.CDLL(None,use_errno=True)\n"
            "if libc.prctl(36,1,0,0,0) != 0: raise OSError(ctypes.get_errno(),'prctl')\n"
            "driver,pid_path,reaped_path,repo=sys.argv[1:]\n"
            "spec=importlib.util.spec_from_file_location('diagnostic',driver)\n"
            "d=importlib.util.module_from_spec(spec); spec.loader.exec_module(d)\n"
            "wanted=[None]; reaped=[]; stop=threading.Event()\n"
            "def reap():\n"
            "  while not stop.is_set():\n"
            "    if wanted[0] is None:\n"
            "      try: wanted[0]=int(open(pid_path).read())\n"
            "      except (FileNotFoundError,ValueError): pass\n"
            "    if wanted[0] is not None:\n"
            "      try: pid,status=os.waitpid(wanted[0],os.WNOHANG)\n"
            "      except ChildProcessError: pid=0\n"
            "      if pid: reaped.append(pid)\n"
            "    time.sleep(0.002)\n"
            "thread=threading.Thread(target=reap,daemon=True); thread.start()\n"
            "d.CLEANUP_SECONDS=1; d.POSTPROCESS_SECONDS=1; d.SEAL_SECONDS=1; d.SEAL_CLEANUP_SECONDS=1\n"
            f"result=d._run_docker([sys.executable,'-c',{leader_source!r},pid_path], "
            "{'PATH':os.environ.get('PATH','/usr/bin:/bin')}, d.ROOT, time.monotonic()+20)\n"
            "stop.set(); thread.join(timeout=2)\n"
            "if thread.is_alive(): raise RuntimeError('subreaper thread did not stop')\n"
            "if wanted[0] is None: raise RuntimeError('descendant PID was never observed')\n"
            "if wanted[0] not in reaped: raise RuntimeError('subreaper did not reap descendant')\n"
            "try: os.kill(wanted[0],0)\n"
            "except ProcessLookupError: pass\n"
            "else: raise RuntimeError('descendant still exists after reaping')\n"
            "fields=('exitCode','groupCleanupConfirmed','complete','timedOut','cleanup')\n"
            "summary={key:result[key] for key in fields}\n"
            "open(reaped_path,'w').write(json.dumps({'result':summary,'reaped':reaped}))\n"
        )
        try:
            completed = subprocess.run(
                [sys.executable, "-c", subreaper_source, str(DRIVER_PATH),
                 str(pid_file), str(reaped_file), str(ROOT)],
                cwd=ROOT, env=os.environ.copy(), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr.decode(errors="replace"))
            evidence = json.loads(reaped_file.read_bytes())
            result = evidence["result"]
            self.assertEqual([int(pid_file.read_text())], evidence["reaped"])
            self.assertEqual(0, result["exitCode"])
            self.assertTrue(result["groupCleanupConfirmed"])
            self.assertTrue(result["complete"])
            self.assertTrue(pid_file.is_file())
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)
        finally:
            shutil.rmtree(scratch)


@unittest.skipUnless(shutil.which("apt-get") and shutil.which("gpg"),
                     "actual apt-get/gpg fixture controls require Debian tooling")
class ActualAptSignatureControlsTest(unittest.TestCase):
    """Use a fresh file:// repository and real apt/gpgv authentication per case."""

    @classmethod
    def setUpClass(cls):
        base = ROOT / "build"
        base.mkdir(parents=True, exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="g", dir=base)
        cls.addClassCleanup(cls._cleanup_fixture)
        cls.root = Path(cls.temp.name)
        cls.root.chmod(0o755)
        cls.homes = {}
        cls.keyrings = {}
        for name, home_leaf in (("trusted", "t"), ("unrelated", "u")):
            home = cls.root / home_leaf
            home.mkdir(mode=0o700)
            cls.homes[name] = home
            # Linux sun_path holds 108 bytes including the terminating NUL.
            # Bound every named GnuPG socket before starting its agent.
            too_long = _overlong_gpg_socket_names(home)
            if too_long:
                raise RuntimeError("GnuPG fixture socket path exceeds the Unix-domain limit")
            subprocess.run([
                "gpg", "--batch", "--passphrase", "", "--homedir", str(home),
                "--quick-generate-key", f"APT fixture {name} <{name}@invalid.example>",
                "rsa2048", "sign", "0",
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
            listing = subprocess.run([
                "gpg", "--batch", "--homedir", str(home), "--with-colons",
                "--list-secret-keys",
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).stdout.decode()
            fingerprints = [line.split(":")[9] for line in listing.splitlines()
                            if line.startswith("fpr:")]
            if not fingerprints:
                raise RuntimeError("fixture signing key fingerprint unavailable")
            fingerprint = fingerprints[0]
            keyring = cls.root / f"{name}.gpg"
            exported = subprocess.run([
                "gpg", "--batch", "--homedir", str(home), "--export", fingerprint,
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).stdout
            keyring.write_bytes(exported)
            keyring.chmod(0o644)
            cls.keyrings[name] = keyring

    @classmethod
    def _cleanup_fixture(cls):
        errors = []
        for home in getattr(cls, "homes", {}).values():
            try:
                subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=10, check=False)
            except (OSError, subprocess.SubprocessError) as error:
                errors.append(error)
        temp = getattr(cls, "temp", None)
        if temp is not None:
            try:
                temp.cleanup()
            except OSError as error:
                errors.append(error)
        if errors:
            raise RuntimeError(f"failed to clean {len(errors)} GnuPG fixture resources") from errors[0]

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="case-", dir=self.root))
        self.case.chmod(0o755)
        self.repo = self.case / "repo"
        index = self.repo / "dists/stable/main/binary-amd64/Packages"
        index.parent.mkdir(parents=True)
        index.write_bytes(b"")
        index.chmod(0o644)
        self.lists = self.case / "lists"
        self.archives = self.case / "archives"
        self.lists.mkdir(mode=0o755)
        (self.lists / "partial").mkdir(mode=0o755)
        self.archives.mkdir(mode=0o755)
        (self.archives / "partial").mkdir(mode=0o755)
        (self.case / "status").write_bytes(b"")
        (self.case / "empty.conf").write_bytes(b"")

    def tearDown(self):
        shutil.rmtree(self.case, ignore_errors=True)

    def _release(self, *, body: bytes | None = None) -> bytes:
        index = b"" if body is None else body
        path = self.repo / "dists/stable/main/binary-amd64/Packages"
        path.write_bytes(index)
        digest = hashlib.sha256(index).hexdigest()
        md5 = hashlib.md5(index).hexdigest()
        return ("Origin: Snapshot fixture\n"
                "Label: Snapshot fixture\n"
                "Suite: stable\n"
                "Codename: stable\n"
                "Date: Wed, 01 Jan 2025 00:00:00 UTC\n"
                "Architectures: amd64\n"
                "Components: main\n"
                "Description: isolated authenticated APT fixture\n"
                "MD5Sum:\n"
                f" {md5} {len(index)} main/binary-amd64/Packages\n"
                "SHA256:\n"
                f" {digest} {len(index)} main/binary-amd64/Packages\n").encode()

    def _sign(self, release: bytes, *, signer="trusted", detached=False):
        (self.repo / "dists/stable/Release").write_bytes(release)
        home = self.homes[signer]
        if detached:
            subprocess.run(["gpg", "--batch", "--yes", "--homedir", str(home),
                            "--armor", "--detach-sign", "--output", str(self.repo / "dists/stable/Release.gpg"),
                            str(self.repo / "dists/stable/Release")],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        else:
            subprocess.run(["gpg", "--batch", "--yes", "--homedir", str(home),
                            "--clearsign", "--output", str(self.repo / "dists/stable/InRelease"),
                            str(self.repo / "dists/stable/Release")],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def _apt(self, *, keyring="trusted", source_uri=None):
        uri = source_uri or self.repo.as_uri()
        signed = self.keyrings[keyring] if keyring in self.keyrings else Path(keyring)
        source = self.case / "sources.list"
        source.write_text(f"deb [signed-by={signed}] {uri} stable main\n")
        command = [
            "apt-get", "-o", f"Dir::Etc::sourcelist={source}",
            "-o", "Dir::Etc::sourceparts=-", "-o", f"Dir::Etc::main={self.case / 'empty.conf'}",
            "-o", f"Dir::State::lists={self.lists}", "-o", f"Dir::State::status={self.case / 'status'}",
            "-o", f"Dir::Cache::archives={self.archives}", "-o", "Debug::NoLocking=1",
            "-o", "Acquire::Retries=0", "-o", "Acquire::Check-Valid-Until=false",
            "-o", "Acquire::Languages=none", "-o", "APT::Get::List-Cleanup=0",
            "-o", "APT::Get::AllowUnauthenticated=false", "-o", "Acquire::AllowInsecureRepositories=false",
            "update",
        ]
        return subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=20, check=False)

    def test_valid_signed_inrelease_is_accepted(self):
        self._sign(self._release())
        result = self._apt()
        self.assertEqual(0, result.returncode, result.stdout.decode(errors="replace"))

    def test_valid_detached_release_signature_is_accepted_when_inrelease_absent(self):
        self._sign(self._release(), detached=True)
        result = self._apt()
        self.assertEqual(0, result.returncode, result.stdout.decode(errors="replace"))

    def test_missing_signatures_on_both_routes_are_refused(self):
        (self.repo / "dists/stable/Release").write_bytes(self._release())
        result = self._apt()
        self.assertNotEqual(0, result.returncode, result.stdout.decode(errors="replace"))

    def test_unknown_signer_is_refused_by_selected_signed_by_keyring(self):
        self._sign(self._release(), signer="unrelated")
        result = self._apt(keyring="trusted")
        self.assertNotEqual(0, result.returncode, result.stdout.decode(errors="replace"))

    def test_missing_signed_by_keyring_is_refused(self):
        self._sign(self._release())
        result = self._apt(keyring=self.case / "missing-keyring.gpg")
        self.assertNotEqual(0, result.returncode, result.stdout.decode(errors="replace"))

    def test_validly_signed_html_metadata_is_refused_as_invalid_release(self):
        self._sign(b"<!doctype html><html>proxy response</html>\n")
        result = self._apt()
        self.assertNotEqual(0, result.returncode, result.stdout.decode(errors="replace"))

    def test_detached_signature_does_not_authenticate_mutated_release_bytes(self):
        self._sign(self._release(), detached=True)
        release = self.repo / "dists/stable/Release"
        release.write_bytes(release.read_bytes() + b"X-Injected: true\n")
        result = self._apt()
        self.assertNotEqual(0, result.returncode, result.stdout.decode(errors="replace"))

    def test_authenticated_release_refuses_mutated_package_index_digest(self):
        package_index = b"Package: expected\nVersion: 1\n"
        self._sign(self._release(body=package_index))
        index_path = self.repo / "dists/stable/main/binary-amd64/Packages"
        index_path.write_bytes(package_index + b"Package: injected\nVersion: 2\n")
        result = self._apt()
        self.assertNotEqual(0, result.returncode, result.stdout.decode(errors="replace"))
        self.assertIn(b"Hash Sum mismatch", result.stdout)


if __name__ == "__main__":
    unittest.main()

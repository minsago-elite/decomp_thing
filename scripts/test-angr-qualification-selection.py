#!/usr/bin/env python3
"""Authored Git/pin fixtures only; run by Actions without installing or invoking Angr."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class AngrQualificationSelectionTest(unittest.TestCase):
    def setUp(self):
        parent = Path("build/test-work/angr-selection").resolve()
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="case-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        self.remote = self.root / "remote.git"
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0")
        self.run_command(["git", "init", "--quiet", "--bare", str(self.remote)], self.root)
        self.run_command(["git", "init", "--quiet", "-b", "fixture"], self.repo)
        self.git("remote", "add", "origin", str(self.remote))
        scripts = self.repo / "scripts"
        scripts.mkdir()
        for name in ("select-angr-qualification.sh", "check-angr-pin.py"):
            shutil.copyfile(Path(__file__).resolve().parent / name, scripts / name)
        self.write("README.md", "initial\n")
        self.write("Dockerfile", "ARG ANGR_VERSION=9.2.213\n")
        self.write("requirements/angr-qualification.txt", "angr==9.2.213\n")
        self.write("requirements/angr-compatibility.txt", "bitstring==4.4.0\npycparser==3.1\n")
        self.base = self.commit("initial authored fixture")
        self.git("push", "--quiet", "origin", "HEAD:refs/heads/fixture")

    def run_command(self, command, cwd, env=None, check=True):
        return subprocess.run(command, cwd=cwd, env=env or self.env, check=check,
                              capture_output=True, text=True, timeout=20)

    def git(self, *args, repo=None):
        return self.run_command(["git", "-c", "core.hooksPath=/dev/null", *args], repo or self.repo).stdout.strip()

    def write(self, relative, text):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, message):
        self.git("add", ".")
        self.git("-c", "user.name=Authored fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD")

    def select(self, base, repo=None):
        repo = repo or self.repo
        output = repo / "selector-output"
        output.unlink(missing_ok=True)
        env = dict(self.env, GITHUB_OUTPUT=str(output), ANGR_DIFF_BASE=base)
        self.run_command(["bash", "scripts/select-angr-qualification.sh"], repo, env)
        result = dict(line.split("=", 1) for line in output.read_text().splitlines())
        record = (repo / "build/angr-qualification/selection.txt").read_text()
        return result["required"], record

    def test_unrelated_update_does_not_install_angr(self):
        self.write("README.md", "unrelated update\n")
        self.commit("unrelated tip")
        required, record = self.select(self.base)
        self.assertEqual("false", required)
        self.assertIn("reason=no-relevant-change", record)

    def test_earlier_relevant_commit_is_not_hidden_by_unrelated_tip(self):
        self.write("src/main/kotlin/decompengine/exploration/fixture.kt", "authored data\n")
        self.commit("relevant first commit")
        self.write("README.md", "unrelated tip\n")
        self.commit("unrelated final commit")
        self.assertEqual("true", self.select(self.base)[0])

    def test_shallow_checkout_fetches_the_full_update_base(self):
        self.write("src/test/kotlin/decompengine/exploration/fixture.kt", "authored data\n")
        self.commit("relevant first commit")
        self.write("README.md", "unrelated tip\n")
        self.commit("unrelated final commit")
        self.git("push", "--quiet", "origin", "HEAD:refs/heads/fixture")
        shallow = self.root / "shallow"
        self.run_command(["git", "clone", "--quiet", "--depth=1", "--branch=fixture", self.remote.as_uri(), str(shallow)], self.root)
        missing = self.run_command(["git", "cat-file", "-e", self.base + "^{commit}"], shallow, check=False)
        self.assertNotEqual(0, missing.returncode)
        required, record = self.select(self.base, shallow)
        self.assertEqual("true", required)
        self.assertIn("comparisonBase=" + self.base, record)

    def test_production_pin_change_selects_qualification(self):
        self.write("Dockerfile", "ARG ANGR_VERSION=9.2.214\n")
        self.commit("production pin change")
        self.assertEqual("true", self.select(self.base)[0])

    def test_zero_invalid_and_unavailable_bases_select_without_disclosing_invalid_text(self):
        for base in ("0" * 40, "PRIVATE-invalid-base\n", "f" * 40):
            with self.subTest(baseKind="unavailable"):
                required, record = self.select(base)
                self.assertEqual("true", required)
                self.assertNotIn("PRIVATE", record)

    def test_shared_compatibility_change_selects_qualification(self):
        self.write("requirements/angr-compatibility.txt", "bitstring==4.3.1\n")
        self.commit("shared compatibility pin change")
        self.assertEqual("true", self.select(self.base)[0])

    def check_pin(self):
        return self.run_command([sys.executable, "scripts/check-angr-pin.py"], self.repo, check=False)

    def test_matching_production_pin_is_identified(self):
        result = self.check_pin()
        self.assertEqual(0, result.returncode, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual("9.2.213", record["angrVersion"])
        self.assertEqual("4.4.0", record["bitstringVersion"])
        self.assertEqual("3.1", record["pycparserVersion"])
        self.assertEqual(64, len(record["dockerfileSha256"]))

    def test_mismatched_or_ambiguous_pin_is_rejected(self):
        for docker in ("ARG ANGR_VERSION=9.2.214\n", "ARG ANGR_VERSION=9.2.213\nARG ANGR_VERSION=9.2.213\n"):
            self.write("Dockerfile", docker)
            result = self.check_pin()
            self.assertNotEqual(0, result.returncode)
            self.assertIn("one matching Docker and requirements pin", result.stderr)

    def test_missing_or_ambiguous_shared_compatibility_pin_is_rejected(self):
        for compatibility in ("", "bitstring==4.4.0\nbitstring==4.4.0\n"):
            self.write("requirements/angr-compatibility.txt", compatibility)
            result = self.check_pin()
            self.assertNotEqual(0, result.returncode)
            self.assertIn("one shared bitstring compatibility pin", result.stderr)

    def test_missing_unpinned_or_ambiguous_pycparser_is_rejected(self):
        for parser in ("", "pycparser>=3.0\n", "pycparser==3.1\npycparser==3.1\n"):
            with self.subTest(parser=parser):
                self.write("requirements/angr-compatibility.txt", "bitstring==4.4.0\n" + parser)
                result = self.check_pin()
                self.assertNotEqual(0, result.returncode)
                self.assertIn("one shared pycparser compatibility pin", result.stderr)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Authored routing controls for the real qualifier; all Gradle/operator tools are stubs.

Every fixture and subprocess output stays beneath this checkout's build directory.
The copied qualifier runs real shell/Python receipt code, but no JVM, privileged
operation, provider, mount, or hosted qualification is exercised.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parent.parent
QUALIFIER = ROOT / "scripts/qualify-contained-module-compilation.sh"
RUN_ID = "90000000001"
ATTEMPT = "2"
IDENTITY = f"{RUN_ID}.{ATTEMPT}.module"
REQUIRED_ACP_CLASS = "decompengine.acp.AcpAgentHarnessTest"
REQUIRED_ACP_METHOD = "public Make and Ninja archival reconstruction follows ACP file roles through verified rebuild"

MOCK_SUPPORT = """\
import json
import os
from pathlib import Path
import sys

def log(command, arguments=None):
    with Path(os.environ['MOCK_CALL_LOG']).open('a', encoding='utf-8') as output:
        json.dump({'command': command, 'arguments': sys.argv[1:] if arguments is None else arguments}, output)
        output.write('\\n')

def code(name):
    return int(os.environ.get(name, '0'))

def option(name):
    return sys.argv[sys.argv.index(name) + 1]
"""


class ModuleCompilationQualificationRoutingTest(unittest.TestCase):
    def make_fixture(self):
        parent = ROOT / "build/test-work/module-compilation-qualification-routing"
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="case-", dir=parent)
        self.addCleanup(temporary.cleanup)
        checkout = Path(temporary.name) / "checkout"
        scripts = checkout / "scripts"
        scripts.mkdir(parents=True)
        binaries = checkout / "mock-bin"
        binaries.mkdir()
        shutil.copyfile(QUALIFIER, scripts / QUALIFIER.name)
        self.assertEqual(QUALIFIER.read_bytes(), (scripts / QUALIFIER.name).read_bytes())
        (scripts / "module-compilation-qualification.init.gradle").write_text(
            "// Authored routing fixture; never interpreted by Gradle.\n", encoding="utf-8")
        self.write_stub(binaries / "git", """
            log('git')
            args = sys.argv[1:]
            if args == ['rev-parse', 'HEAD']:
                print('1' * 40)
            elif args == ['rev-parse', 'HEAD^{tree}']:
                print('2' * 40)
            elif args == ['status', '--porcelain', '--untracked-files=no']:
                pass
            elif args == ['show', '-s', '--format=%P', 'HEAD']:
                print('3' * 40)
            else:
                raise SystemExit('unexpected mocked git invocation: ' + repr(args))
        """)
        self.write_stub(checkout / "gradlew", """
            args = sys.argv[1:]
            root = Path.cwd()
            qualification = root / 'build/module-compilation-qualification'
            if 'moduleCompilerDeploymentManifest' in args:
                log('gradle-prerequisites')
                result = code('MOCK_PREREQUISITES_EXIT')
                if result == 0:
                    helper = root / 'build/native/acp/decomp-acp-gate-helper'
                    helper.parent.mkdir(parents=True, exist_ok=True)
                    helper.write_text('authored inert helper bytes\\n', encoding='utf-8')
                    (qualification / 'worker-classpath.json').write_text('{}\\n', encoding='utf-8')
            elif 'moduleCompilerWriteConfig' in args:
                log('gradle-configuration')
                result = code('MOCK_CONFIGURATION_EXIT')
                if result == 0:
                    config = qualification / 'config'
                    config.mkdir()
                    for profile in ('generated-c-make-v1', 'generated-c-ninja-v1'):
                        (config / (profile + '.json')).write_text('{}\\n', encoding='utf-8')
            elif 'moduleCompilationLiveQualification' in args:
                log('gradle-live')
                inventory_mode = os.environ.get('MOCK_INVENTORY', 'valid')
                if inventory_mode != 'missing':
                    tests = [] if inventory_mode == 'without-required-acp' else [{
                        'class': os.environ['MOCK_REQUIRED_ACP_CLASS'],
                        'method': os.environ['MOCK_REQUIRED_ACP_METHOD'],
                    }]
                    (qualification / 'compiled-live-tests.json').write_text(json.dumps({'tests': tests}) + '\\n', encoding='utf-8')
                if os.environ.get('MOCK_REPORTS', 'present') != 'missing':
                    reports = root / 'build/test-results/moduleCompilationLiveQualification'
                    reports.mkdir(parents=True)
                    (reports / 'TEST-authored.xml').write_text('<testsuite/>\\n', encoding='utf-8')
                result = code('MOCK_LIVE_EXIT')
                print('authored live Gradle routing result=' + str(result))
            else:
                raise SystemExit('unexpected mocked Gradle invocation: ' + repr(args))
            raise SystemExit(result)
        """)
        self.write_stub(binaries / "sudo", """
            args = sys.argv[1:]
            if not args or args[0] != '-n':
                raise SystemExit('only the expected noninteractive operator seam is mocked')
            if len(args) >= 4 and args[1:3] == ['python3', 'scripts/ci-prepare-generated-c-validation.py']:
                action = args[3]
                if action not in ('prepare', 'cleanup'):
                    raise SystemExit('unexpected mocked operator action')
                log(action)
                if option('--run-id') != os.environ['MOCK_IDENTITY']:
                    raise SystemExit('operator identity changed')
                print(json.dumps({'authoredMock': action}))
                raise SystemExit(code('MOCK_PREPARE_EXIT' if action == 'prepare' else 'MOCK_CLEANUP_EXIT'))
            if len(args) >= 2 and args[1] == 'install':
                log('install')
                # Record the intended privileged destination; never touch it.
                if not Path(args[-2]).is_file() or not args[-1].startswith('/var/lib/decomp-generated-c-runtime-ci/'):
                    raise SystemExit('unexpected mocked installation source or destination')
                raise SystemExit(0)
            raise SystemExit('unexpected mocked sudo invocation: ' + repr(args))
        """)
        self.write_stub(scripts / "ci-prepare-generated-c-validation.py", """
            raise SystemExit('provider code must never be invoked outside the mocked sudo seam')
        """)
        self.write_stub(scripts / "reconcile-module-compilation-hosted-cases.py", """
            action = sys.argv[1]
            log('cases-' + action)
            if action == 'initialize':
                Path(option('--directory')).mkdir(parents=True)
                raise SystemExit(0)
            if action != 'finalize':
                raise SystemExit('unexpected mocked reconciliation action')
            # Missing inputs are independently observable after a failed live task.
            if not Path(option('--inventory')).is_file():
                raise SystemExit(23)
            if not Path(option('--reports')).is_dir():
                raise SystemExit(24)
            raise SystemExit(code('MOCK_RECONCILIATION_EXIT'))
        """)
        self.write_stub(scripts / "verify-module-compilation-live-tests.py", """
            log('xml-verifier')
            if not Path(option('--inventory')).is_file() or not Path(option('--reports')).is_dir():
                raise SystemExit(22)
            # Deliberately leave required-ACP membership to the qualifier's real inline check.
            raise SystemExit(code('MOCK_XML_EXIT'))
        """)
        return checkout, binaries

    def write_stub(self, path, body):
        path.write_text("#!/usr/bin/env python3\n" + MOCK_SUPPORT + textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o755)

    def run_scenario(self, **settings):
        self.assertLessEqual(settings.keys(), {
            "MOCK_PREREQUISITES_EXIT", "MOCK_PREPARE_EXIT", "MOCK_CONFIGURATION_EXIT", "MOCK_LIVE_EXIT",
            "MOCK_RECONCILIATION_EXIT", "MOCK_CLEANUP_EXIT", "MOCK_XML_EXIT", "MOCK_INVENTORY", "MOCK_REPORTS",
            "DANGLING_INVENTORY_SYMLINK", "DANGLING_OUTPUT_SYMLINK",
        })
        checkout, binaries = self.make_fixture()
        dangling_inventory = settings.pop("DANGLING_INVENTORY_SYMLINK", False)
        dangling_output = settings.pop("DANGLING_OUTPUT_SYMLINK", None)
        stale_paths = {
            "reports": "build/test-results/moduleCompilationLiveQualification",
            "cases": "build/reports/contained-module-compilation-live/cases",
        }
        self.assertIn(dangling_output, (None, *stale_paths))
        stale = checkout / (stale_paths[dangling_output] if dangling_output else
                            "build/module-compilation-qualification/compiled-live-tests.json")
        if dangling_inventory or dangling_output:
            stale.parent.mkdir(parents=True, exist_ok=True)
            stale.symlink_to("missing-target")
        call_log = checkout / "mock-calls.jsonl"
        env = dict(os.environ)
        for key in tuple(env):
            if key.startswith("MOCK_"):
                del env[key]
        env.update({
            "PATH": str(binaries) + os.pathsep + os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
            "GITHUB_RUN_ID": RUN_ID, "GITHUB_RUN_ATTEMPT": ATTEMPT,
            "GITHUB_SHA": "1" * 40, "GITHUB_EVENT_NAME": "authored-routing-fixture",
            "GITHUB_REPOSITORY": "authored/fixture", "GITHUB_WORKFLOW": "authored routing only",
            "DECOMP_TEST_MODULE_COMPILE_EXT4_SCRATCH": str(checkout / "mock-module-scratch"),
            "DECOMP_TEST_ORACLE_EXT4_SCRATCH": str(checkout / "mock-terminal-scratch"),
            "MOCK_CALL_LOG": str(call_log), "MOCK_IDENTITY": IDENTITY,
            "MOCK_REQUIRED_ACP_CLASS": REQUIRED_ACP_CLASS, "MOCK_REQUIRED_ACP_METHOD": REQUIRED_ACP_METHOD,
        })
        env.update({key: str(value) for key, value in settings.items()})
        result = subprocess.run(["/bin/bash", "scripts/qualify-contained-module-compilation.sh"], cwd=checkout,
                                env=env, capture_output=True, text=True, timeout=15, check=False)
        receipt_path = checkout / "build/module-compilation-qualification/qualification-exit.json"
        if dangling_inventory or dangling_output:
            self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertTrue(stale.is_symlink())
            self.assertFalse((stale.parent / "missing-target").exists())
            self.assertFalse(call_log.exists(), "stale-path refusal must precede all Gradle/operator commands")
            self.assertFalse(receipt_path.exists(), "preflight refusal occurs before the owned run lifecycle")
            return result, None, []
        self.assertTrue(receipt_path.is_file(), result.stdout + result.stderr)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        calls = [json.loads(line) for line in call_log.read_text(encoding="utf-8").splitlines()]
        return result, receipt, calls

    def assert_status(self, actual, *, phase="xml-verification", original, gradle, xml, acp, cases,
                      cleanup, final, prepare_attempts=1):
        result, receipt, calls = actual
        self.assertEqual(final, result.returncode, result.stdout + result.stderr)
        self.assertEqual({
            "schemaVersion": 1, "provider": "contained-module-hosted-exit-v1", "phase": phase,
            "originalExitCode": original, "gradleExitCode": gradle,
            "xmlVerificationExitCode": xml, "requiredAcpInventoryExitCode": acp,
            "caseReconciliationExitCode": cases, "operatorCleanupExitCode": cleanup, "finalExitCode": final,
        }, receipt)
        commands = [row["command"] for row in calls]
        self.assertEqual(prepare_attempts, commands.count("prepare"))
        self.assertEqual(0 if cleanup is None else 1, commands.count("cleanup"))
        self.assertEqual(0 if gradle is None else 1, commands.count("gradle-live"))
        self.assertEqual(0 if xml is None else 1, commands.count("xml-verifier"))
        self.assertEqual(1, commands.count("cases-initialize"))
        self.assertEqual(1, commands.count("cases-finalize"))
        finalize = next(row["arguments"] for row in calls if row["command"] == "cases-finalize")
        self.assertEqual("not-started" if gradle is None else str(gradle), finalize[finalize.index("--gradle-exit-code") + 1])
        self.assertEqual(phase, finalize[finalize.index("--phase") + 1])
        if cleanup is not None:
            self.assertGreater(commands.index("cleanup"), commands.index("cases-finalize"))

    def test_live_failure_survives_successful_reconciliation_and_cleanup(self):
        self.assert_status(self.run_scenario(MOCK_LIVE_EXIT=37),
                           original=37, gradle=37, xml=0, acp=0, cases=0, cleanup=0, final=37)

    def test_live_failure_survives_reconciliation_and_cleanup_failures(self):
        for cases, cleanup in ((31, 0), (0, 32), (31, 32)):
            with self.subTest(cases=cases, cleanup=cleanup):
                self.assert_status(self.run_scenario(MOCK_LIVE_EXIT=37, MOCK_RECONCILIATION_EXIT=cases,
                                                    MOCK_CLEANUP_EXIT=cleanup),
                                   original=37, gradle=37, xml=0, acp=0, cases=cases, cleanup=cleanup, final=37)

    def test_live_failure_survives_missing_inventory_and_cleanup_result(self):
        for cleanup in (0, 32):
            with self.subTest(cleanup=cleanup):
                self.assert_status(self.run_scenario(MOCK_LIVE_EXIT=37, MOCK_INVENTORY="missing", MOCK_CLEANUP_EXIT=cleanup),
                                   original=37, gradle=37, xml=22, acp=1, cases=23, cleanup=cleanup, final=37)

    def test_live_failure_survives_missing_reports_and_cleanup_result(self):
        for cleanup in (0, 32):
            with self.subTest(cleanup=cleanup):
                self.assert_status(self.run_scenario(MOCK_LIVE_EXIT=37, MOCK_REPORTS="missing", MOCK_CLEANUP_EXIT=cleanup),
                                   original=37, gradle=37, xml=22, acp=0, cases=24, cleanup=cleanup, final=37)

    def test_prerequisite_failure_records_live_not_started_without_cleanup(self):
        self.assert_status(self.run_scenario(MOCK_PREREQUISITES_EXIT=17), phase="prerequisites",
                           original=17, gradle=None, xml=None, acp=None, cases=23, cleanup=None, final=17, prepare_attempts=0)

    def test_failed_prepare_does_not_claim_owned_cleanup_or_started_live_tests(self):
        self.assert_status(self.run_scenario(MOCK_PREPARE_EXIT=18), phase="prerequisites",
                           original=18, gradle=None, xml=None, acp=None, cases=23, cleanup=None, final=18)

    def test_configuration_failure_cleans_owned_fixture_once_without_live_execution(self):
        self.assert_status(self.run_scenario(MOCK_CONFIGURATION_EXIT=19, MOCK_CLEANUP_EXIT=32), phase="configuration",
                           original=19, gradle=None, xml=None, acp=None, cases=23, cleanup=32, final=19)

    def test_success_requires_all_statuses_and_exactly_one_cleanup(self):
        self.assert_status(self.run_scenario(), phase="complete",
                           original=0, gradle=0, xml=0, acp=0, cases=0, cleanup=0, final=0)

    def test_dangling_inventory_symlink_is_refused_before_gradle_can_follow_it(self):
        result, receipt, calls = self.run_scenario(DANGLING_INVENTORY_SYMLINK=True)
        self.assertIsNone(receipt)
        self.assertEqual([], calls)
        self.assertIn("refusing to reuse compiler qualification inventory or reports",
                      result.stderr)

    def test_dangling_report_symlink_is_refused_before_any_owned_run_commands(self):
        result, receipt, calls = self.run_scenario(DANGLING_OUTPUT_SYMLINK="reports")
        self.assertIsNone(receipt)
        self.assertEqual([], calls)
        self.assertIn("refusing to reuse compiler qualification inventory or reports", result.stderr)

    def test_dangling_case_symlink_is_refused_before_any_owned_run_commands(self):
        result, receipt, calls = self.run_scenario(DANGLING_OUTPUT_SYMLINK="cases")
        self.assertIsNone(receipt)
        self.assertEqual([], calls)
        self.assertIn("refusing to reuse compiler qualification inventory or reports", result.stderr)

    def test_successful_live_tests_do_not_hide_reconciliation_failure(self):
        self.assert_status(self.run_scenario(MOCK_RECONCILIATION_EXIT=31), phase="complete",
                           original=0, gradle=0, xml=0, acp=0, cases=31, cleanup=0, final=1)

    def test_successful_live_tests_do_not_hide_cleanup_failure(self):
        self.assert_status(self.run_scenario(MOCK_CLEANUP_EXIT=32), phase="complete",
                           original=0, gradle=0, xml=0, acp=0, cases=0, cleanup=32, final=1)

    def test_successful_live_tests_preserve_both_reconciliation_and_cleanup_failures(self):
        self.assert_status(self.run_scenario(MOCK_RECONCILIATION_EXIT=31, MOCK_CLEANUP_EXIT=32), phase="complete",
                           original=0, gradle=0, xml=0, acp=0, cases=31, cleanup=32, final=1)

    def test_missing_required_acp_fails_even_when_xml_verifier_passes(self):
        self.assert_status(self.run_scenario(MOCK_INVENTORY="without-required-acp"),
                           original=1, gradle=0, xml=0, acp=1, cases=0, cleanup=0, final=1)

    def test_xml_verifier_failure_remains_the_original_exit_after_successful_live_tests(self):
        self.assert_status(self.run_scenario(MOCK_XML_EXIT=41, MOCK_RECONCILIATION_EXIT=31, MOCK_CLEANUP_EXIT=32),
                           original=41, gradle=0, xml=41, acp=0, cases=31, cleanup=32, final=41)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Real javac-authored controls for the compiled JUnit return-signature guard."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("junit_signatures", Path(__file__).with_name("check-junit-signatures.py"))
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
JAVAC = None
WORK_ROOT = REPOSITORY / "build/junit-signature-controls"


class CompiledSignatureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        WORK_ROOT.mkdir(parents=True, exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix="javac-", dir=WORK_ROOT)
        cls.work = Path(cls.temporary.name)
        cls.classes = cls.work / "classes"
        cls.classes.mkdir()
        for name in ["tmp", "home"]:
            (cls.work / name).mkdir()
        sources = {}
        for descriptor in sorted(GUARD.ORDINARY | {GUARD.FACTORY}):
            internal = descriptor[1:-1]
            package, name = internal.rsplit("/", 1)
            body = "int value() default 1;" if name == "RepeatedTest" else ""
            sources[internal + ".java"] = f"""package {package.replace('/', '.')};
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target({{ElementType.METHOD, ElementType.ANNOTATION_TYPE}})
                public @interface {name} {{ {body} }}"""
        sources["org/junit/jupiter/api/DynamicNode.java"] = "package org.junit.jupiter.api; public abstract class DynamicNode {}"
        sources["controls/MetaA.java"] = """package controls; import java.lang.annotation.*;
            @Retention(RetentionPolicy.RUNTIME) @Target({ElementType.METHOD,ElementType.ANNOTATION_TYPE})
            @org.junit.jupiter.api.Test @MetaB public @interface MetaA {}"""
        sources["controls/MetaB.java"] = """package controls; import java.lang.annotation.*;
            @Retention(RetentionPolicy.RUNTIME) @Target({ElementType.METHOD,ElementType.ANNOTATION_TYPE})
            @MetaA public @interface MetaB {}"""
        sources["controls/Factory.java"] = """package controls; import java.lang.annotation.*;
            @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
            @org.junit.jupiter.api.TestFactory public @interface Factory {}"""
        sources["controls/Values.java"] = """package controls; import java.lang.annotation.*;
            @Retention(RetentionPolicy.RUNTIME) public @interface Values {
              byte b(); char c(); short s(); int i(); long l(); float f(); double d(); boolean z();
              String text(); Class<?> type(); RetentionPolicy enumeration(); Deprecated nested(); int[] array();
            }"""
        sources["controls/Valid.java"] = r"""package controls;
            import java.util.*; import java.util.stream.*; import org.junit.jupiter.api.*;
            public class Valid {
              static { if (System.nanoTime() != 0) throw new AssertionError("MUST NOT INITIALIZE TEST CLASSES"); }
              @Test @Values(b=1,c='x',s=2,i=3,l=4,f=1.5f,d=2.5,z=true,text="nul\0pair\uD83D\uDE80",
                type=String[].class,enumeration=java.lang.annotation.RetentionPolicy.RUNTIME,nested=@Deprecated,array={1,2})
              public void ordinary() {}
              @RepeatedTest(2) public void repeated() {}
              @TestTemplate public void template() {}
              @org.junit.jupiter.params.ParameterizedTest public void parameterized(int parameter) {}
              @org.junit.Test public void legacy() {}
              @MetaB public void composed() {}
              @TestFactory public Stream<DynamicNode> streamFactory() { return Stream.empty(); }
              @TestFactory public Collection<DynamicNode> collectionFactory() { return List.of(); }
              @TestFactory public Iterable<DynamicNode> iterableFactory() { return List.of(); }
              @TestFactory public Iterator<DynamicNode> iteratorFactory() { return List.<DynamicNode>of().iterator(); }
              @TestFactory public DynamicNode[] arrayFactory() { return new DynamicNode[0]; }
              @Factory public Stream<DynamicNode> composedFactory() { return Stream.empty(); }
              public Object helper() { return null; }
            }"""
        sources["controls/Invalid.java"] = """package controls; import org.junit.jupiter.api.*;
            public class Invalid {
              @Test public Object ordinary() { return null; }
              @RepeatedTest(2) public int repeated() { return 1; }
              @TestTemplate public long template() { return 1; }
              @org.junit.jupiter.params.ParameterizedTest public String parameterized(int parameter) { return "x"; }
              @org.junit.Test public int[] legacy() { return null; }
              @MetaB public Object composed() { return null; }
              @Test @TestFactory public Object mixedOrdinaryFactory() { return null; }
            }"""
        paths = []
        for relative, source in sources.items():
            path = cls.work / "src" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
            paths.append(str(path))
        command = [str(JAVAC), "-J-XX:-UsePerfData", f"-J-Djava.io.tmpdir={cls.work / 'tmp'}",
                   f"-J-Duser.home={cls.work / 'home'}", "--release", "21", "-d", str(cls.classes), *paths]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=45,
                                  env=dict(os.environ, TMPDIR=str(cls.work / "tmp")))
        if compiled.returncode:
            raise AssertionError("authored javac fixtures did not compile:\n" + compiled.stdout + compiled.stderr)
        cls.valid = cls.work / "valid"
        shutil.copytree(cls.classes, cls.valid)
        (cls.valid / "controls/Invalid.class").unlink()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.scratch = Path(tempfile.mkdtemp(prefix="control-", dir=self.work))

    def root(self):
        return Path(shutil.copytree(self.valid, self.scratch / "classes"))

    def assert_rejected(self, report, fragment=None):
        self.assertEqual("failed", report["status"])
        self.assertTrue(report["errors"] or report["violations"])
        if fragment:
            self.assertIn(fragment, " ".join(report["errors"]))

    def test_valid_void_parameterized_repeated_and_template_methods(self):
        report = GUARD.audit([self.valid])
        self.assertEqual("passed", report["status"], report["errors"])
        rows = {item["method"]: item for item in report["methods"]}
        self.assertEqual(12, len(rows))
        for name in ["ordinary", "repeated", "template", "parameterized", "legacy", "composed"]:
            self.assertTrue(rows[name]["descriptor"].endswith(")V"))
        self.assertNotIn("helper", rows)

    def test_all_supported_nonvoid_ordinary_methods_are_rejected(self):
        report = GUARD.audit([self.classes])
        self.assert_rejected(report)
        self.assertEqual([], report["errors"])
        self.assertEqual({"ordinary", "repeated", "template", "parameterized", "legacy", "composed", "mixedOrdinaryFactory"},
                         {row["method"] for row in report["violations"]})
        self.assertTrue(all(row["class"] == "controls.Invalid" for row in report["violations"]))

    def test_valid_dynamic_factory_return_types_remain_exempt(self):
        report = GUARD.audit([self.valid])
        factories = [row for row in report["methods"] if GUARD.FACTORY in row["effectiveAnnotations"]]
        self.assertEqual(6, len(factories))
        self.assertTrue(all(row["status"] == "accepted" and not row["descriptor"].endswith(")V") for row in factories))

    def test_composed_annotation_cycle_propagates_test_marker_once(self):
        report = GUARD.audit([self.classes])
        rows = [row for row in report["methods"] if row["method"] == "composed"]
        self.assertEqual(2, len(rows))
        self.assertTrue(all(row["effectiveAnnotations"] == ["Lorg/junit/jupiter/api/Test;"] for row in rows))

    def test_truncation_header_constant_pool_and_last_attribute_fail(self):
        data = (self.valid / "controls/Valid.class").read_bytes()
        for size in [0, 7, 11, len(data) // 2, len(data) - 1]:
            with self.subTest(size=size), self.assertRaises(GUARD.InvalidClass):
                GUARD.parse_class(data[:size])

    def test_unsupported_class_version_and_pool_tag_fail(self):
        original = (self.valid / "controls/Valid.class").read_bytes()
        for start, value in [(6, b"\0B"), (10, b"\x7f"), (4, b"\xff\xff")]:
            changed = bytearray(original)
            changed[start:start + len(value)] = value
            with self.subTest(start=start), self.assertRaises(GUARD.InvalidClass):
                GUARD.parse_class(changed)

    def test_malformed_method_descriptor_and_utf8_fail(self):
        data = (self.valid / "controls/Valid.class").read_bytes()
        for old, replacement in [(b"()V", b"()Q"), (b"controls/Valid", b"\0ontrols/Valid")]:
            self.assertIn(old, data)
            with self.subTest(old=old), self.assertRaises(GUARD.InvalidClass):
                GUARD.parse_class(data.replace(old, replacement))

    def test_invalid_constant_pool_reference_fails(self):
        # First javac entry is a Methodref: its class reference must refer to CONSTANT_Class.
        data = bytearray((self.valid / "controls/Valid.class").read_bytes())
        self.assertEqual(10, data[10])
        data[11:13] = b"\0\0"
        with self.assertRaisesRegex(GUARD.InvalidClass, "constant-pool reference"):
            GUARD.parse_class(data)

    def test_empty_missing_linked_and_duplicate_roots_fail(self):
        empty = self.scratch / "empty"; empty.mkdir()
        link = self.scratch / "linked"; link.symlink_to(self.valid, target_is_directory=True)
        for roots in [[empty], [self.scratch / "missing"], [link], [self.valid, self.valid]]:
            with self.subTest(roots=roots):
                self.assert_rejected(GUARD.audit(roots))

    def test_linked_class_and_inconsistent_binary_name_fail(self):
        root = self.root()
        (root / "linked.class").symlink_to(self.valid / "controls/Valid.class")
        self.assert_rejected(GUARD.audit([root]), "linked")
        (root / "linked.class").unlink()
        (root / "controls/Valid.class").rename(root / "controls/Different.class")
        self.assert_rejected(GUARD.audit([root]), "binary name")

    def test_oversized_class_rejected_before_reading_body(self):
        root = self.root()
        with (root / "controls/Valid.class").open("wb") as stream:
            stream.truncate(GUARD.MAX_CLASS_BYTES + 1)
        self.assert_rejected(GUARD.audit([root]), "oversized")

    def test_directory_depth_is_bounded_before_filesystem_recursion(self):
        root = self.root()
        directory = root
        for _ in range(GUARD.MAX_DIRECTORY_DEPTH + 1):
            directory = directory / "nested"
        directory.mkdir(parents=True)
        self.assert_rejected(GUARD.audit([root]), "depth")

    def test_class_byte_method_and_report_budgets_fail_closed(self):
        for key, value in [("MAX_CLASSES", 1), ("MAX_TOTAL_BYTES", 1), ("MAX_METHODS", 1), ("MAX_REPORT_BYTES", 16384)]:
            with self.subTest(key=key), patch.object(GUARD, key, value):
                self.assert_rejected(GUARD.audit([self.valid]), "limit")

    def test_annotation_nodes_and_depth_are_bounded(self):
        data = (self.valid / "controls/Valid.class").read_bytes()
        for key, value in [("MAX_ANNOTATION_NODES", 1), ("MAX_DEPTH", 0)]:
            with self.subTest(key=key), patch.object(GUARD, key, value), self.assertRaisesRegex(GUARD.InvalidClass, "bounds"):
                GUARD.parse_class(data)

    def test_evidence_is_deterministic_and_binds_exact_compiled_bytes(self):
        first = GUARD.audit([self.valid])
        self.assertEqual(first, GUARD.audit([self.valid]))
        for row in first["classes"]:
            data = (self.valid / row["path"]).read_bytes()
            self.assertEqual(len(data), row["bytes"])
            self.assertEqual(GUARD.hashlib.sha256(data).hexdigest(), row["sha256"])

    def test_cli_retains_failure_evidence_and_nonzero_exit(self):
        output = self.scratch / "evidence.json"
        result = subprocess.run([sys.executable, "-B", str(REPOSITORY / "scripts/check-junit-signatures.py"),
                                 "--class-root", str(self.classes), "--report", str(output)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(1, result.returncode)
        self.assertEqual(7, len(json.loads(output.read_bytes())["violations"]))
        self.assertIn("controls.Invalid.ordinary", result.stderr)


def main():
    global JAVAC, WORK_ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--javac", type=Path, default=Path(shutil.which("javac") or "javac"))
    parser.add_argument("--work-root", type=Path, default=WORK_ROOT)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    JAVAC, WORK_ROOT = arguments.javac.absolute(), arguments.work_root.absolute()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CompiledSignatureControls)
    names = [case.id() for case in suite]
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({"schemaVersion": 1, "javac": str(JAVAC),
            "status": "passed" if result.wasSuccessful() else "failed", "testsRun": result.testsRun,
            "declaredControls": names, "failures": [(case.id(), message) for case, message in result.failures],
            "errors": [(case.id(), message) for case, message in result.errors], "skipped": result.skipped}, indent=2) + "\n")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())

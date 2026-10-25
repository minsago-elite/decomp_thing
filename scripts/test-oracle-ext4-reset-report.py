#!/usr/bin/env python3
"""Pure report mutations only; these tests supply no mounted reset evidence."""

import importlib.util
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import uuid


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("reset_report", ROOT / "scripts/verify-oracle-ext4-reset.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class ReportGateTests(unittest.TestCase):
    def setUp(self):
        temporary_root = ROOT / "build/issue933-evidence/report-tests"
        temporary_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.reports = self.root / "reports"
        self.reports.mkdir()
        self.path = self.reports / f"TEST-{GATE.CLASS}.xml"
        self.source = self.root / "source"
        self.source.mkdir()
        self.evidence = self.root / "evidence"
        self.commit = "4" * 40

    def write_junit(self, names=GATE.REQUIRED, status=None):
        suite = ET.Element("testsuite", name=GATE.CLASS, tests="32", skipped="0", failures="0", errors="0")
        for name in names:
            case = ET.SubElement(suite, "testcase", classname=GATE.CLASS, name=name + "()", time="0.001")
            if status:
                ET.SubElement(case, status)
        self.path.write_bytes(ET.tostring(suite, encoding="utf-8"))
        return suite

    def test_accepts_exact_named_junit_success(self):
        self.write_junit()
        result = GATE.verify_junit(self.reports)
        self.assertEqual(self.path.stat().st_size, result["bytes"])
        self.assertEqual(GATE._digest(self.path.read_bytes()), result["sha256"])

    def test_accepts_actual_gradle_cdata_output_shape(self):
        self.write_junit()
        raw = self.path.read_bytes().replace(b"</testsuite>", b"<system-out><![CDATA[fixture output <tag> & measurement]]></system-out><system-err><![CDATA[]]></system-err></testsuite>")
        self.path.write_bytes(raw)
        self.assertEqual(len(raw), GATE.verify_junit(self.reports)["bytes"])

    def test_all_nonpassing_statuses_refused(self):
        for status in ("skipped", "failure", "error", "ignored"):
            with self.subTest(status=status):
                self.write_junit(status=status)
                with self.assertRaises(ValueError):
                    GATE.verify_junit(self.reports)

    def test_missing_duplicate_and_renamed_controls_refused(self):
        for names in (GATE.REQUIRED[:-1], GATE.REQUIRED + GATE.REQUIRED[:1], GATE.REQUIRED[:-1] + ("K32 synthetic mutation",)):
            with self.subTest(names=names[-1]):
                self.write_junit(names)
                with self.assertRaises(ValueError):
                    GATE.verify_junit(self.reports)

    def test_junit_inconsistent_counters_refused(self):
        for field, value in (("tests", "31"), ("skipped", "1"), ("errors", "1"), ("failures", "1")):
            with self.subTest(field=field):
                suite = self.write_junit()
                suite.set(field, value)
                self.path.write_bytes(ET.tostring(suite))
                with self.assertRaises(ValueError):
                    GATE.verify_junit(self.reports)

    def test_junit_wrong_class_and_status_attribute_refused(self):
        for attributes in ({"classname": "other.Class"}, {"status": "skipped"}):
            with self.subTest(attributes=attributes):
                suite = self.write_junit()
                suite[0].attrib.update(attributes)
                self.path.write_bytes(ET.tostring(suite))
                with self.assertRaises(ValueError):
                    GATE.verify_junit(self.reports)

    def test_nested_testsuite_and_case_refused(self):
        suite = self.write_junit()
        wrapper = ET.Element("testsuites")
        wrapper.append(suite)
        self.path.write_bytes(ET.tostring(wrapper))
        with self.assertRaises(ValueError):
            GATE.verify_junit(self.reports)
        suite = self.write_junit()
        system_out = ET.SubElement(suite, "system-out")
        ET.SubElement(system_out, "testcase", name=GATE.REQUIRED[0], classname=GATE.CLASS)
        self.path.write_bytes(ET.tostring(suite))
        with self.assertRaises(ValueError):
            GATE.verify_junit(self.reports)

    def test_utf16_and_declarations_refused(self):
        suite = self.write_junit()
        document = '<!DOCTYPE testsuite [<!ENTITY x "secret">]>' + ET.tostring(suite).decode()
        for raw in (ET.tostring(suite, encoding="utf-16"), document.encode(), document.encode("utf-16le"), document.encode("utf-16be")):
            with self.subTest(prefix=raw[:15]):
                self.path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    GATE.verify_junit(self.reports)

    def test_source_manifest_requires_exact_current_bytes(self):
        hashes = {}
        for path in GATE.SOURCE_PATHS:
            target = self.source / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("pure fixture source: " + path + "\n").encode())
            hashes[path] = GATE._digest(target.read_bytes())
        GATE.verify_sources(self.source, hashes)
        target.write_bytes(b"changed\n")
        with self.assertRaisesRegex(ValueError, "source mismatch"):
            GATE.verify_sources(self.source, hashes)
        hashes.pop(path)
        with self.assertRaisesRegex(ValueError, "source hashes"):
            GATE.verify_sources(self.source, hashes)

    def test_canonical_json_rejects_duplicate_and_noncanonical_encodings(self):
        good = GATE.canonical({"a": 1, "b": "actual measurement"})
        self.assertEqual({"a": 1, "b": "actual measurement"}, GATE._json(good, "test"))
        variants = (
            b'{"a":1,"a":1,"b":"actual measurement"}\n',
            good.rstrip(b"\n"),
            b"\xef\xbb\xbf" + good,
            good.replace(b"\n", b"\r\n"),
            b'{"b":"actual measurement","a":1}\n',
            b'{"a":1.0,"b":"actual measurement"}\n',
            b'{"a":1e0,"b":"actual measurement"}\n',
            b'{"a":NaN,"b":"actual measurement"}\n',
            b'{"a":Infinity,"b":"actual measurement"}\n',
            b'{"a":1,"b":"\\ud800"}\n',
        )
        for raw in variants:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    GATE._json(raw, "test")

    def test_booleans_do_not_count_as_integer_measurements(self):
        with self.assertRaises(ValueError):
            GATE._integer(True, 0, 10, "measurement")

    def test_oversized_and_empty_files_refused(self):
        for raw in (b"", b"x" * 33):
            with self.subTest(length=len(raw)):
                self.path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    GATE.read_regular(self.reports, self.path.name, 32)

    def test_file_growth_after_initial_stat_refused(self):
        self.path.write_bytes(b"initial\n")
        original_read = os.read
        changed = False
        def grow_before_read(fd, length):
            nonlocal changed
            if not changed:
                changed = True
                self.path.write_bytes(b"x" * 65)
            return original_read(fd, length)
        with mock.patch.object(GATE.os, "read", side_effect=grow_before_read):
            with self.assertRaisesRegex(ValueError, "changed or oversized"):
                GATE.read_regular(self.reports, self.path.name, 32)

    def test_leaf_swap_to_symlink_at_open_refused(self):
        self.path.write_bytes(b"initial\n")
        target = self.root / "target"
        target.write_bytes(b"replacement\n")
        original_open = os.open
        def swap_at_open(path, flags, *args, **kwargs):
            if path == self.path.name:
                self.path.unlink()
                self.path.symlink_to(target)
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(GATE.os, "open", side_effect=swap_at_open):
            with self.assertRaises(OSError):
                GATE.read_regular(self.reports, self.path.name, 32)

    def test_links_and_directory_in_place_of_file_refused(self):
        target = self.root / "target"
        target.write_bytes(b"content\n")
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            GATE.read_regular(self.reports, self.path.name, 64)
        self.path.unlink()
        os.link(target, self.path)
        with self.assertRaises(ValueError):
            GATE.read_regular(self.reports, self.path.name, 64)
        self.path.unlink()
        self.path.mkdir()
        with self.assertRaises(ValueError):
            GATE.read_regular(self.reports, self.path.name, 64)

    def test_parent_symlink_and_relative_path_escape_refused(self):
        self.write_junit()
        linked = self.root / "linked"
        linked.symlink_to(self.reports, target_is_directory=True)
        with self.assertRaises(OSError):
            GATE.read_regular(linked, self.path.name, GATE.MAX_XML)
        for path in ("../target", "/absolute", "./target", "dir//target", "dir/../target", "dir\\target"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    GATE.read_regular(self.reports, path, 64)

    def test_fifo_refused_without_waiting_for_writer(self):
        os.mkfifo(self.path)
        program = (
            "import importlib.util, pathlib, sys; "
            "s=importlib.util.spec_from_file_location('gate',sys.argv[1]); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "m.read_regular(pathlib.Path(sys.argv[2]),sys.argv[3],1024)"
        )
        result = subprocess.run([sys.executable, "-I", "-S", "-c", program, str(ROOT / "scripts/verify-oracle-ext4-reset.py"), str(self.reports), self.path.name], capture_output=True, timeout=3, check=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn(b"not a single-link ordinary file", result.stderr)

    def synthetic_bundle(self):
        """Invented pure-test inputs, never exported as actual qualification."""
        self.write_junit()
        hashes = {}
        for path in GATE.SOURCE_PATHS:
            target = self.source / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("synthetic verifier test source: " + path + "\n").encode())
        (self.source / "scripts/oracle-ext4-reset-profile.json").write_bytes(GATE.canonical(GATE.EXPECTED_PROFILE, newline=False))
        for path in GATE.SOURCE_PATHS:
            hashes[path] = GATE._digest((self.source / path).read_bytes())
        profile_hash = GATE.qualification_profile_hash(self.source)
        private = "/var/lib/decomp-oracle-ext4-reset-ci/private/"
        installed_sources = {
            private + "oracle-ext4-reset.py": "scripts/oracle-ext4-reset.py",
            private + "oracle-ext4-reset-install.py": "scripts/oracle-ext4-reset-install.py",
            private + "oracle-ext4-reset-fixture-mutations.py": "scripts/oracle-ext4-reset-fixture-mutations.py",
            private + "ci-oracle-ext4-reset.py": "scripts/ci-oracle-ext4-reset.py",
            private + "mke2fs.conf": "scripts/oracle-ext4-reset-mke2fs.conf",
            "/etc/systemd/system/decomp-oracle-ext4-reset-ci.service": "scripts/systemd/decomp-oracle-ext4-reset-ci.service",
            "/etc/systemd/system/decomp-oracle-ext4-reset-retain.target": "scripts/systemd/decomp-oracle-ext4-reset-retain.target",
        }
        identity = {"device": 1, "inode": 2, "mountId": 3, "uid": 0, "gid": 0, "mode": 0o644, "kind": "file", "links": 1, "size": 100, "rdev": 0}
        files = {path: {"resolved": path, "identity": identity.copy(), "sha256": hashes[source]} for path, source in installed_sources.items()}
        files[private + "profile.json"] = {"resolved": private + "profile.json", "identity": identity.copy(), "sha256": profile_hash}
        tools = GATE.INSTALLED_TOOLS.copy()
        for path in tools.values():
            files[path] = {"resolved": path, "identity": identity.copy(), "sha256": GATE._digest(path.encode())}
        packages = {}
        for name in ("e2fsprogs", "libext2fs2t64", "systemd", "python3-minimal"):
            version = "1.47.0-2.4~exp1ubuntu4.1" if name in {"e2fsprogs", "libext2fs2t64"} else "255.4" if name == "systemd" else "3.12.3"
            archive_hash = GATE._digest(("synthetic archive " + name).encode())
            metadata = f"Package: {name}\nVersion: {version}\nSHA256: {archive_hash}\n"
            policy = f"{name}:\n  Installed: {version}\n"
            packages[name] = {"binaryPackage": name, "version": version, "sourcePackage": "e2fsprogs" if name in {"e2fsprogs", "libext2fs2t64"} else name, "sourceVersion": version, "architecture": "amd64", "status": "install ok installed", "verifyOutputSha256": GATE._digest(b""), "aptMetadata": metadata, "aptMetadataSha256": GATE._digest(metadata.encode()), "aptPolicy": policy, "aptPolicySha256": GATE._digest(policy.encode()), "aptArchiveSha256": archive_hash}
        package_provenance = {"schemaVersion": 1, "machine": "x86_64", "kernelRelease": "6.8.0-test", "systemdVersion": "systemd 255 (synthetic verifier fixture)\n", "pythonVersion": "Python 3.12.3\n", "packages": packages, "formatterSource": {"upstreamCommit": "25ad8a431331b4d1d444a70b6079456cc612ac40", "originalArchiveSha256": "6667afde56eef0c6af26684974400e4d2288ea49e9441bf5e6229195d51a3578", "distributionPatchReview": "no-reviewed-formatter-files-modified"}, "aptAuthenticationBoundary": "requires-successful-signature-enforced-workflow-apt-install"}
        manifest_raw = GATE.canonical({"schemaVersion": 1, "owner": {"uid": 65534, "gid": 65534, "groups": []}, "tools": tools, "files": files, "packageProvenance": package_provenance}, newline=False)
        (self.evidence / "cases").mkdir(parents=True)
        self.receipts = {}
        generation = 1
        order = [case for case in GATE.CASE_NAMES if case != "K30"] + ["K30"]
        for case_id in order:
            before = {"generation": str(generation), "filesystemUuid": str(uuid.UUID(int=generation)), "scratch": f"/var/lib/decomp-oracle-ext4-reset-ci/public/g-{generation:016x}/scratch", "phase": "PUBLISHED", "gateMode": 0o711, "mountId": generation + 100, "loopRdev": os.makedev(7, 100), "imageDevice": 8, "imageInode": 900, "imageBytes": GATE.IMAGE_BYTES, "availableBytes": 32 * 1024 * 1024, "availableInodes": 4000}
            after = copy.deepcopy(before)
            outcome = "refused" if case_id == "K01" else "teardown" if case_id == "K30" else "reset"
            if outcome == "reset":
                generation += 1
                after.update(generation=str(generation), filesystemUuid=str(uuid.UUID(int=generation)), scratch=f"/var/lib/decomp-oracle-ext4-reset-ci/public/g-{generation:016x}/scratch", mountId=generation + 100)
            elif outcome == "teardown":
                after.update(phase="RESERVED_UNMOUNTED", gateMode=0, mountId=0, availableBytes=0, availableInodes=0)
            attempts = []
            if outcome == "reset":
                if case_id in {"K02", "K07", "K08", "K09", "K11", "K12", "K22", "K23", "K24", "K25", "K27", "K29", "K32"}:
                    attempts.append({"action": "request", "exitCode": 1, "phaseBefore": "PUBLISHED", "phaseAfter": "PUBLISHED", "invocationId": None, "formatterCount": 0})
                attempts.append({"action": "resume" if attempts else "request", "exitCode": 0, "phaseBefore": "PUBLISHED", "phaseAfter": "PUBLISHED", "invocationId": "1" * 32, "formatterCount": 1})
            deaths = []
            if case_id in GATE.REQUIRED_DEATHS or case_id == "K29":
                role, barrier = GATE.REQUIRED_DEATHS.get(case_id, ("controller", "ACTION_TIMEOUT"))
                deaths = [{"role": role, "pid": 1000 + int(case_id[1:]), "startTicks": 100, "signal": 9, "reaped": True, "barrier": barrier}]
            canaries = []
            if case_id in GATE.REQUIRED_CANARIES:
                label = GATE.REQUIRED_CANARIES[case_id]
                canaries = [{"label": label, "beforeSha256": GATE._digest(label.encode()), "afterSha256": GATE._digest(label.encode())}]
            holders = []
            if case_id in {"K07", "K08", "K12"}:
                holders = [{"kind": {"K07": "file", "K08": "namespace", "K12": "utility"}[case_id], "pid": 2000, "startTicks": 101, "reaped": True, "refusalExitCode": 1}]
            trace_raw = self.synthetic_trace(refused=case_id == "K08", filesystem_uuid=after["filesystemUuid"]) if outcome == "reset" else b""
            trace = {"artifact": f"raw/{case_id}/formatter.trace", "sha256": GATE._digest(trace_raw), "exclusiveOpenFlags": ["O_RDONLY", "O_EXCL"] if case_id == "K08" else ["O_RDWR", "O_EXCL"] if outcome == "reset" else [], "exclusiveOpenErrno": "EBUSY" if case_id == "K08" else None, "deviceMutationCount": 0 if case_id == "K08" or outcome != "reset" else 5, "mutationsBeforeExclusiveOpen": 0, "truncated": False}
            facts = {"oldTreeEntriesVisited": 0, "oldContentBytesRead": 0, "mutatorCount": 6 if outcome == "reset" else 0}
            if case_id in {"K22", "K23", "K24", "K25", "K30", "K32"}:
                facts["restored"] = True
            if case_id == "K10":
                facts["allocatedLoopRdev"] = os.makedev(7, 101)
            if case_id == "K30":
                facts.update(removedOwnedFixture=True, retainedReservation=True)
            events = [{"operation": "state-read", "startMonotonicNs": 1, "endMonotonicNs": 2, "exitCode": 0, "details": {"phaseBefore": "PUBLISHED"}}]
            for attempt in attempts:
                events.append({"operation": "broker-" + attempt["action"], "startMonotonicNs": 3, "endMonotonicNs": 4, "exitCode": attempt["exitCode"], "details": {"phaseBefore": attempt["phaseBefore"], "phaseAfter": attempt["phaseAfter"]}})
            for death in deaths:
                events.append({"operation": "signal", "startMonotonicNs": 5, "endMonotonicNs": 6, "exitCode": 0, "details": {key: death[key] for key in ("pid", "startTicks", "signal", "barrier")}})
            service = {"schemaVersion": 1, "unit": "decomp-oracle-ext4-reset-ci.service", "properties": {"ActiveState": "inactive", "SubState": "dead", "ControlGroup": "", "MainPID": "0", "InvocationID": "1" * 32, "Result": "success", "Job": ""}, "cgroup": {"path": "/system.slice/decomp-oracle-ext4-reset-ci.service", "exists": False, "pids": [], "children": [], "identity": None}, "bootId": "11111111-1111-4111-8111-111111111111", "retentionTarget": {"LoadState": "loaded", "ActiveState": "active", "SubState": "active", "FragmentPath": "/etc/systemd/system/decomp-oracle-ext4-reset-retain.target", "DropInPaths": "", "DefaultDependencies": "no", "After": "decomp-oracle-ext4-reset-ci.service", "Wants": "", "Requires": "", "Job": ""}}
            raw_artifacts = {"formatter.trace": trace_raw, "events.json": GATE.canonical({"schemaVersion": 1, "caseId": case_id, "events": events}, newline=False), "manifest.json": manifest_raw, "service.properties": GATE.canonical(service, newline=False)}
            raw_directory = self.evidence / "raw" / case_id
            raw_directory.mkdir(parents=True)
            references = []
            for name, raw in raw_artifacts.items():
                (raw_directory / name).write_bytes(raw)
                references.append({"name": name, "path": f"raw/{case_id}/{name}", "bytes": len(raw), "sha256": GATE._digest(raw)})
            receipt = {"schemaVersion": 1, "caseId": case_id, "sessionToken": GATE._digest(case_id.encode()), "outcome": outcome, "before": before, "after": after, "observations": {"attempts": attempts, "deaths": deaths, "canaries": canaries, "holders": holders, "trace": trace, "facts": facts}, "profileSha256": profile_hash, "sourceCommit": self.commit, "sourceHashes": hashes, "installedManifestSha256": GATE._digest(manifest_raw), "artifacts": references}
            self.receipts[case_id] = receipt
            self.write_receipt(case_id)
            self.write_probe(case_id, self.synthetic_probe(receipt))

    def synthetic_lease(self, event, snapshot):
        value = {"schemaVersion": 1, "provider": "dedicated-ext4-filesystem-v1", "operationId": GATE._digest(f"{event['caseId']}:{event['sessionToken']}:{event['mode']}".encode()), "requestSha256": "2" * 64, "scopeSha256": "3" * 64, "shardId": "clang-lib-driver", "mountPathSha256": GATE._digest(event["scratch"].encode()), "mountId": snapshot["mountId"], "filesystemDevice": f"{os.major(snapshot['loopRdev'])}:{os.minor(snapshot['loopRdev'])}", "filesystemType": "ext4", "fragmentBytes": 4096, "ownerUid": 65534, "mode": 0o700, "requiredAvailableBytes": 1, "maximumFilesystemBytes": GATE.IMAGE_BYTES, "requiredAvailableInodes": 4, "maximumFilesystemInodes": GATE.INODES, "device": 100, "leaseRootDevice": 100, "rootInode": 2, "leaseRootInode": 20, "totalBytes": 60 * 1024 * 1024, "totalInodes": 4096, "initialAvailableBytes": 32 * 1024 * 1024, "initialAvailableInodes": 4000, "mountFlags": ["noatime", "nodev", "noexec", "nosuid", "rw"], "leaseRecordSha256": "7" * 64}
        raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
        value["evidenceSha256"] = GATE._digest(raw)
        return value

    def synthetic_trace(self, refused=False, filesystem_uuid="00000000-0000-0000-0000-000000000001"):
        argv = ["/proc/self/fd/20", "-t", "ext4", "-q", "-F", "-b", "4096", "-I", "256", "-N", "4096", "-m", "0", "-U", filesystem_uuid, "-O", "none,has_journal,extent,filetype,sparse_super,large_file,dir_index,uninit_bg", "-E", "nodiscard,lazy_itable_init=0,lazy_journal_init=0", "/proc/self/fd/21", "16384"]
        environment = ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "MKE2FS_CONFIG=/var/lib/decomp-oracle-ext4-reset-ci/private/mke2fs.conf", "E2FSPROGS_UNDO_DIR=none"]
        lines = [f'100 execve("/proc/self/fd/20", {json.dumps(argv)}, {json.dumps(environment)}) = 0', '100 newfstatat(AT_FDCWD, "/proc/self/fd/21", {st_mode=S_IFBLK|0660, st_rdev=makedev(0x7, 0x64), ...}, 0) = 0']
        if refused:
            lines.append('100 openat(AT_FDCWD, "/proc/self/fd/21", O_RDONLY|O_EXCL) = -1 EBUSY (Device or resource busy)')
        else:
            lines.append('100 openat(AT_FDCWD, "/proc/self/fd/21", O_RDWR|O_EXCL) = 9</dev/loop100>')
            for offset in range(5):
                lines.append(f'100 pwrite64(9</dev/loop100>, "\\0"..., 4096, {offset * 4096}) = 4096')
            lines.append('100 close(9</dev/loop100>) = 0')
        return ("\n".join(lines) + "\n").encode()

    def synthetic_probe(self, receipt):
        case_id = receipt["caseId"]
        sequences = {"K01": [("access", "access-denied")], "K02": [("hold-canary", "ready"), ("expect-refusal", "acquisition-refused"), ("hold-canary", "checked"), ("hold-canary", "clean-released")], "K03": [("active", "ready")], "K04": [("sparse-deep", "ready")], "K05": [("bytes-full", "ready")], "K06": [("inodes-full", "ready")], "K26": [("quarantine", "ready")], "K31": [("hold-canary", "ready"), ("hold-canary", "checked"), ("hold-canary", "checked"), ("hold-canary", "clean-released")]}
        sequence = sequences.get(case_id, []).copy()
        if receipt["outcome"] == "reset":
            sequence.append(("admit-clean", "admitted-clean"))
        events = []
        mode_pids = {}
        for mode, event_name in sequence:
            mode_pids.setdefault(mode, 3000 + len(mode_pids))
            snapshot = receipt["after"] if mode == "admit-clean" or case_id == "K31" else receipt["before"]
            event = {"schemaVersion": 1, "caseId": case_id, "sessionToken": receipt["sessionToken"], "mode": mode, "event": event_name, "pid": mode_pids[mode], "startTicks": 200, "uid": 65534, "gid": 65534, "scratch": snapshot["scratch"]}
            if mode == "access":
                access_results = [{"object": "private", "access": "list", "result": "AccessDeniedException"}] + [{"object": obj, "access": access, "result": "AccessDeniedException"} for obj in ("image", "state", "loop") for access in ("read", "write")]
                event.update(deniedObjects=7, effectiveCapabilities="0", noNewPrivileges=True, accessResults=access_results, rawDeviceRdev=snapshot["loopRdev"])
            elif mode == "expect-refusal":
                event["reason"] = "already-leased"
            else:
                event["leaseEvidence"] = self.synthetic_lease(event, snapshot)
                if mode == "quarantine":
                    event.update(quarantineName="lease-quarantine-synthetic", recordSha256="8" * 64, barrier="release-after-quarantine-parent-sync")
                elif mode != "admit-clean":
                    event.update(canarySha256=GATE._digest(f"reset-probe:{case_id}:{receipt['sessionToken']}\n".encode()), runRootInode=50, availableBytes=0 if mode == "bytes-full" else 30000000, availableInodes=0 if mode == "inodes-full" else 3900)
                    if mode == "sparse-deep":
                        event.update(sparseLogicalBytes=2**40, directoryDepth=512)
                    if mode == "bytes-full":
                        event["writtenBytes"] = 30000000
                    if mode == "inodes-full":
                        event["createdFiles"] = 3900
            events.append(event)
        kills = []
        if case_id in {"K03", "K04", "K05", "K06", "K26"}:
            kills = [{"pid": events[0]["pid"], "startTicks": events[0]["startTicks"], "signal": 9, "exitCode": 137}]
        return {"schemaVersion": 1, "caseId": case_id, "sessionToken": receipt["sessionToken"], "events": events, "kills": kills}

    def write_receipt(self, case_id):
        (self.evidence / "cases" / f"{case_id}.json").write_bytes(GATE.canonical(self.receipts[case_id]))

    def write_probe(self, case_id, probe):
        (self.evidence / "cases" / f"{case_id}-probe.json").write_bytes(GATE.canonical(probe))

    def rewrite_artifact(self, case_id, name, value):
        raw = GATE.canonical(value, newline=False) if isinstance(value, dict) else value
        (self.evidence / "raw" / case_id / name).write_bytes(raw)
        receipt = self.receipts[case_id]
        reference = next(entry for entry in receipt["artifacts"] if entry["name"] == name)
        reference.update(bytes=len(raw), sha256=GATE._digest(raw))
        if name == "manifest.json":
            receipt["installedManifestSha256"] = GATE._digest(raw)
        if name == "formatter.trace":
            receipt["observations"]["trace"]["sha256"] = GATE._digest(raw)
        self.write_receipt(case_id)

    def check_bundle(self):
        # Only the Git transport boundary is replaced for invented pure-test
        # source files. Its actual local Git behavior is checked separately.
        with mock.patch.object(GATE, "verify_git_sources") as check_commit:
            result = GATE.verify(self.reports, self.evidence, self.source, self.commit)
            check_commit.assert_called_once_with(self.source, self.commit, result["sourceHashes"])
            return result

    def test_actual_git_source_binding_rejects_wrong_head_and_changed_blob(self):
        path = "src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt"
        commit = GATE._git_read(ROOT, ["rev-parse", "--verify", "HEAD"]).decode().strip()
        hashes = {path: GATE._digest((ROOT / path).read_bytes())}
        with mock.patch.object(GATE, "SOURCE_PATHS", (path,)):
            GATE.verify_git_sources(ROOT, commit, hashes)
            with self.assertRaisesRegex(ValueError, "checked-out HEAD"):
                GATE.verify_git_sources(ROOT, "0" * 40, hashes)
            with mock.patch.object(GATE, "_git_read", side_effect=[(commit + "\n").encode(), f"100644 blob {'0' * 40}\t{path}\0".encode()]):
                with self.assertRaisesRegex(ValueError, "committed bytes"):
                    GATE.verify_git_sources(ROOT, commit, hashes)

    def test_accepts_complete_pure_test_bundle(self):
        self.synthetic_bundle()
        result = self.check_bundle()
        self.assertEqual(32, result["passed"])
        self.assertEqual(0, result["skipped"])
        self.assertEqual(32, len(result["controls"]))
        self.assertEqual(13, len(result["sourceHashes"]))
        self.assertIn("separate required gates", result["scope"])

    def test_receipt_semantic_mutations_refused_even_with_canonical_bytes(self):
        self.synthetic_bundle()
        mutations = (
            ("K01", lambda r: r.update(schemaVersion=True)),
            ("K01", lambda r: r.update(sourceCommit="5" * 40)),
            ("K01", lambda r: r.update(profileSha256="0" * 64)),
            ("K01", lambda r: r.update(installedManifestSha256="0" * 64)),
            ("K01", lambda r: r.update(extra=True)),
            ("K02", lambda r: r.update(sessionToken=self.receipts["K01"]["sessionToken"])),
            ("K03", lambda r: r["after"].update(generation=r["before"]["generation"])),
            ("K03", lambda r: r["after"].update(loopRdev=os.makedev(7, 102))),
            ("K03", lambda r: r["after"].update(gateMode=0)),
            ("K03", lambda r: r["after"].update(extra=0)),
            ("K03", lambda r: r["before"].update(mountId=999999)),
            ("K04", lambda r: r["observations"]["facts"].update(mutatorCount=7)),
            ("K04", lambda r: r["observations"]["facts"].update(oldTreeEntriesVisited=512)),
            ("K07", lambda r: r["observations"].update(holders=[])),
            ("K07", lambda r: r["observations"]["holders"][0].update(reaped=False)),
            ("K08", lambda r: r["observations"]["trace"].update(deviceMutationCount=1)),
            ("K08", lambda r: r["observations"]["trace"].update(exclusiveOpenErrno=None)),
            ("K10", lambda r: r["observations"]["facts"].update(allocatedLoopRdev=r["before"]["loopRdev"])),
            ("K14", lambda r: r["observations"].update(deaths=[])),
            ("K14", lambda r: r["observations"]["deaths"][0].update(role="controller")),
            ("K22", lambda r: r["observations"]["canaries"][0].update(afterSha256="0" * 64)),
            ("K28", lambda r: r["observations"]["trace"].update(truncated=True)),
            ("K28", lambda r: r["observations"]["trace"].update(mutationsBeforeExclusiveOpen=1)),
            ("K29", lambda r: r["observations"].update(deaths=[])),
            ("K30", lambda r: r["observations"]["facts"].update(retainedReservation=False)),
            ("K30", lambda r: r["after"].update(phase="PUBLISHED")),
            ("K32", lambda r: r["observations"]["facts"].update(restored=False)),
        )
        for case_id, mutate in mutations:
            with self.subTest(case=case_id, mutation=mutate.__code__.co_firstlineno):
                original = copy.deepcopy(self.receipts[case_id])
                mutate(self.receipts[case_id])
                self.write_receipt(case_id)
                with self.assertRaises(ValueError):
                    self.check_bundle()
                self.receipts[case_id] = original
                self.write_receipt(case_id)

    def test_probe_measurement_mutations_refused(self):
        self.synthetic_bundle()
        mutations = (
            ("K01", lambda p: p["events"][0].update(uid=0)),
            ("K01", lambda p: p["events"][0].update(deniedObjects=3)),
            ("K02", lambda p: p["events"].pop(1)),
            ("K03", lambda p: p.update(kills=[])),
            ("K03", lambda p: p["kills"][0].update(startTicks=201)),
            ("K03", lambda p: p["events"][-1]["leaseEvidence"].update(evidenceSha256="0" * 64)),
            ("K04", lambda p: p["events"][0].update(sparseLogicalBytes=1024)),
            ("K04", lambda p: p["events"][0].update(directoryDepth=1)),
            ("K05", lambda p: p["events"][0].update(availableBytes=1)),
            ("K06", lambda p: p["events"][0].update(availableInodes=1)),
            ("K26", lambda p: p["events"][0].update(barrier="before-quarantine")),
            ("K31", lambda p: p["events"][2].update(canarySha256="0" * 64)),
        )
        for case_id, mutate in mutations:
            with self.subTest(case=case_id, mutation=mutate.__code__.co_firstlineno):
                probe = self.synthetic_probe(self.receipts[case_id])
                mutate(probe)
                self.write_probe(case_id, probe)
                with self.assertRaises(ValueError):
                    self.check_bundle()
                self.write_probe(case_id, self.synthetic_probe(self.receipts[case_id]))

    def test_raw_event_and_service_semantic_mutations_refused_with_rebound_hashes(self):
        self.synthetic_bundle()
        changes = (
            ("K14", "events.json", lambda v: v.update(events=[v["events"][0]])),
            ("K01", "events.json", lambda v: v["events"][0].update(operation="claimed-success")),
            ("K01", "service.properties", lambda v: v["properties"].update(Job="42")),
            ("K01", "service.properties", lambda v: v["cgroup"].update(pids=[999])),
            ("K01", "service.properties", lambda v: v["cgroup"].update(children=["escape"])),
            ("K01", "service.properties", lambda v: v["cgroup"].update(path=[])),
            ("K01", "service.properties", lambda v: v["retentionTarget"].update(ActiveState="inactive")),
            ("K01", "service.properties", lambda v: v["retentionTarget"].update(Wants="decomp-oracle-ext4-reset-ci.service")),
            ("K02", "service.properties", lambda v: v["properties"].update(InvocationID="2" * 32)),
            ("K02", "service.properties", lambda v: v.update(bootId="22222222-2222-4222-8222-222222222222")),
            ("K03", "service.properties", lambda v: v["properties"].update(Result="signal")),
        )
        for case_id, name, mutate in changes:
            with self.subTest(case=case_id, file=name, mutation=mutate.__code__.co_firstlineno):
                original = (self.evidence / "raw" / case_id / name).read_bytes()
                value = json.loads(original)
                mutate(value)
                self.rewrite_artifact(case_id, name, value)
                with self.assertRaises(ValueError):
                    self.check_bundle()
                self.rewrite_artifact(case_id, name, original)

    def test_installed_source_and_package_mutations_refused_with_rebound_manifest_hash(self):
        self.synthetic_bundle()
        path = self.evidence / "raw/K01/manifest.json"
        original = path.read_bytes()
        changes = (
            lambda m: m["owner"].update(uid=0),
            lambda m: m["files"]["/var/lib/decomp-oracle-ext4-reset-ci/private/oracle-ext4-reset.py"].update(sha256="0" * 64),
            lambda m: m["files"]["/var/lib/decomp-oracle-ext4-reset-ci/private/profile.json"].update(sha256="0" * 64),
            lambda m: m["files"][m["tools"]["mke2fs"]]["identity"].update(mode=0o777),
            lambda m: m["packageProvenance"]["packages"]["e2fsprogs"].update(sourceVersion="1.48.0"),
            lambda m: m["packageProvenance"]["packages"]["e2fsprogs"].update(aptMetadataSha256="0" * 64),
            lambda m: m["packageProvenance"]["packages"]["e2fsprogs"].update(verifyOutputSha256="0" * 64),
            lambda m: m["packageProvenance"]["formatterSource"].update(upstreamCommit="0" * 40),
            lambda m: m["packageProvenance"].update(aptAuthenticationBoundary="version-string-only"),
        )
        for mutate in changes:
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                value = json.loads(original)
                mutate(value)
                self.rewrite_artifact("K01", "manifest.json", value)
                with self.assertRaises(ValueError):
                    self.check_bundle()
                self.rewrite_artifact("K01", "manifest.json", original)

    def test_missing_extra_and_cross_case_artifacts_refused(self):
        self.synthetic_bundle()
        receipt = self.receipts["K01"]
        original = copy.deepcopy(receipt["artifacts"])
        for entries in (original[:-1], original[:-1] + original[:1], [{**original[0], "path": "raw/K02/formatter.trace"}] + original[1:]):
            with self.subTest(entries=entries):
                receipt["artifacts"] = entries
                self.write_receipt("K01")
                with self.assertRaises(ValueError):
                    self.check_bundle()
        receipt["artifacts"] = original
        self.write_receipt("K01")
        extra = self.evidence / "cases/K33.json"
        extra.write_bytes(b"{}\n")
        with self.assertRaises(ValueError):
            self.check_bundle()

    def test_changed_actual_artifact_and_source_bytes_refused(self):
        self.synthetic_bundle()
        trace = self.evidence / "raw/K28/formatter.trace"
        original = trace.read_bytes()
        trace.write_bytes(original + b"changed\n")
        with self.assertRaises(ValueError):
            self.check_bundle()
        trace.write_bytes(original)
        source = self.source / "src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt"
        source.write_bytes(b"different production acquisition behavior\n")
        with self.assertRaises(ValueError):
            self.check_bundle()

    def test_trace_summary_cannot_replace_or_contradict_actual_syscalls(self):
        self.synthetic_bundle()
        original = self.synthetic_trace(filesystem_uuid=self.receipts["K28"]["after"]["filesystemUuid"])
        variants = (
            b"not a syscall trace\n",
            original.replace(b"makedev(0x7, 0x64)", b"makedev(0x7, 0x65)"),
            original.replace(b"O_RDWR|O_EXCL", b"O_RDWR"),
            original.replace(b'"-F"', b'"-FF"'),
            original.replace(b"E2FSPROGS_UNDO_DIR=none", b"E2FSPROGS_UNDO_DIR=/tmp"),
            original.replace(b"pwrite64(9</dev/loop100>", b"pwrite64(21</dev/loop100>"),
            original.replace(b"100 pwrite64", b"101 pwrite64"),
            original.replace(b"100 close(9</dev/loop100>) = 0\n", b"100 ioctl(9</dev/loop100>, UNKNOWN_WRITE_IOCTL, 0) = 0\n"),
            original.rstrip(b"\n"),
        )
        for raw in variants:
            with self.subTest(raw=raw[:100]):
                self.rewrite_artifact("K28", "formatter.trace", raw)
                with self.assertRaises(ValueError):
                    self.check_bundle()
        self.rewrite_artifact("K28", "formatter.trace", original)
        self.assertEqual(32, self.check_bundle()["passed"])

    def test_reused_closed_descriptor_no_longer_has_exclusive_claim(self):
        raw = self.synthetic_trace() + b'100 pwrite64(9</dev/loop100>, "x", 1, 0) = 1\n'
        self.assertEqual(1, GATE.decode_formatter_trace(raw, os.makedev(7, 100))["mutationsBeforeExclusiveOpen"])

    def test_refused_open_cannot_reuse_stale_procfd_device_proof(self):
        execution = self.synthetic_trace().splitlines(keepends=True)[0].replace(b"/proc/self/fd/21", b"/proc/self/fd/7")
        proof = execution + b'100 newfstatat(AT_FDCWD, "/proc/self/fd/7", {st_mode=S_IFBLK|0660, st_rdev=makedev(0x7, 0x64), ...}, 0) = 0\n'
        refusal = b'100 openat(AT_FDCWD, "/proc/self/fd/7", O_RDONLY|O_EXCL) = -1 EBUSY (Device or resource busy)\n'
        replacements = (
            b'100 close(7</dev/loop100>) = 0\n100 openat(AT_FDCWD, "/dev/loop101", O_RDONLY) = 7</dev/loop101>\n',
            b'100 close(7) = 0\n',
            b'100 openat(AT_FDCWD, "/dev/loop101", O_RDONLY) = 7</dev/loop101>\n',
        )
        for replacement in replacements:
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(ValueError, "prior exact block-device stat"):
                    GATE.decode_formatter_trace(proof + replacement + refusal, os.makedev(7, 100))

    def test_cli_reports_incomplete_as_failure_and_keeps_output_under_source_root(self):
        self.synthetic_bundle()
        (self.evidence / "cases/K32.json").unlink()
        output = self.source / "build/gate.json"
        command = [sys.executable, "-I", "-S", str(ROOT / "scripts/verify-oracle-ext4-reset.py"), "--reports", str(self.reports), "--evidence", str(self.evidence), "--source-root", str(self.source), "--source-commit", self.commit, "--output", str(output)]
        result = subprocess.run(command, capture_output=True, timeout=10, check=False)
        self.assertEqual(1, result.returncode)
        self.assertEqual("failed", json.loads(output.read_bytes())["status"])
        with self.assertRaises(ValueError):
            GATE._write_output(self.source, self.root / "outside-source.json", b"{}\n")

    def test_required_names_match_actual_unit_returning_kotlin_methods(self):
        source = ROOT / "src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchResetMountedTest.kt"
        names = re.findall(r"@Test\s+(?:@Order\([0-9]+\)\s+)?fun `([^`]+)`\(\): Unit", source.read_text())
        self.assertCountEqual(GATE.REQUIRED, names)


if __name__ == "__main__":
    unittest.main()

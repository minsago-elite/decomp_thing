#!/usr/bin/env python3
"""Finite unprivileged reset protocol controls; these are not kernel qualification."""
from __future__ import annotations

import copy
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, call, patch

ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/oracle-ext4-reset.py"
SPEC = importlib.util.spec_from_file_location("ext4_reset_controller", CONTROLLER)
reset = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reset
SPEC.loader.exec_module(reset)

INTENT = "a" * 64
UUID = "12345678-1234-4234-9234-123456789abc"
OLD_UUID = "87654321-4321-4321-8321-cba987654321"


def synthetic_identity(inode, *, kind="directory", mode=0o700, uid=0):
    """Protocol inputs only: these identities are never offered to a kernel API."""
    value = {"device": 1, "inode": inode, "mountId": 2, "uid": uid,
             "gid": 0 if uid == 0 else 1000, "mode": mode, "kind": kind}
    if kind != "directory":
        value.update(links=1, size=67108864 if kind == "file" else 0,
                     rdev=os.makedev(7, 1) if kind == "block" else 0)
    return value


def synthetic_mount(identifier, path, *, device="7:1"):
    return {"id": identifier, "parent": 2, "device": device, "root": "/", "path": str(path),
            "options": ["noatime", "nodev", "noexec", "nosuid", "rw"], "optional": [],
            "type": "ext4", "source": "/dev/loop1", "superOptions": ["rw"]}


def synthetic_record(phase="INTENT"):
    """A complete parser fixture, never evidence of a real slot or reset result."""
    image = synthetic_identity(11, kind="file", mode=0o600)
    value = {
        "schemaVersion": 1, "profileSha256": reset.sha256(reset.canonical(reset.profile_document())),
        "manifestSha256": "2" * 64, "slotId": "slot0", "bootId": OLD_UUID,
        "sequence": 1, "previousHash": "0" * 64, "phase": phase, "disposition": "RESERVED",
        "owner": {"uid": 1000, "gid": 1000, "groups": [1000]},
        "anchors": {name: synthetic_identity(index) for index, name in enumerate(
            ("root", "private", "public", "quarantine", "underlyingRoot"), 3)},
        "image": image,
        "loop": {"path": "/dev/loop1", "rdev": os.makedev(7, 1),
                 "node": synthetic_identity(12, kind="block", mode=0o600),
                 "backingDevice": 1, "backingInode": 11, "offset": 0,
                 "sizeLimit": 67108864, "number": 1, "flags": 0},
        "parentMount": synthetic_mount(2, reset.ROOT, device="8:1"),
        "generation": 1 if phase == "PUBLISHED" else 0, "previousGeneration": 0,
        "targetGeneration": 0 if phase == "REGISTERED" else 1,
        "intentId": None if phase == "REGISTERED" else INTENT,
        "targetUuid": None if phase == "REGISTERED" else UUID,
        "old": {"generation": 0, "gate": synthetic_identity(13, mode=0o711),
                "underlying": synthetic_identity(14, mode=0),
                "mount": synthetic_mount(10, reset.generation_path(0) / "scratch"),
                "root": synthetic_identity(15, uid=1000), "uuid": OLD_UUID},
        "candidate": None, "submission": {"state": "NONE", "job": None, "invocation": None},
        "custodian": None, "formatter": None,
    }
    if phase in ("FORMATTED", "MOUNT_INTENT", "READY_PRIVATE", "EXPOSURE_INTENT", "PUBLISHED"):
        value["formatter"] = {"exitCode": 0, "uuid": UUID, "traceSha256": "3" * 64,
                              "traceBytes": 0, "argvSha256": "4" * 64}
    if phase in ("MOUNT_INTENT", "READY_PRIVATE", "EXPOSURE_INTENT", "PUBLISHED"):
        mounted = phase != "MOUNT_INTENT"
        value["candidate"] = {"generation": 1, "gate": synthetic_identity(16, mode=0),
                              "underlying": synthetic_identity(17, mode=0), "uuid": UUID,
                              "mount": synthetic_mount(11, reset.generation_path(1) / "scratch") if mounted else None,
                              "root": synthetic_identity(18, uid=1000) if mounted else None}
    return reset.seal_state(value)


def untrusted_payload(value):
    """Recompute a corruption checksum, without asserting producer authority."""
    value = copy.deepcopy(value)
    value.pop("selfHash", None)
    value["selfHash"] = reset.sha256(reset.canonical(value))
    return reset.canonical(value)


class CliTests(unittest.TestCase):
    def test_direct_cli_parser_accepts_the_same_closed_list_and_tuple_forms(self):
        for arguments in (["status"], ["service-run"], ["request", "0"],
                          ["resume", INTENT], ["finalize", INTENT]):
            with self.subTest(arguments=arguments):
                self.assertEqual(reset.parse_cli(tuple(arguments)), reset.parse_cli(arguments))

    def test_invalid_requests_refuse_before_privilege_or_filesystem_access(self):
        cases = (
            [], ["unknown"], ["status", "/other"], ["service-run", "other.service"],
            ["request"], ["request", "-1"], ["request", "01"],
            ["request", str(1 << 64)], ["request", "0", "/other"],
            ["resume"], ["resume", "a" * 63], ["resume", "A" * 64],
            ["finalize", "../state.json"], ["finalize", INTENT, "--force"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), \
                 patch.object(reset.os, "geteuid", side_effect=AssertionError("privilege probe")), \
                 patch.object(reset.os, "open", side_effect=AssertionError("filesystem access")), \
                 patch.object(reset, "opened_store", side_effect=AssertionError("state access")), \
                 redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                self.assertEqual(reset.main(arguments), 64)

    def test_all_closed_actions_refuse_nonroot_before_state_or_commands(self):
        for arguments in (["status"], ["request", "0"], ["resume", INTENT],
                          ["finalize", INTENT], ["service-run"]):
            with self.subTest(arguments=arguments), \
                 patch.object(reset.os, "geteuid", return_value=1000), \
                 patch.object(reset.os, "open", side_effect=AssertionError("filesystem access")), \
                 patch.object(reset, "opened_store", side_effect=AssertionError("state access")), \
                 patch.object(reset, "run_process", side_effect=AssertionError("utility launch")), \
                 redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                self.assertEqual(reset.main(arguments), 77)

    def test_real_cli_rejects_arbitrary_command_and_path(self):
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(CONTROLLER), "request", "/tmp/not-a-generation"],
            capture_output=True, timeout=5, env={},
        )
        self.assertEqual(result.returncode, 64)
        self.assertLessEqual(len(result.stdout), 16384)
        self.assertTrue(result.stdout.endswith(b"\n"))
        response = reset.parse_canonical(result.stdout[:-1])
        self.assertEqual(set(response), {"ok", "error", "disposition"})
        self.assertFalse(response["ok"])
        self.assertEqual(response["disposition"], "RESERVED")
        self.assertLessEqual(len(response["error"]), 512)

    def test_root_cannot_use_checkout_controller_as_installed_authority(self):
        output = io.StringIO()
        with patch.object(reset.os, "geteuid", return_value=0), \
             patch.object(reset, "INSTALLED", ROOT / "build/never-installed-controller.py"), \
             patch.object(reset, "opened_store", side_effect=AssertionError("state access")), \
             patch.object(reset, "run_process", side_effect=AssertionError("utility launch")), \
             redirect_stdout(output):
            self.assertEqual(reset.main(["status"]), 1)
        response = reset.parse_canonical(output.getvalue().rstrip("\n").encode("ascii"))
        self.assertFalse(response["ok"])
        self.assertIn("installed", response["error"])
        self.assertEqual(response["disposition"], "RESERVED")


class FormatterArgumentTests(unittest.TestCase):
    def test_fixed_formatter_arguments_have_one_force_and_pinned_fd(self):
        arguments = reset.formatter_argv(37, UUID)
        self.assertEqual(arguments, [
            "-t", "ext4", "-q", "-F", "-b", "4096", "-I", "256",
            "-N", "4096", "-m", "0", "-U", UUID,
            "-O", "none,has_journal,extent,filetype,sparse_super,large_file,dir_index,uninit_bg",
            "-E", "nodiscard,lazy_itable_init=0,lazy_journal_init=0", "/proc/self/fd/37", "16384",
        ])
        self.assertEqual(arguments.count("-F"), 1)
        self.assertNotIn("-FF", arguments)
        self.assertNotIn("-S", arguments)

    def test_formatter_cannot_select_a_path_or_inject_options(self):
        for descriptor, uuid in (("/dev/loop0", UUID), (-1, UUID), (True, UUID),
                                 (37, "-FF"), (37, UUID + " -E offset=4096"),
                                 (37, "../image")):
            with self.subTest(descriptor=descriptor, uuid=uuid), self.assertRaises((ValueError, reset.ResetError)):
                reset.formatter_argv(descriptor, uuid)


class TracerArgumentTests(unittest.TestCase):
    def test_signal_records_are_suppressed_without_changing_fixed_syscall_evidence(self):
        normal = reset.tracer_argv(10,11,12,13,UUID)
        self.assertEqual(normal[:9],['/proc/self/fd/10','-f','-qq','-s','256','-v','-y','-e',
            'trace=execve,stat,newfstatat,fstat,openat,openat2,write,pwrite64,writev,pwritev,ioctl,close'])
        self.assertEqual(normal[9:14],['-e','signal=none','-o','/proc/self/fd/11','--'])
        self.assertEqual(normal[14:],['/proc/self/fd/12',*reset.formatter_argv(13,UUID)])
        paused = reset.tracer_argv(10,11,12,13,UUID,pause=True)
        injection = '--inject=pwrite64:signal=SIGSTOP:when=1'
        self.assertEqual(paused.count(injection),1)
        self.assertEqual([item for item in paused if item != injection],normal)

    def test_tracer_options_and_descriptor_paths_are_not_caller_selectable(self):
        for replacement in ('--signal=all',True,-1,'/tmp/output'):
            with self.subTest(descriptor=replacement),self.assertRaises(reset.ResetError):
                reset.tracer_argv(replacement,11,12,13,UUID)
        for replacement in ('--inject=write:error=0',1,None):
            with self.subTest(pause=replacement),self.assertRaises(reset.ResetError):
                reset.tracer_argv(10,11,12,13,UUID,pause=replacement)


class CanonicalProtocolTests(unittest.TestCase):
    def test_canonical_payload_is_deterministic_and_ascii(self):
        expected = b'{"a":1,"z":"\\u00e9"}'
        self.assertEqual(reset.canonical({"z": "é", "a": 1}), expected)
        self.assertEqual(reset.parse_canonical(expected), {"a": 1, "z": "é"})

    def test_duplicate_keys_nonfinite_numbers_and_noncanonical_encoding_refuse(self):
        for payload in (b'{"a":1,"a":2}', b'{"outer":{"a":1,"a":2}}',
                        b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1}\n',
                        b'{ "a": 1}', b'{"z":2,"a":1}', b'\xff', b''):
            with self.subTest(payload=payload), self.assertRaises(reset.ResetError):
                reset.parse_canonical(payload)

    def test_record_depth_population_string_and_byte_bounds_refuse(self):
        values = ([0] * 65, {str(index): index for index in range(65)}, "x" * 4097)
        nested = 0
        for _ in range(10):
            nested = [nested]
        for value in (*values, nested):
            with self.subTest(kind=type(value).__name__), self.assertRaises(reset.ResetError):
                reset.parse_canonical(reset.canonical(value))
        with self.assertRaises(reset.ResetError):
            reset.parse_canonical(b" " * (16384 + 1))

    def test_normal_and_qualification_profiles_are_explicitly_distinct(self):
        normal = reset.profile_document()
        qualified = reset.profile_document(qualification=True)
        self.assertEqual(normal["kind"], "production")
        self.assertEqual(qualified["kind"], "qualification")
        self.assertNotEqual(reset.sha256(reset.canonical(normal)), reset.sha256(reset.canonical(qualified)))
        self.assertEqual(normal["imageBytes"], 67108864)
        self.assertEqual(normal["inodes"], 4096)
        self.assertEqual(normal["maximumGenerationDirectories"], 2)

    def test_generation_paths_are_closed_and_uint64_bounded(self):
        self.assertEqual(reset.generation_path(0).name, "g-0000000000000000")
        self.assertEqual(reset.generation_path((1 << 64) - 1).name, "g-ffffffffffffffff")
        for value in (-1, 1 << 64, True, "../other"):
            with self.subTest(value=value), self.assertRaises(reset.ResetError):
                reset.generation_path(value)


class MountInventoryTests(unittest.TestCase):
    def test_mount_parser_preserves_exact_identity_propagation_and_escapes(self):
        rows = reset.parse_mountinfo(
            "42 1 7:10 / /var/lib/with\\040space rw,nosuid,nodev,noexec,noatime shared:2 - ext4 /dev/loop10 rw\n"
        )
        self.assertEqual(rows, [{"id": 42, "parent": 1, "device": "7:10", "root": "/",
                                "path": "/var/lib/with space", "options": ["noatime", "nodev", "noexec", "nosuid", "rw"],
                                "optional": ["shared:2"], "type": "ext4", "source": "/dev/loop10", "superOptions": ["rw"]}])

    def test_duplicate_malformed_relative_and_oversized_mount_tables_refuse(self):
        row = "42 1 7:10 / /root rw - ext4 /dev/loop10 rw\n"
        for text in (row + row, "no separator", row.replace("42 ", "0 ", 1),
                     row.replace("7:10", "not-device"), row.replace("/root", "relative"),
                     row.replace("/root", "/bad\\000path"), "x" * (4194304 + 1)):
            with self.subTest(length=len(text)), self.assertRaises(reset.ResetError):
                reset.parse_mountinfo(text)


class StateProtocolTests(unittest.TestCase):
    def test_complete_protocol_fixture_roundtrips_all_declared_phases(self):
        for phase in ("REGISTERED", "INTENT", "FENCED", "UNMOUNTED", "FORMAT_STARTED",
                      "FORMATTED", "MOUNT_INTENT", "READY_PRIVATE", "EXPOSURE_INTENT", "PUBLISHED"):
            with self.subTest(phase=phase):
                value = synthetic_record(phase)
                self.assertEqual(reset.parse_record(reset.canonical(value)), value)

    def test_unknown_fields_reject_even_with_a_recomputed_checksum(self):
        for path in ((), ("owner",), ("anchors", "private"), ("image",), ("loop",),
                     ("old",), ("old", "mount"), ("submission",)):
            value = synthetic_record()
            target = value
            for key in path:
                target = target[key]
            target["untrustedAuthority"] = "/arbitrary/path"
            with self.subTest(path=path), self.assertRaises(reset.ResetError):
                reset.parse_record(untrusted_payload(value))

    def test_missing_or_corrupt_boot_and_record_hash_refuse(self):
        for boot in (None, "", "unknown", OLD_UUID.upper()):
            value = synthetic_record()
            value["bootId"] = boot
            with self.subTest(boot=boot), self.assertRaises(reset.ResetError):
                reset.parse_record(untrusted_payload(value))
        value = synthetic_record()
        value["selfHash"] = "f" * 64
        with self.assertRaisesRegex(reset.ResetError, "self hash"):
            reset.parse_record(reset.canonical(value))

    def test_generation_phase_and_reservation_cannot_be_relabelled(self):
        for field, replacement in (("phase", "RELEASED"), ("disposition", "RELEASED"),
                                   ("targetGeneration", 2), ("targetGeneration", 1 << 64),
                                   ("generation", 1), ("previousGeneration", True),
                                   ("intentId", None), ("targetUuid", OLD_UUID.upper())):
            value = synthetic_record()
            value[field] = replacement
            with self.subTest(field=field, replacement=replacement), self.assertRaises(reset.ResetError):
                reset.parse_record(untrusted_payload(value))

    def test_boolean_values_cannot_impersonate_schema_or_exit_integers(self):
        value = synthetic_record()
        value["schemaVersion"] = True
        with self.assertRaises(reset.ResetError):
            reset.parse_record(untrusted_payload(value))
        value = synthetic_record("FORMATTED")
        value["formatter"]["exitCode"] = False
        with self.assertRaises(reset.ResetError):
            reset.parse_record(untrusted_payload(value))

    def test_late_phases_require_formatter_candidate_and_actual_mount_identity(self):
        for phase, field in (("FORMATTED", "formatter"), ("MOUNT_INTENT", "candidate"),
                             ("READY_PRIVATE", "candidate")):
            value = synthetic_record(phase)
            value[field] = None
            with self.subTest(phase=phase), self.assertRaises(reset.ResetError):
                reset.parse_record(untrusted_payload(value))
        value = synthetic_record("READY_PRIVATE")
        value["candidate"]["mount"] = value["candidate"]["root"] = None
        with self.assertRaises(reset.ResetError):
            reset.parse_record(untrusted_payload(value))

    def test_rebound_loop_and_changed_image_profile_are_rejected(self):
        for path, field, replacement in (("loop", "flags", 4), ("loop", "offset", 4096),
                                         ("loop", "backingInode", 99), ("loop", "sizeLimit", 0),
                                         ("image", "links", 2), ("image", "size", 134217728),
                                         ("image", "uid", 1000)):
            value = synthetic_record()
            value[path][field] = replacement
            with self.subTest(path=path, field=field), self.assertRaises(reset.ResetError):
                reset.parse_record(untrusted_payload(value))

    def test_intent_replay_and_phase_regression_cannot_be_a_transition(self):
        old = synthetic_record("FENCED")
        for field, replacement in (("intentId", "b" * 64), ("targetUuid", OLD_UUID),
                                   ("phase", "INTENT"), ("phase", "FORMAT_STARTED"),
                                   ("manifestSha256", "9" * 64)):
            new = copy.deepcopy(old)
            new[field] = replacement
            with self.subTest(field=field), self.assertRaises(reset.ResetError):
                reset.Store.validate_transition(old, new)
        old = synthetic_record("EXPOSURE_INTENT")
        with self.assertRaises(reset.ResetError):
            reset.Store.validate_transition(old, synthetic_record("FORMAT_STARTED"))

    def test_boot_mismatch_cannot_reconcile_or_rename_staged_state(self):
        value = synthetic_record()
        store = object.__new__(reset.Store)
        store.profile_hash = value["profileSha256"]
        store.manifest_hash = value["manifestSha256"]
        store.manifest = {"owner": value["owner"]}
        with patch.object(store, "read", return_value=reset.canonical(value)), \
             patch.object(reset, "boot_id", return_value=UUID), \
             patch.object(reset, "fence_old_boot") as fence, \
             patch.object(reset, "_entries", side_effect=AssertionError("reconciliation attempted")), \
             patch.object(reset.os, "rename", side_effect=AssertionError("state mutation")), \
             self.assertRaisesRegex(reset.ResetError, "boot mismatch"):
            store.load()
        fence.assert_called_once_with(store, value)

    def test_boot_fence_refuses_changed_anchor_before_opening_or_chmodding_gates(self):
        value = synthetic_record("EXPOSURE_INTENT")
        paths = {reset.ROOT: "root", reset.PRIVATE: "private", reset.PUBLIC: "public"}
        store = object.__new__(reset.Store)
        for changed in ("root", "private", "public"):
            def observed(path):
                identity = copy.deepcopy(value["anchors"][paths[path]])
                if paths[path] == changed:
                    identity["inode"] += 100
                return identity
            with self.subTest(anchor=changed), \
                 patch.object(reset, "file_identity", side_effect=observed), \
                 patch.object(store, "open_dir", side_effect=AssertionError("unknown anchor used")), \
                 patch.object(reset.os, "fchmod") as chmod, \
                 patch.object(reset.os, "fsync") as fsync, \
                 self.assertRaisesRegex(reset.ResetError, "changed persistent authority anchor"):
                reset.fence_old_boot(store, value)
            chmod.assert_not_called()
            fsync.assert_not_called()

    def test_boot_fence_preflights_both_gates_before_changing_either(self):
        value = synthetic_record("EXPOSURE_INTENT")
        store = object.__new__(reset.Store)
        store.public = -1
        unknown = copy.deepcopy(value["candidate"]["gate"])
        unknown["inode"] += 100
        with patch.object(reset, "file_identity", side_effect=[value["anchors"][key] for key in ("root", "private", "public")]), \
             patch.object(store, "open_dir", side_effect=[101, 102]), \
             patch.object(store, "drop") as drop, \
             patch.object(reset, "fd_identity", side_effect=[value["old"]["gate"], unknown]), \
             patch.object(reset, "_entries", return_value=["scratch"]), \
             patch.object(reset.os, "fchmod") as chmod, \
             patch.object(reset.os, "fsync") as fsync, \
             self.assertRaisesRegex(reset.ResetError, "unknown generation gate"):
            reset.fence_old_boot(store, value)
        chmod.assert_not_called()
        fsync.assert_not_called()
        self.assertEqual(drop.call_args_list, [call(101), call(102)])

    def test_staged_record_with_wrong_predecessor_or_sequence_is_preserved(self):
        old = synthetic_record()
        for field, replacement in (("previousHash", "d" * 64), ("sequence", old["sequence"])):
            new = copy.deepcopy(old)
            new.update(phase="FENCED", previousHash=old["selfHash"], sequence=old["sequence"] + 1)
            new[field] = replacement
            store = object.__new__(reset.Store)
            store.private = -1
            store.profile_hash = old["profileSha256"]
            store.manifest_hash = old["manifestSha256"]
            store.manifest = {"owner": old["owner"]}
            with self.subTest(field=field), \
                 patch.object(store, "read", side_effect=[reset.canonical(old), untrusted_payload(new)]), \
                 patch.object(reset, "boot_id", return_value=OLD_UUID), \
                 patch.object(reset, "_entries", return_value=["state.next"]), \
                 patch.object(reset.os, "rename", side_effect=AssertionError("state mutation")), \
                 self.assertRaisesRegex(reset.ResetError, "staged state"):
                store.load()

    def test_exposed_or_published_generation_cannot_enter_destructive_resume(self):
        for phase in ("EXPOSURE_INTENT", "PUBLISHED"):
            with self.subTest(phase=phase), \
                 patch.object(reset, "inactive_snapshot", side_effect=AssertionError("manager access")), \
                 patch.object(reset, "verify_base", side_effect=AssertionError("disk access")), \
                 patch.object(reset, "submit", side_effect=AssertionError("service start")), \
                 self.assertRaisesRegex(reset.ResetError, "not destructively resumable"):
                reset.resume(object(), synthetic_record(phase), INTENT)

    def test_direct_service_entry_requires_real_fixed_unit_invocation(self):
        with patch.dict(reset.os.environ, {}, clear=True), \
             patch.object(reset, "manager_snapshot", side_effect=AssertionError("manager access")), \
             patch.object(reset, "verify_base", side_effect=AssertionError("disk access")), \
             self.assertRaisesRegex(reset.ResetError, "invocation absent"):
            reset.service_run(object(), synthetic_record())
        with patch.object(reset.Path, "read_text", return_value="0::/unrelated.service\n"), \
             patch.object(reset, "manager_snapshot", side_effect=AssertionError("manager access")), \
             self.assertRaisesRegex(reset.ResetError, "direct custodian entry"):
            reset.service_census(object(), "1" * 32)


class StatePublicationTests(unittest.TestCase):
    """Real file publication with synthetic records; not root/mount qualification."""

    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="reset-publication-", dir=ROOT / "build")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.store = object.__new__(reset.Store)
        self.store.fds = []
        self.store.private = self.store.open_dir(self.directory)
        self.addCleanup(self.store.close)
        self.store.profile = reset.profile_document()
        # Only deployment ownership and metadata census are stand-ins. Exercise
        # the real parser, transition validation, file writes, fsync and rename.
        reader = patch.object(self.store, "read", side_effect=self.read)
        reader.start()
        self.addCleanup(reader.stop)
        budget = patch.object(reset, "verify_metadata_budget", return_value=(0, 0))
        self.budget = budget.start()
        self.addCleanup(budget.stop)

    def read(self, name, maximum):
        data = (self.directory / name).read_bytes()
        self.assertLessEqual(len(data), maximum)
        return data

    def seed(self, record):
        (self.directory / "state.json").write_bytes(reset.canonical(record))
        return record

    def assert_published(self, previous, result):
        self.assertEqual(result["previousHash"], previous["selfHash"])
        self.assertEqual(result["sequence"], previous["sequence"] + 1)
        self.assertEqual(reset.parse_record(self.read("state.json", reset.MAX_RECORD)), result)
        self.assertFalse((self.directory / "state.next").exists())
        self.assertEqual(self.store.current_state, result)

    def test_registration_can_publish_observed_old_gate_without_argument_collision(self):
        initial = copy.deepcopy(synthetic_record("REGISTERED"))
        initial["old"]["gate"]["mode"] = 0
        previous = self.seed(reset.seal_state(initial))
        observed_old = copy.deepcopy(previous["old"])
        observed_old["gate"]["mode"] = 0o711
        result = self.store.publish(previous, old=observed_old)
        self.assert_published(previous, result)
        self.assertEqual(result["old"], observed_old)
        self.assertEqual(previous["old"]["gate"]["mode"], 0, "source state was mutated")
        self.budget.assert_called_once_with(self.store, previous)

    def test_registered_request_uses_real_publication_before_submission(self):
        previous = self.seed(synthetic_record("REGISTERED"))
        with patch.object(reset, "inactive_snapshot"), \
             patch.object(reset, "verify_base", return_value=(10, 11)), \
             patch.object(reset, "verify_live_generation"), \
             patch.object(reset, "superblock", return_value=previous["old"]["uuid"]), \
             patch.object(reset, "submit", side_effect=lambda store, state: state) as submit:
            result = reset.request(self.store, previous, 0)
        self.assert_published(previous, result)
        self.assertEqual(result["phase"], "INTENT")
        self.assertEqual(result["old"], previous["old"])
        self.assertEqual(result["submission"]["state"], "PENDING")
        self.assertEqual(result["targetGeneration"], 1)
        submit.assert_called_once_with(self.store, result)

    def test_published_candidate_can_become_old_generation_in_next_intent(self):
        previous = self.seed(synthetic_record("PUBLISHED"))
        result = self.store.publish(
            previous, phase="INTENT", previousGeneration=1, targetGeneration=2,
            intentId="b" * 64, targetUuid=OLD_UUID, old=previous["candidate"],
            candidate=None, custodian=None, formatter=None,
            submission={"state": "PENDING", "job": None, "invocation": None},
        )
        self.assert_published(previous, result)
        self.assertEqual(result["old"], previous["candidate"])
        self.assertEqual(result["old"]["generation"], 1)
        self.assertEqual(previous["old"]["generation"], 0)

    def test_immutable_update_still_refuses_before_staging(self):
        previous = self.seed(synthetic_record("REGISTERED"))
        with self.assertRaisesRegex(reset.ResetError, "immutable state field changed"):
            self.store.publish(previous, manifestSha256="9" * 64, old=previous["old"])
        self.assertEqual(self.read("state.json", reset.MAX_RECORD), reset.canonical(previous))
        self.assertFalse((self.directory / "state.next").exists())

    def test_changed_predecessor_is_not_overwritten_and_staged_successor_is_retained(self):
        previous = self.seed(synthetic_record("REGISTERED"))
        changed = reset.seal_state(dict(previous, sequence=previous["sequence"] + 1))
        self.seed(changed)
        with self.assertRaisesRegex(reset.ResetError, "state changed before publication"):
            self.store.publish(previous, old=previous["old"])
        self.assertEqual(self.read("state.json", reset.MAX_RECORD), reset.canonical(changed))
        staged = reset.parse_record(self.read("state.next", reset.MAX_RECORD))
        self.assertEqual(staged["previousHash"], previous["selfHash"])

    def test_metadata_reservation_still_refuses_before_staging(self):
        previous = self.seed(synthetic_record("REGISTERED"))
        self.budget.return_value = (self.store.profile["metadataBytes"], 0)
        with self.assertRaisesRegex(reset.ResetError, "metadata reservation"):
            self.store.publish(previous, old=previous["old"])
        self.assertEqual(self.read("state.json", reset.MAX_RECORD), reset.canonical(previous))
        self.assertFalse((self.directory / "state.next").exists())


class QualificationHookTests(unittest.TestCase):
    def test_normal_profile_never_reads_or_signals_a_qualification_hook(self):
        store = object.__new__(reset.Store)
        store.qualification = False
        with patch.object(store, "read", side_effect=AssertionError("fault file read")), \
             patch.object(reset, "_entries", side_effect=AssertionError("directory read")), \
             patch.object(reset.os, "kill", side_effect=AssertionError("signal sent")):
            store.barrier("INTENT_FSYNC", {})

    def test_unknown_barrier_refuses_before_any_file_or_signal(self):
        store = object.__new__(reset.Store)
        store.qualification = True
        with patch.object(store, "read", side_effect=AssertionError("fault file read")), \
             patch.object(reset, "_entries", side_effect=AssertionError("directory read")), \
             patch.object(reset.os, "kill", side_effect=AssertionError("signal sent")), \
             self.assertRaisesRegex(reset.ResetError, "unknown.*barrier"):
            store.barrier("ARBITRARY_COMMAND", {})

    def test_fault_record_cannot_add_an_arbitrary_path_or_pid(self):
        store = object.__new__(reset.Store)
        store.qualification = True
        store.private = -1  # No descriptor is used: only the bounded fault parser runs.
        fault = {"version": 1, "id": INTENT, "generation": 0, "barrier": "INTENT_FSYNC", "pid": 1}
        with patch.object(store, "read", return_value=reset.canonical(fault)), \
             patch.object(reset, "_entries", return_value=["fault.json"]), \
             patch.object(reset.os, "kill", side_effect=AssertionError("signal sent")), \
             self.assertRaisesRegex(reset.ResetError, "fault.*fields differ"):
            store.barrier("INTENT_FSYNC", {})

    def test_fault_generation_must_be_an_exact_bounded_integer(self):
        store = object.__new__(reset.Store)
        store.qualification = True
        store.private = -1
        for generation in (True, -1, 1 << 64, "0"):
            fault = {"version": 1, "id": INTENT, "generation": generation, "barrier": "INTENT_FSYNC"}
            with self.subTest(generation=generation), \
                 patch.object(store, "read", return_value=reset.canonical(fault)), \
                 patch.object(reset, "_entries", return_value=["fault.json"]), \
                 patch.object(reset.os, "kill", side_effect=AssertionError("signal sent")), \
                 self.assertRaises(reset.ResetError):
                store.barrier("INTENT_FSYNC", {"previousGeneration": 0})


class RetentionProtocolTests(unittest.TestCase):
    @staticmethod
    def properties(**updates):
        values = {"LoadState": "loaded", "ActiveState": "active", "SubState": "active",
                  "FragmentPath": str(reset.RETENTION_FILE), "DropInPaths": "", "DefaultDependencies": "no",
                  "After": reset.UNIT, "Wants": "", "Requires": "", "Job": "0"}
        values.update(updates)
        return "".join(f"{key}={value}\n" for key, value in values.items()).encode("ascii")

    def test_property_observation_rejects_truncation_unknown_duplicate_and_oversized_fields(self):
        for payload in (b"A=one\n", b"A=one\nB", b"A=one\nB=two\nC=extra\n",
                        b"A=one\nA=again\nB=two\n", b"A=\xff\nB=two\n", b"x" * (8192 + 1)):
            with self.subTest(payload=payload[:50]), self.assertRaises(reset.ResetError):
                reset.parse_properties(payload, ("A", "B"))

    def test_inactive_modified_or_dependency_expanded_target_is_refused(self):
        for key, replacement in (("LoadState", "not-found"), ("ActiveState", "inactive"),
                                 ("SubState", "dead"), ("Wants", reset.UNIT), ("Requires", reset.UNIT),
                                 ("After", reset.UNIT + " other.service"), ("After", ""),
                                 ("DropInPaths", "/untrusted/override.conf"), ("DefaultDependencies", "yes"),
                                 ("FragmentPath", "/untrusted/retain.target"), ("Job", "44")):
            store = Mock()
            store.command.return_value = (self.properties(**{key: replacement}), b"")
            with self.subTest(property=key, value=replacement), self.assertRaisesRegex(reset.ResetError, "retention target"):
                reset.retention_snapshot(store)
            store.command.assert_called_once()
            role, arguments = store.command.call_args.args
            self.assertEqual(role, "systemctl")
            self.assertEqual(arguments[-1], reset.RETENTION_UNIT)

    def test_target_property_truncation_unknown_and_duplicate_are_refused(self):
        full = self.properties()
        for payload in (full.rsplit(b"Job=", 1)[0], full + b"Unexpected=yes\n", full + b"After=other.service\n"):
            store = Mock()
            store.command.return_value = (payload, b"")
            with self.subTest(payload=payload[-60:]), self.assertRaises(reset.ResetError):
                reset.retention_snapshot(store)

    def test_failed_retention_guard_precedes_service_observation(self):
        store = Mock(platform_checked=True)
        store.command.return_value = (self.properties(ActiveState="inactive"), b"")
        with self.assertRaisesRegex(reset.ResetError, "retention target"):
            reset.manager_snapshot(store)
        store.command.assert_called_once()
        self.assertEqual(store.command.call_args.args[1][-1], reset.RETENTION_UNIT)

    def test_start_rate_limit_drift_refuses_before_service_authority(self):
        for key,replacement in (("StartLimitIntervalUSec","0"),("StartLimitIntervalUSec","1min"),
                                ("StartLimitBurst","0"),("StartLimitBurst","64"),
                                ("StartLimitAction","reboot"),("StartLimitAction","")):
            values = dict(reset.UNIT_FIXED)
            values.update({name:"" for name in reset.UNIT_OBSERVED})
            values.update(LoadState="loaded",**{key:replacement})
            raw = "".join(f"{name}={value}\n" for name,value in values.items()).encode()
            store = Mock(platform_checked=True)
            store.command.return_value = (raw,b"")
            with self.subTest(property=key,value=replacement), \
                 patch.object(reset,"retention_snapshot"), \
                 self.assertRaisesRegex(reset.ResetError,"effective service settings"):
                reset.manager_snapshot(store)
            store.command.assert_called_once()

    def test_profile_pins_supported_finite_default_start_window(self):
        profile = reset.profile_document()
        self.assertEqual(profile["startLimitIntervalSeconds"],10)
        self.assertEqual(profile["startLimitBurst"],5)
        self.assertEqual(profile["startLimitAction"],"none")
        self.assertEqual(reset.UNIT_FIXED["StartLimitIntervalUSec"],"10s")
        self.assertEqual(reset.UNIT_FIXED["StartLimitBurst"],"5")
        self.assertEqual(reset.UNIT_FIXED["StartLimitAction"],"none")
        self.assertEqual((ROOT / "scripts/oracle-ext4-reset-profile.json").read_bytes(),reset.canonical(profile))


class FormatterAttemptProtocolTests(unittest.TestCase):
    @staticmethod
    def value():
        return {"schemaVersion": 1, "intentId": INTENT, "launchAttempts": 1,
                "invocationId": "b" * 32, "argvSha256": "c" * 64, "previousHash": "0" * 64}

    def test_attempt_count_is_a_conservative_record_with_finite_endpoints(self):
        for count in (1, 64):
            value = self.value()
            value["launchAttempts"] = count
            parsed = reset.parse_format_attempt(untrusted_payload(value))
            self.assertEqual(parsed["launchAttempts"], count)
            self.assertNotIn("success", parsed)
            self.assertNotIn("executions", parsed)

    def test_attempt_boolean_overflow_unknown_and_checksum_corruption_refuse(self):
        for field, replacement in (("schemaVersion", True), ("launchAttempts", True),
                                   ("launchAttempts", 0), ("launchAttempts", 65),
                                   ("launchAttempts", 1 << 64), ("invocationId", "unknown"),
                                   ("untrustedAuthority", "/arbitrary/path")):
            value = self.value()
            value[field] = replacement
            with self.subTest(field=field, value=replacement), self.assertRaises(reset.ResetError):
                reset.parse_format_attempt(untrusted_payload(value))
        value = reset.parse_format_attempt(untrusted_payload(self.value()))
        value["selfHash"] = "f" * 64
        with self.assertRaisesRegex(reset.ResetError, "checksum"):
            reset.parse_format_attempt(reset.canonical(value))

    def test_attempt_parser_rejects_noncanonical_or_oversized_input(self):
        payload = untrusted_payload(self.value())
        for invalid in (payload + b"\n", b" " * 16385, b'{"schemaVersion":1,"schemaVersion":1}'):
            with self.subTest(length=len(invalid)), self.assertRaises(reset.ResetError):
                reset.parse_format_attempt(invalid)


class MetadataBudgetRefusalTests(unittest.TestCase):
    def test_unknown_control_member_refuses_before_open_or_traversal(self):
        store = Mock(private=-1, qualification=False, profile={"metadataBytes": 64})
        with patch.object(reset, "_entries", return_value=["alien"]), \
             self.assertRaisesRegex(reset.ResetError, "unknown member"):
            reset.verify_metadata_budget(store, synthetic_record())
        store.open_file.assert_not_called()
        store.open_dir.assert_not_called()

    def test_control_file_byte_cap_refuses_and_closes_owned_descriptor(self):
        store = Mock(private=-1, qualification=False, profile={"metadataBytes": 64})
        store.open_file.return_value = 101
        identity = synthetic_identity(99, kind="file", mode=0o600)
        identity["size"] = 65
        with patch.object(reset, "_entries", return_value=["lock"]), \
             patch.object(reset, "fd_identity", return_value=identity), \
             self.assertRaisesRegex(reset.ResetError, "metadata byte limit"):
            reset.verify_metadata_budget(store, synthetic_record())
        store.drop.assert_called_once_with(101)
        store.open_dir.assert_not_called()


class UtilityTransportTests(unittest.TestCase):
    def test_expired_deadline_refuses_before_subprocess_creation(self):
        with patch.object(reset.subprocess, "Popen") as child, self.assertRaises(reset.ResetError):
            reset.run_process([sys.executable, "-V"], timeout=0)
        child.assert_not_called()

    def test_unprivileged_process_returns_bounded_distinct_streams(self):
        result = reset.run_process([sys.executable, "-I", "-S", "-B", "-c",
                                    "import sys;sys.stdout.write('out');sys.stderr.write('err')"], timeout=3)
        self.assertEqual(result, (b"out", b"err"))

    def test_output_flood_is_stopped_during_read(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream), self.assertRaisesRegex(reset.ResetError, "output.*bound"):
                reset.run_process([sys.executable, "-I", "-S", "-B", "-c",
                                   f"import sys,time;sys.{stream}.write('x'*8192);sys.{stream}.flush();time.sleep(10)"],
                                  timeout=3, maximum_output=1024)

    def test_actual_trace_pipe_accepts_exact_bound_and_remains_separate_from_stdio(self):
        pipe = os.pipe2(os.O_CLOEXEC)
        trace = bytearray()
        program = "import os,sys;os.write(int(sys.argv[1]),b't'*128);sys.stdout.write('out');sys.stderr.write('err')"
        try:
            result = reset.run_process([sys.executable, "-I", "-S", "-B", "-c", program, str(pipe[1])],
                                       pass_fds=(pipe[1],), capture_pipe=pipe, capture_sink=trace,
                                       maximum_capture=128, timeout=3)
            self.assertEqual(result, (b"out", b"err"))
            self.assertEqual(trace, b"t" * 128)
            for descriptor in pipe:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        finally:
            for descriptor in pipe:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_actual_trace_pipe_flood_refuses_after_one_over_bound_without_truncation_success(self):
        pipe = os.pipe2(os.O_CLOEXEC)
        trace = bytearray()
        program = "import os,sys,time;os.write(int(sys.argv[1]),b't'*4096);time.sleep(10)"
        try:
            with self.assertRaisesRegex(reset.ResetError, "output.*bound"):
                reset.run_process([sys.executable, "-I", "-S", "-B", "-c", program, str(pipe[1])],
                                  pass_fds=(pipe[1],), capture_pipe=pipe, capture_sink=trace,
                                  maximum_capture=128, timeout=3)
            self.assertEqual(len(trace), 129)
            for descriptor in pipe:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        finally:
            for descriptor in pipe:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_real_timeout_terminates_and_reaps_leader(self):
        started = time.monotonic()
        with self.assertRaisesRegex(reset.ResetError, "deadline"):
            reset.run_process([sys.executable, "-I", "-S", "-B", "-c", "import time;time.sleep(10)"], timeout=0.05)
        self.assertLess(time.monotonic() - started, 2)

    def test_exited_leader_cannot_leave_owned_descendant_on_success_or_failure(self):
        (ROOT / "build").mkdir(exist_ok=True)
        program = """import os,sys,time
if os.fork() == 0:
    for fd in (0, 1, 2):
        os.close(fd)
    time.sleep(0.5)
    with open(sys.argv[1], 'w') as stream:
        stream.write('owned descendant survived')
    os._exit(0)
os._exit(int(sys.argv[2]))
"""
        with tempfile.TemporaryDirectory(prefix="ext4-reset-transport-", dir=ROOT / "build") as directory:
            for code in (0, 7):
                marker = Path(directory) / f"child-{code}"
                argv = [sys.executable, "-I", "-S", "-B", "-c", program, str(marker), str(code)]
                with self.subTest(code=code):
                    if code:
                        with self.assertRaisesRegex(reset.ResetError, "exit 7"):
                            reset.run_process(argv, timeout=3)
                    else:
                        self.assertEqual(reset.run_process(argv, timeout=3), (b"", b""))
                    time.sleep(0.6)
                    self.assertFalse(marker.exists(), "owned descendant survived utility completion")


if __name__ == "__main__":
    unittest.main(verbosity=2)

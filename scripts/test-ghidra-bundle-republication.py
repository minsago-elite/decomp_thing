#!/usr/bin/env python3
"""Mocked harness controls only: no JVM, Gradle, compiler, native input or Ghidra.

Every temporary fixture is repository-owned. A passing suite is NOT T3/T4 evidence.
"""

import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("republication", ROOT / "scripts/qualify-ghidra-bundle-republication.py")
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


def process(pid=101, parent=1, ticks=1000, state="S"):
    return {"pid": pid, "ppid": parent, "start_ticks": ticks, "state": state}


def proc_text(entry):
    fields = [entry["state"], str(entry["ppid"])] + ["0"] * 17 + [str(entry["start_ticks"])] + ["0"] * 10
    return f'{entry["pid"]} (java with ) tricky name) ' + " ".join(fields)


def marker_set():
    return [{"event": "ready", "ns": 10, "selection": {
        "build_sha256": "source", "index": 2, "count": 3,
        "actions": [{"index": 0}, {"index": 1}, {"index": 2, "implementation": "Build_gradle$fixture",
                                                "class_sha256": "a" * 64}], "publisher_candidates": [2]}},
        {"event": "begin", "ns": 30}, {"event": "end", "ns": 40, "success": True}]


class Fixture(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="mock-republication-", dir=ROOT / "build")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        # Any accidental runtime invocation fails this suite, including execute().
        self.spawn = patch.object(H.subprocess, "Popen", side_effect=AssertionError("runtime execution forbidden in mocked controls"))
        self.spawn.start()
        self.addCleanup(self.spawn.stop)

    def tree(self, name):
        root = self.root / name
        (root / "empty").mkdir(parents=True)
        (root / "bundle.sha256").write_bytes(b"manifest fixture\n")
        for arch in ("win32", "win64"):
            (root / arch).mkdir()
            (root / arch / "mfc140u.exports").write_bytes(b"exports fixture\n")
        (root / "native").write_bytes(b"inert, never executed")
        (root / "native").chmod(0o755)
        return root


class InventoryControls(Fixture):
    def test_complete_inventory_and_same_bundle_retains_every_inode(self):
        staged, installed = self.tree("staged"), self.tree("installed")
        first = {"staged": H.inventory(staged), "installed": H.inventory(installed)}
        second = {"staged": H.inventory(staged), "installed": H.inventory(installed)}
        H.verify_snapshot(first, second)
        self.assertEqual("D", first["installed"]["entries"]["empty"]["type"])
        self.assertEqual(0o755, first["installed"]["entries"]["native"]["mode"])
        self.assertEqual(3, len([n for n in first["installed"]["entries"] if n.endswith("mfc140u.exports") or n == "bundle.sha256"]))

    def test_replacement_even_with_identical_bytes_and_mode_refused(self):
        staged, installed = self.tree("staged"), self.tree("installed")
        before = {"staged": H.inventory(staged), "installed": H.inventory(installed)}
        replacement = installed / "replacement"
        replacement.write_bytes((installed / "native").read_bytes())
        replacement.chmod(0o755)
        replacement.replace(installed / "native")
        with self.assertRaisesRegex(H.Refusal, "inode"):
            H.verify_snapshot(before, {"staged": H.inventory(staged), "installed": H.inventory(installed)})

    def test_missing_empty_directory_mode_and_content_changes_refused(self):
        staged, installed = self.tree("staged"), self.tree("installed")
        original = {"staged": H.inventory(staged), "installed": H.inventory(installed)}
        for change in ("directory", "mode", "bytes", "extra"):
            with self.subTest(change=change):
                current = copy.deepcopy(original)
                entries = current["installed"]["entries"]
                if change == "directory":
                    del entries["empty"]
                elif change == "mode":
                    entries["native"]["mode"] = 0o644
                elif change == "extra":
                    entries["extra"] = entries["empty"]
                else:
                    entries["bundle.sha256"]["sha256"] = "changed"
                with self.assertRaises(H.Refusal):
                    H.verify_snapshot(original, current)

    def test_symlink_and_fifo_refused_without_opening_fifo(self):
        root = self.tree("linked")
        (root / "link").symlink_to(root / "native")
        with self.assertRaises(H.Refusal):
            H.inventory(root)
        (root / "link").unlink()
        os.mkfifo(root / "fifo")
        with self.assertRaises(H.Refusal):
            H.inventory(root)

    def test_inventory_limits_and_file_mutation_refused(self):
        root = self.tree("bounded")
        with patch.object(H, "MAX_ENTRIES", 2), self.assertRaises(H.Refusal):
            H.inventory(root)
        with patch.object(H, "MAX_FILE", 1), self.assertRaises(H.Refusal):
            H.stable_file(root / "native")
        read = os.read
        changed = False

        def mutate(fd, size):
            nonlocal changed
            data = read(fd, size)
            if not changed:
                changed = True
                (root / "native").write_bytes(b"changed size")
            return data

        with patch.object(H.os, "read", side_effect=mutate), self.assertRaises(H.Refusal):
            H.stable_file(root / "native")


class SourcePinControls(Fixture):
    COMMIT = "a" * 40

    def setUp(self):
        super().setUp()
        (self.root / "scripts").mkdir()
        for name in H.SOURCE_DRIVERS:
            (self.root / name).write_bytes(b"inert driver")
        self.records = self.record("160000", "module")
        self.calls = []
        self.head = (self.COMMIT + "\n").encode()
        self.status = b""
        self.subindex = b""
        self.toplevel = None

    def record(self, mode, name, commit=None, stage="0"):
        return f"{mode} {commit or self.COMMIT} {stage}\t{name}\0".encode()

    def command(self, label, args, timeout):
        self.calls.append((label, args, timeout))
        self.assertEqual(60, timeout)
        self.assertEqual(["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                          "-c", "core.untrackedCache=false", "-C"], args[:7])
        root, operation = Path(args[7]), args[8:]
        if operation == ["ls-files", "--stage", "-z"]:
            return self.records if root == self.root else self.subindex
        if operation == ["rev-parse", "--show-toplevel"]:
            return os.fsencode(self.toplevel or root) + b"\n"
        if operation == ["rev-parse", "--verify", "HEAD"]:
            return self.head
        if operation == ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"]:
            return self.status
        self.fail(f"unexpected Git operation: {operation}")

    def snapshot(self, phase="before"):
        return H.SourcePins(self.root, self.command, phase).snapshot()

    def initialized(self):
        path = self.root / "module"
        path.mkdir(exist_ok=True)
        (path / ".git").mkdir()
        return path

    def test_missing_and_empty_gitlinks_explicitly_attested_without_git_discovery(self):
        for state in ("absent-uninitialized", "empty-uninitialized"):
            with self.subTest(state=state):
                if state.startswith("empty"):
                    (self.root / "module").mkdir()
                self.calls.clear()
                snapshot = self.snapshot()
                pin = snapshot["tracked"]["module"]
                self.assertEqual(state, pin["state"])
                self.assertEqual(self.COMMIT, pin["index_commit"])
                self.assertEqual("160000", pin["index"]["mode"])
                self.assertEqual("none", pin["content_hash_scope"])
                self.assertEqual(2, len(self.calls))
                self.assertEqual(set(H.SOURCE_DRIVERS), set(snapshot["untracked_drivers"]))
                H.verify_source_pins(snapshot, self.snapshot("after"))

    def test_initialized_matching_clean_checkout_is_accepted_with_honest_evidence(self):
        path = self.initialized()
        self.subindex = self.record("100644", "inert-source")
        before = self.snapshot()
        pin = before["tracked"]["module"]
        self.assertEqual("initialized", pin["state"])
        self.assertEqual(str(path), pin["repository_root"])
        self.assertEqual(self.COMMIT, pin["head"])
        self.assertEqual("none", pin["content_hash_scope"])
        self.assertEqual(1, pin["index_entries"])
        self.assertEqual(H.digest(H.encode(H.source_index(self.subindex))), pin["index_sha256"])
        self.assertEqual("", pin["status_porcelain_hex"])
        self.assertNotIn("sha256", pin)
        H.verify_source_pins(before, self.snapshot("after"))
        self.assertEqual(len(self.calls), len({label for label, _, _ in self.calls}))

    def test_wrong_commit_dirty_untracked_and_dirty_submodule_are_refused(self):
        self.initialized()
        for head, status in ((b"b" * 40 + b"\n", b""), (self.head, b" M source\0"),
                             (self.head, b"M  source\0"), (self.head, b"?? untracked\0"),
                             (self.head, b" m nested\0"), (self.head, b" ? nested\0")):
            with self.subTest(head=head, status=status):
                self.head, self.status = head, status
                with self.assertRaises(H.Refusal):
                    self.snapshot()

    def test_nonempty_directory_cannot_mistake_parent_repository_for_own_root(self):
        path = self.root / "module"
        path.mkdir()
        (path / "inert").write_bytes(b"not a Git checkout")
        self.toplevel = self.root
        with self.assertRaisesRegex(H.Refusal, "own repository root"):
            self.snapshot()

    def test_initialized_gitfile_marker_supported_but_linked_or_fifo_marker_refused(self):
        path = self.initialized()
        marker = path / ".git"
        marker.rmdir()
        marker.write_bytes(b"gitdir: ../inert-git-metadata\n")
        snapshot = self.snapshot()
        self.assertEqual("F", snapshot["tracked"]["module"]["repository_marker"]["type"])
        H.verify_source_pins(snapshot, self.snapshot("after"))
        marker.unlink()
        marker.symlink_to("../scripts")
        with self.assertRaisesRegex(H.Refusal, "repository marker"):
            self.snapshot()
        marker.unlink()
        os.mkfifo(marker)
        with self.assertRaisesRegex(H.Refusal, "repository marker"):
            self.snapshot()

    def test_initialized_checkout_is_revalidated_for_final_head_index_and_status(self):
        self.initialized()
        before = self.snapshot()
        for change in ("head", "index", "dirty", "untracked", "conflict"):
            self.head = (("b" * 40 if change == "head" else self.COMMIT) + "\n").encode()
            self.subindex = self.record("100644", "changed") if change == "index" else b""
            if change == "conflict":
                self.subindex = self.record("100644", "source", stage="1")
            self.status = {"dirty": b" M source\0", "untracked": b"?? extra\0"}.get(change, b"")
            with self.subTest(change=change), self.assertRaises(H.Refusal):
                H.verify_source_pins(before, self.snapshot("after"))

    def test_nested_gitlink_state_is_pinned_and_rechecked(self):
        path = self.initialized()
        self.subindex = self.record("160000", "nested")
        before = self.snapshot()
        self.assertEqual("absent-uninitialized", before["tracked"]["module"]["gitlinks"]["nested"]["state"])
        (path / "nested").mkdir()
        with self.assertRaises(H.Refusal):
            H.verify_source_pins(before, self.snapshot("after"))

    def test_regular_files_keep_hash_mode_and_full_stable_identity(self):
        self.records = self.record("100644", "source") + self.record("100755", "executable")
        for name in ("source", "executable"):
            (self.root / name).write_bytes(b"inert bytes")
        (self.root / "executable").chmod(0o755)
        before = self.snapshot()
        for name in ("source", "executable"):
            pin = before["tracked"][name]
            for key, value in H.stable_file(self.root / name).items():
                self.assertEqual(value, pin[key])
            self.assertEqual(list(H.file_identity((self.root / name).lstat())), pin["identity"])
        (self.root / "source").write_bytes(b"other bytes")
        with self.assertRaises(H.Refusal):
            H.verify_source_pins(before, self.snapshot("after"))

    def test_tracked_drivers_preserve_index_metadata_and_untracked_driver_changes_fail(self):
        self.records = self.record("100755", H.SOURCE_DRIVERS[0])
        before = self.snapshot()
        self.assertEqual("100755", before["tracked"][H.SOURCE_DRIVERS[0]]["index"]["mode"])
        self.assertEqual({H.SOURCE_DRIVERS[1]}, set(before["untracked_drivers"]))
        (self.root / H.SOURCE_DRIVERS[1]).write_bytes(b"changed driver")
        with self.assertRaises(H.Refusal):
            H.verify_source_pins(before, self.snapshot("after"))

    def test_symlink_mode_target_and_identity_are_pinned_without_following_target(self):
        self.records = self.record("120000", "link")
        path = self.root / "link"
        path.symlink_to("missing-target")
        before = self.snapshot()
        pin = before["tracked"]["link"]
        self.assertEqual("L", pin["type"])
        self.assertEqual("missing-target", pin["target"])
        self.assertEqual("120000", pin["index"]["mode"])
        self.assertEqual(list(H.file_identity(path.lstat())), pin["identity"])
        H.verify_source_pins(before, self.snapshot("after"))
        path.unlink()
        path.symlink_to("other-target")
        with self.assertRaises(H.Refusal):
            H.verify_source_pins(before, self.snapshot("after"))

    def test_symlink_mutation_during_read_is_refused(self):
        self.records = self.record("120000", "link")
        path = self.root / "link"
        path.symlink_to("before")
        original = H.os.readlink

        def change(value, *args, **kwargs):
            target = original(value, *args, **kwargs)
            if Path(value) == path:
                path.unlink()
                path.symlink_to("after")
            return target

        with patch.object(H.os, "readlink", side_effect=change), self.assertRaises(H.Refusal):
            self.snapshot()

    def test_index_modes_refuse_wrong_filesystem_type_including_symlink_and_fifo(self):
        path = self.root / "item"
        for kind in ("file", "directory", "symlink", "fifo"):
            if kind == "file":
                path.write_bytes(b"inert")
            elif kind == "directory":
                path.mkdir()
            elif kind == "symlink":
                path.symlink_to("scripts")
            else:
                os.mkfifo(path)
            for mode in ("100644", "100755", "120000", "160000"):
                if ((kind == "file" and mode in ("100644", "100755"))
                        or (kind == "directory" and mode == "160000")
                        or (kind == "symlink" and mode == "120000")):
                    continue
                self.records = self.record(mode, "item")
                with self.subTest(kind=kind, mode=mode), self.assertRaises(H.Refusal):
                    self.snapshot()
            path.rmdir() if kind == "directory" else path.unlink()

    def test_linked_or_special_ancestors_fail_even_for_missing_gitlink(self):
        alias = self.root / "alias"
        for kind in ("symlink", "fifo", "file"):
            if kind == "symlink":
                alias.symlink_to(self.root / "scripts", target_is_directory=True)
            elif kind == "fifo":
                os.mkfifo(alias)
            else:
                alias.write_bytes(b"inert")
            for mode in ("100644", "120000", "160000"):
                self.records = self.record(mode, "alias/missing")
                with self.subTest(kind=kind, mode=mode), self.assertRaises(H.Refusal):
                    self.snapshot()
            alias.unlink()

    def test_malformed_index_conflicts_duplicates_unsafe_paths_and_unknown_modes_fail(self):
        valid = self.record("100644", "source")
        invalid = [valid[:-1], b"\0", valid + b"\0", valid + valid,
                   valid.replace(b"100644", b"100664"), valid.replace(b"100644", b"040000"),
                   valid.replace(b" 0\t", b" 1\t"), valid.replace(b" 0\t", b" 2\t"),
                   valid + valid.replace(b" 0\t", b" 3\t"), valid.replace(b" 0\t", b" 00\t"),
                   valid.replace(b"a" * 40, b"0" * 40), valid.replace(b"a" * 40, b"g" * 40),
                   valid.replace(b"a" * 40, b"a" * 39), valid.replace(b"\t", b" "),
                   valid + self.record("100644", "source/child")]
        invalid += [self.record("100644", name) for name in
                    ("", "/absolute", "../escape", "a/../escape", "a//b", "a/./b", "a/",
                     ".git/config", "a/.GIT/config", "a\\b", "a\nb", "a\tb")]
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(H.Refusal):
                H.source_index(data)
        self.assertEqual({}, H.source_index(b""))
        self.assertEqual("b" * 64, H.source_index(self.record("100644", "sha256", "b" * 64))["sha256"]["object"])

    def test_source_count_bytes_and_index_bounds_are_enforced(self):
        with patch.object(H, "MAX_ENTRIES", 0), self.assertRaises(H.Refusal):
            self.snapshot()
        with patch.object(H, "MAX_LOG", 1), self.assertRaises(H.Refusal):
            self.snapshot()
        with patch.object(H, "MAX_TREE", 1), self.assertRaises(H.Refusal):
            self.snapshot()
        collector = H.SourcePins(self.root, self.command, "bound")
        collector.gitlinks = 128
        with self.assertRaises(H.Refusal):
            collector.snapshot()
        with self.assertRaises(H.Refusal):
            collector.gitlink(self.root / "module", None, self.COMMIT, 16)

    def test_added_removed_index_swapped_and_type_changed_sources_fail_final_verification(self):
        (self.root / "source").write_bytes(b"inert")
        (self.root / "added").write_bytes(b"inert")
        original = self.record("100644", "source")
        self.records = original
        before = self.snapshot()
        for changed in (b"", original + self.record("100644", "added"),
                        self.record("100644", "source", "b" * 40), self.record("100755", "source")):
            self.records = changed
            with self.subTest(index=changed), self.assertRaises(H.Refusal):
                H.verify_source_pins(before, self.snapshot("after"))
        self.records = original
        (self.root / "source").unlink()
        (self.root / "source").symlink_to("added")
        with self.assertRaises(H.Refusal):
            H.verify_source_pins(before, self.snapshot("after"))

    def test_every_gitlink_initialization_transition_fails_final_verification(self):
        missing = self.snapshot()
        path = self.root / "module"
        path.mkdir()
        empty = self.snapshot()
        self.initialized()
        initialized = self.snapshot()
        for before, after in ((missing, empty), (empty, missing), (empty, initialized),
                              (initialized, empty), (missing, initialized), (initialized, missing)):
            with self.subTest(before=before["tracked"]["module"]["state"],
                              after=after["tracked"]["module"]["state"]), self.assertRaises(H.Refusal):
                H.verify_source_pins(before, after)

    def test_index_or_submodule_state_change_during_snapshot_is_refused(self):
        original = self.command
        for change in ("index", "head", "subindex", "directory", "status"):
            if change == "head":
                self.initialized()
            self.head = (self.COMMIT + "\n").encode()
            self.subindex = b""
            self.status = b""
            head_reads = index_reads = 0

            def command(label, args, timeout):
                nonlocal head_reads, index_reads
                result = original(label, args, timeout)
                if change == "index" and args[-3:] == ["ls-files", "--stage", "-z"]:
                    index_reads += 1
                    if index_reads == 2:
                        return b""
                if args[-3:] == ["rev-parse", "--verify", "HEAD"]:
                    head_reads += 1
                    if change == "head" and head_reads == 2:
                        return b"b" * 40 + b"\n"
                if "status" in args:
                    if change == "subindex":
                        self.subindex = self.record("100644", "added")
                    if change == "directory":
                        (self.root / "module/new").write_bytes(b"inert")
                    if change == "status":
                        self.status = b"?? new\0"
                return result

            with self.subTest(change=change), patch.object(self, "command", side_effect=command), self.assertRaises(H.Refusal):
                self.snapshot()


class MarkerControls(Fixture):
    def test_order_and_selection_controls(self):
        self.assertEqual((30, 40), H.validate_markers(marker_set(), "source"))
        cases = []
        markers = marker_set(); markers.reverse(); cases.append(markers)
        markers = marker_set(); markers.pop(); cases.append(markers)
        markers = marker_set(); markers[2]["ns"] = 29; cases.append(markers)
        markers = marker_set(); markers[2]["success"] = False; cases.append(markers)
        markers = marker_set(); markers[0]["selection"]["index"] = 1; cases.append(markers)
        markers = marker_set(); markers[0]["selection"]["publisher_candidates"] = [1, 2]; cases.append(markers)
        markers = marker_set(); markers[0]["selection"]["build_sha256"] = "other"; cases.append(markers)
        markers = marker_set(); markers[0]["selection"]["actions"][-1]["class_sha256"] = None; cases.append(markers)
        for markers in cases:
            with self.subTest(markers=markers), self.assertRaises(H.Refusal):
                H.validate_markers(markers, "source")

    def test_worker_spans_entire_publication_bracket(self):
        samples = [{"pid": 2, "start_ticks": 10, "lo_ns": 20, "hi_ns": 21},
                   {"pid": 2, "start_ticks": 10, "lo_ns": 45, "hi_ns": 46}]
        self.assertTrue(H.overlap_proofs(samples, 30, 40)[0]["spans_begin"])
        self.assertFalse(H.overlap_proofs(samples, 10, 40))

    def test_overlap_confined_to_marker_overhead_is_not_execution_evidence(self):
        samples = [{"pid": 2, "start_ticks": 10, "lo_ns": 90, "hi_ns": 91},
                   {"pid": 2, "start_ticks": 10, "lo_ns": 109, "hi_ns": 110}]
        # The actual action could start at 120, after writing the begin marker at 100.
        self.assertFalse(H.overlap_proofs(samples, 100, 140))

    def test_startup_only_single_sample_pid_reuse_and_uncertainty_are_not_overlap(self):
        samples = [{"pid": 2, "start_ticks": 10, "lo_ns": 20, "hi_ns": 21},
                   {"pid": 2, "start_ticks": 10, "lo_ns": 25, "hi_ns": 26}]
        self.assertFalse(H.overlap_proofs(samples, 30, 40))
        self.assertFalse(H.overlap_proofs(samples[:1], 20, 40))
        samples[1].update(start_ticks=11, lo_ns=35, hi_ns=36)
        self.assertFalse(H.overlap_proofs(samples, 30, 40))
        # A single slow /proc read spanning publication is not guaranteed overlap.
        self.assertFalse(H.overlap_proofs([{"pid": 2, "start_ticks": 10, "lo_ns": 1, "hi_ns": 50}], 30, 40))

    def test_source_layout_is_pinned_and_unknown_layout_refused(self):
        source = self.root / "build.gradle.kts"
        source.write_text(H.PUBLISHER_BLOCK)
        init = H.make_init(self.root, self.root / "action", "source")
        self.assertIn("selected.execute(runningTask)", init)
        self.assertIn("publisher_candidates: candidates", init)
        self.assertNotIn("--rerun-tasks", init)
        source.write_text(H.PUBLISHER_BLOCK.replace("doLast", "doFirst"))
        with self.assertRaises(H.Refusal):
            H.make_init(self.root, self.root / "action", "source")


class OwnershipControls(Fixture):
    def test_proc_comm_and_start_ticks_and_reuse(self):
        original = process()
        self.assertEqual(original, H.parse_stat(proc_text(original)))
        self.assertTrue(H.same_live(original, dict(original)))
        for changed in (process(ticks=1001), process(parent=2), process(state="Z"), None):
            self.assertFalse(H.same_live(original, changed))

    def test_exact_java_main_class_not_an_argument_or_substring(self):
        command = b"/jdk/bin/java\0-Duser.home=/repo/home\0-cp\0some-classpath\0" + H.WORKER.encode() + b"\0secret-argument\0"
        self.assertTrue(H.worker_main(command))
        for invalid in (command.replace(b"/jdk/bin/java", b"python"),
                        command.replace(H.WORKER.encode(), H.WORKER.encode() + b"Other"),
                        b"java\0some.OtherMain\0" + H.WORKER.encode(),
                        b"java\0-jar\0" + H.WORKER.encode(),
                        b"java\0-cp\0" + H.WORKER.encode()):
            self.assertFalse(H.worker_main(invalid))

    def proc_fixture(self):
        proc = self.root / "proc"
        for entry, children, main in ((process(101, 1, 100), "102", "app.Main"),
                                      (process(102, 101, 110), "", H.WORKER),
                                      (process(999, 1, 120), "", H.WORKER)):
            folder = proc / str(entry["pid"])
            (folder / "task" / str(entry["pid"])).mkdir(parents=True)
            (folder / "stat").write_text(proc_text(entry))
            (folder / "task" / str(entry["pid"]) / "children").write_text(children)
            (folder / "cmdline").write_bytes(b"java\0-cp\0fixture\0" + main.encode() + b"\0never-retain-secret\0")
        return proc

    def test_only_owned_descendants_observed_never_unrelated_worker(self):
        proc = self.proc_fixture()
        actual_path = Path

        def path(value):
            text = str(value)
            return proc / text.removeprefix("/proc/") if text.startswith("/proc/") else actual_path(value)

        with patch.object(H, "Path", side_effect=path), patch.object(H.os, "pidfd_open", side_effect=lambda pid: pid + 10000), \
                patch.object(H.os, "readlink", return_value="/jdk/bin/java"), patch.object(H.os, "close"):
            tree = H.OwnedTree(101)
            observations = tree.sample(workers=True)
            self.assertEqual([102], [item["pid"] for item in observations])
            self.assertEqual({(101, 100), (102, 110)}, set(tree.known))
            self.assertNotIn("secret", json.dumps(observations))
            self.assertEqual(101, observations[0]["ancestors"][0]["pid"])
            # Reuse the child's PID while an old start identity is retained.
            (proc / "102/stat").write_text(proc_text(process(102, 999, 111)))
            self.assertEqual([], tree.sample(workers=True))
            self.assertEqual([(101, 100)], tree.alive())

    def test_pidfd_is_closed_when_identity_changes_during_acquisition(self):
        tree = H.OwnedTree.__new__(H.OwnedTree)
        tree.known = {}
        with patch.object(H.os, "pidfd_open", return_value=42), \
                patch.object(H, "proc_stat", return_value=process(ticks=2000)), patch.object(H.os, "close") as close:
            tree.add(process())
            close.assert_called_once_with(42)
            self.assertEqual({}, tree.known)

    def test_detached_owned_descendants_remain_cleanup_targets_not_overlap_evidence(self):
        proc = self.proc_fixture()
        actual_path = Path

        def path(value):
            text = str(value)
            return proc / text.removeprefix("/proc/") if text.startswith("/proc/") else actual_path(value)

        with patch.object(H, "Path", side_effect=path), patch.object(H.os, "pidfd_open", side_effect=lambda pid: pid + 10000), \
                patch.object(H.os, "readlink", return_value="/jdk/bin/java"), patch.object(H.os, "close"):
            tree = H.OwnedTree(101)
            self.assertEqual(1, len(tree.sample(workers=True)))
            (proc / "101/stat").write_text(proc_text(process(101, 1, 100, "Z")))
            (proc / "102/stat").write_text(proc_text(process(102, 1, 110)))
            (proc / "102/task/102/children").write_text("103")
            (proc / "103/task/103").mkdir(parents=True)
            (proc / "103/stat").write_text(proc_text(process(103, 102, 130)))
            (proc / "103/task/103/children").write_text("")
            (proc / "103/cmdline").write_bytes(b"java\0" + H.WORKER.encode() + b"\0")
            self.assertEqual([], tree.sample(workers=True))
            self.assertIn((103, 130), tree.known)
            self.assertEqual([(102, 110), (103, 130)], tree.alive())

    def test_cleanup_uses_only_known_pidfds_and_reports_survivors(self):
        tree = H.OwnedTree.__new__(H.OwnedTree)
        tree.known = {(101, 100): 42}
        with patch.object(tree, "alive", return_value=[(101, 100)]), patch.object(tree, "sample", return_value=[]), \
                patch.object(H.time, "monotonic", side_effect=range(100)), \
                patch.object(H.time, "sleep"), patch.object(H.signal, "pidfd_send_signal") as send, \
                patch.object(H.os, "close") as close:
            result = tree.cleanup()
            self.assertFalse(result["complete"])
            self.assertEqual([(101, 100)], result["survivors"])
            self.assertEqual([((42, signal.SIGTERM),), ((42, signal.SIGKILL),)], [call[:1] for call in send.call_args_list])
            close.assert_called_once_with(42)


class OrchestrationControls(Fixture):
    def test_actual_jar_task_distinguishes_rebuild_from_unchanged_or_copy(self):
        skipped = {"did_work": False, "skipped": True, "skip_message": "UP-TO-DATE"}
        self.assertEqual("unchanged", H.jar_classification({"inode": 1}, {"inode": 1}, skipped))
        self.assertEqual("jar-republished", H.jar_classification({"inode": 1}, {"inode": 2}, skipped))
        rebuilt = {"did_work": True, "skipped": False, "skip_message": None}
        self.assertEqual("jar-rebuilt", H.jar_classification({"inode": 1}, {"inode": 1}, rebuilt))
        cached = {"did_work": False, "skipped": True, "skip_message": "FROM-CACHE"}
        self.assertEqual("jar-restored-from-cache", H.jar_classification({}, {}, cached))

    def test_process_output_and_timeout_bounds(self):
        run = H.Run.__new__(H.Run)
        run.selector = Mock()
        run.selector.select.return_value = [(SimpleNamespace(fd=42), None)]
        run.log = Mock()
        run.size = 0
        run.deadline = time.monotonic() - 1
        run.record = {}
        run.process = Mock()
        run.process.poll.return_value = None
        with patch.object(H.os, "read", return_value=b"12345"), patch.object(H, "MAX_LOG", 4):
            with self.assertRaisesRegex(H.Refusal, "output exceeded"):
                run.pump()
            run.log.write.assert_called_once_with(b"1234")
            with self.assertRaisesRegex(H.Refusal, "output exceeded"):
                run.pump()
            self.assertEqual(b"", run.log.write.call_args.args[0])
        run.selector.select.return_value = []
        with self.assertRaisesRegex(H.Refusal, "deadline"):
            run.pump()

    def test_exited_root_with_open_pipe_or_live_descendant_keeps_deadline(self):
        run = H.Run.__new__(H.Run)
        run.selector = Mock()
        run.selector.select.return_value = []
        run.selector.get_map.return_value = {42: "open inherited stdout"}
        run.log = Mock()
        run.deadline = time.monotonic() - 1
        run.record = {}
        run.process = Mock()
        run.process.poll.return_value = 0
        run.tree = Mock()
        run.tree.alive.return_value = []
        with self.assertRaisesRegex(H.Refusal, "deadline"):
            run.pump()
        run.selector.get_map.return_value = {}
        run.tree.alive.return_value = [(103, 1000)]
        with self.assertRaisesRegex(H.Refusal, "deadline"):
            run.pump()
        run.tree.alive.return_value = []
        self.assertEqual(0, run.pump())

    def test_cancellation_and_unexpected_exception_retain_failure_evidence(self):
        for failure in (KeyboardInterrupt(), RuntimeError("must-not-serialize-sensitive-message")):
            harness = H.Harness(self.root)
            with patch.object(harness, "execute", side_effect=failure):
                self.assertEqual(1, harness.run())
            evidence = (harness.attempt / "evidence.json").read_text()
            self.assertNotIn("sensitive-message", evidence)
            self.assertEqual("FAIL", json.loads(evidence)["status"])

    def test_path_escape_and_symlink_refusal(self):
        with self.assertRaises(H.Refusal):
            H.contained(self.root.parent, self.root)
        (self.root / "alias").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(H.Refusal):
            H.contained(self.root / "alias/new", self.root)

    def test_environment_omits_secrets_home_and_external_bundle_selectors(self):
        java = self.root / "jdk"
        (java / "bin").mkdir(parents=True)
        (java / "bin/java").write_bytes(b"inert")
        (self.root / "build/gradle-user-home").mkdir(parents=True)
        attempt = self.root / "attempt"
        attempt.mkdir()
        with patch.dict(os.environ, {"JAVA_HOME": str(java), "GHIDRA_HOME": "/external", "SECRET_TOKEN": "secret",
                                     "HOME": "/not-owned", "GRADLE_USER_HOME": str(self.root / "build/gradle-user-home")}, clear=True):
            env = H.environment(self.root, attempt)
        for key in ("HOME", "GHIDRA_HOME", "SECRET_TOKEN"):
            self.assertNotIn(key, env)
        self.assertIn("-XX:-UsePerfData", env["JAVA_TOOL_OPTIONS"])
        self.assertEqual(str(attempt / "tmp"), env["TMPDIR"])

    def test_finally_preserves_failure_and_cleanup_evidence_without_runtime(self):
        harness = H.Harness(self.root)
        run = Mock()
        run.label = "mock-owned-process"
        run.close.return_value = {"complete": True, "survivors": []}
        harness.runs = [run]
        with patch.object(harness, "execute", side_effect=H.Refusal("controlled refusal")):
            self.assertEqual(1, harness.run())
        evidence = json.loads((harness.attempt / "evidence.json").read_text())
        self.assertEqual("FAIL", evidence["status"])
        self.assertEqual("controlled refusal", evidence["failure"])
        self.assertTrue(evidence["cleanup"][0]["complete"])
        run.close.assert_called_once()
        second = H.Harness(self.root)
        self.assertNotEqual(harness.attempt, second.attempt)
        second.timeline.close()

    def test_cleanup_failure_overrides_mocked_success(self):
        harness = H.Harness(self.root)
        run = Mock(label="mock-owned-process")
        run.close.return_value = {"complete": False, "survivors": [[101, 100]]}
        harness.runs = [run]

        def pretend_complete():
            harness.evidence["status"] = "PASS"

        with patch.object(harness, "execute", side_effect=pretend_complete):
            self.assertEqual(1, harness.run())
        self.assertEqual("FAIL", json.loads((harness.attempt / "evidence.json").read_text())["status"])

    def test_classloading_failure_cannot_be_waived_by_zero_exit(self):
        harness = H.Harness(self.root)
        self.addCleanup(harness.timeline.close)
        log = self.root / "mock.log"
        log.write_bytes(b"java.util.zip.ZipException: fixture only")
        harness.evidence["cases"].append({"case": "mock", "status": "RUNNING"})
        run = Mock(log_path=log)
        run.process.returncode = 0
        with self.assertRaisesRegex(H.Refusal, "no waiver"):
            harness.finish_case(run, self.root)

    def mocked_execution(self, missed=False, source_change=False):
        """Exercise the actual fixed orchestration with inert process/marker providers."""
        self.tree("ghidra-bridge/build/bundle")
        self.tree("build/install/llm_bin_patch/libexec/ghidra")
        install = self.root / "build/install/llm_bin_patch"
        (install / "lib").mkdir()
        (install / "lib/llm-bin-patch-fixture.jar").write_bytes(b"inert app fixture")
        (install / "bin").mkdir()
        (install / "bin/llm_bin_patch").write_bytes(b"inert cli fixture")
        (self.root / "scripts").mkdir()
        for script in ("qualify-ghidra-bundle-republication.py", "test-ghidra-bundle-republication.py"):
            (self.root / "scripts" / script).write_bytes(b"inert driver pin fixture")
        (self.root / "src/test/fixtures/c").mkdir(parents=True)
        (self.root / "src/test/fixtures/c/hello_world.c").write_bytes(b"inert authored source fixture")
        (self.root / "build.gradle.kts").write_text(H.PUBLISHER_BLOCK)
        (self.root / "build/gradle-user-home").mkdir()
        (self.root / "jdk/bin").mkdir(parents=True)
        (self.root / "jdk/bin/java").write_bytes(b"inert java fixture")
        (self.root / "jdk/release").write_bytes(b"inert release fixture")
        cc = self.root / "cc"
        cc.write_bytes(b"inert cc fixture")
        harness = H.Harness(self.root)
        self.addCleanup(harness.timeline.close)
        started = []

        def command(label, args, timeout=60):
            if label == "source-head":
                return b"a" * 40
            if "ls-files" in args:
                self.assertEqual(["ls-files", "--stage", "-z"], args[-3:])
                if source_change and label.startswith("source-after-"):
                    return b"100644 " + b"c" * 40 + b" 0\tbuild.gradle.kts\0"
                return b"100644 " + b"a" * 40 + b" 0\tbuild.gradle.kts\0" + \
                    b"100644 " + b"b" * 40 + b" 0\tsrc/test/fixtures/c/hello_world.c\0"
            if label == "compile-fixture":
                (harness.attempt / "hello_world").write_bytes(b"inert, never executed")
            return b"mocked version output"

        def start(label, command, timeout):
            run = SimpleNamespace(label=label, started=time.monotonic_ns(), steps=0,
                                  process=SimpleNamespace(returncode=None), selector=Mock(),
                                  log_path=harness.attempt / (label + ".log"))
            run.log_path.write_bytes(b"inert mocked output")
            run.process.poll = lambda: run.process.returncode
            run.selector.get_map.return_value = {}
            run.pending = lambda: run.process.returncode is None or bool(run.selector.get_map())
            started.append((run, command))
            if label.startswith("install-"):
                run.action = Path(command[command.index("--init-script") + 1]).parent
                ready = marker_set()[0]
                ready["ns"] = time.monotonic_ns()
                ready["selection"]["build_sha256"] = H.stable_file(self.root / "build.gradle.kts")["sha256"]
                H.write_json(run.action / "ready.json", ready)
                H.write_json(run.action / "jar-task.json", {"event": "jar-task", "path": ":jar", "success": True,
                                                           "did_work": False, "skipped": True, "skip_message": "UP-TO-DATE"})
            else:
                output = Path(command[command.index("--output") + 1])
                output.mkdir()
                (output / "source_tree_manifest.json").write_bytes(b"{}")
            return run

        def tick(active, cli=None):
            for run in active:
                run.steps += 1
                if run.label.startswith("install-") and (run.action / "release").exists():
                    if not (run.action / "begin.json").exists():
                        H.write_json(run.action / "begin.json", {"event": "begin", "ns": time.monotonic_ns()})
                    if run.steps >= 3:
                        H.write_json(run.action / "end.json", {"event": "end", "ns": time.monotonic_ns(), "success": True})
                        run.process.returncode = 0
                elif not run.label.startswith("install-") and run.steps >= 3:
                    run.process.returncode = 0
            if cli:
                now = time.monotonic_ns()
                sample = {"case": cli.label, "pid": 102, "start_ticks": 110, "lo_ns": now, "hi_ns": now + 1}
                harness.samples.append(sample)
                return [sample]
            return []

        with patch.dict(os.environ, {"JAVA_HOME": str(self.root / "jdk"),
                                     "GRADLE_USER_HOME": str(self.root / "build/gradle-user-home")}, clear=True), \
                patch.object(H.shutil, "which", return_value=str(cc)), \
                patch.object(harness, "command", side_effect=command), \
                patch.object(harness, "start", side_effect=start), patch.object(harness, "tick", side_effect=tick):
            if missed:
                outcomes = [[{"spans_begin": True}], []] if missed == "second" else [[], []]
                with patch.object(H, "overlap_proofs", side_effect=outcomes), self.assertRaisesRegex(H.Refusal, "two publications"):
                    harness.execute()
            elif source_change:
                with self.assertRaisesRegex(H.Refusal, "source index or pins changed"):
                    harness.execute()
                self.assertEqual("FAIL", harness.evidence["status"])
                self.assertNotEqual(harness.evidence["source_pins_sha256"], harness.evidence["final_source_pins_sha256"])
                self.assertTrue((harness.attempt / "source-pins-final.json").exists())
            else:
                harness.execute()
                self.assertTrue(harness.evidence["all_installed_bundle_regular_file_inodes_retained"])
                self.assertEqual("unchanged", harness.evidence["application_jar_classification"])
                self.assertEqual(5, len(harness.evidence["snapshots"]))
        commands = [args for run, args in started if run.label.startswith("install-")]
        self.assertEqual(2, len(commands))
        for args in commands:
            self.assertEqual(["installDist", "--rerun"], args[-2:])
            self.assertNotIn("--rerun-tasks", args)
        self.assertEqual(["baseline", "publication-1", "publication-2"], [c["case"] for c in harness.evidence["cases"]])
        self.assertTrue(all(c["status"] == "PASS" for c in harness.evidence["cases"]))
        # No evidence.json claiming successful qualification is emitted by this simulation.
        self.assertFalse((harness.attempt / "evidence.json").exists())

    def test_mocked_fixed_three_cases_and_two_original_action_intervals(self):
        self.mocked_execution()

    def test_mocked_successful_cases_without_overlap_fail_without_retry(self):
        self.mocked_execution(missed=True)

    def test_one_proven_and_one_missed_publication_cannot_pass(self):
        self.mocked_execution(missed="second")

    def test_completed_cases_and_overlaps_cannot_pass_changed_authoritative_source_index(self):
        self.mocked_execution(source_change=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

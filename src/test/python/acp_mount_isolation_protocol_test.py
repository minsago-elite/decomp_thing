#!/usr/bin/env python3
"""Authored protocol/verifier tests by default; --run is a separate, explicit native driver.
No imports, pure tests or discovery execute a JVM, unshare, mount or Gradle.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[3]
PREFIX = "ACP_FIXTURE "
SCENARIOS = ("external", "sensitivity", "hostile", "eof", "death", "malformed", "oversize",
             "order", "cancel-pre", "cancel-descriptor", "cancel-restore", "cancel-close", "restore-failure", "cleanup-failure")
SOURCES = ("src/test/c/acp_mount_isolation_fixture.c",
           "src/test/kotlin/decompengine/acp/AcpMountIsolationFixtureMain.kt",
           "src/test/python/acp_mount_isolation_protocol_test.py", "scripts/test-acp-mount-isolation.sh",
           "src/main/kotlin/decompengine/acp/LinuxBubblewrapBoundary.kt",
           "src/main/kotlin/decompengine/acp/LinuxFilesystemSyscalls.kt",
           "src/test/kotlin/decompengine/acp/LinuxBubblewrapBoundaryTest.kt", "build.gradle.kts")
NESTED_MARKERS = (
    "nestedSameAndCrossFilesystemLeasesDenyBothAdmissionOrders=true persistentCrossMountRefreshPassed=true",
    "nestedControlParentsRefused=5 relocatedLiveInnerPreserved=true exactRemediationProved=true",
    "cancelledRootAndRuleAdmissionPreserved=true admissionDescriptorsReleased=true",
    "actual64MiBHashPassed=true liveChunkModeDriftRefused=true disjointCopyRegistryChurnPassed=true partialCopyCancellationCleaned=true",
    "scoped manifest scale, concurrent registry, mount restore, bind rename passed",
    "all native controls passed",
)


class Protocol:
    """Pure oracle of the literal native/JVM record contract, not kernel evidence."""
    def __init__(self, peer, deadline):
        self.peer, self.deadline, self.count = peer, deadline, 0

    def accept(self, data, seq, role, op, peer, now):
        self.count += 1
        if self.count > 32 or not 0 < len(data) <= 4096 or now >= self.deadline:
            raise ValueError("frame/deadline bound")
        if peer != self.peer or data != f"1 {seq} {role} {op}\n".encode("ascii"):
            raise ValueError("peer/role/sequence/grammar")


def records(text):
    if len(text.encode()) > 262144:
        raise ValueError("log overflow")
    result = []
    for line in text.splitlines():
        if line.startswith(PREFIX):
            row = json.loads(line[len(PREFIX):])
            if row.get("role") not in ("O", "A", "J") or not isinstance(row.get("event"), str):
                raise ValueError("unknown evidence role/schema")
            if type(row.get("rc")) is not int or type(row.get("errno")) is not int:
                raise ValueError("missing syscall result")
            result.append(row)
    if len(result) > 256:
        raise ValueError("evidence count overflow")
    return result


def verify(scenario, rc, text, nested=""):
    if scenario not in SCENARIOS:
        raise ValueError("unknown scenario")
    rows = records(text)

    def one(role, event, result=0):
        found = [r for r in rows if r["role"] == role and r["event"] == event]
        if len(found) != 1 or (result is not None and found[0]["rc"] != result):
            raise ValueError(f"missing/duplicate/failed {role}:{event}")
        if result == 0 and found[0]["errno"] != 0:
            raise ValueError("successful syscall with contradictory errno")
        return found[0]

    if any(r["event"] == "cleanup_UNVERIFIED" for r in rows):
        raise ValueError("cleanup unverified")
    one("O", "synthetic_rootless_O")
    one("A", "namespace_equal" if scenario == "sensitivity" else "namespace_distinct")
    one("O", "cleanup_VERIFIED")
    one("A", "cleanup_VERIFIED")
    one("A", "control_closed")
    for role in ("O", "A"):
        ledger = one(role, "cleanup_ledger")
        if ledger.get("mountsRemaining") != 0 or ledger.get("childReaped") != 1:
            raise ValueError("owned mount/process cleanup incomplete")
    one("J", "adopted_CLOEXEC")
    # Completion is ordered, not an unordered bag of success words.
    def before(a, b):
        if next(i for i, row in enumerate(rows) if row is a) >= next(i for i, row in enumerate(rows) if row is b):
            raise ValueError("phase order violated")
    before(one("O", "synthetic_rootless_O"), one("J", "adopted_CLOEXEC"))
    before(one("O", "synthetic_rootless_O"), one("A", "namespace_equal" if scenario == "sensitivity" else "namespace_distinct"))
    before(one("A", "namespace_equal" if scenario == "sensitivity" else "namespace_distinct"), one("J", "adopted_CLOEXEC"))
    before(one("A", "cleanup_VERIFIED"), one("O", "cleanup_VERIFIED"))
    for role in ("A", "O"):
        before(one(role, "cleanup_ledger"), one(role, "cleanup_VERIFIED"))
    before(one("A", "cleanup_VERIFIED"), one("A", "control_closed"))
    before(one("A", "control_closed"), one("O", "cleanup_ledger"))
    # Typed owners are correlated by role + monotonic owner ID, never a reused
    # manifest boolean. Actual wait status and per-owner disposition are mandatory.
    budgets = []
    for role in ("O", "A"):
        ready = one(role, "subreaper_ready")
        absent = one(role, "descendants_absent")
        ledger = one(role, "cleanup_ledger")
        if ledger.get("descendantsAbsent") != 1 or ledger.get("adopted") != 0:
            raise ValueError("descendant absence not established")
        end, operation = ledger.get("cleanupDeadline"), ledger.get("operationDeadline")
        if type(end) is not int or type(operation) is not int or not 0 < end <= operation + 3000:
            raise ValueError("invalid shared cleanup deadline")
        budgets.append((end, operation))
        before(absent, ledger)
        owned = [r for r in rows if r["role"] == role and r["event"] == "child_owned"]
        expected = {"cleaner"} if role == "O" else {"manifest-jvm"} | ({"nested-unshare-jvm"} if scenario == "hostile" else set())
        if len(owned) != len(expected) or {r.get("kind") for r in owned} != expected:
            raise ValueError("missing/duplicate/unexpected child ownership")
        identities = set()
        for child in owned:
            ident = child.get("ownerId")
            if type(ident) is not int or ident <= 0 or ident in identities or type(child.get("pid")) is not int or child["pid"] <= 0:
                raise ValueError("invalid owner identity")
            identities.add(ident)
            if child["rc"] != 0 or child["errno"] != 0 or child.get("reaped") != 0 or child.get("status") != -1 or child.get("pidfd") != 0:
                raise ValueError("invalid ownership publication")
            matched = [r for r in rows if r["role"] == role and r["event"] in ("child_reaped", "child_ledger", "child_UNVERIFIED") and r.get("ownerId") == ident]
            if len(matched) != 2 or {r["event"] for r in matched} != {"child_reaped", "child_ledger"}:
                raise ValueError("unreaped/duplicate child disposition")
            waited = next(r for r in matched if r["event"] == "child_reaped")
            disposed = next(r for r in matched if r["event"] == "child_ledger")
            for record in matched:
                if any(record.get(k) != child[k] for k in ("ownerId", "kind", "pid")) or record.get("reaped") != 1 or record.get("pidfd") != 1 or record["errno"] != 0:
                    raise ValueError("child disposition lost correlation")
            status = waited.get("status")
            if type(status) is not int or status < 0 or not (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                raise ValueError("missing actual terminal wait status")
            code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
            if waited["rc"] != code or disposed["rc"] != 0 or disposed.get("status") != status:
                raise ValueError("contradictory terminal wait status")
            expected_code = (1 if scenario in ("restore-failure", "cleanup-failure") else 2 if scenario not in ("external", "sensitivity", "hostile") else 0) if role == "O" else (137 if scenario == "death" else 1 if scenario in ("restore-failure", "eof", "malformed", "oversize", "order") else 0)
            if child["kind"] == "nested-unshare-jvm": expected_code = 0
            if code != expected_code:
                raise ValueError("wrong child termination outcome")
            before(ready, child); before(child, waited); before(waited, absent)
            before(absent, disposed); before(disposed, ledger)
            if child["kind"] == "manifest-jvm":
                before(child, one("J", "adopted_CLOEXEC"))
                if scenario != "death": before(one("J", "inherited_fds_closed"), waited)
            elif child["kind"] == "nested-unshare-jvm":
                manifest_wait = next(r for r in rows if r["role"] == "A" and r["event"] == "child_reaped" and r.get("kind") == "manifest-jvm")
                before(manifest_wait, child); before(waited, one("A", "nested_probe"))
            else:
                before(one("A", "control_closed"), waited)
        extra = [r for r in rows if r["role"] == role and r["event"] in ("child_reaped", "child_ledger", "child_UNVERIFIED") and r.get("ownerId") not in identities]
        if extra: raise ValueError("uncorrelated child disposition")
    if budgets[0] != budgets[1]: raise ValueError("cleanup budget renewed across owners")
    early = scenario in ("cancel-pre", "cancel-descriptor", "eof", "death", "malformed", "oversize", "order")
    if scenario != "cancel-pre":
        before(one("J", "adopted_CLOEXEC"), one("J", "ADMITTED_AT_DESCRIPTOR"))
    if scenario != "death":
        one("J", "inherited_fds_closed")
        if scenario != "cancel-pre":
            before(one("J", "ADMITTED_AT_DESCRIPTOR"), one("J", "scope_observer_released"))
            before(one("J", "scope_observer_released"), one("J", "inherited_fds_closed"))
    if not early:
        before(one("J", "ADMITTED_AT_DESCRIPTOR"), one("J", "view_checked"))
        before(one("J", "view_checked"), one("J", "scope_observer_released"))
        outcome = one("J", "CHECKPOINT_EVENT" if scenario in ("sensitivity", "hostile", "cleanup-failure")
                      else "manifest_finished_original_observer_NONE")
        before(one("J", "scope_observer_released"), outcome)
        if scenario in ("hostile", "cleanup-failure"):
            for op in ("bind", "move_away", "move_back", "unmount"):
                one("A", op)
            before(one("A", "bind"), one("J", "ADMITTED_AT_DESCRIPTOR"))
            before(one("J", "ADMITTED_AT_DESCRIPTOR"), one("A", "move_away"))
            before(one("A", "move_away"), one("A", "move_back"))
            before(one("A", "move_back"), one("J", "view_checked"))
            before(one("J", "CHECKPOINT_EVENT"), one("A", "unmount"))
            if scenario == "hostile":
                before(one("A", "nested_probe"), one("A", "cleanup_VERIFIED"))
                if len(nested.encode()) > 262144 or any(nested.count("private-control-bind-probe: " + m) != 1 for m in NESTED_MARKERS):
                    raise ValueError("unchanged nested native probe markers missing/duplicated")
            if one("J", "view_checked")["detail"] != "restored_mount_and_key":
                raise ValueError("missing unchanged mount/key")
        else:
            before(one("J", "ADMITTED_AT_DESCRIPTOR"), one("O", "bind"))
            poll = one("O", "outer_event", 1)
            if poll["errno"] != 0 or poll.get("revents", 0) & 10 == 0 or poll.get("revents", 0) & 48:
                raise ValueError("outer EVENT not observed")
            before(one("O", "bind"), poll)
            before(poll, one("J", "view_checked"))
            before(outcome, one("O", "unmount"))
            expected_view = "injected" if scenario == "sensitivity" else "original"
            if one("J", "view_checked")["detail"] != expected_view:
                raise ValueError("namespace visible bytes mismatch")
        if scenario in ("sensitivity", "hostile", "cleanup-failure"):
            witness = one("J", "CHECKPOINT_EVENT")["detail"]
            if not witness.startswith("mount-event-v1 phase=CHECKPOINT ") or " outcome=EVENT " not in witness:
                raise ValueError("original checkpoint witness missing")
        else:
            digest = one("J", "manifest_finished_original_observer_NONE")["detail"]
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("manifest digest absent")
    expected_rc = 0 if scenario in ("external", "sensitivity", "hostile") else 1 if scenario in ("restore-failure", "cleanup-failure") else 2
    if rc != expected_rc or one("O", "result", expected_rc)["rc"] != rc:
        raise ValueError("unexpected native exit")
    before(one("O", "cleanup_VERIFIED"), one("O", "result", expected_rc))
    if rows[-1] is not one("O", "result", expected_rc):
        raise ValueError("records after terminal result")
    if scenario in ("external", "sensitivity", "hostile"):
        if any(r["rc"] != 0 for r in rows if r["event"] != "outer_event"):
            raise ValueError("successful scenario contains a failed phase/syscall")
        one("J", "subject_complete")
        one("O", "PASS")
        one("O", "reaped")
        reaped = [r for r in rows if r["role"] == "A" and r["event"] == "reaped"]
        if len(reaped) != (2 if scenario == "hostile" else 1) or any(r["rc"] != 0 for r in reaped):
            raise ValueError("missing/failed native child reap")
        before(one("A" if scenario == "hostile" else "O", "unmount"), one("J", "subject_complete"))
        before(one("J", "subject_complete"), one("J", "inherited_fds_closed"))
        before(one("J", "inherited_fds_closed"), reaped[0])
        if scenario == "hostile":
            before(reaped[0], reaped[1])
            before(reaped[1], one("A", "nested_probe"))
        before(reaped[-1], one("A", "cleanup_ledger"))
        before(one("A", "cleanup_VERIFIED"), one("O", "PASS"))
        before(one("O", "PASS"), one("O", "reaped"))
        before(one("A", "control_closed"), one("O", "reaped"))
        before(one("O", "reaped"), one("O", "cleanup_ledger"))
    elif scenario.startswith("cancel-"):
        one("A", "expected_cancel_observed")
        cancellation = one("J", {"cancel-pre": "cancel_before_admission", "cancel-descriptor": "cancel_at_descriptor",
                  "cancel-restore": "cancel_during_restore", "cancel-close": "cancel_during_close"}[scenario])
        before(one("J", "adopted_CLOEXEC"), cancellation)
        if scenario != "cancel-pre": before(one("J", "scope_observer_released"), cancellation)
        if scenario in ("cancel-restore", "cancel-close"): before(one("O", "unmount"), cancellation)
        before(cancellation, one("J", "inherited_fds_closed"))
        before(one("J", "inherited_fds_closed"), one("A", "reaped"))
        before(one("A", "reaped"), one("A", "expected_cancel_observed"))
        before(one("A", "expected_cancel_observed"), one("A", "cleanup_ledger"))
        before(one("A", "cleanup_VERIFIED"), one("O", "EXPECTED_FAILURE"))
        before(one("O", "EXPECTED_FAILURE"), one("O", "reaped", 2))
        before(one("O", "reaped", 2), one("O", "cleanup_ledger"))
    elif scenario == "cleanup-failure":
        fault = one("A", "cleanup_fault_syscall", -1)
        if fault["errno"] != 22:
            raise ValueError("expected actual cleanup syscall refusal")
        before(fault, one("A", "unmount"))
        before(one("J", "CHECKPOINT_EVENT"), one("J", "cancel_during_restore"))
        before(one("J", "cancel_during_restore"), one("J", "inherited_fds_closed"))
        before(one("J", "inherited_fds_closed"), one("A", "reaped"))
        before(one("A", "reaped"), one("A", "expected_cancel_observed"))
        before(one("A", "expected_cancel_observed"), fault)
        before(one("A", "unmount"), one("A", "cleanup_ledger"))
        before(one("A", "cleanup_VERIFIED"), one("O", "FAIL"))
        before(one("O", "FAIL"), one("O", "reaped", 1))
        before(one("O", "reaped", 1), one("O", "cleanup_ledger"))
        one("O", "FAIL")
        one("A", "expected_cancel_observed")
        one("J", "cancel_during_restore")
        one("O", "reaped", 1)
        one("A", "reaped")
    elif scenario == "restore-failure":
        fault = one("O", "restore_fault_syscall", -1)
        if fault["errno"] != 22:
            raise ValueError("expected actual invalid-flag restoration refusal")
        manifest_reap = next(r for r in rows if r["role"] == "A" and r["event"] == "child_reaped" and r["kind"] == "manifest-jvm")
        cleaner_reap = next(r for r in rows if r["role"] == "O" and r["event"] == "child_reaped" and r["kind"] == "cleaner")
        before(one("J", "manifest_finished_original_observer_NONE"), fault)
        before(fault, one("J", "protocol_refused_EOF"))
        before(one("J", "protocol_refused_EOF"), one("J", "inherited_fds_closed"))
        before(one("J", "inherited_fds_closed"), manifest_reap)
        before(manifest_reap, one("A", "cleanup_ledger"))
        before(one("A", "control_closed"), cleaner_reap)
        before(cleaner_reap, one("O", "unmount"))
        before(one("O", "unmount"), one("O", "cleanup_ledger"))
    else:
        one("A", "expected_fault_observed")
        if scenario == "death":
            one("A", "injected_death")
        else:
            one("J", "protocol_refused_" + ("EOF" if scenario == "eof" else "OVERSIZE" if scenario == "oversize" else "ROLE_SEQUENCE_GRAMMAR"))
            if scenario != "eof":
                one("A", "injected_frame")
        exited = one("A", "fault_subject_exit", None)
        if exited["errno"] != 0 or exited["rc"] != (137 if scenario == "death" else 1):
            raise ValueError("fault subject unexpectedly succeeded")
        before(one("J", "ADMITTED_AT_DESCRIPTOR"), exited)
        if scenario == "death": before(one("A", "injected_death"), exited)
        else: before(one("J", "inherited_fds_closed"), exited)
        before(exited, one("A", "expected_fault_observed"))
        before(one("A", "expected_fault_observed"), one("A", "cleanup_ledger"))
        before(one("A", "cleanup_VERIFIED"), one("O", "EXPECTED_FAILURE"))
        before(one("O", "EXPECTED_FAILURE"), one("O", "reaped", 2))
        before(one("O", "reaped", 2), one("O", "cleanup_ledger"))
    return {"scenario": scenario, "status": "PASS", "nativeExit": rc,
            "scope": "synthetic prevention mechanism only",
            "subjectDescriptorRelease": "kernel release after retained pidfd death/reap; JVM finally not observed" if scenario == "death" else "JVM finally and inherited handle close",
            "privateControlCgroupQuota": "No cgroup/quota/sandbox lifecycle is created by this synthetic manifest subject; nested probe has its own original controls.",
            "records": rows}


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def bindings(native, java, entries):
    leaves = {str(ROOT / p): digest(ROOT / p) for p in SOURCES}
    for path in [native, java] + entries:
        files = sorted(path.rglob("*")) if path.is_dir() else [path]
        if len(files) > 50000:
            raise ValueError("classpath inventory exceeds bound")
        for f in files:
            if f.is_file():
                leaves[str(f)] = digest(f)
    return leaves


def bounded(command, cwd, env):
    """One execution, one absolute deadline, capped output; never retries a failed command."""
    p = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + 65
    chunks, length = [], 0
    selector = selectors.DefaultSelector()
    selector.register(p.stdout, selectors.EVENT_READ)
    failure = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("driver deadline; cleanup UNVERIFIED")
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    chunks.append(chunk)
                    length += len(chunk)
                    if length > 262144:
                        raise ValueError("log overflow; cleanup UNVERIFIED")
        code = p.wait(timeout=max(0.001, deadline-time.monotonic()))
    except BaseException as e:
        failure = str(e)
        os.killpg(p.pid, signal.SIGKILL)
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            failure += "; reap UNVERIFIED"
        code = p.returncode if p.returncode is not None else -1
    finally:
        selector.close()
        p.stdout.close()
    return code, b"".join(chunks).decode("utf-8", errors="replace"), failure


def run(args):
    root = ROOT / "build/acp-isolation-fixture"
    root.mkdir(parents=True, exist_ok=True)
    output = root / ("run-" + uuid.uuid4().hex)
    output.mkdir(mode=0o700)
    summary = {"schema": 1, "scope": "synthetic rootless fixture; not production support or historical attribution",
               "cases": [], "unexecuted": list(SCENARIOS), "status": "FAIL"}
    try:
        native = Path(args.native).resolve(strict=True)
        java = Path(args.java).resolve(strict=True)
        cpfile = Path(args.classpath_file).resolve(strict=True)
        if not native.is_relative_to(ROOT) or not cpfile.is_relative_to(ROOT):
            raise ValueError("native and classpath export must reside in repository")
        cp = cpfile.read_text().strip()
        if not cp or len(cp) > 131072 or "\n" in cp:
            raise ValueError("invalid classpath export")
        entries = [Path(p).resolve(strict=True) for p in cp.split(os.pathsep)]
        if not all(Path(p).is_absolute() for p in cp.split(os.pathsep)):
            raise ValueError("classpath entries must be absolute before namespace/chdir")
        unshare = shutil.which("unshare")
        if not unshare or os.geteuid() == 0:
            raise ValueError("requires existing unshare and ordinary unprivileged invoking user")
        before = bindings(native, java, entries)
        (output / "source-classes-native-before.json").write_text(json.dumps(before, indent=2))
        summary["kernel"] = list(os.uname())
        summary["tools"] = {p: digest(Path(p)) for p in (unshare, str(java), str(native))}
        for scenario in SCENARIOS:
            base = output / scenario
            base.mkdir(mode=0o700)
            for name in ("closure", "target", "injected", "moved", "tmp", "home", "nested"):
                (base / name).mkdir(mode=0o700)
            (base / "closure/input").write_text("synthetic fixture closure\n")
            (base / "target/marker").write_text("original\n")
            (base / "injected/marker").write_text("injected\n")
            command = [unshare, "--user", "--map-root-user", "--mount", "--fork", "--kill-child=KILL", "--",
                       str(native), scenario, str(base), str(java), cp]
            env = dict(os.environ, TMPDIR=str(base / "tmp"))
            for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
                env.pop(key, None)
            rc, text, execution_error = bounded(command, ROOT, env)
            (base / "command.json").write_text(json.dumps(command))
            (base / "native.log").write_text(text)
            summary["unexecuted"].remove(scenario)
            try:
                if execution_error:
                    raise ValueError(execution_error)
                nested = ""
                if scenario == "hostile":
                    if (base / "nested.log").stat().st_size > 262144:
                        raise ValueError("nested log overflow")
                    nested = (base / "nested.log").read_text()
                outcome = verify(scenario, rc, text, nested)
            except Exception as e:
                outcome = {"scenario": scenario, "status": "FAIL", "nativeExit": rc, "error": str(e)}
            summary["cases"].append(outcome)
            if outcome["status"] != "PASS":
                break
        after = bindings(native, java, entries)
        (output / "source-classes-native-after.json").write_text(json.dumps(after, indent=2))
        if before != after:
            raise ValueError("source/classes/native drift during fixture")
        summary["compiledSourceQualification"] = "Parent must bind actual compiler outputs; hashes alone do not establish qualification."
        if len(summary["cases"]) == len(SCENARIOS) and all(c["status"] == "PASS" for c in summary["cases"]):
            summary["status"] = "PASS"
    except Exception as e:
        summary["error"] = str(e)
    finally:
        (output / "summary.json").write_text(json.dumps(summary, indent=2))
        print(json.dumps({"status": summary["status"], "summary": str(output / "summary.json")}))
    return 0 if summary["status"] == "PASS" else 1


class PureControls(unittest.TestCase):
    def test_protocol_exact_peer_role_sequence_and_original_deadline(self):
        p = Protocol(7, 100)
        p.accept(b"1 2 J AT_DESCRIPTOR\n", 2, "J", "AT_DESCRIPTOR", 7, 99)
        for data, seq, role, peer, now in ((b"", 2, "J", 7, 99), (b"x" * 4097, 2, "J", 7, 99),
                (b"1 2 J AT_DESCRIPTOR\n", 3, "J", 7, 99), (b"1 2 J AT_DESCRIPTOR\n", 2, "A", 7, 99),
                (b"1 2 J AT_DESCRIPTOR\n", 2, "J", 8, 99), (b"1 2 J AT_DESCRIPTOR\n", 2, "J", 7, 100)):
            with self.assertRaises(ValueError):
                p.accept(data, seq, role, "AT_DESCRIPTOR", peer, now)

    def test_global_frame_count_not_reset_by_sequence(self):
        p = Protocol(1, 100)
        for i in range(32):
            p.accept(f"1 {i} A ACK\n".encode(), i, "A", "ACK", 1, 1)
        with self.assertRaises(ValueError):
            p.accept(b"1 32 A ACK\n", 32, "A", "ACK", 1, 1)

    @staticmethod
    def authored_positive():
        def row(role, event, rc=0, **kw):
            return {"role": role, "event": event, "rc": rc, "errno": 0, **kw}
        rows = [row("O", "synthetic_rootless_O"), row("A", "namespace_distinct"), row("J", "adopted_CLOEXEC"),
                row("J", "ADMITTED_AT_DESCRIPTOR"), row("O", "bind"), row("O", "outer_event", 1, revents=10),
                row("J", "view_checked", detail="original"), row("J", "scope_observer_released"),
                row("J", "manifest_finished_original_observer_NONE", detail="a"*64), row("O", "unmount"),
                row("J", "subject_complete"), row("J", "inherited_fds_closed"),
                row("A", "reaped"), row("A", "cleanup_ledger", mountsRemaining=0, childReaped=1), row("A", "cleanup_VERIFIED"), row("A", "control_closed"),
                row("O", "PASS"), row("O", "reaped"), row("O", "cleanup_ledger", mountsRemaining=0, childReaped=1), row("O", "cleanup_VERIFIED"), row("O", "result")]

        return PureControls.attach_owners(rows)

    @staticmethod
    def attach_owners(rows):
        # Authored data only, following actual native publication/wait/disposal order.
        rows = [r for r in rows if r["event"] not in ("child_owned", "child_reaped", "child_ledger", "subreaper_ready", "descendants_absent")]
        def insert_before(anchor, row): rows.insert(next(i for i, r in enumerate(rows) if r is anchor), row)
        def row(role, event, **kw): return dict(role=role, event=event, rc=0, errno=0, **kw)
        for role in ("O", "A"):
            first = next(r for r in rows if r["role"] == role)
            insert_before(first, row(role, "subreaper_ready"))
            ledger = next(r for r in rows if r["role"] == role and r["event"] == "cleanup_ledger")
            ledger.update(descendantsAbsent=1, adopted=0, cleanupDeadline=61000, operationDeadline=60000)
            absent = row(role, "descendants_absent")
            insert_before(ledger, absent)
            reaps = [r for r in rows if r["role"] == role and r["event"] in ("reaped", "fault_subject_exit")]
            for index, reaped in enumerate(reaps):
                kind = "cleaner" if role == "O" else "manifest-jvm" if index == 0 else "nested-unshare-jvm"
                ident = index + 1
                attrs = dict(ownerId=ident, kind=kind, pid=(71 if role == "O" else 81) + index)
                owner = row(role, "child_owned", **attrs, pidfd=0, reaped=0, status=-1)
                anchor = next(r for r in rows if r["event"] == ("namespace_distinct" if role == "O" else "adopted_CLOEXEC")) if index == 0 else reaped
                insert_before(anchor, owner)
                status = reaped["rc"] << 8 if reaped["rc"] < 128 else reaped["rc"] - 128
                waited = row(role, "child_reaped", **attrs, pidfd=1, reaped=1, status=status)
                waited["rc"] = reaped["rc"]
                insert_before(reaped, waited)
                insert_before(ledger, row(role, "child_ledger", **attrs, pidfd=1, reaped=1, status=status))
        return rows

    @staticmethod
    def encode(rows):
        return "\n".join(PREFIX+json.dumps(r) for r in rows)

    def test_verifier_requires_every_operation_and_cleanup_not_hash_alone(self):
        rows = self.authored_positive()
        self.assertEqual("PASS", verify("external", 0, self.encode(rows))["status"])
        for i in range(len(rows)):
            with self.assertRaises(ValueError, msg=rows[i]["event"]):
                verify("external", 0, self.encode(rows[:i]+rows[i+1:]))
        with self.assertRaises(ValueError):
            verify("external", 1, self.encode(rows))
        with self.assertRaises(ValueError):
            verify("external", 0, self.encode(rows+[rows[5]]))
        rows[-2]["event"] = "cleanup_UNVERIFIED"
        with self.assertRaises(ValueError):
            verify("external", 0, self.encode(rows))

    def test_sensitivity_success_cannot_substitute_for_typed_refusal(self):
        rows = self.authored_positive()
        next(r for r in rows if r["event"] == "namespace_distinct")["event"] = "namespace_equal"
        next(r for r in rows if r["event"] == "view_checked")["detail"] = "injected"
        with self.assertRaises(ValueError):
            verify("sensitivity", 0, self.encode(rows))

    def test_phase_order_and_cleanup_uncertainty_fail_closed(self):
        rows = self.authored_positive()
        left = next(i for i, r in enumerate(rows) if r["event"] == "ADMITTED_AT_DESCRIPTOR")
        right = next(i for i, r in enumerate(rows) if r["event"] == "bind")
        rows[left], rows[right] = rows[right], rows[left]
        with self.assertRaises(ValueError):
            verify("external", 0, self.encode(rows))

    def test_observation_and_cleanup_lifetime_reorderings_are_refused(self):
        ordered_pairs = (
            (("O", "synthetic_rootless_O"), ("A", "namespace_distinct")),
            (("A", "namespace_distinct"), ("J", "adopted_CLOEXEC")),
            (("J", "adopted_CLOEXEC"), ("J", "ADMITTED_AT_DESCRIPTOR")),
            (("J", "ADMITTED_AT_DESCRIPTOR"), ("O", "bind")),
            (("O", "bind"), ("O", "outer_event")),
            (("O", "outer_event"), ("J", "view_checked")),
            (("J", "view_checked"), ("J", "scope_observer_released")),
            (("J", "scope_observer_released"), ("J", "manifest_finished_original_observer_NONE")),
            (("J", "manifest_finished_original_observer_NONE"), ("O", "unmount")),
            (("O", "unmount"), ("J", "subject_complete")),
            (("J", "subject_complete"), ("J", "inherited_fds_closed")),
            (("J", "inherited_fds_closed"), ("A", "reaped")),
            (("A", "reaped"), ("A", "cleanup_ledger")),
            (("A", "cleanup_ledger"), ("A", "cleanup_VERIFIED")),
            (("A", "cleanup_VERIFIED"), ("A", "control_closed")),
            (("A", "cleanup_VERIFIED"), ("O", "PASS")),
            (("A", "control_closed"), ("O", "reaped")),
            (("O", "PASS"), ("O", "reaped")),
            (("O", "reaped"), ("O", "cleanup_ledger")),
            (("O", "cleanup_ledger"), ("O", "cleanup_VERIFIED")),
            (("O", "cleanup_VERIFIED"), ("O", "result")),
        )
        for first, second in ordered_pairs:
            with self.subTest(first=first, second=second):
                rows = self.authored_positive()
                index = next(i for i, r in enumerate(rows) if (r["role"], r["event"]) == second)
                moved = rows.pop(index)
                anchor = next(i for i, r in enumerate(rows) if (r["role"], r["event"]) == first)
                rows.insert(anchor, moved)
                with self.assertRaises(ValueError): verify("external", 0, self.encode(rows))

    def test_every_external_phase_rejects_duplicates_and_poll_errno(self):
        rows = self.authored_positive()
        for row in rows:
            with self.subTest(event=row["event"]):
                with self.assertRaises(ValueError): verify("external", 0, self.encode(rows + [row]))
        next(r for r in rows if r["event"] == "outer_event")["errno"] = 5
        with self.assertRaises(ValueError): verify("external", 0, self.encode(rows))
        rows = self.authored_positive()
        rows.append({"role": "A", "event": "cleanup_UNVERIFIED", "rc": -1, "errno": 5})
        with self.assertRaises(ValueError):
            verify("external", 0, self.encode(rows))

    def test_syscall_failure_is_not_success_even_with_later_hash(self):
        rows = self.authored_positive()
        next(r for r in rows if r["event"] == "unmount")["rc"] = -1
        with self.assertRaises(ValueError):
            verify("external", 0, self.encode(rows))
        rows = self.authored_positive()
        next(r for r in rows if r["event"] == "outer_event")["revents"] = 32
        with self.assertRaises(ValueError):
            verify("external", 0, self.encode(rows))

    @classmethod
    def authored_hostile(cls):
        rows = cls.authored_positive()
        rows = [r for r in rows if r["event"] not in ("bind", "outer_event", "unmount")]
        next(r for r in rows if r["event"] == "view_checked")["detail"] = "restored_mount_and_key"
        finished = next(r for r in rows if r["event"] == "manifest_finished_original_observer_NONE")
        finished.update(event="CHECKPOINT_EVENT", detail="mount-event-v1 phase=CHECKPOINT generation=NOT_EVALUATED outcome=EVENT rc=1 revents=10 errno=NA")
        rows += [{"role": "A", "event": e, "rc": 0, "errno": 0} for e in ("bind", "move_away", "move_back", "unmount", "nested_probe", "reaped")]
        # Place authored events in the native program's required causal order.
        for event, anchor in (("bind", "ADMITTED_AT_DESCRIPTOR"), ("move_away", "view_checked"),
                              ("move_back", "view_checked"), ("unmount", "subject_complete"),
                              ("nested_probe", "cleanup_ledger")):
            r = next(r for r in rows if r["event"] == event)
            rows.remove(r)
            index = next(i for i, candidate in enumerate(rows) if candidate["event"] == anchor)
            rows.insert(index, r)
        nested_reap = [r for r in rows if r["role"] == "A" and r["event"] == "reaped"][-1]
        del rows[next(i for i, r in enumerate(rows) if r is nested_reap)]
        rows.insert(next(i for i, r in enumerate(rows) if r["event"] == "nested_probe"), nested_reap)
        markers = "\n".join("private-control-bind-probe: " + m for m in NESTED_MARKERS)
        return cls.attach_owners(rows), markers

    def test_hostile_requires_both_moves_and_unchanged_probe_reachability(self):
        rows, markers = self.authored_hostile()
        self.assertEqual("PASS", verify("hostile", 0, self.encode(rows), markers)["status"])
        for missing in ("move_away", "move_back", "nested_probe"):
            with self.assertRaises(ValueError):
                verify("hostile", 0, self.encode([r for r in rows if r["event"] != missing]), markers)
        for m in NESTED_MARKERS:
            with self.assertRaises(ValueError):
                verify("hostile", 0, self.encode(rows), markers.replace("private-control-bind-probe: "+m, ""))

    def test_cleanup_refusal_remains_failure_after_successful_remediation(self):
        rows, _ = self.authored_hostile()
        rows = [r for r in rows if r["event"] != "nested_probe"]
        reaps = [r for r in rows if r["role"] == "A" and r["event"] == "reaped"]
        rows.remove(reaps[-1])
        for r in rows:
            if r["event"] == "subject_complete":
                r["event"] = "cancel_during_restore"
            if r["role"] == "O" and r["event"] in ("result", "reaped"):
                r["rc"] = 1
            if r["event"] == "PASS":
                r["event"] = "FAIL"
        fault = {"role": "A", "event": "cleanup_fault_syscall", "rc": -1, "errno": 22}
        unmount = next(r for r in rows if r["event"] == "unmount")
        rows.remove(unmount)
        index = next(i for i, r in enumerate(rows) if r["role"] == "A" and r["event"] == "cleanup_ledger")
        rows[index:index] = [{"role": "A", "event": "expected_cancel_observed", "rc": 0, "errno": 0}, fault, unmount]
        rows = self.attach_owners(rows)
        self.assertEqual("PASS", verify("cleanup-failure", 1, self.encode(rows))["status"])
        with self.assertRaises(ValueError):
            verify("cleanup-failure", 0, self.encode(rows))
        with self.assertRaises(ValueError):
            verify("cleanup-failure", 1, self.encode([r for r in rows if r is not fault]))

    @staticmethod
    def authored_restoration_failure():
        rows = PureControls.authored_positive()
        unmount = next(r for r in rows if r["event"] == "unmount")
        rows.remove(unmount)
        rows = [r for r in rows if r["event"] != "PASS"]
        for r in rows:
            if r["event"] == "subject_complete": r["event"] = "protocol_refused_EOF"
            if r["event"] == "reaped" or (r["role"] == "O" and r["event"] == "result"): r["rc"] = 1
        rows = PureControls.attach_owners(rows)
        # Error cleanup emits correlated wait records, not generic success-path reaped events.
        rows = [r for r in rows if r["event"] != "reaped"]
        outcome = next(i for i, r in enumerate(rows) if r["event"] == "manifest_finished_original_observer_NONE")
        rows.insert(outcome + 1, dict(role="O", event="restore_fault_syscall", rc=-1, errno=22))
        cleanup = next(i for i, r in enumerate(rows) if r["role"] == "O" and r["event"] == "cleanup_ledger")
        rows.insert(cleanup, unmount)
        return rows

    def test_restoration_failure_has_finite_ordered_cleanup(self):
        original = self.authored_restoration_failure()
        self.assertEqual("PASS", verify("restore-failure", 1, self.encode(original))["status"])
        chain = [("J", "manifest_finished_original_observer_NONE"), ("O", "restore_fault_syscall"),
                 ("J", "protocol_refused_EOF"), ("J", "inherited_fds_closed"),
                 ("A", "child_reaped"), ("A", "cleanup_ledger"), ("A", "cleanup_VERIFIED"),
                 ("A", "control_closed"), ("O", "child_reaped"), ("O", "unmount"),
                 ("O", "cleanup_ledger"), ("O", "cleanup_VERIFIED"), ("O", "result")]
        for index, identity in enumerate(chain):
            with self.subTest(missing=identity):
                rows = [r for r in original if (r["role"], r["event"]) != identity]
                with self.assertRaises(ValueError): verify("restore-failure", 1, self.encode(rows))
            with self.subTest(duplicate=identity):
                row = next(r for r in original if (r["role"], r["event"]) == identity)
                with self.assertRaises(ValueError): verify("restore-failure", 1, self.encode(original + [dict(row)]))
            for later in chain[index + 1:]:
                with self.subTest(moved=identity, after=later):
                    rows = list(original)
                    moved = next(r for r in rows if (r["role"], r["event"]) == identity)
                    rows.remove(moved)
                    at = next(i for i, r in enumerate(rows) if (r["role"], r["event"]) == later)
                    rows.insert(at + 1, moved)
                    with self.assertRaises(ValueError): verify("restore-failure", 1, self.encode(rows))
        rows = self.authored_restoration_failure()
        next(r for r in rows if r["event"] == "restore_fault_syscall")["errno"] = 1
        with self.assertRaises(ValueError): verify("restore-failure", 1, self.encode(rows))

    def test_result_is_terminal_even_for_unrecognized_trailing_record(self):
        rows = self.authored_positive()
        rows.append(dict(role="O", event="late_failure", rc=-1, errno=5))
        with self.assertRaises(ValueError): verify("external", 0, self.encode(rows))
        rows = self.authored_restoration_failure()
        rows.append(dict(role="O", event="late_failure", rc=-1, errno=5))
        with self.assertRaises(ValueError): verify("restore-failure", 1, self.encode(rows))

    def test_child_ownership_status_and_shared_budget_are_required(self):
        for field, value in (("ownerId", 99), ("pid", 99), ("status", 7 << 8), ("reaped", 0), ("pidfd", 0)):
            with self.subTest(field=field):
                rows = self.authored_positive()
                next(r for r in rows if r["event"] == "child_reaped")[field] = value
                with self.assertRaises(ValueError): verify("external", 0, self.encode(rows))
        for field, value in (("descendantsAbsent", 0), ("adopted", 1), ("cleanupDeadline", 61001), ("operationDeadline", 1)):
            with self.subTest(field=field):
                rows = self.authored_positive()
                next(r for r in rows if r["event"] == "cleanup_ledger")[field] = value
                with self.assertRaises(ValueError): verify("external", 0, self.encode(rows))

    def test_nested_owner_cannot_reuse_manifest_reap_or_omit_descendant_absence(self):
        original, markers = self.authored_hostile()
        for event in ("child_owned", "child_reaped", "child_ledger"):
            rows = [r for r in original if not (r["event"] == event and r.get("kind") == "nested-unshare-jvm")]
            with self.assertRaises(ValueError): verify("hostile", 0, self.encode(rows), markers)
        for event in ("child_reaped", "child_ledger"):
            rows = self.authored_hostile()[0]
            next(r for r in rows if r["event"] == event and r.get("kind") == "nested-unshare-jvm")["ownerId"] = 1
            with self.assertRaises(ValueError): verify("hostile", 0, self.encode(rows), markers)
        rows = [r for r in original if not (r["role"] == "A" and r["event"] == "descendants_absent")]
        with self.assertRaises(ValueError): verify("hostile", 0, self.encode(rows), markers)

    def test_malformed_and_oversize_evidence_are_errors(self):
        for text in (PREFIX+"{", PREFIX+json.dumps({"role":"X", "event":"PASS"}), "x"*262145):
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                records(text)


if __name__ == "__main__":
    if "--run" not in sys.argv:
        unittest.main()
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("--run", action="store_true", required=True)
        parser.add_argument("--native", required=True)
        parser.add_argument("--java", required=True)
        parser.add_argument("--classpath-file", required=True)
        sys.exit(run(parser.parse_args()))

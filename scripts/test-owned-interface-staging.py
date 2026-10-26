#!/usr/bin/env python3
"""Compile the real dispatcher with authored collaborators; no Ghidra/native execution.

These controls verify invocation9 orchestration and filesystem accounting, not native
collector behavior. Actual collector/spool controls live in NativeInferredInterfaceControls.
All compiler/JVM/temp outputs stay under this repository's build directory.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
STUBS = {
    "ghidra/util/task/TaskMonitor.java": """
package ghidra.util.task;
public interface TaskMonitor { void checkCancelled() throws Exception; }
""",
    "ghidra/app/script/GhidraScript.java": """
package ghidra.app.script;
import ghidra.util.task.TaskMonitor;
public abstract class GhidraScript {
    public static String[] arguments;
    protected Object currentProgram = new Object();
    protected TaskMonitor monitor = () -> {};
    protected String[] getScriptArgs() { return arguments; }
    protected void runScript(String name, String[] args) {}
    protected abstract void run() throws Exception;
}
""",
    "decompengine/ghidra/BundledGhidraWorker.java": """
package decompengine.ghidra;
public class BundledGhidraWorker {
    public static boolean completed;
    public static void diagnosticsGuard() {}
    public static void diagnosticsExporter(String name) {}
    public static void diagnosticsFinalization() {}
    public static void exportsCompleted() { completed = true; }
}
""",
    "Controls.java": r"""
import ghidra.app.script.GhidraScript;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.*;

public class Controls {
    static final long MAX = 1024L * 1024 * 1024, STREAMS = 2L * 64 * 1024 * 1024;
    static final long OUTPUT = 4000, MANIFEST = 300, SPOOL = 2000, PEAK = OUTPUT + SPOOL + 65536;
    static long listingAllowance, inferredLimit;
    static boolean legacyListing, legacyInferred;
    static long limit(Path reports, long included, TaskMonitor monitor) throws Exception {
        var method = RunBundledExports.class.getDeclaredMethod("interfaceByteLimit", Path.class, long.class, TaskMonitor.class);
        method.setAccessible(true);
        try { return (long)method.invoke(null, reports, included, monitor); }
        catch (InvocationTargetException failure) { throw (Exception)failure.getCause(); }
    }
    static void size(Path file, long bytes) throws Exception {
        Files.createDirectories(file.getParent());
        try (var output = new RandomAccessFile(file.toFile(), "rw")) { output.setLength(bytes); }
    }
    static void require(boolean value) { if (!value) throw new AssertionError("control failed"); }
    static void rejected(Action action, Class<? extends Exception> type) throws Exception {
        try { action.run(); } catch (Exception failure) {
            if (type.isInstance(failure)) return;
            throw failure;
        }
        throw new AssertionError("expected refusal: " + type);
    }
    interface Action { void run() throws Exception; }
    static String[] paired(Path reports) {
        String model = reports.resolve("program_model.json").toString();
        String listing = reports.resolve("native-interfaces-v1").toString();
        String inferred = reports.resolve("native-inferred-interfaces-v1").toString();
        String sha = "a".repeat(64);
        return new String[]{"ExportProgramModel.java", "4", sha, sha, "full", model,
            "ExportNativeInterfacesV1.class", "6", sha, sha, sha, sha, model, listing,
            "ExportInferredInterfacesV1.class", "11", sha, sha, sha, sha, sha, sha, sha, sha, model, listing, inferred};
    }
    public static void main(String[] args) throws Exception {
        String test = args[0];
        Path reports = Files.createDirectory(Path.of(args[1]).resolve("reports"));
        if (test.equals("exact") || test.equals("one-over")) {
            long over = test.equals("one-over") ? 1 : 0;
            size(reports.resolve("program_model.json"), 101);
            size(reports.resolve("program_model.json.progress.json"), 103);
            size(reports.resolve("program_model.json.export/state.json"), 107);
            size(reports.resolve("program_model.json.export/functions/0.json"), 109);
            // Leave exactly the comparison peak AFTER retaining the listing. Streams
            // are still empty but their entire possible future growth must be reserved.
            long retained = MAX - STREAMS - (OUTPUT + MANIFEST) - PEAK + over;
            size(reports.resolve("program_model.json.export/planning-batches/pad"), retained - 420);
            GhidraScript.arguments = paired(reports);
            if (over == 0) new RunBundledExports().run();
            else rejected(() -> new RunBundledExports().run(), IOException.class);
            require(!legacyListing && !legacyInferred);
            require(listingAllowance == OUTPUT + MANIFEST + PEAK - over);
            long included = 101 + OUTPUT + MANIFEST;
            require(inferredLimit == included + PEAK - over);
            // The final inventory would fit even in the refused case; transient
            // comparison output + spool + reserved manifest is the distinguishing charge.
            require(retained + STREAMS + OUTPUT + MANIFEST + 1000 < MAX);
            require(decompengine.ghidra.BundledGhidraWorker.completed == (over == 0));
        } else if (test.equals("inventory")) {
            size(reports.resolve("program_model.json"), 101);
            size(reports.resolve("program_model.json.progress.json"), 103);
            size(reports.resolve("program_model.json.export/state.json"), 107);
            size(reports.resolve("program_model.json.export/types/0.json"), 109);
            size(reports.resolve("native-interfaces-v1/native-interfaces.json"), 113);
            size(reports.resolve("native-interfaces-v1/manifest.json"), 127);
            require(limit(reports, 0, () -> {}) == MAX - STREAMS - 660);
            require(limit(reports, 341, () -> {}) == MAX - STREAMS - 319);
            rejected(() -> limit(reports, -1, () -> {}), IllegalArgumentException.class);
            rejected(() -> limit(reports, 661, () -> {}), IllegalArgumentException.class);
        } else if (test.equals("overflow")) {
            Path pad = reports.resolve("pad");
            size(pad, MAX - STREAMS);
            rejected(() -> limit(reports, 0, () -> {}), IllegalStateException.class);
            size(pad, 2 * MAX);
            rejected(() -> limit(reports, 0, () -> {}), IllegalStateException.class);
        } else if (test.equals("nonregular")) {
            Files.createSymbolicLink(reports.resolve("link"), reports);
            rejected(() -> limit(reports, 0, () -> {}), IllegalStateException.class);
        } else if (test.equals("depth-cancellation")) {
            rejected(() -> limit(reports, 0, () -> { throw new IOException("authored cancellation"); }), IOException.class);
            Files.createDirectories(reports.resolve("1/2/3/4/5/6/7/8"));
            rejected(() -> limit(reports, 0, () -> {}), IllegalStateException.class);
        } else if (test.equals("legacy")) {
            String[] paired = paired(reports);
            GhidraScript.arguments = java.util.Arrays.copyOfRange(paired, 6, 14);
            new RunBundledExports().run();
            GhidraScript.arguments = java.util.Arrays.copyOfRange(paired, 14, 27);
            new RunBundledExports().run();
            require(legacyListing && legacyInferred && listingAllowance == 0 && inferredLimit == 0);
        } else throw new AssertionError(test);
        System.out.println("PASS " + test);
    }
}
// Authored collectors deliberately expose only the bounded API used by invocation9.
// Their peak is synthetic; actual collector charging is separately exercised on Ghidra.
class ExportNativeInterfacesV1 {
    static void collect(Object p, TaskMonitor m, String[] a) { Controls.legacyListing = true; }
    static long collectWithStagingBudget(Object p, TaskMonitor m, String[] a, long limit) throws Exception {
        Controls.listingAllowance = limit;
        if (limit < Controls.PEAK) throw new IOException("authored listing staging refusal");
        Controls.size(Path.of(a[5]).resolve("native-interfaces.json"), Controls.OUTPUT);
        Controls.size(Path.of(a[5]).resolve("manifest.json"), Controls.MANIFEST);
        return Controls.PEAK;
    }
}
class ExportInferredInterfacesV1 {
    static void collect(Object p, TaskMonitor m, String[] a) { Controls.legacyInferred = true; }
    static void collectWithByteLimit(Object p, TaskMonitor m, String[] a, long limit) throws Exception {
        Controls.inferredLimit = limit;
        long included = Files.size(Path.of(a[8])) + Files.size(Path.of(a[9]).resolve("native-interfaces.json")) +
            Files.size(Path.of(a[9]).resolve("manifest.json"));
        if (limit - included < Controls.PEAK) throw new IOException("authored comparison staging refusal");
    }
}
class ExportNativeCallsV1 { static void collect(Object p, TaskMonitor m, String[] a) {} }
""",
}


class OwnedInterfaceStagingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = ROOT / "build/owned-interface-dispatch-controls"
        base.mkdir(parents=True, exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(dir=base)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.env = dict(os.environ, TMPDIR=str(cls.root))
        cls.classes = cls.root / "classes"
        cls.classes.mkdir()
        sources = []
        for name, content in STUBS.items():
            path = cls.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            sources.append(str(path))
        subprocess.run(["javac", "-proc:none", f"-J-Djava.io.tmpdir={cls.root}", "-J-XX:-UsePerfData",
                        "-d", str(cls.classes), *sources,
                        str(ROOT / "ghidra-bridge/src/main/java/RunBundledExports.java")],
                       cwd=ROOT, env=cls.env, check=True, capture_output=True, text=True, timeout=30)

    def control(self, name):
        root = self.root / name
        root.mkdir()
        result = subprocess.run(["java", f"-Djava.io.tmpdir={self.root}", "-XX:-UsePerfData", "-cp",
                                 str(self.classes), "Controls", name, str(root)],
                                cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("PASS " + name, result.stdout)

    def test_exact_shared_comparison_peak(self):
        self.control("exact")

    def test_one_over_shared_comparison_peak_though_final_fits(self):
        self.control("one-over")

    def test_complete_tree_and_no_double_charged_inputs(self):
        self.control("inventory")

    def test_no_space_or_oversized_retained_file(self):
        self.control("overflow")

    def test_symlink_is_not_followed_or_omitted(self):
        self.control("nonregular")

    def test_bounded_depth_and_cancellation(self):
        self.control("depth-cancellation")

    def test_non_invocation9_dispatch_keeps_default_collectors(self):
        self.control("legacy")


if __name__ == "__main__":
    unittest.main()

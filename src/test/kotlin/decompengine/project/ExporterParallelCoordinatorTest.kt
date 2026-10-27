package decompengine.project

import java.io.ByteArrayOutputStream
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import javax.tools.ToolProvider
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test

class ExporterParallelCoordinatorTest {
    @Test
    fun `completion order preserves canonical records and first ownership without blocking later work`() =
        withParallelHarness("reordering")

    @Test
    fun `incomplete metadata blocks later ownership until a successful native retry`() =
        withParallelHarness("retry-success")

    @Test
    fun `failed native retry keeps the complete original outcome`() =
        withParallelHarness("retry-failure")

    @Test
    fun `native retry with partial metadata replaces the original failed outcome`() =
        withParallelHarness("retry-partial")

    @Test
    fun `cancellation stops every active worker before returning`() =
        withParallelHarness("cancellation")

    @Test
    fun `worker infrastructure failure stops peers and cannot become a failed function`() =
        withParallelHarness("infrastructure")
}

private fun withParallelHarness(scenario: String) {
    val exporter = Path.of("src/main/resources/ghidra_scripts/ExportProgramModel.java").readText()
    val beginMarker = "// PARALLEL_EXPORT_TEST_BEGIN\n"
    val endMarker = "// PARALLEL_EXPORT_TEST_END"
    val begin = exporter.indexOf(beginMarker)
    val end = exporter.indexOf(endMarker)
    require(begin >= 0 && end > begin) { "production parallel exporter implementation markers are missing" }
    val implementation = exporter.substring(begin + beginMarker.length, end)
    val temporary = Files.createTempDirectory(Path.of("build").createDirectories(), "exporter-parallel-test-")
    try {
        val source = temporary.resolve("ParallelExporterHarness.java").also {
            it.writeText(PARALLEL_HARNESS_PREFIX + implementation + PARALLEL_HARNESS_BODY)
        }
        val compiler = ToolProvider.getSystemJavaCompiler() ?: error("parallel exporter tests require a JDK")
        val diagnostics = ByteArrayOutputStream()
        val result = compiler.run(null, diagnostics, diagnostics, "-Xlint:all", "-Werror", "-d", temporary.toString(), source.toString())
        check(result == 0) { diagnostics.toString(Charsets.UTF_8) }
        URLClassLoader(arrayOf(temporary.toUri().toURL())).use { loader ->
            loader.loadClass("ParallelExporterHarness").getMethod("run", String::class.java).invoke(null, scenario)
        }
    } finally {
        temporary.toFile().deleteRecursively()
    }
}

private val PARALLEL_HARNESS_PREFIX = """
    import java.io.IOException;
    import java.util.*;
    import java.util.concurrent.*;
    import java.util.concurrent.atomic.*;

""".trimIndent() + "\n"

private val PARALLEL_HARNESS_BODY = """
    public final class ParallelExporterHarness {
        static final class Metadata {
            final int index;
            final boolean complete;
            Metadata(int index, boolean complete) { this.index = index; this.complete = complete; }
        }
        static final class Result {
            final String status, body;
            Result(String status, String body) { this.status = status; this.body = body; }
        }
        static void require(boolean condition, String message) {
            if (!condition) throw new AssertionError(message);
        }
        static abstract class Source implements ExporterParallelCoordinatorV1.Source<Metadata, Result> {
            public void checkCancelled() throws Exception { }
            public boolean accepted(int index) { return false; }
            public boolean metadataComplete(Metadata metadata) { return metadata.complete; }
            public boolean retryRequired(Result result) { return result.status.equals("timeout"); }
            public boolean retrySucceeded(Result result) { return !result.status.equals("failed") && !result.status.equals("timeout"); }
        }
        static abstract class Worker implements ExporterParallelCoordinatorV1.Worker<Metadata, Result> {
            public void cancel() { }
            public void dispose() { }
        }
        public static void run(String scenario) throws Exception {
            switch (scenario) {
                case "reordering":
                    require(orderedRun(1).equals(orderedRun(4)), "scheduling changed canonical model or type ownership");
                    break;
                case "retry-success": retry("recovered"); break;
                case "retry-failure": retry("failed"); break;
                case "retry-partial": retry("partial"); break;
                case "cancellation": stopping(false); break;
                case "infrastructure": stopping(true); break;
                default: throw new AssertionError("unknown scenario");
            }
        }
        static String orderedRun(int workerCount) throws Exception {
            final int count = 12;
            CountDownLatch firstEntered = new CountDownLatch(1);
            CountDownLatch laterCommitted = new CountDownLatch(count - 1);
            AtomicInteger active = new AtomicInteger();
            AtomicInteger peakActive = new AtomicInteger();
            AtomicInteger disposed = new AtomicInteger();
            List<Integer> prepared = new ArrayList<>();
            List<Integer> committed = new ArrayList<>();
            Map<String, String> types = new TreeMap<>();
            Map<Integer, String> records = new TreeMap<>();
            int[] retained = {0, 0};
            List<ExporterParallelCoordinatorV1.Worker<Metadata, Result>> workers = new ArrayList<>();
            for (int i = 0; i < workerCount; i++) workers.add(new Worker() {
                public Result execute(Metadata metadata, boolean retry) throws Exception {
                    int now = active.incrementAndGet();
                    peakActive.accumulateAndGet(now, Math::max);
                    try {
                        if (workerCount > 1 && metadata.index == 0) {
                            firstEntered.countDown();
                            require(laterCommitted.await(3, TimeUnit.SECONDS), "earliest slow job blocked dispatch past the live-job window");
                        } else if (workerCount > 1) {
                            require(firstEntered.await(3, TimeUnit.SECONDS), "slow first job did not enter");
                        }
                        return new Result("recovered", "function:" + metadata.index);
                    } finally { active.decrementAndGet(); }
                }
                public void dispose() { disposed.incrementAndGet(); }
            });
            try (ExporterParallelCoordinatorV1<Metadata, Result> coordinator = new ExporterParallelCoordinatorV1<>(workers)) {
                coordinator.run(count, new Source() {
                    public Metadata prepare(int index, boolean retry) {
                        require(!retry && index == prepared.size(), "metadata was not prepared in address order");
                        prepared.add(index);
                        types.putIfAbsent("shared-type", "source:" + index);
                        retained[0]++;
                        retained[1] = Math.max(retained[1], retained[0]);
                        require(retained[0] <= workerCount, "completed but uncommitted jobs escaped the live-job bound");
                        return new Metadata(index, true);
                    }
                    public void commit(int index, Result result) {
                        require(records.put(index, result.body) == null, "function was committed twice");
                        committed.add(index);
                        retained[0]--;
                        if (index != 0) laterCommitted.countDown();
                    }
                });
            }
            require(prepared.size() == count && committed.size() == count && retained[0] == 0, "inventory was dropped");
            require(active.get() == 0 && disposed.get() == workerCount, "worker resources survived normal completion");
            require(peakActive.get() <= workerCount && retained[1] <= workerCount, "worker bound was exceeded");
            if (workerCount > 1) require(peakActive.get() > 1 && committed.get(0) != 0 && committed.get(count - 1) == 0,
                "completion was not deliberately reversed across concurrent workers");
            return records.toString() + types.toString();
        }
        static void retry(String retryStatus) throws Exception {
            List<String> preparation = new ArrayList<>();
            Map<String, Integer> types = new TreeMap<>();
            Map<Integer, String> records = new TreeMap<>();
            AtomicInteger firstCalls = new AtomicInteger();
            AtomicInteger retryCalls = new AtomicInteger();
            List<ExporterParallelCoordinatorV1.Worker<Metadata, Result>> workers = new ArrayList<>();
            for (int i = 0; i < 4; i++) workers.add(new Worker() {
                public Result execute(Metadata metadata, boolean retry) {
                    if (metadata.index == 0) {
                        if (!retry) { firstCalls.incrementAndGet(); return new Result("timeout", "original metadata failure and timeout"); }
                        retryCalls.incrementAndGet();
                        return new Result(retryStatus, "retry outcome");
                    }
                    return new Result("recovered", "function:" + metadata.index);
                }
            });
            try (ExporterParallelCoordinatorV1<Metadata, Result> coordinator = new ExporterParallelCoordinatorV1<>(workers)) {
                coordinator.run(8, new Source() {
                    public Metadata prepare(int index, boolean retry) {
                        if (index == 0 && retry) require(preparation.equals(List.of("0:false")), "later metadata stole first ownership before retry");
                        if (index > 0) require(records.containsKey(0), "metadata failure barrier ended before retry committed");
                        preparation.add(index + ":" + retry);
                        if (index != 0 || retry) types.putIfAbsent("shared-type", index);
                        return new Metadata(index, index != 0 || (retry && !retryStatus.equals("partial")));
                    }
                    public void commit(int index, Result result) { require(records.put(index, result.body) == null, "duplicate retry commit"); }
                });
            }
            require(types.get("shared-type") == 0, "retry metadata lost first ownership");
            require(firstCalls.get() == 1 && retryCalls.get() == 1 && records.size() == 8, "native retry changed inventory or retry count");
            require(records.get(0).equals(!retryStatus.equals("failed") ? "retry outcome" : "original metadata failure and timeout"), "retry outcome selection changed");
        }
        static void stopping(boolean infrastructure) throws Exception {
            CountDownLatch entered = new CountDownLatch(4);
            CountDownLatch release = new CountDownLatch(1);
            AtomicBoolean cancelled = new AtomicBoolean();
            AtomicInteger active = new AtomicInteger();
            AtomicInteger disposed = new AtomicInteger();
            AtomicInteger cancellations = new AtomicInteger();
            AtomicInteger commits = new AtomicInteger();
            AtomicReference<Throwable> failure = new AtomicReference<>();
            List<ExporterParallelCoordinatorV1.Worker<Metadata, Result>> workers = new ArrayList<>();
            for (int i = 0; i < 4; i++) workers.add(new Worker() {
                public Result execute(Metadata metadata, boolean retry) throws Exception {
                    active.incrementAndGet();
                    entered.countDown();
                    try {
                        if (infrastructure && metadata.index == 1) {
                            require(entered.await(3, TimeUnit.SECONDS), "peers did not enter before infrastructure fault");
                            throw new IOException("native transport fixture failure");
                        }
                        release.await();
                        throw new InterruptedException("native work cancelled");
                    } finally { active.decrementAndGet(); }
                }
                public void cancel() { cancellations.incrementAndGet(); release.countDown(); }
                public void dispose() { disposed.incrementAndGet(); }
            });
            Thread owner = new Thread(() -> {
                try (ExporterParallelCoordinatorV1<Metadata, Result> coordinator = new ExporterParallelCoordinatorV1<>(workers)) {
                    coordinator.run(20, new Source() {
                        public void checkCancelled() throws Exception { if (cancelled.get()) throw new InterruptedException("cancelled fixture owner"); }
                        public Metadata prepare(int index, boolean retry) { return new Metadata(index, true); }
                        public void commit(int index, Result result) { commits.incrementAndGet(); }
                    });
                } catch (Throwable problem) { failure.set(problem); }
            });
            try {
                owner.start();
                require(entered.await(3, TimeUnit.SECONDS), "all bounded workers did not enter");
                long started = System.nanoTime();
                if (!infrastructure) cancelled.set(true);
                owner.join(3_000);
                require(!owner.isAlive() && System.nanoTime() - started < TimeUnit.SECONDS.toNanos(3), "cleanup was not bounded");
                require(infrastructure ? failure.get() instanceof IOException : failure.get() instanceof InterruptedException,
                    "infrastructure or cancellation was reclassified: " + failure.get());
                require(active.get() == 0 && disposed.get() == 4 && cancellations.get() == 4, "worker resource leaked during failure");
                require(commits.get() == 0, "failed native work was published");
            } finally {
                cancelled.set(true);
                release.countDown();
                owner.interrupt();
                owner.join(3_000);
            }
        }
    }
""".trimIndent()

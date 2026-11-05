package decompengine.web

import decompengine.jobs.JobStore
import decompengine.repair.StableRegularFile
import java.lang.management.ManagementFactory
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Explicit CLI only. Uses production service callbacks; never executes a workflow. */
object StructureAllocationDiagnostic {
    @JvmStatic fun main(args: Array<String>) {
        val root = Path.of(args[0]); val mode = args[1]
        val bean = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
        bean.isThreadAllocatedMemoryEnabled = true
        fun allocated() = bean.getThreadAllocatedBytes(Thread.currentThread().threadId())
        val events = mutableListOf<JsonObject>()
        fun memory() = buildJsonObject {
            val heap = ManagementFactory.getMemoryMXBean().heapMemoryUsage
            put("heapUsed", heap.used); put("heapCommitted", heap.committed)
            put("vmRSS", Files.readAllLines(Path.of("/proc/self/status")).first { it.startsWith("VmRSS:") })
        }
        fun <T> measure(kind: String, name: String, action: () -> T): T {
            val a = allocated(); val n = System.nanoTime()
            val result = action()
            val bytes = allocated() - a; val nanos = System.nanoTime() - n
            events += buildJsonObject {
                put("kind", kind); put("name", name); put("allocatedBytes", bytes); put("nanos", nanos)
                if (result is StableRegularFile) { put("size", result.bytes.size); put("sha256", result.sha256) }
                if (kind == "request") put("memory", memory())
            }
            return result
        }
        val baseline = memory()
        WebJobService(JobStore(root), JobAnalyzer { _, _ -> error("No execution") },
            JobReconstructor { _, _ -> error("No execution") }).use { service ->
            service.initializeExistingStorage()
            fun field(target: Any, name: String) = target.javaClass.getDeclaredField(name).also { it.isAccessible = true }
            val evidence = field(service, "sourceCatalogEvidence").get(service) as WebSourceCatalogEvidence
            @Suppress("UNCHECKED_CAST")
            val input = field(evidence, "readInput").get(evidence) as (String) -> StableRegularFile
            @Suppress("UNCHECKED_CAST")
            val artifact = field(evidence, "readArtifact").get(evidence) as (String, String, Long) -> StableRegularFile
            field(evidence, "readInput").set(evidence, { job: String -> measure("read", "input.elf") { input(job) } })
            field(evidence, "readArtifact").set(evidence, { job: String, path: String, max: Long -> measure("read", path) { artifact(job, path, max) } })
            val referenceMethod = service.javaClass.getDeclaredMethod("revisionSourceReference", String::class.java, String::class.java, String::class.java).also { it.isAccessible = true }
            val cache = WebProgramStructureCache()
            var phaseAllocated = allocated()
            val pages = WebProgramStructurePages { job, run, revision, project ->
                if (mode == "service") service.readProgramStructure(job, run, revision, project)
                else {
                    val reference = referenceMethod.invoke(service, job, run, revision) as WebRevisionSourceReference
                    phaseAllocated = allocated()
                    evidence.readStructureMeasured(reference, cache, { phase, nanos ->
                        val now = allocated()
                        events += buildJsonObject { put("kind", "phase"); put("name", phase); put("nanos", nanos); put("allocatedSincePreviousMarker", now - phaseAllocated) }
                        phaseAllocated = allocated()
                    }, project)
                }
            }
            val job = "f".repeat(32); val run = "run_structure_scale"; val revision = "revision_structure_scale"
            var firstVersion: JsonElement? = null
            var cursor: String? = null
            repeat(51) { page ->
                val result = measure("request", "page-$page") { pages.functions("owner", job, run, revision, "limit=100" + (cursor?.let { "&cursor=$it" } ?: "")) }
                check(result.getValue("totalFunctions").jsonPrimitive.int == 100000)
                if (page == 0) firstVersion = result.getValue("page").jsonObject["snapshotVersion"]
                cursor = result.getValue("page").jsonObject["nextCursor"]?.jsonPrimitive?.contentOrNull
            }
            measure("request", "reload") { pages.functions("owner", job, run, revision, "limit=100") }
            measure("request", "search") { pages.functions("owner", job, run, revision, "search=synthetic_function_99999") }
            measure("request", "modules") { pages.modules("owner", job, run, revision, "limit=100") }
            if (mode != "service") {
                check(events.count { it["name"]?.jsonPrimitive?.content == "parse-model" } == 1)
                check(events.count { it["name"]?.jsonPrimitive?.content == "build-projection" } == 1)
                val manifest = root.resolve("$job/reports/runs/$run/source-tree/source_tree_manifest.json")
                val original = Files.readAllBytes(manifest)
                try {
                    Files.write(manifest, original + byteArrayOf(10))
                    val changed = measure("request", "changed-stable-manifest") { pages.functions("owner", job, run, revision, "limit=100") }
                    check(changed.getValue("page").jsonObject["snapshotVersion"] != firstVersion)
                    check(events.count { it["name"]?.jsonPrimitive?.content == "build-projection" } == 2)
                    check(events.count { it["name"]?.jsonPrimitive?.content == "parse-model" } == 2)
                } finally { Files.write(manifest, original) }
            }
        }
        Files.writeString(Path.of(args[2]), buildJsonObject {
            put("mode", mode); put("baseline", baseline); put("events", JsonArray(events))
            put("allocationNote", "Request totals include nested reads; phase marker deltas overlap nested timing scopes and are not exclusive. Heap used is not retained charge; no forced GC.")
        }.toString())
    }
}

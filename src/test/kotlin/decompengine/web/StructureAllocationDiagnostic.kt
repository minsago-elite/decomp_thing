package decompengine.web

import decompengine.jobs.JobStore
import decompengine.project.SourceTreeManifestProbe
import decompengine.project.SourceTreeManifestStage
import java.util.function.LongSupplier
import decompengine.repair.StableRegularFile
import decompengine.repair.StableComparison
import java.lang.management.ManagementFactory
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import kotlinx.serialization.json.*

/** Explicit CLI only. Uses production service callbacks; never executes a workflow. */
object StructureAllocationDiagnostic {
    @JvmStatic fun main(args: Array<String>) {
        val root = Path.of(args[0]); val mode = args[1]
        require(mode == "catalog" || mode == "service")
        fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        fun pins(): Map<String, String> = Files.walk(root).use { paths ->
            paths.filter { Files.isRegularFile(it) }.sorted().toList().associate { root.relativize(it).toString() to sha(Files.readAllBytes(it)) }
        }
        val sourcePins = pins()
        val sourceTree = "${"f".repeat(32)}/reports/runs/run_structure_scale/source-tree"
        check(sourcePins.size == 8344)
        check(Files.size(root.resolve("$sourceTree/reports/program_model.json")) == 29_349_734L)
        check(sourcePins["$sourceTree/reports/program_model.json"] == "be44553df47a17b40aac623a27a957b32e923f8137edf743a172525d0182c832")
        val bean = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
        bean.isThreadAllocatedMemoryEnabled = true
        fun allocated() = bean.getThreadAllocatedBytes(Thread.currentThread().threadId())
        val events = mutableListOf<JsonObject>()
        val manifestAttributions = mutableListOf<JsonObject>()
        val manifestProbe = ManifestAllocationCollector(
            LongSupplier { System.nanoTime() },
            LongSupplier { bean.getThreadAllocatedBytes(Thread.currentThread().threadId()) },
        )
        fun memory() = buildJsonObject {
            val heap = ManagementFactory.getMemoryMXBean().heapMemoryUsage
            put("heapUsed", heap.used); put("heapCommitted", heap.committed)
            put("vmRSS", Files.readAllLines(Path.of("/proc/self/status")).first { it.startsWith("VmRSS:") })
        }
        fun <T> measure(kind: String, name: String, action: () -> T): T {
            val a = allocated(); val n = System.nanoTime()
            var result: T? = null
            var failure: Throwable? = null
            try { return action().also { result = it } }
            catch (caught: Throwable) { failure = caught; throw caught }
            finally {
                val bytes = allocated() - a; val nanos = System.nanoTime() - n
                events += buildJsonObject {
                    put("kind", kind); put("name", name); put("allocatedBytes", bytes); put("nanos", nanos)
                    when (val value = result) {
                        is StableRegularFile -> { put("size", value.bytes.size); put("sha256", value.sha256) }
                        is StableComparison -> put("comparison", value.name)
                    }
                    failure?.let { put("failure", "${it.javaClass.name}: ${it.message}") }
                    if (kind == "request") put("memory", memory())
                }
            }
        }
        val baseline = memory()
        var failureMessage: String? = null
        try {
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
                @Suppress("UNCHECKED_CAST")
                val compare = field(evidence, "compareArtifact").get(evidence) as (String, String, Long, StableRegularFile) -> StableComparison
                field(evidence, "compareArtifact").set(evidence, { job: String, path: String, max: Long, expected: StableRegularFile ->
                    measure("compare", path) { compare(job, path, max, expected) }
                })
                val referenceMethod = service.javaClass.getDeclaredMethod("revisionSourceReference", String::class.java, String::class.java, String::class.java).also { it.isAccessible = true }
                val cache = if (mode == "service") field(service, "programStructureCache").get(service) as WebProgramStructureCache
                    else WebProgramStructureCache()
                var projected: WebProgramStructureIndex? = null
                val built = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<WebProgramStructureIndex, Boolean>())
                var phaseAllocated = allocated()
                val pages = WebProgramStructurePages { job, run, revision, project ->
                    val measuredProject: (WebProgramStructureIndex, () -> ByteArray) -> JsonObject = { index, model ->
                        projected = index
                        if (built.add(index)) {
                            val sourceRoot = root.resolve("$job/reports/runs/$run/source-tree")
                            val metadataBytes = Files.size(sourceRoot.resolve("source_tree_manifest.json")) +
                                Files.size(sourceRoot.resolve("reports/build_contract.json"))
                            events += buildJsonObject {
                                put("kind", "retention"); put("name", "projection-${built.size}")
                                put("modelSha256", index.model!!.sha256); put("planSha256", index.plan!!.sha256)
                                put("functions", index.table(WebStructureKind.FUNCTION).size)
                                put("globals", index.table(WebStructureKind.GLOBAL).size)
                                put("types", index.table(WebStructureKind.TYPE).size)
                                put("modules", index.modules.size)
                                put("sourceFiles", index.sourceFileIds.size)
                                put("callSlots", index.tables.sumOf { table -> table.calls.sumOf { it.size } })
                                put("globalSlots", index.tables.sumOf { table -> table.referencedGlobals.sumOf { it.size } })
                                put("planSlots", index.modules.sumOf { it.functionIds.size + it.globalIds.size + it.typeIds.size })
                                put("unknownPlanReferences", index.unknownPlanReferences)
                                put("indexBytes", index.retainedBytes); put("metadataBytes", metadataBytes)
                                put("entryBytes", index.retainedBytes + metadataBytes + 1024L)
                                put("maximumEntryBytes", 96L * 1024 * 1024)
                            }
                        }
                        project(index, model)
                    }
                    if (mode == "service") service.readProgramStructure(job, run, revision, measuredProject)
                    else {
                        val reference = referenceMethod.invoke(service, job, run, revision) as WebRevisionSourceReference
                        phaseAllocated = allocated()
                        evidence.readStructureDiagnosed(reference, cache, { phase, nanos ->
                            val now = allocated()
                            events += buildJsonObject { put("kind", "phase"); put("name", phase); put("nanos", nanos); put("allocatedSincePreviousMarker", now - phaseAllocated) }
                            if (phase == "validate-manifest") {
                                manifestAttributions += manifestProbe.snapshot(nanos)
                                manifestProbe.reset()
                            }
                            phaseAllocated = allocated()
                        }, { charges ->
                            events += buildJsonObject {
                                put("kind", "charges"); put("name", "build-${built.size + 1}"); put("total", charges.bytes)
                                put("categories", buildJsonObject { WebStructureCharge.entries.forEach { put(it.name, charges[it]) } })
                            }
                        }, manifestProbe, measuredProject)
                    }
                }
                val job = "f".repeat(32); val run = "run_structure_scale"; val revision = "revision_structure_scale"
                fun retained(): WebProgramStructureCache.Entry {
                    val index = checkNotNull(projected)
                    val candidates = cache.candidates(WebProgramStructureCache.Prefix(job, run, revision, index.reference.sourceSha256, index.inputSha256))
                    check(candidates.size == 1) { "Expected one retained entry under total cap, got ${candidates.size}" }
                    val entry = candidates.single()
                    check(entry.index === index)
                    check(entry.retainedBytes <= 96L * 1024 * 1024)
                    return entry
                }
                var firstVersion: JsonElement? = null
                var cursor: String? = null
                repeat(51) { page ->
                    val result = measure("request", "page-$page") { pages.functions("owner", job, run, revision, "limit=100" + (cursor?.let { "&cursor=$it" } ?: "")) }
                    check(result.getValue("totalFunctions").jsonPrimitive.int == 100000)
                    if (page == 0) {
                        firstVersion = result.getValue("page").jsonObject["snapshotVersion"]
                        // Cursor authenticators are process-local; all other response bytes are pinned.
                        val normalized = JsonObject(result + ("page" to JsonObject(result.getValue("page").jsonObject - "nextCursor")))
                        Files.writeString(Path.of(args[2] + ".first-page.json"), normalized.toString())
                    }
                    cursor = result.getValue("page").jsonObject["nextCursor"]?.jsonPrimitive?.contentOrNull
                }
                measure("request", "reload") { pages.functions("owner", job, run, revision, "limit=100") }
                measure("request", "search") { pages.functions("owner", job, run, revision, "search=synthetic_function_99999") }
                measure("request", "modules") { pages.modules("owner", job, run, revision, "limit=100") }
                val firstEntry = retained()
                check(built.size == 1)
                check(events.count { it["kind"]?.jsonPrimitive?.content == "read" && it["name"]?.jsonPrimitive?.content == "input.elf" } == 54)
                for (suffix in listOf("/program_model.json", "/module_plan.json")) {
                    check(events.count { it["kind"]?.jsonPrimitive?.content == "read" && it["name"]!!.jsonPrimitive.content.endsWith(suffix) } == 1)
                }
                events += buildJsonObject { put("kind", "checkpoint"); put("name", "54-requests"); put("builds", built.size); put("cacheRetained", true) }
                val manifestSuffix = "/source_tree_manifest.json"
                val descriptorSuffix = "/reports/build_contract.json"
                for (suffix in listOf(manifestSuffix, descriptorSuffix)) {
                    val reads = events.count { it["kind"]?.jsonPrimitive?.content == "read" && it["name"]!!.jsonPrimitive.content.endsWith(suffix) }
                    val comparisons = events.count { it["kind"]?.jsonPrimitive?.content == "compare" && it["name"]!!.jsonPrimitive.content.endsWith(suffix) }
                    check(reads == 1 && comparisons == 53) { "$suffix full reads=$reads comparisons=$comparisons; expected 1 and 53" }
                }
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
                        val changedEntry = retained()
                        check(cache.getEntry(firstEntry.key) == null)
                        check(firstEntry.retainedBytes + changedEntry.retainedBytes > 128L * 1024 * 1024)
                        val current = Files.readAllBytes(manifest)
                        val currentSha = sha(current)
                        val replacement = Path.of(args[2]).toAbsolutePath().parent.resolve("identical-current-manifest.json")
                        Files.write(replacement, current)
                        Files.move(replacement, manifest, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                        check(sha(Files.readAllBytes(manifest)) == currentSha)
                        val rebound = measure("request", "identical-current-manifest-new-inode") { pages.functions("owner", job, run, revision, "limit=100") }
                        check(rebound.getValue("page").jsonObject["snapshotVersion"] == changed.getValue("page").jsonObject["snapshotVersion"])
                        check(events.count { it["name"]?.jsonPrimitive?.content == "build-projection" } == 3)
                        check(events.count { it["name"]?.jsonPrimitive?.content == "parse-model" } == 3)
                        val reboundEntry = retained()
                        check(reboundEntry !== changedEntry && reboundEntry.index !== changedEntry.index)
                        check(reboundEntry.key == changedEntry.key)
                        check(reboundEntry.manifest.identity.key != changedEntry.manifest.identity.key)
                        events += buildJsonObject {
                            put("kind", "checkpoint"); put("name", "invalidation-and-rebind"); put("builds", built.size)
                            put("oldEntryEvicted", true); put("sameSha256", currentSha); put("differentInode", true)
                        }
                    } finally { Files.write(manifest, original) }
                }
            }
        } catch (failure: Throwable) {
            failureMessage = "${failure.javaClass.name}: ${failure.message}"
            throw failure
        } finally {
            val finalPins = pins()
            val restored = finalPins == sourcePins
            if (!restored && failureMessage == null) failureMessage = "Fixture source pins changed"
            Files.writeString(Path.of(args[2] + ".pins.json"), buildJsonObject {
                put("restored", restored); put("files", sourcePins.size)
                put("before", buildJsonObject { sourcePins.forEach { (path, hash) -> put(path, hash) } })
                put("after", buildJsonObject { finalPins.forEach { (path, hash) -> put(path, hash) } })
            }.toString())
            Files.writeString(Path.of(args[2]), buildJsonObject {
                put("mode", mode); put("fixtureRestored", restored); put("fixtureFiles", sourcePins.size); put("baseline", baseline); put("events", JsonArray(events))
                put("failure", failureMessage?.let(::JsonPrimitive) ?: JsonNull)
                put("manifestAttribution", JsonArray(manifestAttributions))
                put("coldMeasurementLimitation", "Fixture hashes are computed inside this JVM before its first request, warming filesystem/JVM state. These are attribution runs, not genuine-cold or D0 qualification evidence.")
                put("manifestAttributionNote", "Stage totals are exclusive and omit collector overhead and inter-stage map bookkeeping. FILE_FIELDS includes argument evaluation; FILE_EVIDENCE_INIT is the entire constructor; PATH_ORDER includes input identity and unresolved-ID checks. Do not add sub-markers to the enclosing validate-manifest or other nested phase/request timings and allocation deltas.")
                put("counters", buildJsonObject {
                    for (kind in listOf("read", "compare", "phase", "request")) {
                        put(kind, buildJsonObject {
                            events.filter { it["kind"]?.jsonPrimitive?.content == kind }
                                .groupingBy { it["name"]!!.jsonPrimitive.content }.eachCount().forEach { (name, count) -> put(name, count) }
                        })
                    }
                })
                put("allocationNote", "Request totals include nested reads; phase marker deltas overlap nested timing scopes and are not exclusive. Heap used is not retained charge; no forced GC.")
            }.toString())
            check(restored) { "Fixture source pins changed" }
        }
    }
}

/** Diagnostic-only allocation reads. Primitive suppliers also permit deterministic accounting controls. */
internal class ManifestAllocationCollector(
    private val nanoTime: LongSupplier,
    private val allocatedBytes: LongSupplier,
) : SourceTreeManifestProbe {
    private val nanos = LongArray(SourceTreeManifestStage.entries.size)
    private val bytes = LongArray(SourceTreeManifestStage.entries.size)
    private val segments = IntArray(SourceTreeManifestStage.entries.size)
    private var active: SourceTreeManifestStage? = null
    private var startedNanos = 0L
    private var startedBytes = 0L

    override fun start(stage: SourceTreeManifestStage) {
        end()
        active = stage
        startedBytes = allocatedBytes.asLong
        startedNanos = nanoTime.asLong
    }

    override fun end() {
        val stage = active ?: return
        val endedNanos = nanoTime.asLong
        val endedBytes = allocatedBytes.asLong
        active = null
        nanos[stage.ordinal] += endedNanos - startedNanos
        bytes[stage.ordinal] += endedBytes - startedBytes
        segments[stage.ordinal]++
    }

    fun snapshot(envelopeNanos: Long): JsonObject {
        check(active == null) { "Manifest stage was not closed" }
        return buildJsonObject {
            put("envelopeNanos", envelopeNanos)
            put("measuredNanos", nanos.sum())
            put("measuredAllocatedBytes", bytes.sum())
            put("stages", buildJsonObject {
                for (stage in SourceTreeManifestStage.entries) put(stage.marker, buildJsonObject {
                    put("nanos", nanos[stage.ordinal])
                    put("allocatedBytes", bytes[stage.ordinal])
                    put("segments", segments[stage.ordinal])
                })
            })
        }
    }

    fun reset() {
        check(active == null) { "Cannot reset an active manifest stage" }
        nanos.fill(0); bytes.fill(0); segments.fill(0)
    }
}

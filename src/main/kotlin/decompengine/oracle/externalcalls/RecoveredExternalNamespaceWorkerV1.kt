package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.requireStableDirectory
import decompengine.oracle.machinecalls.AuthenticatedMachineCallRuntimeV1
import decompengine.oracle.machinecalls.MachineCallFileV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV1
import decompengine.oracle.machinecalls.publishMachineCallResultV1
import decompengine.project.NativeCallAddressV1
import decompengine.project.NativeCallBindingsV1
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/** Raw native observations are selected before the authenticated ELF namespace is opened. */
internal data class RecoveredExternalNamespaceRequestV1(
    val nativeManifest: MachineCallFileV1,
    val nativeObservations: MachineCallFileV1,
    val artifactManifest: MachineCallFileV1,
    val richFile: MachineCallFileV1,
    val strippedFile: MachineCallFileV1,
    val expectedNativeBindings: NativeCallBindingsV1,
    val runtime: MachineCallRuntimeV1,
    val outputPath: Path,
    val limits: RecoveredExternalNamespaceLimitsV1 = RecoveredExternalNamespaceLimitsV1(),
) {
    init {
        requirePath(outputPath)
        require(nativeManifest.bytes <= 64 * 1024 && nativeObservations.bytes <= 64L * 1024 * 1024 &&
            artifactManifest.bytes <= 2L * 1024 * 1024 && richFile.bytes <= 512L * 1024 * 1024 &&
            strippedFile.bytes <= 512L * 1024 * 1024) { "recovered external namespace input exceeds its bound" }
        val inputs = listOf(nativeManifest.path, nativeObservations.path, artifactManifest.path, richFile.path, strippedFile.path)
        require(inputs.distinct().size == inputs.size && outputPath !in inputs && outputPath != runtime.ghidraArchivePath &&
            !outputPath.startsWith(runtime.bundleRoot)) { "recovered external namespace input/output paths overlap" }
        with(expectedNativeBindings) {
            listOf(collectorSha256, ghidraArchiveSha256, inputSha256, programModelExporterSha256, programModelSha256).forEach(::requireDigest)
            require(programModelBytes in 1..512L * 1024 * 1024 && !imageBase.isNoAddress && imageBase.spaceIndex!! < 256)
            require(compilerSpecId.length in 1..4096 && compilerSpecId.none { it.code < 32 || it.code == 127 })
            require(inputSha256 == strippedFile.sha256 && languageId == runtime.languageId && ghidraArchiveSha256 == runtime.archiveSha256) {
                "native input or runtime commitments differ"
            }
        }
    }

    val canonicalBytes: ByteArray get() = OracleJson.canonicalBytes(JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1), "kind" to JsonPrimitive(REQUEST_KIND),
        "nativeManifest" to nativeManifest.json(), "nativeObservations" to nativeObservations.json(),
        "artifactManifest" to artifactManifest.json(), "richFile" to richFile.json(), "strippedFile" to strippedFile.json(),
        "expectedNativeBindings" to nativeExternalBindingsJsonV1(expectedNativeBindings), "runtime" to runtime.json(),
        "outputPath" to JsonPrimitive(outputPath.toString()), "limits" to limits.toJson(),
    )), REQUEST_LIMITS)

    companion object {
        fun parse(bytes: ByteArray): RecoveredExternalNamespaceRequestV1 {
            val root = OracleJson.parseCanonical(bytes, REQUEST_LIMITS) as? JsonObject
                ?: error("recovered external namespace request must be an object")
            root.fields("schemaVersion", "kind", "nativeManifest", "nativeObservations", "artifactManifest", "richFile", "strippedFile",
                "expectedNativeBindings", "runtime", "outputPath", "limits")
            require(root.number("schemaVersion") == 1L && root.string("kind") == REQUEST_KIND)
            fun input(key: String): MachineCallFileV1 {
                val record = root.obj(key)
                record.fields("path", "bytes", "sha256")
                return MachineCallFileV1(Path.of(record.string("path")), record.number("bytes"), record.string("sha256"))
            }
            val binding = root.obj("expectedNativeBindings")
            binding.fields("collectorSha256", "compilerSpecId", "ghidraArchiveSha256", "imageBase", "inputSha256", "languageId",
                "programModelBytes", "programModelExporterSha256", "programModelSha256")
            val base = binding.obj("imageBase")
            base.fields("kind", "spaceIndex", "offsetBits")
            require(base.string("kind") == "address")
            val native = NativeCallBindingsV1(binding.string("collectorSha256"), binding.string("compilerSpecId"),
                binding.string("ghidraArchiveSha256"), NativeCallAddressV1(Math.toIntExact(base.number("spaceIndex")), base.string("offsetBits")),
                binding.string("inputSha256"), binding.string("languageId"), binding.number("programModelBytes"),
                binding.string("programModelExporterSha256"), binding.string("programModelSha256"))
            val runtime = root.obj("runtime")
            runtime.fields("bundleRoot", "ghidraArchivePath", "archiveSha256", "archiveBytes", "bridgeSha256", "bundleManifestSha256", "languageId", "languageVersion")
            val limits = root.obj("limits")
            limits.fields("maximumSites", "maximumWorkUnits", "maximumOutputBytes", "maximumWallMillis")
            return RecoveredExternalNamespaceRequestV1(input("nativeManifest"), input("nativeObservations"), input("artifactManifest"),
                input("richFile"), input("strippedFile"), native,
                MachineCallRuntimeV1(Path.of(runtime.string("bundleRoot")), Path.of(runtime.string("ghidraArchivePath")),
                    runtime.string("archiveSha256"), runtime.number("archiveBytes"), runtime.string("bridgeSha256"),
                    runtime.string("bundleManifestSha256"), runtime.string("languageId"), runtime.string("languageVersion")),
                Path.of(root.string("outputPath")), RecoveredExternalNamespaceLimitsV1(Math.toIntExact(limits.number("maximumSites")),
                    limits.number("maximumWorkUnits"), Math.toIntExact(limits.number("maximumOutputBytes")), limits.number("maximumWallMillis")))
        }
    }
}

/** Standalone diagnostic computation; the external owner supplies process containment and cleanup. */
object RecoveredExternalNamespaceWorkerV1 {
    @JvmStatic fun main(arguments: Array<String>) {
        require(arguments.size == 2) { "recovered external namespace worker requires request path and SHA-256" }
        run(Path.of(arguments[0]), arguments[1])
    }

    internal fun run(requestPath: Path, requestSha256: String, checkpoint: (String) -> Unit = {}) {
        requirePath(requestPath)
        requireDigest(requestSha256)
        val budget = WorkerBudget(checkpoint)
        StableControlFile.openWithCheckpoint(requestPath, REQUEST_LIMITS.maximumInputBytes.toLong(), "recovered namespace request", budget::step).use { requestFile ->
            require(requestFile.authenticatedSha256 == requestSha256) { "recovered namespace request commitment differs" }
            val request = RecoveredExternalNamespaceRequestV1.parse(requestFile.readExactly(0, requestFile.size.toInt(), "recovered namespace request", budget::step))
            budget.configure(request.limits)
            val inputPaths = listOf(request.nativeManifest.path, request.nativeObservations.path, request.artifactManifest.path, request.richFile.path, request.strippedFile.path)
            require(requestPath !in inputPaths && request.outputPath != requestPath && requestPath != request.runtime.ghidraArchivePath &&
                !requestPath.startsWith(request.runtime.bundleRoot)) { "recovered namespace request path overlaps an input or output" }
            requireStableDirectory(requireNotNull(request.outputPath.parent), "recovered namespace output parent")
            require(!Files.exists(request.outputPath, LinkOption.NOFOLLOW_LINKS)) { "recovered namespace output already exists" }
            openCommitted(request.nativeManifest, "native external manifest", budget::step).use { nativeManifest ->
                openCommitted(request.nativeObservations, "native external observations", budget::step).use { nativeObservations ->
                    val frozen = FrozenNativeExternalClaimsV1.freeze(
                        nativeManifest.readExactly(0, nativeManifest.size.toInt(), "native external manifest", budget::step),
                        nativeObservations.readExactly(0, nativeObservations.size.toInt(), "native external observations", budget::step),
                        request.expectedNativeBindings, NativeExternalClaimLimitsV1(maximumSites = request.limits.maximumSites),
                    ) { budget.step("freeze native external claims") }
                    budget.step("after-native-freeze")
                    nativeManifest.verifyUnchanged("native external manifest after freeze")
                    nativeObservations.verifyUnchanged("native external observations after freeze")
                    // These are the first opens of any independent ELF or namespace metadata input.
                    openCommitted(request.artifactManifest, "external namespace artifact manifest", budget::step).use { artifactManifest ->
                        openCommitted(request.richFile, "external namespace rich ELF", budget::step).use { rich ->
                            openCommitted(request.strippedFile, "external namespace stripped ELF", budget::step).use { stripped ->
                                val pair = ElfExternalNamespacePairV1.prove(artifactManifest, request.artifactManifest.sha256, rich, stripped,
                                    ElfExternalNamespacePairLimitsV1(maximumWorkUnits = maxOf(16, request.limits.maximumWorkUnits),
                                        maximumOutputBytes = request.limits.maximumOutputBytes, maximumWallMillis = request.limits.maximumWallMillis), budget::step)
                                AuthenticatedMachineCallRuntimeV1.open(request.runtime, budget::step).use { runtime ->
                                    val result = runtime.withDecoder { basic -> runtime.withStaticMemoryTransferDecoder { memory ->
                                        RecoveredExternalNamespaceV1.compose(frozen, pair, basic, memory, request.limits, budget::step)
                                    } }
                                    val final = JsonObject(result + mapOf(
                                        "requestSha256" to JsonPrimitive(requestSha256), "runtime" to request.runtime.json(),
                                        "decoderAuthentication" to JsonPrimitive("authenticated-bundled-worker-v1"),
                                        "containmentStatus" to JsonPrimitive("external-owner-required"),
                                    ))
                                    validateRecoveredExternalWorkerCommitmentsV1(final, requestSha256, request, budget::step)
                                    val bytes = OracleJson.canonicalBytes(final, recoveryNamespaceJsonLimits(request.limits), budget::step)
                                    runtime.verify(budget::step)
                                    pair.requireCurrent()
                                    nativeManifest.verifyUnchanged("native external manifest before publication")
                                    nativeObservations.verifyUnchanged("native external observations before publication")
                                    requestFile.verifyUnchanged("recovered namespace request before publication")
                                    budget.step("before publication")
                                    publishMachineCallResultV1(request.outputPath, bytes)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/** Checks request/output commitments only. Raw native sources and the held pair remain necessary for full revalidation. */
internal fun validateRecoveredExternalWorkerCommitmentsV1(
    document: JsonObject, expectedRequestSha256: String, request: RecoveredExternalNamespaceRequestV1,
    checkpoint: (String) -> Unit = {},
) {
    OracleJson.canonicalBytes(document, recoveryNamespaceJsonLimits(request.limits), checkpoint)
    requireDigest(expectedRequestSha256)
    require(OracleArtifacts.sha256(request.canonicalBytes) == expectedRequestSha256)
    require(document.keys == COMPONENT_FIELDS + setOf("requestSha256", "runtime", "containmentStatus")) { "unexpected recovered namespace worker fields" }
    require(document["schemaVersion"] == JsonPrimitive(1) && document["kind"] == JsonPrimitive("recovered-external-namespace-component-v1") &&
        document["scope"] == JsonPrimitive("component") && document["policy"] == JsonPrimitive("native-claim-before-pair-v1"))
    require(document["requestSha256"] == JsonPrimitive(expectedRequestSha256) && document["runtime"] == request.runtime.json() &&
        document["limits"] == request.limits.toJson()) { "recovered namespace worker commitments differ" }
    require(document["decoderAuthentication"] == JsonPrimitive("authenticated-bundled-worker-v1") &&
        document["containmentStatus"] == JsonPrimitive("external-owner-required") && document["rawSitesEnumerated"] == JsonPrimitive(true))
    for (key in listOf("complete", "releaseEligible", "negativeCompleteness", "productionVerified", "runtimeProviderAvailable", "runtimeImplementationAvailable")) {
        require(document[key] == JsonPrimitive(false)) { "recovered namespace worker grants unsupported authority" }
    }
    val binding = document.obj("frozenClaimsBinding")
    binding.fields("schemaVersion", "kind", "rawSourcesRequired", "manifestSha256", "manifestBytes", "observationsSha256", "observationsBytes",
        "frozenClaimsSha256", "frozenClaimsBytes", "policySha256", "inputSha256", "programModelSha256", "programModelBytes",
        "rawRecordCount", "rawSiteCount", "bindings", "negativeCompleteness")
    require(binding["schemaVersion"] == JsonPrimitive(1) && binding["kind"] == JsonPrimitive("required-frozen-native-external-source-binding-v1") &&
        binding["rawSourcesRequired"] == JsonPrimitive(true) && binding["negativeCompleteness"] == JsonPrimitive(false))
    require(binding["manifestSha256"] == JsonPrimitive(request.nativeManifest.sha256) && binding["manifestBytes"] == JsonPrimitive(request.nativeManifest.bytes) &&
        binding["observationsSha256"] == JsonPrimitive(request.nativeObservations.sha256) && binding["observationsBytes"] == JsonPrimitive(request.nativeObservations.bytes) &&
        binding["inputSha256"] == JsonPrimitive(request.strippedFile.sha256) &&
        binding["programModelSha256"] == JsonPrimitive(request.expectedNativeBindings.programModelSha256) &&
        binding["programModelBytes"] == JsonPrimitive(request.expectedNativeBindings.programModelBytes) &&
        binding["bindings"] == nativeExternalBindingsJsonV1(request.expectedNativeBindings)) { "recovered namespace native source commitments differ" }
    require(binding["frozenClaimsSha256"] == document["frozenClaimsSha256"])
    requireDigest(binding.string("frozenClaimsSha256"))
    requireDigest(binding.string("policySha256"))
    require(binding.number("frozenClaimsBytes") in 1..64L * 1024 * 1024 && binding.number("rawRecordCount") in 0..362144 &&
        binding.number("rawSiteCount") in 0..request.limits.maximumSites.toLong())
    val pair = document.obj("pairProof")
    require(pair["manifestSha256"] == JsonPrimitive(request.artifactManifest.sha256) &&
        pair["rich"] == pinJson(request.richFile) && pair["stripped"] == pinJson(request.strippedFile)) {
        "recovered namespace ELF commitments differ"
    }
    for ((payload, digest) in listOf("pairProof" to "pairProofSha256", "externalNamespace" to "externalNamespaceSha256")) {
        val expected = document.string(digest)
        requireDigest(expected)
        require(OracleArtifacts.sha256(OracleJson.canonicalBytes(document.obj(payload), recoveryNamespaceJsonLimits(request.limits), checkpoint)) == expected) {
            "recovered namespace payload commitment differs: $payload"
        }
    }
}

private class WorkerBudget(private val checkpoint: (String) -> Unit) {
    private val started = System.nanoTime()
    private var limits = RecoveredExternalNamespaceLimitsV1()
    private var work = 0L
    fun configure(value: RecoveredExternalNamespaceLimitsV1) { limits = value; step("configured worker budget") }
    fun step(stage: String) {
        require(++work <= limits.maximumWorkUnits) { "recovered namespace worker work limit exceeded" }
        check(!Thread.currentThread().isInterrupted) { "recovered namespace worker interrupted: $stage" }
        check((System.nanoTime() - started) / 1_000_000 <= limits.maximumWallMillis) { "recovered namespace worker wall limit exceeded: $stage" }
        checkpoint(stage)
    }
}

private fun pinJson(input: MachineCallFileV1) = JsonObject(mapOf("sha256" to JsonPrimitive(input.sha256), "bytes" to JsonPrimitive(input.bytes)))
private fun openCommitted(input: MachineCallFileV1, label: String, checkpoint: (String) -> Unit): StableControlFile {
    val file = StableControlFile.openWithCheckpoint(input.path, input.bytes, label, checkpoint)
    try {
        require(file.size == input.bytes && file.authenticatedSha256 == input.sha256) { "$label bytes or SHA-256 differ" }
        return file
    } catch (failure: Throwable) { file.close(); throw failure }
}
private fun requirePath(path: Path) {
    val text = path.toString()
    require(path.isAbsolute && path.normalize() == path && path.parent != null && text.length in 1..4096 && text.none { it.code < 32 || it.code == 127 })
}
private fun requireDigest(value: String) { require(value.matches(Regex("[0-9a-f]{64}"))) }
private fun JsonObject.fields(vararg keys: String) { require(this.keys == keys.toSet()) { "unknown or missing recovered namespace request fields" } }
private fun JsonObject.obj(key: String): JsonObject = getValue(key) as? JsonObject ?: error("$key must be an object")
private fun JsonObject.string(key: String): String = (getValue(key) as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("$key must be a string")
private fun JsonObject.number(key: String): Long = (getValue(key) as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull ?: error("$key must be an integer")
private const val REQUEST_KIND = "recovered-external-namespace-request-v1"
private val REQUEST_LIMITS = StrictJsonLimits(maximumInputBytes = 65536, maximumCanonicalBytes = 65536, maximumDepth = 8,
    maximumNodes = 256, maximumStringBytes = 4096, maximumTotalStringBytes = 32768)
private val COMPONENT_FIELDS = setOf("schemaVersion", "kind", "scope", "policy", "decoderAuthentication", "complete", "releaseEligible",
    "negativeCompleteness", "productionVerified", "runtimeProviderAvailable", "runtimeImplementationAvailable", "rawSitesEnumerated",
    "frozenClaimsSha256", "frozenClaimsBinding", "pairProofSha256", "pairProof", "externalNamespaceSha256", "externalNamespace", "sites", "counts", "limits")

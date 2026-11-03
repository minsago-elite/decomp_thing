package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.machinecalls.AuthenticatedMachineCallRuntimeV2
import decompengine.oracle.machinecalls.MachineCallFileV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV2
import decompengine.oracle.machinecalls.publishMachineCallResultV1
import java.nio.file.Path
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/** Closed commitments to independently retained inputs; original source-request paths are not inputs. */
internal data class IndependentExternalCallRequestV1(
    val richFile: MachineCallFileV1,
    val sourceReport: MachineCallFileV1,
    val sourceRequest: MachineCallFileV1,
    val runtime: MachineCallRuntimeV1,
    val outputPath: Path,
    val limits: ExternalCallLimitsV1 = ExternalCallLimitsV1(),
) {
    init {
        requirePath(outputPath)
        require(richFile.bytes <= 512L * 1024 * 1024 && sourceReport.bytes <= 64L * 1024 * 1024 && sourceRequest.bytes <= 65536) {
            "external-call inputs exceed their producer bounds"
        }
        val inputs = listOf(richFile.path, sourceReport.path, sourceRequest.path)
        require(inputs.distinct().size == inputs.size && outputPath !in inputs && outputPath != runtime.ghidraArchivePath &&
            !outputPath.startsWith(runtime.bundleRoot)) { "external-call input/output paths overlap" }
        require(limits.metadata == ElfDynamicBindingLimitsV1()) { "external-call worker supports only the pinned default metadata policy" }
    }

    val canonicalBytes: ByteArray get() = OracleJson.canonicalBytes(JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1), "kind" to JsonPrimitive(REQUEST_KIND),
        "richFile" to richFile.json(), "sourceReport" to sourceReport.json(), "sourceRequest" to sourceRequest.json(),
        "runtime" to runtime.json(), "outputPath" to JsonPrimitive(outputPath.toString()),
        "limits" to externalCallLimitsJsonV1(limits), "metadataPolicy" to JsonPrimitive(METADATA_POLICY),
    )), REQUEST_LIMITS)

    companion object {
        fun parse(bytes: ByteArray): IndependentExternalCallRequestV1 {
            val root = OracleJson.parseCanonical(bytes, REQUEST_LIMITS) as? JsonObject
                ?: throw IllegalArgumentException("external-call request must be an object")
            root.fields("schemaVersion", "kind", "richFile", "sourceReport", "sourceRequest", "runtime", "outputPath", "limits", "metadataPolicy")
            require(root.number("schemaVersion") == 1L && root.string("kind") == REQUEST_KIND && root.string("metadataPolicy") == METADATA_POLICY)
            fun input(key: String): MachineCallFileV1 {
                val record = root.obj(key)
                record.fields("path", "bytes", "sha256")
                return MachineCallFileV1(Path.of(record.string("path")), record.number("bytes"), record.string("sha256"))
            }
            val runtime = root.obj("runtime")
            runtime.fields("bundleRoot", "ghidraArchivePath", "archiveSha256", "archiveBytes", "bridgeSha256", "bundleManifestSha256", "languageId", "languageVersion")
            val limits = root.obj("limits")
            limits.fields("maximumCalls", "maximumWorkUnits", "maximumOutputBytes", "maximumWallMillis")
            return IndependentExternalCallRequestV1(input("richFile"), input("sourceReport"), input("sourceRequest"),
                MachineCallRuntimeV1(Path.of(runtime.string("bundleRoot")), Path.of(runtime.string("ghidraArchivePath")),
                    runtime.string("archiveSha256"), runtime.number("archiveBytes"), runtime.string("bridgeSha256"),
                    runtime.string("bundleManifestSha256"), runtime.string("languageId"), runtime.string("languageVersion")),
                Path.of(root.string("outputPath")), ExternalCallLimitsV1(Math.toIntExact(limits.number("maximumCalls")),
                    limits.number("maximumWorkUnits"), Math.toIntExact(limits.number("maximumOutputBytes")), limits.number("maximumWallMillis")))
        }
    }
}

/** Live request; V1 remains available only to frozen readers and compatibility tests. */
internal data class IndependentExternalCallRequestV2(
    val legacy: IndependentExternalCallRequestV1,
    val runtime: MachineCallRuntimeV2,
    val controlRoot: Path,
) {
    val richFile get() = legacy.richFile
    val sourceReport get() = legacy.sourceReport
    val sourceRequest get() = legacy.sourceRequest
    val outputPath get() = legacy.outputPath
    val limits get() = legacy.limits
    init {
        require(controlRoot.isAbsolute && controlRoot.normalize() == controlRoot &&
            controlRoot == legacy.outputPath.parent?.parent && legacy.outputPath ==
                controlRoot.resolve("reports/independent-external-call-observations.json")) {
            "external-call output path differs from fixed owned control root"
        }
        requireExternalRuntimeSnapshotBindingsShape(runtime, controlRoot)
    }
    val canonicalBytes: ByteArray get() = v2ExternalRequestBytes(legacy.canonicalBytes, runtime, controlRoot,
        "independent-external-call-request-v2")

    companion object {
        fun parse(bytes: ByteArray): IndependentExternalCallRequestV2 {
            val root = OracleJson.parseCanonical(bytes, REQUEST_LIMITS) as? JsonObject
                ?: error("external-call V2 request must be an object")
            root.fields("schemaVersion", "kind", "richFile", "sourceReport", "sourceRequest", "runtime", "controlRoot",
                "outputPath", "limits", "metadataPolicy")
            require(root.number("schemaVersion") == 2L && root.string("kind") == "independent-external-call-request-v2" &&
                root.string("metadataPolicy") == METADATA_POLICY)
            val runtime = parseMachineCallRuntimeV2(root.obj("runtime"))
            val legacy = IndependentExternalCallRequestV1.parse(legacyExternalRequestBytes(root, runtime, REQUEST_KIND))
            return IndependentExternalCallRequestV2(legacy, runtime, Path.of(root.string("controlRoot")))
        }
    }
}

private fun requireExternalRuntimeSnapshotBindingsShape(runtime: MachineCallRuntimeV2, controlRoot: Path) {
    require(runtime.bridgeSnapshot.path == controlRoot.resolve("runtime/ghidra-bridge.runtime") &&
        runtime.bundleManifestSnapshot.path == controlRoot.resolve("runtime/ghidra-bundle-manifest.runtime")) {
        "external-call snapshots differ from fixed control-root locations"
    }
}

/** Diagnostic child computation. Process isolation, resource limits and cleanup remain the external owner's responsibility. */
object IndependentExternalCallWorkerV1 {
    @JvmStatic fun main(arguments: Array<String>) {
        require(arguments.size == 2) { "external-call worker requires request path and SHA-256" }
        run(Path.of(arguments[0]), arguments[1])
    }

    internal fun run(requestPath: Path, requestSha256: String) {
        requirePath(requestPath)
        requireDigest(requestSha256)
        StableControlFile.open(requestPath, REQUEST_LIMITS.maximumInputBytes.toLong(), "external-call request").use { requestFile ->
            require(requestFile.authenticatedSha256 == requestSha256) { "external-call request commitment differs" }
            val request = IndependentExternalCallRequestV2.parse(requestFile.readExactly(0, requestFile.size.toInt(), "external-call request"))
            val legacy = request.legacy
            require(legacy.outputPath != requestPath) { "external-call output overlaps its request" }
            val started = System.nanoTime()
            val checkpoint: (String) -> Unit = { stage ->
                check(!Thread.currentThread().isInterrupted) { "external-call worker interrupted: $stage" }
                check((System.nanoTime() - started) / 1000000L <= legacy.limits.maximumWallMillis) { "external-call worker wall limit exceeded: $stage" }
            }
            openCommitted(legacy.richFile, "external-call rich ELF", checkpoint).use { rich ->
                openCommitted(legacy.sourceReport, "external-call source report", checkpoint).use { sourceReport ->
                    openCommitted(legacy.sourceRequest, "external-call source request", checkpoint).use { sourceRequest ->
                        AuthenticatedMachineCallRuntimeV2.open(request.runtime, checkpoint).use { runtime ->
                            val result = runtime.withDecoder { basic ->
                                runtime.withStaticMemoryTransferDecoder { memory ->
                                    IndependentExternalCallsV1.produce(legacy.richFile.path, legacy.sourceReport.path, legacy.sourceRequest.path,
                                        legacy.richFile.sha256, legacy.sourceReport.sha256, legacy.sourceRequest.sha256, basic, memory, legacy.limits)
                                }
                            }
                            runtime.verify(checkpoint)
                            rich.verifyUnchanged("external-call rich ELF after composition")
                            sourceReport.verifyUnchanged("external-call source report after composition")
                            sourceRequest.verifyUnchanged("external-call source request after composition")
                            requestFile.verifyUnchanged("external-call request after composition")
                            checkpoint("before publication")
                            val final = JsonObject(result + mapOf(
                                "requestSha256" to JsonPrimitive(requestSha256), "runtime" to request.runtime.reportJson(),
                                "limits" to externalCallLimitsJsonV1(legacy.limits), "metadataPolicy" to JsonPrimitive(METADATA_POLICY),
                                "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false), "negativeCompleteness" to JsonPrimitive(false),
                                "decoderAuthentication" to JsonPrimitive("authenticated-bundled-worker-v1"),
                                "containmentStatus" to JsonPrimitive("external-owner-required"),
                            ))
                            IndependentExternalCallReportV1.validateWorker(final, requestSha256, request)
                            val bytes = OracleJson.canonicalBytes(final, outputLimits(legacy.limits), checkpoint)
                            publishMachineCallResultV1(legacy.outputPath, bytes)
                        }
                    }
                }
            }
        }
    }
}

/** Worker commitments only; component-wide evidence consistency is validated by its composer/consumer. */
internal fun validateExternalWorkerCommitmentsV1(document: JsonObject, expectedRequestSha256: String, request: IndependentExternalCallRequestV1,
    canonicalRequestBytes: ByteArray = request.canonicalBytes) {
    requireDigest(expectedRequestSha256)
    require(OracleArtifacts.sha256(canonicalRequestBytes) == expectedRequestSha256)
    require(document["requestSha256"] == JsonPrimitive(expectedRequestSha256) && document["runtime"] == request.runtime.json() &&
        document["limits"] == externalCallLimitsJsonV1(request.limits) && document["metadataPolicy"] == JsonPrimitive(METADATA_POLICY)) {
        "external-call worker commitments differ"
    }
    require(document["inputSha256"] == JsonPrimitive(request.richFile.sha256) && document["inputBytes"] == JsonPrimitive(request.richFile.bytes) &&
        document["sourceReportSha256"] == JsonPrimitive(request.sourceReport.sha256) && document["sourceRequestSha256"] == JsonPrimitive(request.sourceRequest.sha256))
    require(document["decoderAuthentication"] == JsonPrimitive("authenticated-bundled-worker-v1") &&
        document["containmentStatus"] == JsonPrimitive("external-owner-required"))
    require(document["schemaVersion"] == JsonPrimitive(1) && document["kind"] == JsonPrimitive("independent-external-call-component-v1") &&
        document["scope"] == JsonPrimitive("component"))
    for (key in listOf("complete", "releaseEligible", "negativeCompleteness")) require(document[key] == JsonPrimitive(false))
}

internal fun externalCallLimitsJsonV1(limits: ExternalCallLimitsV1): JsonObject = JsonObject(mapOf(
    "maximumCalls" to JsonPrimitive(limits.maximumCalls), "maximumWorkUnits" to JsonPrimitive(limits.maximumWorkUnits),
    "maximumOutputBytes" to JsonPrimitive(limits.maximumOutputBytes), "maximumWallMillis" to JsonPrimitive(limits.maximumWallMillis),
))

/** Exact JDK-only record conversion. Source identity and same-loader checks precede this function. */
internal fun staticMemoryTransferFromBridgeV1(record: Any): StaticMemoryTransferV1 {
    val components = record.javaClass.recordComponents
    require(record.javaClass.isRecord && components != null) { "static memory decoder did not return a record" }
    val types = mapOf("address" to String::class.java, "length" to Int::class.javaPrimitiveType, "bytes" to ByteArray::class.java,
        "classification" to String::class.java, "pointerSlotAddress" to String::class.java, "pointerWidthBytes" to Int::class.javaObjectType,
        "relationship" to String::class.java, "rawReadOpcode" to String::class.java, "rawReadOpIndex" to Int::class.javaObjectType,
        "rawTransferOpcode" to String::class.java, "rawTransferOpIndex" to Int::class.javaObjectType, "rawCopyOpIndices" to List::class.java,
        "contextStatus" to String::class.java, "unresolvedReason" to String::class.java)
    require(components.size == types.size && components.all { types[it.name] === it.type }) { "static memory decoder record schema differs" }
    val values = components.associate { it.name to it.accessor.invoke(record) }
    fun string(key: String, nullable: Boolean = false): String? {
        val value = values.getValue(key)
        if (nullable && value == null) return null
        require(value is String && value.length in 1..128 && value.none { it.code < 32 || it.code == 127 }) { "invalid static memory decoder string" }
        return value
    }
    fun address(key: String, nullable: Boolean = false): ULong? = string(key, nullable)?.let {
        require(it.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})"))) { "invalid static memory decoder address" }
        it.substring(2).toULong(16)
    }
    fun index(key: String): Int? = values.getValue(key)?.let {
        require(it is Int && it in 0..4095) { "invalid static memory decoder p-code index" }; it
    }
    val length = values.getValue("length") as? Int ?: error("invalid static memory decoder length")
    val bytes = values.getValue("bytes") as? ByteArray ?: error("invalid static memory decoder bytes")
    require(length in 1..15 && bytes.size == length)
    val copies = values.getValue("rawCopyOpIndices") as? List<*> ?: error("invalid static memory decoder copy chain")
    require(copies.size <= 4096 && copies.all { it is Int && it in 0..4095 })
    val copyIndices = copies.map { it as Int }
    require(copyIndices == copyIndices.distinct().sorted())
    val classification = requireNotNull(string("classification"))
    require(classification in CLASSIFICATIONS)
    val context = requireNotNull(string("contextStatus"))
    require(context in setOf("language-default-no-commits-v1", "context-change", "unassessed-userop-context", "unassessed-pcode-context"))
    require(classification.startsWith("unsupported-") || context == "language-default-no-commits-v1")
    val slot = address("pointerSlotAddress", true)
    val width = values.getValue("pointerWidthBytes") as? Int
    val relationship = requireNotNull(string("relationship"))
    val readOpcode = string("rawReadOpcode", true); val readIndex = index("rawReadOpIndex")
    val transferOpcode = string("rawTransferOpcode", true); val transferIndex = index("rawTransferOpIndex")
    val reason = string("unresolvedReason", true)
    val expectedTransfer = when (classification) { "indirect-call" -> "CALLIND"; "indirect-jump" -> "BRANCHIND"; else -> null }
    require((transferOpcode == null) == (transferIndex == null))
    require(transferOpcode == null || transferOpcode == expectedTransfer)
    if (slot == null) {
        require(width == null && relationship == "unresolved" && reason in UNRESOLVED_REASONS && readOpcode == null && readIndex == null && copyIndices.isEmpty())
    } else {
        require(slot <= ULong.MAX_VALUE - 7UL && width == 8 && reason == null && expectedTransfer != null && transferOpcode == expectedTransfer &&
            transferIndex != null && readIndex != null && readIndex <= transferIndex && context == "language-default-no-commits-v1")
        require(copyIndices.all { it in readIndex until transferIndex })
        when (relationship) {
            "single-static-load-exact-transfer-v1" -> require(readOpcode == "LOAD" && readIndex < transferIndex && copyIndices.all { it > readIndex })
            "static-ram-varnode-exact-transfer-v1" -> when (readOpcode) {
                "COPY" -> require(readIndex < transferIndex && copyIndices.firstOrNull() == readIndex)
                expectedTransfer -> require(readIndex == transferIndex && copyIndices.isEmpty())
                else -> error("invalid implicit RAM read opcode")
            }
            else -> error("unknown static memory decoder relationship")
        }
    }
    return StaticMemoryTransferV1(requireNotNull(address("address")), length, bytes.copyOf(), classification, slot, width, relationship,
        readOpcode, readIndex, transferOpcode, transferIndex, copyIndices.toList(), context, reason)
}

private fun openCommitted(input: MachineCallFileV1, label: String, checkpoint: (String) -> Unit): StableControlFile {
    val file = StableControlFile.openWithCheckpoint(input.path, input.bytes, label, checkpoint)
    try {
        require(file.size == input.bytes && file.authenticatedSha256 == input.sha256) { "$label bytes or SHA-256 differ" }
        return file
    } catch (failure: Throwable) { file.close(); throw failure }
}
private fun outputLimits(limits: ExternalCallLimitsV1) = StrictJsonLimits(maximumInputBytes = limits.maximumOutputBytes,
    maximumCanonicalBytes = limits.maximumOutputBytes, maximumNodes = 1000000, maximumStringBytes = limits.maximumOutputBytes,
    maximumTotalStringBytes = limits.maximumOutputBytes)
private fun requirePath(path: Path) {
    val text = path.toString()
    require(path.isAbsolute && path.normalize() == path && path.parent != null && text.length in 1..4096 && text.none { it.code < 32 || it.code == 127 })
}
private fun requireDigest(value: String) { require(value.matches(Regex("[0-9a-f]{64}"))) }
private fun JsonObject.fields(vararg keys: String) { require(this.keys == keys.toSet()) { "unknown or missing external-call request fields" } }
private fun JsonObject.obj(key: String): JsonObject = getValue(key) as? JsonObject ?: error("$key must be an object")
private fun JsonObject.string(key: String): String = (getValue(key) as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("$key must be a string")
private fun JsonObject.number(key: String): Long = (getValue(key) as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull ?: error("$key must be an integer")
private const val REQUEST_KIND = "independent-external-call-request-v1"
private const val METADATA_POLICY = "elf-dynamic-binding-default-limits-v1"
private val REQUEST_LIMITS = StrictJsonLimits(maximumInputBytes = 65536, maximumCanonicalBytes = 65536, maximumDepth = 8,
    maximumNodes = 128, maximumStringBytes = 4096, maximumTotalStringBytes = 16384)
private val CLASSIFICATIONS = setOf("direct-call", "indirect-call", "direct-jump", "indirect-jump", "return", "ordinary",
    "unsupported-pcode", "unsupported-context", "unsupported-trap-or-userop", "unsupported-flow")
private val UNRESOLVED_REASONS = setOf("pcode-bound", "unsupported-transfer-profile", "pcode-varnode-bound", "unsupported-pcode-or-userop",
    "competing-or-invalid-transfers", "internal-pcode-control", "missing-indirect-transfer", "trailing-pcode-after-transfer", "multiple-memory-loads",
    "unsupported-pointer-width", "nondefault-memory-space", "register-transfer", "nonmemory-indirect-value", "overlapping-value-write",
    "missing-value-definition", "unsupported-value-transform", "nondefault-load-space", "nonstatic-load-address", "pointer-slot-wrap",
    "memory-write-before-read", "typed-flow-disagreement", "not-indirect-transfer", "unsupported-context", "unsupported-pcode",
    "unsupported-trap-or-userop", "unsupported-flow")

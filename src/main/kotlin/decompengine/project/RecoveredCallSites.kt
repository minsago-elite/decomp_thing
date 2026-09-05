package decompengine.project

import decompengine.oracle.fulltree.FullTreeCanonicalStreaming
import decompengine.oracle.fulltree.FullTreeCanonicalStreamingLimits
import java.nio.file.Path
import java.time.Duration
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

data class RecoveredCallSite(
    val callerRva: ULong,
    val instructionRva: ULong,
    val instructionBytes: String,
    val flowKind: String,
    val physicalTargetRva: ULong?,
    val recoveredTargetRvas: List<ULong>,
    val returnPcRva: ULong?,
) {
    val callerId: String get() = "function-rva-0x${callerRva.toString(16)}"
    val callerLocalInstructionOffset: ULong? get() = instructionRva.takeIf { it >= callerRva }?.minus(callerRva)
}

data class RecoveredCallSiteBindings(
    val inputSha256: String,
    val programModelSha256: String,
    val exporterSha256: String,
    val analysisToolSha256: String,
)

data class RecoveredCallSiteLimits(
    val maximumInputBytes: Long = 4L * 1024 * 1024 * 1024,
    val maximumSites: Long = 10_000_000L,
    val maximumTargetsPerSite: Int = 16,
    val maximumWallClock: Duration = Duration.ofMinutes(5),
) {
    init {
        require(maximumInputBytes in 1L..4L * 1024 * 1024 * 1024)
        require(maximumSites in 1L..10_000_000L)
        require(maximumTargetsPerSite in 1..16)
        require(!maximumWallClock.isNegative && !maximumWallClock.isZero && maximumWallClock <= Duration.ofHours(24))
    }
}

data class RecoveredCallSiteReceipt(
    val path: Path,
    val artifactSha256: String,
    val bytes: Long,
    val sites: Long,
    val imageBaseAddress: ULong,
    val bindings: RecoveredCallSiteBindings,
) {
    val recoveredModelScored: Boolean = false
    val authoritativeOracleEvidence: Boolean = false
}

object RecoveredCallSites {
    fun read(
        path: Path,
        expectedArtifactSha256: String,
        expectedBindings: RecoveredCallSiteBindings,
        limits: RecoveredCallSiteLimits = RecoveredCallSiteLimits(),
        consume: (RecoveredCallSite) -> Unit,
    ): RecoveredCallSiteReceipt {
        val started = System.nanoTime()
        fun checkpoint() {
            check(!Thread.currentThread().isInterrupted) { "recovered call-site read interrupted" }
            check(System.nanoTime() - started < limits.maximumWallClock.toNanos()) {
                "recovered call-site read exceeded its wall-clock bound"
            }
        }
        listOf(
            expectedArtifactSha256, expectedBindings.inputSha256, expectedBindings.programModelSha256,
            expectedBindings.exporterSha256, expectedBindings.analysisToolSha256,
        ).forEach { require(it.matches(DIGEST_PATTERN)) { "call-site binding must be a SHA-256 digest" } }
        checkpoint()
        var previous: Pair<ULong, ULong>? = null
        var sites = 0L
        var greatestRva = 0UL
        val streamed = FullTreeCanonicalStreaming.readObject(
            path, "recovered call-site candidate", expectedArtifactSha256,
            listOf("analysisToolSha256", "calls", "exporterSha256", "imageBaseAddress", "inputSha256", "programModelSha256", "schemaVersion"),
            setOf("calls"), null,
            FullTreeCanonicalStreamingLimits(
                maximumInputBytes = limits.maximumInputBytes,
                maximumTokens = 1_000_000_000L,
                maximumEntities = limits.maximumSites,
                maximumEntityBytes = 4096,
                maximumEntityNodes = 64,
                maximumDepth = 4,
                maximumStringBytes = 128,
                maximumTotalStringBytes = limits.maximumInputBytes,
                maximumNumberCharacters = 1,
            ),
        ) { _, _, value, _ ->
            checkpoint()
            require(value.keys == CALL_SITE_FIELDS) { "recovered call site has missing or extra fields" }
            val caller = rva(value.getValue("callerRva"))
            val instruction = rva(value.getValue("instructionRva"))
            val prior = previous
            require(prior == null || caller > prior.first || caller == prior.first && instruction > prior.second) {
                "recovered call sites must have unique caller/instruction keys in unsigned address order"
            }
            previous = caller to instruction
            val bytes = text(value.getValue("instructionBytes"))
            require(bytes.matches(INSTRUCTION_BYTES_PATTERN)) { "invalid x86-64 instruction bytes" }
            val kind = text(value.getValue("flowKind"))
            require(kind in FLOW_KINDS) { "unsupported recovered call-site flow kind" }
            val physical = nullableRva(value.getValue("physicalTargetRva"))
            val targets = (value.getValue("recoveredTargetRvas") as? JsonArray
                ?: error("recovered targets must be an array")).map(::rva)
            require(targets.size <= limits.maximumTargetsPerSite && targets == targets.distinct().sorted()) {
                "recovered call targets must be a bounded unique unsigned-ordered set"
            }
            val returnPc = nullableRva(value.getValue("returnPcRva"))
            val length = (bytes.length / 2).toULong()
            require(instruction <= ULong.MAX_VALUE - length) { "recovered instruction end overflows its address space" }
            if (kind == "direct-call" || kind == "indirect-call") {
                require(returnPc == instruction + length) { "call return PC must follow the exact instruction bytes" }
            } else {
                require(returnPc == null) { "a tail call or unresolved indirect jump has no return PC" }
            }
            require(kind != "direct-tail-call" || physical != null) { "direct tail candidate has no physical target" }
            require(kind !in setOf("indirect-call", "indirect-jump") || physical == null) {
                "computed flow cannot claim a statically encoded physical target"
            }
            greatestRva = maxOf(maxOf(greatestRva, caller, instruction + length), physical ?: 0UL, targets.maxOrNull() ?: 0UL)
            sites = Math.addExact(sites, 1L)
            consume(RecoveredCallSite(caller, instruction, bytes, kind, physical, targets.toList(), returnPc))
        }
        val root = streamed.envelope
        require(root["schemaVersion"] == JsonPrimitive(1)) { "unsupported recovered call-site schema version" }
        val bindings = RecoveredCallSiteBindings(
            text(root.getValue("inputSha256")), text(root.getValue("programModelSha256")),
            text(root.getValue("exporterSha256")), text(root.getValue("analysisToolSha256")),
        )
        require(bindings == expectedBindings) { "recovered call-site candidate belongs to a different input, model or exporter" }
        val imageBase = rva(root.getValue("imageBaseAddress"))
        require(greatestRva <= ULong.MAX_VALUE - imageBase) { "recovered call-site image address overflows" }
        checkpoint()
        return RecoveredCallSiteReceipt(path, streamed.sourceSha256, streamed.sourceBytes, sites, imageBase, bindings)
    }

    private fun text(value: kotlinx.serialization.json.JsonElement): String {
        val primitive = value as? JsonPrimitive ?: error("call-site value must be a string")
        require(primitive.isString) { "call-site value must be a string" }
        return primitive.content
    }

    private fun rva(value: kotlinx.serialization.json.JsonElement): ULong {
        val valueText = text(value)
        require(valueText.matches(ADDRESS_PATTERN)) { "call-site address must be canonical unsigned hex" }
        return valueText.substring(2).toULong(16)
    }

    private fun nullableRva(value: kotlinx.serialization.json.JsonElement): ULong? =
        if (value == JsonNull) null else rva(value)

    private val CALL_SITE_FIELDS = setOf(
        "callerRva", "flowKind", "instructionBytes", "instructionRva", "physicalTargetRva",
        "recoveredTargetRvas", "returnPcRva",
    )
    private val FLOW_KINDS = setOf("direct-call", "indirect-call", "direct-tail-call", "indirect-jump")
    private val DIGEST_PATTERN = Regex("[0-9a-f]{64}")
    private val ADDRESS_PATTERN = Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")
    private val INSTRUCTION_BYTES_PATTERN = Regex("(?:[0-9a-f]{2}){1,15}")
}

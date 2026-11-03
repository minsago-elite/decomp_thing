package decompengine.oracle.externalcalls

import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.machinecalls.IndependentMachineCallsV1
import decompengine.oracle.machinecalls.IndependentMachineCallReportV1
import decompengine.oracle.machinecalls.IndependentMachineCallRequestV1
import decompengine.oracle.machinecalls.MachineCallFileV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV2
import decompengine.oracle.machinecalls.MachineInstructionDecoderV1
import decompengine.oracle.machinecalls.MachineInstructionV1
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Authored ELF and authored oracle only. Fake callbacks exercise components, never production authority. */
internal class ExternalCallFixtureV1(
    val root: Path,
    mutate: (DynamicBindingElfFixtureV1) -> Unit = {},
    excludedCaller: Boolean = false,
) {
    val fixture = DynamicBindingElfFixtureV1().also {
        it.word64(0x618, 0x400818UL) // give each relocation its own slot
        byteArrayOf(-1, 37, -6, 5, 0, 0).copyInto(it.bytes, 0x200) // jmp [rip+0x5fa] -> GOT0x800
        byteArrayOf(-24, -117, -1, -1, -1, -1, 21, -83, 5, 0, 0, -61).copyInto(it.bytes, 0x270)
        // call0x200; call [rip+0x5ad] -> GOT0x828; ret
        mutate(it)
    }
    val rich: Path = Files.write(root.resolve("rich.elf"), fixture.bytes)
    val inputSha: String = OracleArtifacts.sha256(fixture.bytes)
    val manifestSha: String = "6".repeat(64)
    val oracle: Path
    val oracleSha: String
    val sourceRequest: Path = root.resolve("source-request.json")
    val sourceReport: Path = root.resolve("source-report.json")
    private val machineRuntime = MachineCallRuntimeV1(root.resolve("bundle"), root.resolve("ghidra.zip"), BundledGhidra.ARCHIVE_SHA256,
        569445154L, "a".repeat(64), "b".repeat(64), "x86:LE:64:default", "4.8")
    val runtime: MachineCallRuntimeV2 = run {
        val snapshotRoot = Files.createDirectories(root.resolve("runtime-snapshots"))
        val bridgeBytes = byteArrayOf(1, 2, 3)
        val manifestBytes = byteArrayOf(4, 5, 6)
        val bridgePath = Files.write(snapshotRoot.resolve("bridge.runtime"), bridgeBytes)
        val manifestPath = Files.write(snapshotRoot.resolve("manifest.runtime"), manifestBytes)
        val bridgeSha = OracleArtifacts.sha256(bridgeBytes)
        val manifestSha = OracleArtifacts.sha256(manifestBytes)
        MachineCallRuntimeV2(root.resolve("bundle"), root.resolve("ghidra.zip"), BundledGhidra.ARCHIVE_SHA256,
            569445154L, bridgeSha, manifestSha, "x86:LE:64:default", "4.8",
            MachineCallFileV1(bridgePath, bridgeBytes.size.toLong(), bridgeSha),
            MachineCallFileV1(manifestPath, manifestBytes.size.toLong(), manifestSha))
    }
    val request: IndependentMachineCallRequestV1
    val requestSha: String
    var reportSha: String
        private set

    init {
        val executableEnd = (0..7).fold(0UL) { result, index -> result or ((fixture.bytes[0x68 + index].toULong() and 255UL) shl (index * 8)) }
        fun artifact(sha: String) = obj("inputSha256" to text(sha), "elfType" to text("ET_DYN"), "elfImageBase" to text("0x400000"),
            "executableRvaRanges" to JsonArray(listOf(obj("start" to text("0x0"), "endExclusive" to text("0x${executableEnd.toString(16)}")))))
        val oracleBytes = OracleJson.canonicalBytes(obj("schemaVersion" to JsonPrimitive(1), "scope" to text("production"),
            "oracle" to obj("id" to text("authored-external-call-oracle"), "source" to text("dwarf-and-symbols"),
                "artifactManifestSha256" to text(manifestSha)), "artifacts" to obj("rich" to artifact(inputSha), "stripped" to artifact("7".repeat(64))),
            "scoringPolicy" to obj("nearMissBytes" to JsonPrimitive(8)),
            "functions" to JsonArray(listOf(obj("id" to text("canonical-270"), "rva" to text("0x270"),
                "aliases" to JsonArray(listOf(obj("name" to text("local_export"),
                    "availability" to obj("rich" to text("surviving"), "stripped" to text("removed")),
                    "evidence" to JsonArray(listOf(obj("kind" to text("dwarf-subprogram"), "locator" to text("fixture-cu:die:270")),
                        obj("kind" to text("elf-symbol"), "locator" to text("fixture-sym:6"))))))),
                "exclusion" to if (excludedCaller) obj("kind" to text("compiler-generated"), "reason" to text("authored excluded caller")) else JsonNull)) +
                if (excludedCaller) listOf(obj("id" to text("canonical-290"), "rva" to text("0x290"),
                    "aliases" to JsonArray(listOf(obj("name" to text("eligible-unlocated"),
                        "availability" to obj("rich" to text("surviving"), "stripped" to text("removed")),
                        "evidence" to JsonArray(listOf(obj("kind" to text("dwarf-subprogram"), "locator" to text("fixture-cu:die:290"))))))),
                    "exclusion" to JsonNull)) else emptyList())))
        oracle = Files.write(root.resolve("oracle.json"), oracleBytes)
        oracleSha = OracleArtifacts.sha256(oracleBytes)
        request = IndependentMachineCallRequestV1(MachineCallFileV1(rich, Files.size(rich), inputSha),
            MachineCallFileV1(oracle, oracleBytes.size.toLong(), oracleSha), manifestSha, machineRuntime, sourceReport)
        requestSha = OracleArtifacts.sha256(request.canonicalBytes)
        Files.write(sourceRequest, request.canonicalBytes)
        val component = IndependentMachineCallsV1.produce(rich, oracle, inputSha, oracleSha, manifestSha, decoder)
        val worker = JsonObject(component + mapOf("requestSha256" to text(requestSha), "runtime" to machineRuntime.json(),
            "decoderAuthentication" to text("authenticated-bundled-worker-v1"), "containmentStatus" to text("external-owner-required")))
        IndependentMachineCallReportV1.validateWorker(worker, requestSha, request)
        val reportBytes = OracleJson.canonicalBytes(worker)
        Files.write(sourceReport, reportBytes)
        reportSha = OracleArtifacts.sha256(reportBytes)
    }

    fun replaceSourceReport(report: JsonObject) {
        IndependentMachineCallReportV1.validateWorker(report, requestSha, request)
        val bytes = OracleJson.canonicalBytes(report); Files.write(sourceReport, bytes); reportSha = OracleArtifacts.sha256(bytes)
    }
    fun sourceDocument(): JsonObject = OracleJson.parseCanonical(Files.readAllBytes(sourceReport)) as JsonObject
    fun produce(
        instructionDecoder: MachineInstructionDecoderV1 = decoder,
        memoryDecoder: StaticMemoryTransferDecoderV1 = memory,
        limits: ExternalCallLimitsV1 = ExternalCallLimitsV1(),
    ): JsonObject = IndependentExternalCallsV1.produce(rich, sourceReport, sourceRequest, inputSha, reportSha, requestSha,
        instructionDecoder, memoryDecoder, limits)

    companion object {
        val decoder = MachineInstructionDecoderV1 { address, bytes ->
            val first = bytes[0].toInt() and 255
            val kind: String; val length: Int; val target: ULong?
            when {
                first == 0xe8 -> { kind = "direct-call"; length = 5; target = relative(address, bytes, 1, length) }
                first == 0xff && bytes[1] == 0x15.toByte() -> { kind = "indirect-call"; length = 6; target = null }
                first == 0xff && bytes[1] == 0x25.toByte() -> { kind = "indirect-jump"; length = 6; target = null }
                first == 0xc3 -> { kind = "return"; length = 1; target = null }
                else -> { kind = "ordinary"; length = 1; target = null }
            }
            MachineInstructionV1(address, length, bytes.copyOf(length), kind,
                if (kind in setOf("ordinary", "direct-call", "indirect-call")) address + length.toULong() else null,
                target?.let { listOf(it) }.orEmpty(), target, "language-default-no-commits-v1")
        }
        val memory = StaticMemoryTransferDecoderV1 { address, bytes ->
            val instruction = decoder.decode(address, bytes)
            val supported = instruction.classification in setOf("indirect-call", "indirect-jump")
            val call = instruction.classification == "indirect-call"
            StaticMemoryTransferV1(address, instruction.length, instruction.bytes, instruction.classification,
                if (supported) relative(address, bytes, 2, 6) else null, if (supported) 8 else null,
                if (supported) "static-ram-varnode-exact-transfer-v1" else "unresolved",
                if (supported) if (call) "COPY" else "BRANCHIND" else null, if (supported) 0 else null,
                if (supported) if (call) "CALLIND" else "BRANCHIND" else null, if (supported) if (call) 3 else 0 else null,
                if (supported && call) listOf(0) else emptyList(), instruction.contextStatus, if (supported) null else "not-indirect-transfer")
        }
        private fun relative(address: ULong, bytes: ByteArray, offset: Int, length: Int): ULong {
            var value = 0; repeat(4) { value = value or ((bytes[offset + it].toInt() and 255) shl (it * 8)) }
            return (address.toLong() + length + value).toULong()
        }
        private fun obj(vararg entries: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*entries))
        private fun text(value: String) = JsonPrimitive(value)
    }
}

internal fun withExternalCallFixtureV1(action: (ExternalCallFixtureV1) -> Unit): Unit =
    withDynamicFixture { action(ExternalCallFixtureV1(it)) }

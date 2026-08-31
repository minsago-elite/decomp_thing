package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

internal class GccCompilerEngineContainmentContractException(message: String) :
    IllegalArgumentException(message)

internal enum class GccCompilerEngineContainmentRunKind(val wireName: String) {
    INTERRUPTED("interrupted"),
    RESUMED("resumed"),
    FRESH_CONTROL("fresh-control"),
}

internal enum class GccCompilerEngineAnalysisStateMode(val wireName: String) {
    FRESH_EMPTY("fresh-empty"),
    RESUME_MANIFEST("resume-manifest"),
}

internal enum class GccCompilerEngineContainmentArtifactRole(val wireName: String) {
    ENGINE_BINARY("engine-binary"),
    BENCHMARK_PROFILE("benchmark-profile"),
    SOURCE_LOCK("source-lock"),
    BUILD_RECORD("build-record"),
    ORACLE_MANIFEST("oracle-manifest"),
    TOOLCHAIN_REPRODUCTION("toolchain-reproduction"),
    GHIDRA_ARCHIVE("ghidra-archive"),
    GHIDRA_RUNTIME_MANIFEST("ghidra-runtime-manifest"),
    GHIDRA_ANALYZE_HEADLESS("ghidra-analyze-headless"),
    EXPORTER_CLASSFILE("exporter-classfile"),
    JAVA_EXECUTABLE("java-executable"),
    BUBBLEWRAP_EXECUTABLE("bubblewrap-executable"),
    RESOURCE_LIMITER_EXECUTABLE("resource-limiter-executable"),
    SYSTEMD_RUN_EXECUTABLE("systemd-run-executable"),
    SYSTEMCTL_EXECUTABLE("systemctl-executable"),
    SYSTEMD_BUSCTL_EXECUTABLE("systemd-busctl-executable"),
    BOOT_KEEPER_CLASSPATH("boot-keeper-classpath"),
}

internal data class GccCompilerEngineContainmentArtifactIdentity(
    val role: GccCompilerEngineContainmentArtifactRole,
    val path: Path,
    val bytes: Long,
    val sha256: String,
) {
    init {
        requireAbsoluteNormalized(path, "containment artifact")
        require(bytes in 1L..MAXIMUM_SINGLE_ARTIFACT_BYTES) {
            "containment artifact bytes are outside the bounded range"
        }
        requireSha256(sha256, "containment artifact")
    }
}

internal data class GccCompilerEngineAnalysisStateIdentity(
    val mode: GccCompilerEngineAnalysisStateMode,
    val path: Path,
    val manifestSha256: String?,
    val entryCount: Long,
    val totalBytes: Long,
) {
    init {
        requireAbsoluteNormalized(path, "analysis-state")
        require(entryCount in 0L..MAXIMUM_ANALYSIS_STATE_ENTRIES)
        require(totalBytes in 0L..MAXIMUM_ANALYSIS_STATE_BYTES)
        when (mode) {
            GccCompilerEngineAnalysisStateMode.FRESH_EMPTY -> require(
                manifestSha256 == null && entryCount == 0L && totalBytes == 0L,
            ) { "fresh analysis state must be empty and have no manifest" }

            GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST -> {
                requireSha256(manifestSha256, "analysis-state manifest")
                require(entryCount > 0L && totalBytes > 0L) {
                    "resume analysis state must bind a nonempty manifest"
                }
            }
        }
    }
}

internal data class GccCompilerEngineOutputLeaseIdentity(
    val path: Path,
    val device: Long,
    val inode: Long,
    val mountId: Long,
    val uid: Int,
    val gid: Int,
    val permissions: Int,
    val requiredAvailableBytes: Long,
    val maximumFilesystemBytes: Long,
    val requiredAvailableInodes: Long,
    val maximumFilesystemInodes: Long,
) {
    init {
        requireAbsoluteNormalized(path, "output lease")
        require(path != Path.of("/")) { "output lease cannot be the filesystem root" }
        require(device > 0L && inode > 0L && mountId > 0L)
        require(uid >= 0 && gid >= 0 && permissions == OWNER_ONLY_DIRECTORY_MODE)
        require(requiredAvailableBytes > 0L && maximumFilesystemBytes >= requiredAvailableBytes)
        require(requiredAvailableInodes >= MINIMUM_OUTPUT_INODES)
        require(maximumFilesystemInodes >= requiredAvailableInodes)
    }
}

internal data class GccCompilerEngineContainmentBudgets(
    val wallClockMillis: Long,
    val maximumResidentBytes: Long,
    val pidsMax: Long,
) {
    init {
        require(wallClockMillis in 1L..MAXIMUM_WALL_CLOCK_MILLIS)
        require(maximumResidentBytes in MINIMUM_RESIDENT_BYTES..MAXIMUM_RESIDENT_BYTES)
        require(pidsMax in MINIMUM_PIDS_MAX..MAXIMUM_PIDS_MAX)
    }
}

/**
 * Caller-supplied preimage for a future host-owned controller.
 *
 * Construction validates and snapshots a bounded definition only. It does not authenticate any
 * path, reserve a systemd unit, create a cgroup, grant START, or publish benchmark evidence.
 */
internal class GccCompilerEngineContainmentRequest(
    val engineId: String,
    val runKind: GccCompilerEngineContainmentRunKind,
    artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
    val analysisState: GccCompilerEngineAnalysisStateIdentity,
    command: List<String>,
    environment: Map<String, String>,
    val outputLease: GccCompilerEngineOutputLeaseIdentity,
    val budgets: GccCompilerEngineContainmentBudgets,
) {
    val artifacts: List<GccCompilerEngineContainmentArtifactIdentity> = boundedArtifactCopy(artifacts)
    val command: List<String> = boundedStringCopy(command, MAXIMUM_COMMAND_ARGUMENTS, "command")
    val environment: Map<String, String> = boundedEnvironmentCopy(environment)

    init {
        require(engineId == "cc1" || engineId == "lto1")
        when (runKind) {
            GccCompilerEngineContainmentRunKind.INTERRUPTED,
            GccCompilerEngineContainmentRunKind.FRESH_CONTROL ->
                require(analysisState.mode == GccCompilerEngineAnalysisStateMode.FRESH_EMPTY) {
                    "$runKind containment requires fresh-empty analysis state"
                }

            GccCompilerEngineContainmentRunKind.RESUMED ->
                require(analysisState.mode == GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST) {
                    "resumed containment requires manifest-bound analysis state"
                }
        }
        val byRole = this.artifacts.associateBy(GccCompilerEngineContainmentArtifactIdentity::role)
        require(byRole.size == this.artifacts.size && byRole.keys == REQUIRED_ARTIFACT_ROLES) {
            "containment definition must bind every exact artifact role once"
        }
        require(this.artifacts.map { it.path }.toSet().size == this.artifacts.size) {
            "containment artifact paths must be unique"
        }
        require(analysisState.path.startsWith(outputLease.path) && analysisState.path != outputLease.path) {
            "analysis state must be a child of the exact output lease"
        }
        require(this.artifacts.none { pathsOverlap(it.path, outputLease.path) }) {
            "read-only containment inputs must not overlap the output lease"
        }
        require(this.command.isNotEmpty())
        require(this.command.first() == byRole.getValue(
            GccCompilerEngineContainmentArtifactRole.GHIDRA_ANALYZE_HEADLESS,
        ).path.toString()) { "command must start with the bound analyzeHeadless executable" }
        val requiredArguments = setOf(
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).path.toString(),
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_CLASSFILE).path.toString(),
            analysisState.path.toString(),
            outputLease.path.toString(),
        )
        require(requiredArguments.all(this.command::contains)) {
            "command must explicitly bind the engine, analysis state, and output lease paths"
        }
    }
}

internal interface GccCompilerEngineContainmentDefinitionAssessment {
    val authority: String
    val releaseEligible: Boolean
    val startAuthorized: Boolean
    val requestSha256: String
    val bindingSha256: String
    val unitName: String
    val canonicalBytes: ByteArray
}

internal interface GccCompilerEngineUnitAttachedAtBootAssessment {
    val authority: String
    val releaseEligible: Boolean
    val startAuthorized: Boolean
    val bindingSha256: String
    val receiptSha256: String
    val unitName: String
}

internal interface GccCompilerEngineTerminalAbsenceAssessment {
    val authority: String
    val releaseEligible: Boolean
    val startAuthorized: Boolean
    val bindingSha256: String
    val attachedReceiptSha256: String
    val absenceReceiptSha256: String
}

/**
 * Bounded, non-authoritative durable-state contract for the future GCC process controller.
 *
 * Every operation consumes fresh raw bytes. No assessment is accepted as an authority token. The
 * contract deliberately exposes no START, launch, attach, adoption, publication, or release API.
 */
internal object GccCompilerEngineContainmentContract {
    fun assessDefinition(
        request: GccCompilerEngineContainmentRequest,
    ): GccCompilerEngineContainmentDefinitionAssessment = DefinitionAssessmentImpl.assess(request)

    fun assessUnitAttachedAtBoot(
        definitionBytes: ByteArray,
        receiptBytes: ByteArray,
    ): GccCompilerEngineUnitAttachedAtBootAssessment =
        UnitAttachedAssessmentImpl.assess(definitionBytes, receiptBytes)

    fun assessTerminalAbsence(
        definitionBytes: ByteArray,
        attachedReceiptBytes: ByteArray,
        absenceReceiptBytes: ByteArray,
    ): GccCompilerEngineTerminalAbsenceAssessment =
        TerminalAbsenceAssessmentImpl.assess(definitionBytes, attachedReceiptBytes, absenceReceiptBytes)

    /** Forgeable canonical bytes used only to exercise the raw-byte assessment boundary. */
    internal fun renderUnitAttachedAtBootReceiptForTesting(
        definitionBytes: ByteArray,
        bootId: String,
        invocationId: String,
        processIds: List<Long>,
        cgroupDevice: Long = 11L,
        cgroupInode: Long = 12L,
        cgroupMountId: Long = 13L,
    ): ByteArray {
        val definition = parseDefinition(snapshot(definitionBytes, MAXIMUM_DEFINITION_BYTES, "definition"))
        val pids = boundedLongCopy(processIds, REQUIRED_BOOT_PROCESS_COUNT, "BOOT process IDs")
        if (pids.size != REQUIRED_BOOT_PROCESS_COUNT || pids.toSet().size != pids.size || pids.any { it <= 0L }) {
            containmentFail("BOOT process IDs must be three distinct positive values")
        }
        if (!bootId.matches(BOOT_ID) || !invocationId.matches(SYSTEMD_ID128) || invocationId == ZERO_ID128) {
            containmentFail("test receipt has an invalid boot or invocation identity")
        }
        val controlGroup = derivedControlGroup(definition)
        val processes = bootProcessObjects(definition, pids)
        val unsigned = attachedReceiptUnsigned(
            definition,
            bootId,
            invocationId,
            controlGroup,
            cgroupDevice,
            cgroupInode,
            cgroupMountId,
            processes,
        )
        return withSelfHash(unsigned, "receiptSha256")
    }

    /** Forgeable canonical bytes used only to exercise the raw-byte assessment boundary. */
    internal fun renderTerminalAbsenceReceiptForTesting(
        definitionBytes: ByteArray,
        attachedReceiptBytes: ByteArray,
    ): ByteArray {
        val definition = parseDefinition(snapshot(definitionBytes, MAXIMUM_DEFINITION_BYTES, "definition"))
        val attached = parseAttachedReceipt(
            definition,
            snapshot(attachedReceiptBytes, MAXIMUM_RECEIPT_BYTES, "UNIT_ATTACHED-at-BOOT receipt"),
        )
        val unsigned = JsonObject(
            linkedMapOf(
                "schemaVersion" to JsonPrimitive(1),
                "provider" to JsonPrimitive(ABSENCE_RECEIPT_PROVIDER),
                "phase" to JsonPrimitive("TERMINAL_ABSENT"),
                "bindingSha256" to JsonPrimitive(definition.bindingSha256),
                "attachedReceiptSha256" to JsonPrimitive(attached.receiptSha256),
                "bootId" to JsonPrimitive(attached.bootId),
                "unitName" to JsonPrimitive(definition.unitName),
                "kill" to JsonObject(
                    mapOf(
                        "mechanism" to JsonPrimitive("systemd-control-group"),
                        "whom" to JsonPrimitive("all"),
                        "signal" to JsonPrimitive("SIGKILL"),
                        "killMode" to JsonPrimitive("control-group"),
                    ),
                ),
                "unit" to JsonObject(
                    mapOf(
                        "loadState" to JsonPrimitive("not-found"),
                        "sameNameCandidates" to JsonPrimitive(0),
                        "invocationPresent" to JsonPrimitive(false),
                    ),
                ),
                "cgroup" to JsonObject(
                    mapOf(
                        "pathPresent" to JsonPrimitive(false),
                        "sameNameCandidates" to JsonPrimitive(0),
                        "populated" to JsonPrimitive(0),
                    ),
                ),
                "processes" to JsonArray(
                    attached.processes.map { process ->
                        JsonObject(
                            mapOf(
                                "role" to JsonPrimitive(process.role),
                                "pid" to JsonPrimitive(process.pid),
                                "startTimeTicks" to JsonPrimitive(process.startTimeTicks),
                                "pidfdAlive" to JsonPrimitive(false),
                            ),
                        )
                    },
                ),
                "independentAbsenceSweeps" to JsonPrimitive(REQUIRED_ABSENCE_SWEEPS),
            ),
        )
        return withSelfHash(unsigned, "absenceReceiptSha256")
    }
}

private data class DefinitionFacts(
    val canonicalBytes: ByteArray,
    val requestSha256: String,
    val bindingSha256: String,
    val unitName: String,
    val commandSha256: String,
    val runtimeSha256: String,
    val inputSetSha256: String,
    val outputLeaseSha256: String,
    val outputUid: Int,
    val budgets: GccCompilerEngineContainmentBudgets,
    val artifactSha256: Map<GccCompilerEngineContainmentArtifactRole, String>,
)

private data class AttachedProcessFacts(
    val role: String,
    val pid: Long,
    val startTimeTicks: Long,
)

private data class AttachedReceiptFacts(
    val receiptSha256: String,
    val bootId: String,
    val processes: List<AttachedProcessFacts>,
)

private class DefinitionAssessmentImpl private constructor(
    request: GccCompilerEngineContainmentRequest,
) : GccCompilerEngineContainmentDefinitionAssessment {
    private val facts = renderDefinition(request)
    override val requestSha256: String = facts.requestSha256
    override val bindingSha256: String = facts.bindingSha256
    override val unitName: String = facts.unitName
    override val authority: String = ASSESSMENT_AUTHORITY
    override val releaseEligible: Boolean = false
    override val startAuthorized: Boolean = false
    private val bytes = facts.canonicalBytes.copyOf()
    override val canonicalBytes: ByteArray
        get() = bytes.copyOf()

    companion object {
        fun assess(
            request: GccCompilerEngineContainmentRequest,
        ): GccCompilerEngineContainmentDefinitionAssessment = DefinitionAssessmentImpl(request)
    }
}

private class UnitAttachedAssessmentImpl private constructor(
    definitionBytes: ByteArray,
    receiptBytes: ByteArray,
) : GccCompilerEngineUnitAttachedAtBootAssessment {
    private val definition = parseDefinition(snapshot(definitionBytes, MAXIMUM_DEFINITION_BYTES, "definition"))
    private val receipt = parseAttachedReceipt(
        definition,
        snapshot(receiptBytes, MAXIMUM_RECEIPT_BYTES, "UNIT_ATTACHED-at-BOOT receipt"),
    )
    override val bindingSha256: String = definition.bindingSha256
    override val receiptSha256: String = receipt.receiptSha256
    override val unitName: String = definition.unitName
    override val authority: String = ASSESSMENT_AUTHORITY
    override val releaseEligible: Boolean = false
    override val startAuthorized: Boolean = false

    companion object {
        fun assess(
            definitionBytes: ByteArray,
            receiptBytes: ByteArray,
        ): GccCompilerEngineUnitAttachedAtBootAssessment =
            UnitAttachedAssessmentImpl(definitionBytes, receiptBytes)
    }
}

private class TerminalAbsenceAssessmentImpl private constructor(
    definitionBytes: ByteArray,
    attachedReceiptBytes: ByteArray,
    absenceReceiptBytes: ByteArray,
) : GccCompilerEngineTerminalAbsenceAssessment {
    private val definition = parseDefinition(snapshot(definitionBytes, MAXIMUM_DEFINITION_BYTES, "definition"))
    private val attached = parseAttachedReceipt(
        definition,
        snapshot(attachedReceiptBytes, MAXIMUM_RECEIPT_BYTES, "UNIT_ATTACHED-at-BOOT receipt"),
    )
    override val bindingSha256: String = definition.bindingSha256
    override val attachedReceiptSha256: String = attached.receiptSha256
    override val absenceReceiptSha256: String = parseAbsenceReceipt(
        definition,
        attached,
        snapshot(absenceReceiptBytes, MAXIMUM_RECEIPT_BYTES, "terminal-absence receipt"),
    )
    override val authority: String = ASSESSMENT_AUTHORITY
    override val releaseEligible: Boolean = false
    override val startAuthorized: Boolean = false

    companion object {
        fun assess(
            definitionBytes: ByteArray,
            attachedReceiptBytes: ByteArray,
            absenceReceiptBytes: ByteArray,
        ): GccCompilerEngineTerminalAbsenceAssessment =
            TerminalAbsenceAssessmentImpl(definitionBytes, attachedReceiptBytes, absenceReceiptBytes)
    }
}

private fun renderDefinition(request: GccCompilerEngineContainmentRequest): DefinitionFacts {
    val artifacts = JsonArray(request.artifacts.sortedBy { it.role.wireName }.map(::artifactJson))
    val runtimeArtifacts = JsonArray(request.artifacts.filter { it.role in RUNTIME_ARTIFACT_ROLES }
        .sortedBy { it.role.wireName }.map(::artifactJson))
    val inputArtifacts = JsonArray(request.artifacts.filter { it.role in ANALYSIS_INPUT_ROLES }
        .sortedBy { it.role.wireName }.map(::artifactJson))
    val analysisState = analysisStateJson(request.analysisState)
    val commandWithoutHash = JsonObject(
        mapOf(
            "argv" to JsonArray(request.command.map(::JsonPrimitive)),
            "environment" to JsonArray(request.environment.entries.map { (name, value) ->
                JsonObject(mapOf("name" to JsonPrimitive(name), "value" to JsonPrimitive(value)))
            }),
        ),
    )
    val commandSha256 = sha256(commandWithoutHash)
    val command = JsonObject(commandWithoutHash + ("commandSha256" to JsonPrimitive(commandSha256)))
    val leaseWithoutHash = outputLeaseJson(request.outputLease)
    val outputLeaseSha256 = sha256(leaseWithoutHash)
    val outputLease = JsonObject(leaseWithoutHash + ("leaseSha256" to JsonPrimitive(outputLeaseSha256)))
    val runtimeSha256 = sha256(runtimeArtifacts)
    val inputSetSha256 = sha256(
        JsonObject(mapOf("analysisState" to analysisState, "artifacts" to inputArtifacts)),
    )
    val requestObject = JsonObject(
        linkedMapOf(
            "engineId" to JsonPrimitive(request.engineId),
            "runKind" to JsonPrimitive(request.runKind.wireName),
            "artifacts" to artifacts,
            "analysisState" to analysisState,
            "command" to command,
            "outputLease" to outputLease,
            "budgets" to budgetsJson(request.budgets),
            "runtimeSha256" to JsonPrimitive(runtimeSha256),
            "inputSetSha256" to JsonPrimitive(inputSetSha256),
        ),
    )
    val requestSha256 = sha256(requestObject)
    val unitName = "decomp-gcc-${request.engineId}-${requestSha256.take(32)}.scope"
    val unsigned = JsonObject(
        linkedMapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive(DEFINITION_PROVIDER),
            "authority" to JsonPrimitive(ASSESSMENT_AUTHORITY),
            "releaseEligible" to JsonPrimitive(false),
            "startAuthorized" to JsonPrimitive(false),
            "request" to requestObject,
            "requestSha256" to JsonPrimitive(requestSha256),
            "unitName" to JsonPrimitive(unitName),
            "containment" to containmentJson(request.budgets),
        ),
    )
    val bindingSha256 = sha256(unsigned)
    val canonical = OracleJson.canonicalBytes(
        JsonObject(unsigned + ("bindingSha256" to JsonPrimitive(bindingSha256))),
        JSON_LIMITS,
    )
    return DefinitionFacts(
        canonical,
        requestSha256,
        bindingSha256,
        unitName,
        commandSha256,
        runtimeSha256,
        inputSetSha256,
        outputLeaseSha256,
        request.outputLease.uid,
        request.budgets,
        Collections.unmodifiableMap(request.artifacts.associate { it.role to it.sha256 }),
    )
}

private fun parseDefinition(bytes: ByteArray): DefinitionFacts {
    val root = parseCanonicalObject(bytes, "containment definition")
    root.requireKeys(DEFINITION_FIELDS, "containment definition")
    root.requireInt("schemaVersion", 1, "containment definition")
    root.requireString("provider", DEFINITION_PROVIDER, "containment definition")
    root.requireString("authority", ASSESSMENT_AUTHORITY, "containment definition")
    root.requireBoolean("releaseEligible", false, "containment definition")
    root.requireBoolean("startAuthorized", false, "containment definition")
    val requestObject = root.objectField("request", "containment definition")
    requestObject.requireKeys(REQUEST_FIELDS, "containment request")
    val artifacts = requestObject.arrayField("artifacts", "containment request").map { element ->
        val artifact = element as? JsonObject ?: containmentFail("containment artifact must be an object")
        artifact.requireKeys(ARTIFACT_FIELDS, "containment artifact")
        GccCompilerEngineContainmentArtifactIdentity(
            role = artifact.stringField("role", "containment artifact").let(::artifactRole),
            path = strictPath(artifact.stringField("path", "containment artifact"), "containment artifact"),
            bytes = artifact.longField("bytes", "containment artifact"),
            sha256 = artifact.stringField("sha256", "containment artifact"),
        )
    }
    val stateObject = requestObject.objectField("analysisState", "containment request")
    stateObject.requireKeys(ANALYSIS_STATE_FIELDS, "analysis state")
    val state = GccCompilerEngineAnalysisStateIdentity(
        mode = stateObject.stringField("mode", "analysis state").let(::analysisStateMode),
        path = strictPath(stateObject.stringField("path", "analysis state"), "analysis state"),
        manifestSha256 = when (val value = stateObject["manifestSha256"]) {
            JsonNull -> null
            is JsonPrimitive -> value.takeIf { it.isString }?.content
                ?: containmentFail("analysis state manifest must be a string or null")
            else -> containmentFail("analysis state manifest must be a string or null")
        },
        entryCount = stateObject.longField("entryCount", "analysis state"),
        totalBytes = stateObject.longField("totalBytes", "analysis state"),
    )
    val commandObject = requestObject.objectField("command", "containment request")
    commandObject.requireKeys(COMMAND_FIELDS, "containment command")
    val command = commandObject.arrayField("argv", "containment command").map { element ->
        val value = element as? JsonPrimitive
        if (value == null || !value.isString) containmentFail("command argument must be a string")
        value.content
    }
    val environment = linkedMapOf<String, String>()
    commandObject.arrayField("environment", "containment command").forEach { element ->
        val entry = element as? JsonObject ?: containmentFail("environment entry must be an object")
        entry.requireKeys(ENVIRONMENT_FIELDS, "environment entry")
        val name = entry.stringField("name", "environment entry")
        val value = entry.stringField("value", "environment entry")
        if (environment.put(name, value) != null) containmentFail("environment contains a duplicate name")
    }
    val leaseObject = requestObject.objectField("outputLease", "containment request")
    leaseObject.requireKeys(OUTPUT_LEASE_FIELDS, "output lease")
    val outputLease = GccCompilerEngineOutputLeaseIdentity(
        path = strictPath(leaseObject.stringField("path", "output lease"), "output lease"),
        device = leaseObject.longField("device", "output lease"),
        inode = leaseObject.longField("inode", "output lease"),
        mountId = leaseObject.longField("mountId", "output lease"),
        uid = leaseObject.intField("uid", "output lease"),
        gid = leaseObject.intField("gid", "output lease"),
        permissions = leaseObject.intField("permissions", "output lease"),
        requiredAvailableBytes = leaseObject.longField("requiredAvailableBytes", "output lease"),
        maximumFilesystemBytes = leaseObject.longField("maximumFilesystemBytes", "output lease"),
        requiredAvailableInodes = leaseObject.longField("requiredAvailableInodes", "output lease"),
        maximumFilesystemInodes = leaseObject.longField("maximumFilesystemInodes", "output lease"),
    )
    val budgetsObject = requestObject.objectField("budgets", "containment request")
    budgetsObject.requireKeys(BUDGET_FIELDS, "containment budgets")
    val budgets = GccCompilerEngineContainmentBudgets(
        wallClockMillis = budgetsObject.longField("wallClockMillis", "containment budgets"),
        maximumResidentBytes = budgetsObject.longField("maximumResidentBytes", "containment budgets"),
        pidsMax = budgetsObject.longField("pidsMax", "containment budgets"),
    )
    val reconstructed = GccCompilerEngineContainmentRequest(
        engineId = requestObject.stringField("engineId", "containment request"),
        runKind = requestObject.stringField("runKind", "containment request").let(::runKind),
        artifacts = artifacts,
        analysisState = state,
        command = command,
        environment = environment,
        outputLease = outputLease,
        budgets = budgets,
    )
    val expected = renderDefinition(reconstructed)
    if (!MessageDigest.isEqual(bytes, expected.canonicalBytes)) {
        containmentFail("containment definition differs from its exact derived encoding")
    }
    return expected
}

private fun attachedReceiptUnsigned(
    definition: DefinitionFacts,
    bootId: String,
    invocationId: String,
    controlGroup: String,
    cgroupDevice: Long,
    cgroupInode: Long,
    cgroupMountId: Long,
    processes: JsonArray,
): JsonObject = JsonObject(
    linkedMapOf(
        "schemaVersion" to JsonPrimitive(1),
        "provider" to JsonPrimitive(ATTACHED_RECEIPT_PROVIDER),
        "phase" to JsonPrimitive("UNIT_ATTACHED_AT_BOOT"),
        "bindingSha256" to JsonPrimitive(definition.bindingSha256),
        "requestSha256" to JsonPrimitive(definition.requestSha256),
        "unitName" to JsonPrimitive(definition.unitName),
        "bootId" to JsonPrimitive(bootId),
        "invocationId" to JsonPrimitive(invocationId),
        "commandSha256" to JsonPrimitive(definition.commandSha256),
        "runtimeSha256" to JsonPrimitive(definition.runtimeSha256),
        "inputSetSha256" to JsonPrimitive(definition.inputSetSha256),
        "outputLeaseSha256" to JsonPrimitive(definition.outputLeaseSha256),
        "systemd" to JsonObject(
            mapOf(
                "id" to JsonPrimitive(definition.unitName),
                "transient" to JsonPrimitive(true),
                "loadState" to JsonPrimitive("loaded"),
                "activeState" to JsonPrimitive("active"),
                "subState" to JsonPrimitive("running"),
                "controlGroup" to JsonPrimitive(controlGroup),
                "collectMode" to JsonPrimitive("inactive-or-failed"),
                "runtimeMaxMillis" to JsonPrimitive(definition.budgets.wallClockMillis),
                "timeoutStopMillis" to JsonPrimitive(SYSTEMD_TIMEOUT_STOP_MILLIS),
                "tasksMax" to JsonPrimitive(definition.budgets.pidsMax),
                "memoryMaxBytes" to JsonPrimitive(definition.budgets.maximumResidentBytes),
                "memorySwapMaxBytes" to JsonPrimitive(0),
                "oomPolicy" to JsonPrimitive("kill"),
                "killMode" to JsonPrimitive("control-group"),
                "sendSigkill" to JsonPrimitive(true),
                "delegate" to JsonPrimitive(false),
            ),
        ),
        "cgroup" to JsonObject(
            mapOf(
                "version" to JsonPrimitive(2),
                "path" to JsonPrimitive("/sys/fs/cgroup$controlGroup"),
                "device" to JsonPrimitive(cgroupDevice),
                "inode" to JsonPrimitive(cgroupInode),
                "mountId" to JsonPrimitive(cgroupMountId),
                "populated" to JsonPrimitive(1),
                "frozen" to JsonPrimitive(0),
                "controllers" to JsonArray(listOf("cpu", "memory", "pids").map(::JsonPrimitive)),
                "memoryMaxBytes" to JsonPrimitive(definition.budgets.maximumResidentBytes),
                "memorySwapMaxBytes" to JsonPrimitive(0),
                "pidsMax" to JsonPrimitive(definition.budgets.pidsMax),
                "killMode" to JsonPrimitive("control-group"),
                "sendSigkill" to JsonPrimitive(true),
            ),
        ),
        "bootProtocol" to JsonObject(
            mapOf(
                "version" to JsonPrimitive(1),
                "state" to JsonPrimitive("BOOT"),
                "nonce" to JsonPrimitive(definition.bindingSha256),
                "protocolSha256" to JsonPrimitive(
                    OracleArtifacts.sha256("BOOT\u0000${definition.bindingSha256}".toByteArray()),
                ),
            ),
        ),
        "processes" to processes,
    ),
)

private fun parseAttachedReceipt(definition: DefinitionFacts, bytes: ByteArray): AttachedReceiptFacts {
    val root = parseCanonicalObject(bytes, "UNIT_ATTACHED-at-BOOT receipt")
    root.requireKeys(ATTACHED_RECEIPT_FIELDS, "UNIT_ATTACHED-at-BOOT receipt")
    root.requireInt("schemaVersion", 1, "UNIT_ATTACHED-at-BOOT receipt")
    root.requireString("provider", ATTACHED_RECEIPT_PROVIDER, "UNIT_ATTACHED-at-BOOT receipt")
    root.requireString("phase", "UNIT_ATTACHED_AT_BOOT", "UNIT_ATTACHED-at-BOOT receipt")
    root.requireString("bindingSha256", definition.bindingSha256, "UNIT_ATTACHED-at-BOOT receipt")
    root.requireString("requestSha256", definition.requestSha256, "UNIT_ATTACHED-at-BOOT receipt")
    root.requireString("unitName", definition.unitName, "UNIT_ATTACHED-at-BOOT receipt")
    root.requireString("commandSha256", definition.commandSha256, "UNIT_ATTACHED-at-BOOT receipt")
    root.requireString("runtimeSha256", definition.runtimeSha256, "UNIT_ATTACHED-at-BOOT receipt")
    root.requireString("inputSetSha256", definition.inputSetSha256, "UNIT_ATTACHED-at-BOOT receipt")
    root.requireString("outputLeaseSha256", definition.outputLeaseSha256, "UNIT_ATTACHED-at-BOOT receipt")
    val bootId = root.stringField("bootId", "UNIT_ATTACHED-at-BOOT receipt")
    val invocationId = root.stringField("invocationId", "UNIT_ATTACHED-at-BOOT receipt")
    if (!bootId.matches(BOOT_ID) || !invocationId.matches(SYSTEMD_ID128) || invocationId == ZERO_ID128) {
        containmentFail("UNIT_ATTACHED-at-BOOT receipt has an invalid boot or invocation identity")
    }
    val systemd = root.objectField("systemd", "UNIT_ATTACHED-at-BOOT receipt")
    systemd.requireKeys(SYSTEMD_FIELDS, "systemd receipt")
    systemd.requireString("id", definition.unitName, "systemd receipt")
    systemd.requireBoolean("transient", true, "systemd receipt")
    systemd.requireString("loadState", "loaded", "systemd receipt")
    systemd.requireString("activeState", "active", "systemd receipt")
    systemd.requireString("subState", "running", "systemd receipt")
    systemd.requireString("collectMode", "inactive-or-failed", "systemd receipt")
    systemd.requireLong("runtimeMaxMillis", definition.budgets.wallClockMillis, "systemd receipt")
    systemd.requireLong("timeoutStopMillis", SYSTEMD_TIMEOUT_STOP_MILLIS, "systemd receipt")
    systemd.requireLong("tasksMax", definition.budgets.pidsMax, "systemd receipt")
    systemd.requireLong("memoryMaxBytes", definition.budgets.maximumResidentBytes, "systemd receipt")
    systemd.requireLong("memorySwapMaxBytes", 0L, "systemd receipt")
    systemd.requireString("oomPolicy", "kill", "systemd receipt")
    systemd.requireString("killMode", "control-group", "systemd receipt")
    systemd.requireBoolean("sendSigkill", true, "systemd receipt")
    systemd.requireBoolean("delegate", false, "systemd receipt")
    val controlGroup = systemd.stringField("controlGroup", "systemd receipt")
    if (controlGroup != derivedControlGroup(definition)) {
        containmentFail("systemd control group is not the exact derived user-manager unit leaf")
    }
    val cgroup = root.objectField("cgroup", "UNIT_ATTACHED-at-BOOT receipt")
    cgroup.requireKeys(CGROUP_FIELDS, "cgroup receipt")
    cgroup.requireInt("version", 2, "cgroup receipt")
    cgroup.requireString("path", "/sys/fs/cgroup$controlGroup", "cgroup receipt")
    listOf("device", "inode", "mountId").forEach { field ->
        if (cgroup.longField(field, "cgroup receipt") <= 0L) containmentFail("cgroup identity is invalid")
    }
    cgroup.requireInt("populated", 1, "cgroup receipt")
    cgroup.requireInt("frozen", 0, "cgroup receipt")
    val controllers = cgroup.arrayField("controllers", "cgroup receipt").map { it.jsonPrimitive.content }
    if (controllers != listOf("cpu", "memory", "pids")) containmentFail("cgroup controllers differ")
    cgroup.requireLong("memoryMaxBytes", definition.budgets.maximumResidentBytes, "cgroup receipt")
    cgroup.requireLong("memorySwapMaxBytes", 0L, "cgroup receipt")
    cgroup.requireLong("pidsMax", definition.budgets.pidsMax, "cgroup receipt")
    cgroup.requireString("killMode", "control-group", "cgroup receipt")
    cgroup.requireBoolean("sendSigkill", true, "cgroup receipt")
    val boot = root.objectField("bootProtocol", "UNIT_ATTACHED-at-BOOT receipt")
    boot.requireKeys(BOOT_PROTOCOL_FIELDS, "BOOT protocol")
    boot.requireInt("version", 1, "BOOT protocol")
    boot.requireString("state", "BOOT", "BOOT protocol")
    boot.requireString("nonce", definition.bindingSha256, "BOOT protocol")
    boot.requireString(
        "protocolSha256",
        OracleArtifacts.sha256("BOOT\u0000${definition.bindingSha256}".toByteArray()),
        "BOOT protocol",
    )
    val processes = parseBootProcesses(definition, root.arrayField("processes", "UNIT_ATTACHED-at-BOOT receipt"))
    val receiptSha256 = root.stringField("receiptSha256", "UNIT_ATTACHED-at-BOOT receipt")
    requireSha256(receiptSha256, "UNIT_ATTACHED-at-BOOT receipt")
    val unsigned = JsonObject(root - "receiptSha256")
    if (sha256(unsigned) != receiptSha256) containmentFail("UNIT_ATTACHED-at-BOOT self hash differs")
    return AttachedReceiptFacts(receiptSha256, bootId, Collections.unmodifiableList(processes))
}

private fun parseAbsenceReceipt(
    definition: DefinitionFacts,
    attached: AttachedReceiptFacts,
    bytes: ByteArray,
): String {
    val root = parseCanonicalObject(bytes, "terminal-absence receipt")
    root.requireKeys(ABSENCE_RECEIPT_FIELDS, "terminal-absence receipt")
    root.requireInt("schemaVersion", 1, "terminal-absence receipt")
    root.requireString("provider", ABSENCE_RECEIPT_PROVIDER, "terminal-absence receipt")
    root.requireString("phase", "TERMINAL_ABSENT", "terminal-absence receipt")
    root.requireString("bindingSha256", definition.bindingSha256, "terminal-absence receipt")
    root.requireString("attachedReceiptSha256", attached.receiptSha256, "terminal-absence receipt")
    root.requireString("bootId", attached.bootId, "terminal-absence receipt")
    root.requireString("unitName", definition.unitName, "terminal-absence receipt")
    val kill = root.objectField("kill", "terminal-absence receipt")
    kill.requireKeys(KILL_FIELDS, "whole-cgroup kill")
    kill.requireString("mechanism", "systemd-control-group", "whole-cgroup kill")
    kill.requireString("whom", "all", "whole-cgroup kill")
    kill.requireString("signal", "SIGKILL", "whole-cgroup kill")
    kill.requireString("killMode", "control-group", "whole-cgroup kill")
    val unit = root.objectField("unit", "terminal-absence receipt")
    unit.requireKeys(UNIT_ABSENCE_FIELDS, "unit absence")
    unit.requireString("loadState", "not-found", "unit absence")
    unit.requireInt("sameNameCandidates", 0, "unit absence")
    unit.requireBoolean("invocationPresent", false, "unit absence")
    val cgroup = root.objectField("cgroup", "terminal-absence receipt")
    cgroup.requireKeys(CGROUP_ABSENCE_FIELDS, "cgroup absence")
    cgroup.requireBoolean("pathPresent", false, "cgroup absence")
    cgroup.requireInt("sameNameCandidates", 0, "cgroup absence")
    cgroup.requireInt("populated", 0, "cgroup absence")
    val processes = root.arrayField("processes", "terminal-absence receipt")
    if (processes.size != attached.processes.size) containmentFail("terminal pidfd inventory differs")
    processes.zip(attached.processes).forEach { (element, expected) ->
        val process = element as? JsonObject ?: containmentFail("terminal pidfd record must be an object")
        process.requireKeys(ABSENT_PROCESS_FIELDS, "terminal pidfd record")
        process.requireString("role", expected.role, "terminal pidfd record")
        process.requireLong("pid", expected.pid, "terminal pidfd record")
        process.requireLong("startTimeTicks", expected.startTimeTicks, "terminal pidfd record")
        process.requireBoolean("pidfdAlive", false, "terminal pidfd record")
    }
    root.requireInt("independentAbsenceSweeps", REQUIRED_ABSENCE_SWEEPS, "terminal-absence receipt")
    val digest = root.stringField("absenceReceiptSha256", "terminal-absence receipt")
    requireSha256(digest, "terminal-absence receipt")
    if (sha256(JsonObject(root - "absenceReceiptSha256")) != digest) {
        containmentFail("terminal-absence self hash differs")
    }
    return digest
}

private fun bootProcessObjects(definition: DefinitionFacts, pids: List<Long>): JsonArray {
    val outer = pids[0]
    val init = pids[1]
    val keeper = pids[2]
    return JsonArray(
        listOf(
            bootProcessJson("scope-leader", outer, outer * 100L + 1L, null, listOf(outer),
                definition.artifactSha256.getValue(GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE)),
            bootProcessJson("namespace-init", init, init * 100L + 1L, "scope-leader", listOf(init, 1L),
                definition.artifactSha256.getValue(GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE)),
            bootProcessJson("kotlin-boot-keeper", keeper, keeper * 100L + 1L, "namespace-init", listOf(keeper, 2L),
                definition.artifactSha256.getValue(GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE)),
        ),
    )
}

private fun bootProcessJson(
    role: String,
    pid: Long,
    startTimeTicks: Long,
    parentRole: String?,
    namespacePids: List<Long>,
    executableSha256: String,
): JsonObject = JsonObject(
    mapOf(
        "role" to JsonPrimitive(role),
        "pid" to JsonPrimitive(pid),
        "startTimeTicks" to JsonPrimitive(startTimeTicks),
        "parentRole" to (parentRole?.let(::JsonPrimitive) ?: JsonNull),
        "namespacePids" to JsonArray(namespacePids.map(::JsonPrimitive)),
        "executableSha256" to JsonPrimitive(executableSha256),
        "pidfdPinned" to JsonPrimitive(true),
    ),
)

private fun parseBootProcesses(definition: DefinitionFacts, array: JsonArray): List<AttachedProcessFacts> {
    if (array.size != REQUIRED_BOOT_PROCESS_COUNT) containmentFail("BOOT receipt must bind exactly three processes")
    val expected = listOf(
        Triple("scope-leader", null, GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE),
        Triple("namespace-init", "scope-leader", GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE),
        Triple("kotlin-boot-keeper", "namespace-init", GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE),
    )
    val seen = hashSetOf<Long>()
    return array.zip(expected).map { (element, expectedProcess) ->
        val process = element as? JsonObject ?: containmentFail("BOOT process record must be an object")
        process.requireKeys(BOOT_PROCESS_FIELDS, "BOOT process record")
        process.requireString("role", expectedProcess.first, "BOOT process record")
        val parent = process["parentRole"]
        val observedParent = when (parent) {
            JsonNull -> null
            is JsonPrimitive -> parent.takeIf { it.isString }?.content
                ?: containmentFail("BOOT parent role must be a string or null")
            else -> containmentFail("BOOT parent role must be a string or null")
        }
        if (observedParent != expectedProcess.second) containmentFail("BOOT process parent chain differs")
        val pid = process.longField("pid", "BOOT process record")
        val start = process.longField("startTimeTicks", "BOOT process record")
        if (pid <= 0L || start <= 0L || !seen.add(pid)) containmentFail("BOOT process identity is invalid")
        val namespacePids = process.arrayField("namespacePids", "BOOT process record").map { element ->
            val primitive = element as? JsonPrimitive
            primitive?.takeIf { !it.isString }?.longOrNull
                ?: containmentFail("BOOT namespace PID must be an integer")
        }
        val expectedNamespace = when (expectedProcess.first) {
            "scope-leader" -> listOf(pid)
            "namespace-init" -> listOf(pid, 1L)
            else -> listOf(pid, 2L)
        }
        if (namespacePids != expectedNamespace) containmentFail("BOOT namespace process identity differs")
        process.requireString(
            "executableSha256",
            definition.artifactSha256.getValue(expectedProcess.third),
            "BOOT process record",
        )
        process.requireBoolean("pidfdPinned", true, "BOOT process record")
        AttachedProcessFacts(expectedProcess.first, pid, start)
    }
}

private fun artifactJson(identity: GccCompilerEngineContainmentArtifactIdentity): JsonObject = JsonObject(
    mapOf(
        "role" to JsonPrimitive(identity.role.wireName),
        "path" to JsonPrimitive(identity.path.toString()),
        "bytes" to JsonPrimitive(identity.bytes),
        "sha256" to JsonPrimitive(identity.sha256),
    ),
)

private fun analysisStateJson(state: GccCompilerEngineAnalysisStateIdentity): JsonObject = JsonObject(
    mapOf(
        "mode" to JsonPrimitive(state.mode.wireName),
        "path" to JsonPrimitive(state.path.toString()),
        "manifestSha256" to (state.manifestSha256?.let(::JsonPrimitive) ?: JsonNull),
        "entryCount" to JsonPrimitive(state.entryCount),
        "totalBytes" to JsonPrimitive(state.totalBytes),
    ),
)

private fun outputLeaseJson(lease: GccCompilerEngineOutputLeaseIdentity): JsonObject = JsonObject(
    linkedMapOf(
        "path" to JsonPrimitive(lease.path.toString()),
        "device" to JsonPrimitive(lease.device),
        "inode" to JsonPrimitive(lease.inode),
        "mountId" to JsonPrimitive(lease.mountId),
        "uid" to JsonPrimitive(lease.uid),
        "gid" to JsonPrimitive(lease.gid),
        "permissions" to JsonPrimitive(lease.permissions),
        "requiredAvailableBytes" to JsonPrimitive(lease.requiredAvailableBytes),
        "maximumFilesystemBytes" to JsonPrimitive(lease.maximumFilesystemBytes),
        "requiredAvailableInodes" to JsonPrimitive(lease.requiredAvailableInodes),
        "maximumFilesystemInodes" to JsonPrimitive(lease.maximumFilesystemInodes),
    ),
)

private fun budgetsJson(budgets: GccCompilerEngineContainmentBudgets): JsonObject = JsonObject(
    mapOf(
        "wallClockMillis" to JsonPrimitive(budgets.wallClockMillis),
        "maximumResidentBytes" to JsonPrimitive(budgets.maximumResidentBytes),
        "pidsMax" to JsonPrimitive(budgets.pidsMax),
    ),
)

private fun containmentJson(budgets: GccCompilerEngineContainmentBudgets): JsonObject = JsonObject(
    mapOf(
        "phaseOrder" to JsonArray(
            listOf("PREPARED", "UNIT_ATTACHED_AT_BOOT", "TERMINAL_ABSENT").map(::JsonPrimitive),
        ),
        "startTransitionPresent" to JsonPrimitive(false),
        "cgroupVersion" to JsonPrimitive(2),
        "bootBarrier" to JsonPrimitive("BOOT"),
        "collectMode" to JsonPrimitive("inactive-or-failed"),
        "runtimeMaxMillis" to JsonPrimitive(budgets.wallClockMillis),
        "timeoutStopMillis" to JsonPrimitive(SYSTEMD_TIMEOUT_STOP_MILLIS),
        "killMode" to JsonPrimitive("control-group"),
        "sendSigkill" to JsonPrimitive(true),
        "memoryMaxBytes" to JsonPrimitive(budgets.maximumResidentBytes),
        "memorySwapMaxBytes" to JsonPrimitive(0),
        "pidsMax" to JsonPrimitive(budgets.pidsMax),
        "terminalKillWhom" to JsonPrimitive("all"),
        "terminalSignal" to JsonPrimitive("SIGKILL"),
        "requireUnitAbsent" to JsonPrimitive(true),
        "requireCgroupAbsent" to JsonPrimitive(true),
        "requireAllReceiptPidfdsDead" to JsonPrimitive(true),
        "requiredIndependentAbsenceSweeps" to JsonPrimitive(REQUIRED_ABSENCE_SWEEPS),
    ),
)

private fun withSelfHash(unsigned: JsonObject, field: String): ByteArray {
    val digest = sha256(unsigned)
    return OracleJson.canonicalBytes(JsonObject(unsigned + (field to JsonPrimitive(digest))), JSON_LIMITS)
}

private fun sha256(element: JsonElement): String =
    OracleArtifacts.sha256(OracleJson.canonicalBytes(element, JSON_LIMITS))

private fun parseCanonicalObject(bytes: ByteArray, label: String): JsonObject = try {
    OracleJson.parseCanonical(bytes, JSON_LIMITS) as? JsonObject
        ?: containmentFail("$label must be an object")
} catch (failure: GccCompilerEngineContainmentContractException) {
    throw failure
} catch (failure: Exception) {
    throw GccCompilerEngineContainmentContractException("$label is not strict canonical JSON")
}

private fun snapshot(bytes: ByteArray, maximum: Int, label: String): ByteArray {
    if (bytes.isEmpty() || bytes.size > maximum) containmentFail("$label exceeds its bounded byte limit")
    return bytes.copyOf()
}

private fun boundedArtifactCopy(
    source: List<GccCompilerEngineContainmentArtifactIdentity>,
): List<GccCompilerEngineContainmentArtifactIdentity> {
    val copied = ArrayList<GccCompilerEngineContainmentArtifactIdentity>(REQUIRED_ARTIFACT_ROLES.size)
    val iterator = source.iterator()
    var total = 0L
    while (iterator.hasNext()) {
        if (copied.size == MAXIMUM_ARTIFACT_IDENTITIES) {
            throw IllegalArgumentException("containment artifact list exceeds its hard bound")
        }
        val next = iterator.next()
        total = try {
            Math.addExact(total, next.bytes)
        } catch (_: ArithmeticException) {
            throw IllegalArgumentException("containment artifact bytes overflow")
        }
        require(total <= MAXIMUM_AGGREGATE_ARTIFACT_BYTES)
        copied += next
    }
    return Collections.unmodifiableList(copied)
}

private fun boundedStringCopy(source: List<String>, maximum: Int, label: String): List<String> {
    val copied = ArrayList<String>(maximum)
    val iterator = source.iterator()
    var characters = 0
    while (iterator.hasNext()) {
        if (copied.size == maximum) throw IllegalArgumentException("$label exceeds its entry bound")
        val value = iterator.next()
        require(
            value.isNotEmpty() && value.length <= MAXIMUM_COMMAND_COMPONENT_CHARS &&
                value.none { character -> character.code < 0x20 || character.code == 0x7f },
        )
        characters = Math.addExact(characters, value.length)
        require(characters <= MAXIMUM_COMMAND_TOTAL_CHARS)
        copied += value
    }
    return Collections.unmodifiableList(copied)
}

private fun boundedEnvironmentCopy(source: Map<String, String>): Map<String, String> {
    val copied = TreeMap<String, String>()
    var characters = 0
    val iterator = source.entries.iterator()
    while (iterator.hasNext()) {
        if (copied.size == MAXIMUM_ENVIRONMENT_ENTRIES) {
            throw IllegalArgumentException("environment exceeds its entry bound")
        }
        val (name, value) = iterator.next()
        require(name.matches(ENVIRONMENT_NAME) && value.length <= MAXIMUM_ENVIRONMENT_VALUE_CHARS)
        require(value.none { character -> character.code < 0x20 || character.code == 0x7f })
        characters = Math.addExact(characters, name.length + value.length)
        require(characters <= MAXIMUM_ENVIRONMENT_TOTAL_CHARS)
        require(copied.put(name, value) == null) { "environment contains a duplicate name" }
    }
    require(copied == REQUIRED_ENVIRONMENT) {
        "containment environment must be the exact deterministic locale and timezone"
    }
    return Collections.unmodifiableMap(copied)
}

private fun boundedLongCopy(source: List<Long>, maximum: Int, label: String): List<Long> {
    val copied = ArrayList<Long>(maximum)
    val iterator = source.iterator()
    while (iterator.hasNext()) {
        if (copied.size == maximum) containmentFail("$label exceeds its hard bound")
        copied += iterator.next()
    }
    return Collections.unmodifiableList(copied)
}

private fun JsonObject.requireKeys(expected: Set<String>, label: String) {
    if (keys != expected) containmentFail("$label has an unexpected shape")
}

private fun JsonObject.stringField(name: String, label: String): String {
    val primitive = this[name] as? JsonPrimitive
    if (primitive == null || !primitive.isString) containmentFail("$label field $name must be a string")
    return primitive.content
}

private fun JsonObject.longField(name: String, label: String): Long {
    val primitive = this[name] as? JsonPrimitive
    if (primitive == null || primitive.isString || primitive.content.any { it in ".eE" }) {
        containmentFail("$label field $name must be an integer")
    }
    return primitive.longOrNull ?: containmentFail("$label field $name exceeds the integer range")
}

private fun JsonObject.intField(name: String, label: String): Int =
    longField(name, label).takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()
        ?: containmentFail("$label field $name exceeds the Kotlin Int range")

private fun JsonObject.objectField(name: String, label: String): JsonObject =
    this[name] as? JsonObject ?: containmentFail("$label field $name must be an object")

private fun JsonObject.arrayField(name: String, label: String): JsonArray =
    this[name] as? JsonArray ?: containmentFail("$label field $name must be an array")

private fun JsonObject.requireString(name: String, expected: String, label: String) {
    if (stringField(name, label) != expected) containmentFail("$label field $name differs")
}

private fun JsonObject.requireBoolean(name: String, expected: Boolean, label: String) {
    val primitive = this[name] as? JsonPrimitive
    if (primitive == null || primitive.isString || primitive.booleanOrNull != expected) {
        containmentFail("$label field $name differs")
    }
}

private fun JsonObject.requireLong(name: String, expected: Long, label: String) {
    if (longField(name, label) != expected) containmentFail("$label field $name differs")
}

private fun JsonObject.requireInt(name: String, expected: Int, label: String) =
    requireLong(name, expected.toLong(), label)

private fun artifactRole(value: String): GccCompilerEngineContainmentArtifactRole =
    GccCompilerEngineContainmentArtifactRole.entries.singleOrNull { it.wireName == value }
        ?: containmentFail("containment artifact role is unsupported")

private fun analysisStateMode(value: String): GccCompilerEngineAnalysisStateMode =
    GccCompilerEngineAnalysisStateMode.entries.singleOrNull { it.wireName == value }
        ?: containmentFail("analysis-state mode is unsupported")

private fun runKind(value: String): GccCompilerEngineContainmentRunKind =
    GccCompilerEngineContainmentRunKind.entries.singleOrNull { it.wireName == value }
        ?: containmentFail("containment run kind is unsupported")

private fun strictPath(value: String, label: String): Path = try {
    Path.of(value).also { requireAbsoluteNormalized(it, label) }
} catch (failure: IllegalArgumentException) {
    throw GccCompilerEngineContainmentContractException("$label path is invalid")
}

private fun requireAbsoluteNormalized(path: Path, label: String) {
    require(path.isAbsolute && path.normalize() == path && path.parent != null) {
        "$label path must be absolute and normalized"
    }
}

private fun requireSha256(value: String?, label: String) {
    require(value != null && value.matches(SHA256)) { "$label SHA-256 is invalid" }
}

private fun pathsOverlap(first: Path, second: Path): Boolean =
    first == second || first.startsWith(second) || second.startsWith(first)

private fun derivedControlGroup(definition: DefinitionFacts): String =
    "/user.slice/user-${definition.outputUid}.slice/" +
        "user@${definition.outputUid}.service/app.slice/${definition.unitName}"

private fun containmentFail(message: String): Nothing =
    throw GccCompilerEngineContainmentContractException(message)

private const val DEFINITION_PROVIDER = "gcc-compiler-engine-containment-definition-v1"
private const val ATTACHED_RECEIPT_PROVIDER = "gcc-compiler-engine-unit-attached-at-boot-receipt-v1"
private const val ABSENCE_RECEIPT_PROVIDER = "gcc-compiler-engine-terminal-absence-receipt-v1"
private const val ASSESSMENT_AUTHORITY = "non-authoritative-caller-supplied-containment-bytes-v1"
private const val OWNER_ONLY_DIRECTORY_MODE = 0x1c0 // 0700
private const val MINIMUM_OUTPUT_INODES = 128L
private const val MAXIMUM_SINGLE_ARTIFACT_BYTES = 1024L * 1024 * 1024 * 1024
private const val MAXIMUM_AGGREGATE_ARTIFACT_BYTES = 4L * 1024 * 1024 * 1024 * 1024
private const val MAXIMUM_ANALYSIS_STATE_ENTRIES = 2_000_000L
private const val MAXIMUM_ANALYSIS_STATE_BYTES = 1024L * 1024 * 1024 * 1024
private const val MAXIMUM_ARTIFACT_IDENTITIES = 64
private const val MAXIMUM_COMMAND_ARGUMENTS = 128
private const val MAXIMUM_COMMAND_COMPONENT_CHARS = 16_384
private const val MAXIMUM_COMMAND_TOTAL_CHARS = 65_536
private const val MAXIMUM_ENVIRONMENT_ENTRIES = 64
private const val MAXIMUM_ENVIRONMENT_VALUE_CHARS = 16_384
private const val MAXIMUM_ENVIRONMENT_TOTAL_CHARS = 65_536
private const val MINIMUM_RESIDENT_BYTES = 64L * 1024 * 1024
private const val MAXIMUM_RESIDENT_BYTES = 64L * 1024 * 1024 * 1024
private const val MAXIMUM_WALL_CLOCK_MILLIS = 24L * 60 * 60 * 1000
private const val MINIMUM_PIDS_MAX = 4L
private const val MAXIMUM_PIDS_MAX = 4096L
private const val MAXIMUM_DEFINITION_BYTES = 1024 * 1024
private const val MAXIMUM_RECEIPT_BYTES = 1024 * 1024
private const val REQUIRED_BOOT_PROCESS_COUNT = 3
private const val REQUIRED_ABSENCE_SWEEPS = 2
private const val SYSTEMD_TIMEOUT_STOP_MILLIS = 30_000L
private const val ZERO_ID128 = "00000000000000000000000000000000"
private val SHA256 = Regex("[0-9a-f]{64}")
private val BOOT_ID = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
private val SYSTEMD_ID128 = Regex("[0-9a-f]{32}")
private val ENVIRONMENT_NAME = Regex("[A-Z_][A-Z0-9_]{0,127}")
private val REQUIRED_ENVIRONMENT = sortedMapOf(
    "LANG" to "C.UTF-8",
    "LC_ALL" to "C.UTF-8",
    "TZ" to "UTC",
)
private val REQUIRED_ARTIFACT_ROLES = GccCompilerEngineContainmentArtifactRole.entries.toSet()
private val RUNTIME_ARTIFACT_ROLES = setOf(
    GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE,
    GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST,
    GccCompilerEngineContainmentArtifactRole.GHIDRA_ANALYZE_HEADLESS,
    GccCompilerEngineContainmentArtifactRole.EXPORTER_CLASSFILE,
    GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE,
    GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE,
    GccCompilerEngineContainmentArtifactRole.RESOURCE_LIMITER_EXECUTABLE,
    GccCompilerEngineContainmentArtifactRole.SYSTEMD_RUN_EXECUTABLE,
    GccCompilerEngineContainmentArtifactRole.SYSTEMCTL_EXECUTABLE,
    GccCompilerEngineContainmentArtifactRole.SYSTEMD_BUSCTL_EXECUTABLE,
    GccCompilerEngineContainmentArtifactRole.BOOT_KEEPER_CLASSPATH,
)
private val ANALYSIS_INPUT_ROLES = REQUIRED_ARTIFACT_ROLES - RUNTIME_ARTIFACT_ROLES
private val DEFINITION_FIELDS = setOf(
    "schemaVersion", "provider", "authority", "releaseEligible", "startAuthorized", "request",
    "requestSha256", "unitName", "containment", "bindingSha256",
)
private val REQUEST_FIELDS = setOf(
    "engineId", "runKind", "artifacts", "analysisState", "command", "outputLease", "budgets",
    "runtimeSha256", "inputSetSha256",
)
private val ARTIFACT_FIELDS = setOf("role", "path", "bytes", "sha256")
private val ANALYSIS_STATE_FIELDS = setOf("mode", "path", "manifestSha256", "entryCount", "totalBytes")
private val COMMAND_FIELDS = setOf("argv", "environment", "commandSha256")
private val ENVIRONMENT_FIELDS = setOf("name", "value")
private val OUTPUT_LEASE_FIELDS = setOf(
    "path", "device", "inode", "mountId", "uid", "gid", "permissions", "requiredAvailableBytes",
    "maximumFilesystemBytes", "requiredAvailableInodes", "maximumFilesystemInodes", "leaseSha256",
)
private val BUDGET_FIELDS = setOf("wallClockMillis", "maximumResidentBytes", "pidsMax")
private val ATTACHED_RECEIPT_FIELDS = setOf(
    "schemaVersion", "provider", "phase", "bindingSha256", "requestSha256", "unitName", "bootId",
    "invocationId", "commandSha256", "runtimeSha256", "inputSetSha256", "outputLeaseSha256",
    "systemd", "cgroup", "bootProtocol", "processes", "receiptSha256",
)
private val SYSTEMD_FIELDS = setOf(
    "id", "transient", "loadState", "activeState", "subState", "controlGroup", "collectMode",
    "runtimeMaxMillis", "timeoutStopMillis", "tasksMax", "memoryMaxBytes", "memorySwapMaxBytes",
    "oomPolicy", "killMode", "sendSigkill", "delegate",
)
private val CGROUP_FIELDS = setOf(
    "version", "path", "device", "inode", "mountId", "populated", "frozen", "controllers",
    "memoryMaxBytes", "memorySwapMaxBytes", "pidsMax", "killMode", "sendSigkill",
)
private val BOOT_PROTOCOL_FIELDS = setOf("version", "state", "nonce", "protocolSha256")
private val BOOT_PROCESS_FIELDS = setOf(
    "role", "pid", "startTimeTicks", "parentRole", "namespacePids", "executableSha256", "pidfdPinned",
)
private val ABSENCE_RECEIPT_FIELDS = setOf(
    "schemaVersion", "provider", "phase", "bindingSha256", "attachedReceiptSha256", "bootId",
    "unitName", "kill", "unit", "cgroup", "processes", "independentAbsenceSweeps",
    "absenceReceiptSha256",
)
private val KILL_FIELDS = setOf("mechanism", "whom", "signal", "killMode")
private val UNIT_ABSENCE_FIELDS = setOf("loadState", "sameNameCandidates", "invocationPresent")
private val CGROUP_ABSENCE_FIELDS = setOf("pathPresent", "sameNameCandidates", "populated")
private val ABSENT_PROCESS_FIELDS = setOf("role", "pid", "startTimeTicks", "pidfdAlive")
private val JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_DEFINITION_BYTES,
    maximumCanonicalBytes = MAXIMUM_DEFINITION_BYTES,
    maximumDepth = 24,
    maximumNodes = 10_000,
    maximumStringBytes = 64 * 1024,
    maximumTotalStringBytes = 512 * 1024,
)

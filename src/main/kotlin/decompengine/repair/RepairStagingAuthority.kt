package decompengine.repair

import decompengine.acp.LinuxDescriptor
import decompengine.acp.ACP_CAPTURED_REPAIR_WORKSPACE
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentHarness
import decompengine.agent.AgentWorkspaceRoot
import decompengine.agent.captureAgentExecutionReceipt
import java.nio.file.Path
import java.util.Collections
import java.util.LinkedHashMap
import java.util.TreeMap
import java.util.TreeSet

/**
 * Program-neutral authority for one repair-agent workspace.
 *
 * A production authority must enforce quotas while output is captured and must not hand an
 * untrusted agent a writable ordinary host directory. The repair loop rejects test-only
 * authorities before beginning an attempt.
 */
interface RepairStagingAuthority {
    val assurance: RepairStagingAssurance

    fun execute(
        harness: AgentHarness,
        initialFiles: Map<String, ByteArray>,
        writablePaths: Set<String>,
        budget: RepairResourceBudget,
        requestFactory: (AgentWorkspaceRoot) -> AgentExecutionRequest,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): RepairStagingExecution

    /**
     * Receipt-bearing execution for workflows that must persist the terminal invocation before
     * interpreting its result. The default keeps third-party version-1 authorities source
     * compatible, but cannot supply provider evidence; strict production authorities override it.
     */
    fun executeReceipt(
        harness: AgentHarness,
        initialFiles: Map<String, ByteArray>,
        writablePaths: Set<String>,
        budget: RepairResourceBudget,
        requestFactory: (AgentWorkspaceRoot) -> AgentExecutionRequest,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): RepairStagingExecution {
        lateinit var request: AgentExecutionRequest
        val execution = execute(
            harness,
            initialFiles,
            writablePaths,
            budget,
            { root -> requestFactory(root).also { request = it } },
            onEvent,
        )
        return RepairStagingExecution(
            captureAgentExecutionReceipt(request) { execution.result },
            execution.files,
        )
    }
}

enum class RepairStagingAssurance { STRICT_CAPTURED, TEST_ONLY_HOST_DIRECTORY }

class RepairStagingExecution(
    val receipt: AgentExecutionReceipt,
    files: Map<String, ByteArray?>,
) {
    private val frozenFiles = immutableCapturedFiles(files)

    /** Compatibility projection; receipt-aware workflows persist [receipt] before calling this. */
    val result: AgentExecutionResult get() = receipt.requireResult()

    /** Every read is detached so no caller-visible array is shared with captured staging state. */
    val files: Map<String, ByteArray?> get() = immutableCapturedFiles(frozenFiles)
}

/** A trusted adapter that emits proposed file bodies through the authority-owned bounded sink. */
interface CapturedRepairAgentHarness : AgentHarness {
    fun executeCaptured(
        request: AgentExecutionRequest,
        initialFiles: Map<String, ByteArray>,
        output: BoundedRepairOutput,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): AgentExecutionResult

    /** Receipt-returning seam retained alongside the version-1 captured-harness contract. */
    fun executeCapturedReceipt(
        request: AgentExecutionRequest,
        initialFiles: Map<String, ByteArray>,
        output: BoundedRepairOutput,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): AgentExecutionReceipt = captureAgentExecutionReceipt(request) {
        executeCaptured(request, initialFiles, output, onEvent)
    }
}

/** The only mutation surface exposed by [CapturedRepairStagingAuthority]. */
class BoundedRepairOutput internal constructor(
    private val initialFiles: Map<String, ByteArray>,
    private val writablePaths: Set<String>,
    internal val resourceBudget: RepairResourceBudget,
) {
    /** Detached trusted metadata for adapters binding the effective sink authority across continuation. */
    internal fun allowedReplacementPaths(): Set<String> = Collections.unmodifiableSet(TreeSet(writablePaths))

    private val replacements = TreeMap<String, ByteArray?>()
    private val currentFiles = TreeMap<String, ByteArray>().apply {
        initialFiles.forEach { (path, bytes) -> put(path, bytes.copyOf()) }
    }
    private var replacementBytes = 0L
    private var workspaceBytes = initialFiles.values.fold(0L) { total, bytes ->
        Math.addExact(total, bytes.size.toLong())
    }
    private var closed = false

    @Synchronized
    fun replace(relativePath: String, bytes: ByteArray) {
        check(!closed) { "captured repair output is closed" }
        require(relativePath in writablePaths) { "captured repair output is unauthorized: $relativePath" }
        if (bytes.size.toLong() > resourceBudget.maximumSourceFileBytes) {
            throw RepairBudgetExceededException(
                "captured repair output $relativePath exceeds the source-file byte budget",
            )
        }
        val wasChanged = relativePath in replacements
        val previousReplacementBytes = replacements[relativePath]?.size?.toLong() ?: 0L
        val remainsChanged = !bytes.contentEquals(initialFiles.getValue(relativePath))
        val projectedPatchFiles = replacements.size - (if (wasChanged) 1 else 0) +
            (if (remainsChanged) 1 else 0)
        if (projectedPatchFiles > resourceBudget.maximumPatchFiles) {
            throw RepairBudgetExceededException("captured repair output exceeds the patch-file budget")
        }
        val projectedReplacementBytes = Math.addExact(
            Math.subtractExact(replacementBytes, previousReplacementBytes),
            if (remainsChanged) bytes.size.toLong() else 0L,
        )
        if (projectedReplacementBytes > resourceBudget.maximumPatchBytes) {
            throw RepairBudgetExceededException(
                "captured repair output contains $projectedReplacementBytes bytes; " +
                    "limit=${resourceBudget.maximumPatchBytes}",
            )
        }
        val projected = Math.addExact(
            Math.subtractExact(workspaceBytes, currentFiles[relativePath]?.size?.toLong() ?: 0L),
            bytes.size.toLong(),
        )
        if (projected > resourceBudget.maximumStagingBytes) {
            throw RepairBudgetExceededException(
                "captured repair workspace contains $projected bytes; limit=${resourceBudget.maximumStagingBytes}",
            )
        }
        replacementBytes = projectedReplacementBytes
        workspaceBytes = projected
        currentFiles[relativePath] = bytes.copyOf()
        if (remainsChanged) replacements[relativePath] = bytes.copyOf() else replacements.remove(relativePath)
    }

    @Synchronized
    fun delete(relativePath: String) {
        check(!closed) { "captured repair output is closed" }
        require(relativePath in writablePaths) { "captured repair deletion is unauthorized: $relativePath" }
        val current = currentFiles[relativePath] ?: return
        val wasChanged = relativePath in replacements
        val projectedPatchFiles = replacements.size - (if (wasChanged) 1 else 0) + 1
        if (projectedPatchFiles > resourceBudget.maximumPatchFiles) {
            throw RepairBudgetExceededException("captured repair output exceeds the patch-file budget")
        }
        replacementBytes = Math.subtractExact(
            replacementBytes,
            replacements[relativePath]?.size?.toLong() ?: 0L,
        )
        workspaceBytes = Math.subtractExact(workspaceBytes, current.size.toLong())
        currentFiles.remove(relativePath)
        replacements[relativePath] = null
    }

    @Synchronized
    internal fun finish(): Map<String, ByteArray?> {
        closed = true
        return immutableCapturedFiles(replacements)
    }
}

/**
 * Strict in-memory capture for adapters such as the legacy patch-response client. There are no
 * filesystem entries for an agent to turn into sparse files, FIFOs, links, or background-writer
 * handles. File and directory quotas are checked before the adapter is invoked.
 */
object CapturedRepairStagingAuthority : RepairStagingAuthority {
    override val assurance: RepairStagingAssurance = RepairStagingAssurance.STRICT_CAPTURED

    override fun execute(
        harness: AgentHarness,
        initialFiles: Map<String, ByteArray>,
        writablePaths: Set<String>,
        budget: RepairResourceBudget,
        requestFactory: (AgentWorkspaceRoot) -> AgentExecutionRequest,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): RepairStagingExecution = executeReceipt(
        harness,
        initialFiles,
        writablePaths,
        budget,
        requestFactory,
        onEvent,
    ).also { it.receipt.requireResult() }

    override fun executeReceipt(
        harness: AgentHarness,
        initialFiles: Map<String, ByteArray>,
        writablePaths: Set<String>,
        budget: RepairResourceBudget,
        requestFactory: (AgentWorkspaceRoot) -> AgentExecutionRequest,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): RepairStagingExecution {
        val captured = harness as? CapturedRepairAgentHarness
            ?: throw IllegalArgumentException(
                "strict repair staging requires a CapturedRepairAgentHarness or another strict authority",
            )
        require(initialFiles.keys == initialFiles.keys.map(::normalizedCapturedPath).distinct().toSet())
        require(writablePaths.all { it in initialFiles }) { "repair writable paths must be staged source inputs" }
        require(initialFiles.size <= budget.maximumContextFiles) { "repair staging exceeds the file-entry budget" }
        val directories = buildSet {
            add("") // The virtual root itself is an inode/entry in a filesystem-backed authority.
            initialFiles.keys.forEach { relative ->
                val components = relative.split('/').dropLast(1)
                components.indices.forEach { index -> add(components.take(index + 1).joinToString("/")) }
            }
        }
        require(directories.size <= budget.maximumStagingDirectories) {
            "repair staging requires ${directories.size} directories; limit=${budget.maximumStagingDirectories}"
        }
        val initialBytes = initialFiles.values.fold(0L) { total, bytes -> Math.addExact(total, bytes.size.toLong()) }
        if (initialBytes > budget.maximumStagingBytes) {
            throw RepairBudgetExceededException(
                "repair staging requires $initialBytes bytes; limit=${budget.maximumStagingBytes}",
            )
        }
        val frozenInitial = immutableRequiredCapturedFiles(initialFiles)
        val frozenWritable = Collections.unmodifiableSet(TreeSet(writablePaths))
        val harnessView = immutableRequiredCapturedFiles(frozenInitial)
        val output = BoundedRepairOutput(frozenInitial, frozenWritable, budget)
        // The ACP outer sandbox creates only an empty namespace anchor at this path. It is never a
        // host bind: captured adapters can mutate source state only through the bounded sink.
        val request = requestFactory(AgentWorkspaceRoot("project", ACP_CAPTURED_REPAIR_WORKSPACE))
        val receipt = try {
            captured.executeCapturedReceipt(request, harnessView, output, onEvent)
        } catch (failure: Throwable) {
            output.finish()
            throw failure
        }
        val files = frozenInitial.mapValuesTo(TreeMap()) { (_, bytes) -> bytes.copyOf() as ByteArray? }
        output.finish().forEach { (path, bytes) -> files[path] = bytes }
        return RepairStagingExecution(receipt, files)
    }
}

private fun normalizedCapturedPath(value: String): String {
    require(value.isNotBlank() && '\\' !in value && !value.startsWith('/')) { "invalid captured repair path: $value" }
    require(value.split('/').none { it in setOf("", ".", "..") }) { "invalid captured repair path: $value" }
    return value
}

private fun immutableCapturedFiles(values: Map<String, ByteArray?>): Map<String, ByteArray?> {
    val copied = LinkedHashMap<String, ByteArray?>(values.size)
    values.toSortedMap().forEach { (path, bytes) -> copied[path] = bytes?.copyOf() }
    return Collections.unmodifiableMap(copied)
}

private fun immutableRequiredCapturedFiles(values: Map<String, ByteArray>): Map<String, ByteArray> {
    val copied = LinkedHashMap<String, ByteArray>(values.size)
    values.toSortedMap().forEach { (path, bytes) -> copied[path] = bytes.copyOf() }
    return Collections.unmodifiableMap(copied)
}
/** Kernel-owned path to an already-open repair descriptor; no workspace pathname is re-resolved. */
internal fun repairDescriptorPath(descriptor: LinuxDescriptor): Path =
    Path.of("/proc/self/fd", descriptor.fd.toString())

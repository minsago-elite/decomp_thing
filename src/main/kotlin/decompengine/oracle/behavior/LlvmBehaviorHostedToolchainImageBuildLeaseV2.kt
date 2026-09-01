package decompengine.oracle.behavior

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateInspection
import decompengine.oracle.core.DescriptorBoundStateSnapshot
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.lang.reflect.InvocationTargetException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.SecureRandom
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

internal class LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/**
 * Durable positions in the deliberately fact-free toolchain image-build lease.
 *
 * A phase name records only that future orchestration reached a code position. Until a fixed
 * Docker Engine session supplies reviewed unforgeable tokens, no phase authenticates an Engine
 * observation, POST, image, deletion, or absence fact.
 */
internal enum class LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase(val wireName: String) {
    RECOVERED("recovered"),
    RECOVERY_LOCATORS_ABSENT("recovery-locators-absent"),
    IMAGE_BUILD_POST_ARMED("image-build-post-armed"),
    IMAGE_BUILD_OUTCOME_AMBIGUOUS("image-build-outcome-ambiguous"),
    IMAGE_AUTHENTICATED("image-authenticated"),
    ORPHAN_IMAGE_IDENTIFIED("orphan-image-identified"),
    RECOVERY_FENCE_REQUIRED("recovery-fence-required"),
    BUILD_TERMINATED_NO_IMAGE("build-terminated-no-image"),
    IMAGE_DELETE_ARMED("image-delete-armed"),
    IMAGE_ABSENCE_PROVED("image-absence-proved"),
    CLEANUP_BLOCKED("cleanup-blocked"),
}

/**
 * One descriptor-locked, append-only lease for the exact reviewed LLVM toolchain image recipe.
 *
 * The owner binds the recipe and a unique recovery namespace but performs no Docker, HTTP, image,
 * deletion, CREATE, START, observation, scoring, publication, or release operation. The transition
 * methods accept no facts and confer no authority. In particular, `IMAGE_BUILD_POST_ARMED` is a
 * one-way code checkpoint exposed only by an owner returned from the exact call that created both
 * the binding and initial transition. A recovered owner can never arm a build POST, even if a
 * valid journal suffix was destructively removed. Deleting the whole journal namespace is outside
 * this lease's guarantees and is destructive abandonment, not proof that prior Engine work ended.
 *
 * The BuildKit build ID is exactly [operationId]. The retained cancel locator is useful for
 * recovery, but a successful cancel response does not prove quiescence or image absence: Moby can
 * return success for an unknown ID and cancellation can race BuildKit registration.
 *
 * ACP remains the required first-class candidate producer/operator, is not an input to this lease,
 * and gains no authority from it. The reviewed image recipe truthfully installs Python as a package;
 * neither Python nor this journal implements or supplies oracle or control authority.
 */
internal sealed interface LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner : AutoCloseable {
    val authority: String
    val operationId: String
    val buildId: String
    val buildCancelRequestTarget: String
    val buildIntentSha256: String
    val requestIntentSha256: String
    val bindingSha256: String
    val latestTransitionSha256: String
    val phase: LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
    val recoveryTag: String
    val recoveryLeaseLabelKey: String
    val recoveryLeaseLabelValue: String
    val contentSha256LabelKey: String
    val contentSha256LabelValue: String
    val journalRootPathSha256: String

    val reproductionLockSha256: String
    val buildRecordSha256: String
    val dockerfileSha256: String
    val dockerfileBytes: Long
    val deterministicTarSha256: String
    val deterministicTarBytes: Long
    val baseImageReference: String
    val platform: String
    val sourceDateEpoch: String

    /** Returns a defensive copy of the exact durable binding. */
    val canonicalBindingBytes: ByteArray

    fun requireCurrentBinding()

    fun recordRecoveryLocatorsAbsent(): LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
    fun recordImageBuildOutcomeAmbiguous(): LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
    fun recordImageAuthenticated(): LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
    fun recordOrphanImageIdentified(): LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
    fun requireRecoveryFence(): LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
    fun recordBuildTerminatedNoImage(): LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
    fun armImageDelete(): LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
    fun recordImageAbsenceProved(): LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
    fun blockCleanup(): LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase

    override fun close()
}

/** Fresh-only capability that can durably arm exactly one image-build POST. */
internal sealed interface LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner :
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner {
    fun armImageBuildPost(): LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
}

/** Retained fresh-only lease ownership available only inside the fixed hosted Engine coordinator. */
internal sealed interface LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner : AutoCloseable {
    val operationId: String
    val buildId: String

    fun requireCurrentBinding()

    override fun close()
}

/**
 * Creates or recovers a lease from one raw journal-root path and a consuming recipe handoff.
 *
 * [createFresh] succeeds only for an empty journal and only when that call durably publishes both
 * binding and initial transition. [recover] requires a preexisting binding or exact pending
 * publication and never returns POST-arm capability. Consuming the same recipe binding twice fails
 * without touching the first successful lease. No mode flag, nonce, locator, ID, digest, request
 * bytes, parsed fact, runner, Engine, or callback is caller supplied.
 */
internal object LlvmBehaviorHostedToolchainImageBuildLeaseV2 {
    /** Irreversibly consumes an exact untouched fresh lease for the fixed Engine owner. */
    private fun consumeFreshForHostedToolchainImageEngineV1(
        owner: LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner,
    ): LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner {
        val bound = owner as? FreshBoundOwner
            ?: leaseFail("fresh hosted toolchain image-build lease v2 owner is not owned here")
        val method = BoundOwner::class.java.declaredMethods.single {
            it.name == "consumeForHostedToolchainImageEngineV1"
        }
        check(method.trySetAccessible())
        return try {
            method.invoke(bound) as LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
    }

    fun createFresh(
        journalRootPath: Path,
        recipeBinding: LlvmBehaviorHostedToolchainImageRecipeV1LeaseBinding,
    ): LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner = consumeRecipeBinding(
        recipeBinding,
        "create fresh hosted toolchain image-build lease v2",
    ) { recipe ->
        val opened = createFreshBoundLease(journalRootPath, recipe)
        try {
            val constructor = FreshBoundOwner::class.java.getDeclaredConstructor(
                LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner::class.java,
                OpenedToolchainImageBuildLease::class.java,
            )
            check(constructor.trySetAccessible())
            constructor.newInstance(recipe, opened)
                as LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner
        } catch (failure: Throwable) {
            runCatching { opened.journal.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    fun recover(
        journalRootPath: Path,
        recipeBinding: LlvmBehaviorHostedToolchainImageRecipeV1LeaseBinding,
    ): LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner = consumeRecipeBinding(
        recipeBinding,
        "recover hosted toolchain image-build lease v2",
    ) { recipe ->
        val opened = recoverBoundLease(journalRootPath, recipe)
        try {
            val constructor = RecoveredBoundOwner::class.java.getDeclaredConstructor(
                LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner::class.java,
                OpenedToolchainImageBuildLease::class.java,
            )
            check(constructor.trySetAccessible())
            constructor.newInstance(recipe, opened)
                as LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner
        } catch (failure: Throwable) {
            runCatching { opened.journal.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    private inline fun <T> consumeRecipeBinding(
        binding: LlvmBehaviorHostedToolchainImageRecipeV1LeaseBinding,
        label: String,
        action: (LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner) -> T,
    ): T {
        var recipe: LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner? = null
        try {
            val method = LlvmBehaviorHostedToolchainImageRecipeV1::class.java.declaredMethods.single {
                it.name == "consumeImageBuildLeaseBinding"
            }
            check(method.trySetAccessible())
            recipe = try {
                method.invoke(LlvmBehaviorHostedToolchainImageRecipeV1, binding)
                    as LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner
            } catch (failure: InvocationTargetException) {
                throw failure.targetException
            }
            return translateLeaseFailures(label) {
                action(checkNotNull(recipe))
            }
        } catch (failure: Throwable) {
            val closeTarget: AutoCloseable = recipe ?: binding
            runCatching { closeTarget.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    /* Kept inside the sole lease factory so Kotlin emits no public file-facade journal opener. */
    private fun createFreshBoundLease(
        journalRootPath: Path,
        recipeOwner: LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner,
    ): OpenedToolchainImageBuildLease {
        requireExactRawPath(journalRootPath)
        val recipe = ToolchainRecipePins.capture(recipeOwner)
        val rootPathSha256 = pathCommitment(journalRootPath)
        val authority = ToolchainImageBuildJournalRoot.open(journalRootPath)
        val journal = try {
            newDescriptorJournal(rootPathSha256, recipe, authority)
        } catch (failure: Throwable) {
            runCatching { authority.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
        try {
            val history = journal.createFresh()
            recipeOwner.requireCurrent()
            return newOpenedLease(journal, history.binding, history)
        } catch (failure: Throwable) {
            runCatching { journal.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    /* Recovery stays equally sealed even though it can never produce POST-arm capability. */
    private fun recoverBoundLease(
        journalRootPath: Path,
        recipeOwner: LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner,
    ): OpenedToolchainImageBuildLease {
        requireExactRawPath(journalRootPath)
        val recipe = ToolchainRecipePins.capture(recipeOwner)
        val rootPathSha256 = pathCommitment(journalRootPath)
        val authority = ToolchainImageBuildJournalRoot.open(journalRootPath)
        val journal = try {
            newDescriptorJournal(rootPathSha256, recipe, authority)
        } catch (failure: Throwable) {
            runCatching { authority.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
        try {
            val history = journal.recover()
            recipeOwner.requireCurrent()
            return newOpenedLease(journal, history.binding, history)
        } catch (failure: Throwable) {
            runCatching { journal.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    private fun newDescriptorJournal(
        rootPathSha256: String,
        recipe: ToolchainRecipePins,
        authority: ToolchainImageBuildJournalRoot,
    ): ToolchainImageBuildDescriptorJournal {
        val constructor = ToolchainImageBuildDescriptorJournal::class.java.getDeclaredConstructor(
            String::class.java,
            ToolchainRecipePins::class.java,
            ToolchainImageBuildJournalRoot::class.java,
        )
        check(constructor.trySetAccessible())
        return constructor.newInstance(rootPathSha256, recipe, authority)
    }

    private fun newOpenedLease(
        journal: ToolchainImageBuildDescriptorJournal,
        binding: ToolchainImageBuildLeaseBinding,
        history: ToolchainImageBuildLeaseHistory,
    ): OpenedToolchainImageBuildLease {
        val constructor = OpenedToolchainImageBuildLease::class.java.getDeclaredConstructor(
            ToolchainImageBuildDescriptorJournal::class.java,
            ToolchainImageBuildLeaseBinding::class.java,
            ToolchainImageBuildLeaseHistory::class.java,
        )
        check(constructor.trySetAccessible())
        return constructor.newInstance(journal, binding, history)
    }

    private abstract class BoundOwner(
        private val recipe: LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner,
        private val opened: OpenedToolchainImageBuildLease,
        private val freshOpen: Boolean,
    ) : LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner {
        private var history = opened.history
        private var closed = false
        private var poisoned = false
        private var transferred = false
        private var retainedClosed = false

        override val authority: String
            @Synchronized get() = currentForCaller().let { LEASE_AUTHORITY }
        override val operationId: String
            @Synchronized get() = currentForCaller().binding.operationId
        override val buildId: String
            @Synchronized get() = currentForCaller().binding.operationId
        override val buildCancelRequestTarget: String
            @Synchronized get() = buildCancelRequestTarget(currentForCaller().binding.operationId)
        override val buildIntentSha256: String
            @Synchronized get() = currentForCaller().binding.buildIntentSha256
        override val requestIntentSha256: String
            @Synchronized get() = currentForCaller().binding.requestIntentSha256
        override val bindingSha256: String
            @Synchronized get() = currentForCaller().binding.bindingSha256
        override val latestTransitionSha256: String
            @Synchronized get() = currentForCaller().let { history.latest.transitionSha256 }
        override val phase: LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
            @Synchronized get() = currentForCaller().let { history.phase }
        override val recoveryTag: String
            @Synchronized get() = currentForCaller().binding.recoveryTag
        override val recoveryLeaseLabelKey: String
            @Synchronized get() = currentForCaller().let { RECOVERY_LEASE_LABEL_KEY }
        override val recoveryLeaseLabelValue: String
            @Synchronized get() = currentForCaller().binding.operationId
        override val contentSha256LabelKey: String
            @Synchronized get() = currentForCaller().let { CONTENT_SHA256_LABEL_KEY }
        override val contentSha256LabelValue: String
            @Synchronized get() = currentForCaller().binding.recipe.deterministicTarSha256
        override val journalRootPathSha256: String
            @Synchronized get() = currentForCaller().binding.journalRootPathSha256

        override val reproductionLockSha256: String
            @Synchronized get() = currentForCaller().binding.recipe.reproductionLockSha256
        override val buildRecordSha256: String
            @Synchronized get() = currentForCaller().binding.recipe.buildRecordSha256
        override val dockerfileSha256: String
            @Synchronized get() = currentForCaller().binding.recipe.dockerfileSha256
        override val dockerfileBytes: Long
            @Synchronized get() = currentForCaller().binding.recipe.dockerfileBytes
        override val deterministicTarSha256: String
            @Synchronized get() = currentForCaller().binding.recipe.deterministicTarSha256
        override val deterministicTarBytes: Long
            @Synchronized get() = currentForCaller().binding.recipe.deterministicTarBytes
        override val baseImageReference: String
            @Synchronized get() = currentForCaller().binding.recipe.baseImageReference
        override val platform: String
            @Synchronized get() = currentForCaller().binding.recipe.platform
        override val sourceDateEpoch: String
            @Synchronized get() = currentForCaller().binding.recipe.sourceDateEpoch

        override val canonicalBindingBytes: ByteArray
            @Synchronized get() = currentForCaller().binding.canonicalBytes()

        @Synchronized
        override fun requireCurrentBinding() = translateLeaseFailures(
            "recheck hosted toolchain image-build lease v2",
        ) {
            checkOpen()
            try {
                recipe.requireCurrent()
                opened.journal.requireCurrent(history)
                recipe.requireCurrent()
            } catch (failure: Throwable) {
                poisoned = true
                throw failure
            }
        }

        override fun recordRecoveryLocatorsAbsent() = append(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_LOCATORS_ABSENT,
        )

        override fun recordImageBuildOutcomeAmbiguous() = append(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_OUTCOME_AMBIGUOUS,
        )

        override fun recordImageAuthenticated() = append(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_AUTHENTICATED,
        )

        override fun recordOrphanImageIdentified() = append(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.ORPHAN_IMAGE_IDENTIFIED,
        )

        override fun requireRecoveryFence() = append(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_FENCE_REQUIRED,
        )

        override fun recordBuildTerminatedNoImage() = append(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.BUILD_TERMINATED_NO_IMAGE,
        )

        override fun armImageDelete() = append(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_DELETE_ARMED,
        )

        override fun recordImageAbsenceProved() = append(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_ABSENCE_PROVED,
        )

        override fun blockCleanup() = append(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
        )

        @Synchronized
        protected fun append(
            target: LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase,
        ): LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase = translateLeaseFailures(
            "append hosted toolchain image-build lease v2 phase ${target.wireName}",
        ) {
            checkOpen()
            try {
                if (
                    !freshOpen &&
                    history.phase == LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_POST_ARMED &&
                    target !in RECOVERED_ARMED_ALLOWED_TARGETS
                ) {
                    leaseFail(
                        "cold-recovered hosted toolchain image-build POST must enter " +
                            "ambiguous recovery before any outcome",
                    )
                }
                recipe.requireCurrent()
                history = opened.journal.append(history, target)
                recipe.requireCurrent()
                history.phase
            } catch (failure: Throwable) {
                poisoned = true
                throw failure
            }
        }

        @Synchronized
        private fun consumeForHostedToolchainImageEngineV1():
            LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner = translateLeaseFailures(
            "consume hosted toolchain image-build lease v2 for fixed Engine",
        ) {
            checkOpen()
            try {
                recipe.requireCurrent()
                opened.journal.requireCurrent(history)
                recipe.requireCurrent()
                if (
                    !freshOpen ||
                    history.phase != LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERED
                ) {
                    leaseFail(
                        "fixed Engine requires the untouched initial fresh image-build lease position",
                    )
                }
                val constructor = RetainedEngineOwner::class.java.getDeclaredConstructor(
                    BoundOwner::class.java,
                    String::class.java,
                )
                check(constructor.trySetAccessible())
                val engineOwner = constructor.newInstance(this, opened.binding.operationId)
                transferred = true
                engineOwner
            } catch (failure: Throwable) {
                poisoned = true
                throw failure
            }
        }

        @Synchronized
        fun requireCurrentFromEngine() = translateLeaseFailures(
            "recheck fixed Engine hosted toolchain image-build lease v2",
        ) {
            checkRetainedOpen()
            try {
                recipe.requireCurrent()
                opened.journal.requireCurrent(history)
                recipe.requireCurrent()
            } catch (failure: Throwable) {
                poisoned = true
                throw failure
            }
        }

        private fun currentForCaller(): OpenedToolchainImageBuildLease {
            checkOpen()
            return opened
        }

        private fun checkOpen() {
            check(!closed) { "hosted toolchain image-build lease v2 owner is closed" }
            check(!transferred) { "hosted toolchain image-build lease v2 owner was transferred" }
            check(!poisoned) { "hosted toolchain image-build lease v2 owner is poisoned" }
        }

        private fun checkRetainedOpen() {
            check(transferred) { "hosted toolchain image-build lease v2 owner was not transferred" }
            check(!retainedClosed) { "fixed Engine hosted toolchain image-build lease v2 owner is closed" }
            check(!poisoned) { "fixed Engine hosted toolchain image-build lease v2 owner is poisoned" }
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            if (transferred) return
            closeRetainedResources()
        }

        @Synchronized
        fun closeFromEngine() {
            if (retainedClosed) return
            check(transferred) { "hosted toolchain image-build lease v2 owner was not transferred" }
            closeRetainedResources()
        }

        private fun closeRetainedResources() {
            if (retainedClosed) return
            retainedClosed = true
            var failure: Throwable? = null
            runCatching { opened.journal.close() }.exceptionOrNull()?.let { failure = it }
            runCatching { recipe.close() }.exceptionOrNull()?.let { closeFailure ->
                failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
            }
            failure?.let { throw it }
        }
    }

    private class RetainedEngineOwner private constructor(
        private val owner: BoundOwner,
        private val retainedOperationId: String,
    ) : LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner {
        private var closed = false

        override val operationId: String
            @Synchronized get() = currentOperationId()
        override val buildId: String
            @Synchronized get() = currentOperationId()

        @Synchronized
        override fun requireCurrentBinding() {
            check(!closed) { "fixed Engine hosted toolchain image-build lease v2 owner is closed" }
            owner.requireCurrentFromEngine()
        }

        private fun currentOperationId(): String {
            check(!closed) { "fixed Engine hosted toolchain image-build lease v2 owner is closed" }
            return retainedOperationId
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            owner.closeFromEngine()
        }
    }

    private class FreshBoundOwner private constructor(
        recipe: LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner,
        opened: OpenedToolchainImageBuildLease,
    ) : BoundOwner(recipe, opened, freshOpen = true),
        LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner {
        override fun armImageBuildPost() = append(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_POST_ARMED,
        )
    }

    private class RecoveredBoundOwner private constructor(
        recipe: LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner,
        opened: OpenedToolchainImageBuildLease,
    ) : BoundOwner(recipe, opened, freshOpen = false)
}

private data class ToolchainRecipePins(
    val reproductionLockSha256: String,
    val buildRecordSha256: String,
    val dockerfileSha256: String,
    val dockerfileBytes: Long,
    val deterministicTarSha256: String,
    val deterministicTarBytes: Long,
    val baseImageReference: String,
    val platform: String,
    val sourceDateEpoch: String,
) {
    init {
        if (
            reproductionLockSha256 != PINNED_REPRODUCTION_LOCK_SHA256 ||
            buildRecordSha256 != PINNED_BUILD_RECORD_SHA256 ||
            dockerfileSha256 != PINNED_DOCKERFILE_SHA256 ||
            dockerfileBytes != PINNED_DOCKERFILE_BYTES ||
            deterministicTarSha256 != PINNED_DETERMINISTIC_TAR_SHA256 ||
            deterministicTarBytes != PINNED_DETERMINISTIC_TAR_BYTES ||
            baseImageReference != PINNED_BASE_IMAGE_REFERENCE || platform != PINNED_PLATFORM ||
            sourceDateEpoch != PINNED_SOURCE_DATE_EPOCH
        ) leaseFail("hosted toolchain image-build lease recipe pins differ from the reviewed closure")
    }

    fun json(): JsonObject = JsonObject(
        mapOf(
            "baseImageReference" to JsonPrimitive(baseImageReference),
            "buildRecordSha256" to JsonPrimitive(buildRecordSha256),
            "deterministicTarBytes" to JsonPrimitive(deterministicTarBytes),
            "deterministicTarSha256" to JsonPrimitive(deterministicTarSha256),
            "dockerfileBytes" to JsonPrimitive(dockerfileBytes),
            "dockerfileSha256" to JsonPrimitive(dockerfileSha256),
            "platform" to JsonPrimitive(platform),
            "reproductionLockSha256" to JsonPrimitive(reproductionLockSha256),
            "sourceDateEpoch" to JsonPrimitive(sourceDateEpoch),
        ),
    )

    companion object {
        fun capture(owner: LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner): ToolchainRecipePins {
            owner.requireCurrent()
            val pins = ToolchainRecipePins(
                owner.reproductionLockSha256,
                owner.buildRecordSha256,
                owner.dockerfileSha256,
                owner.dockerfileBytes,
                owner.deterministicTarSha256,
                owner.deterministicTarBytes,
                owner.baseImageReference,
                owner.platform,
                owner.sourceDateEpoch,
            )
            owner.requireCurrent()
            return pins
        }

        fun parse(root: JsonObject): ToolchainRecipePins {
            root.requireExactKeys(RECIPE_FIELDS, "hosted toolchain image-build lease recipe")
            return ToolchainRecipePins(
                root.requiredString("reproductionLockSha256"),
                root.requiredString("buildRecordSha256"),
                root.requiredString("dockerfileSha256"),
                root.requiredLong("dockerfileBytes"),
                root.requiredString("deterministicTarSha256"),
                root.requiredLong("deterministicTarBytes"),
                root.requiredString("baseImageReference"),
                root.requiredString("platform"),
                root.requiredString("sourceDateEpoch"),
            )
        }
    }
}

private class ToolchainImageBuildLeaseBinding private constructor(
    val schemaVersion: Int,
    val provider: String,
    val authority: String,
    val leaseNonce: String,
    val journalRootPathSha256: String,
    val recipe: ToolchainRecipePins,
    val buildIntentSha256: String,
    val operationId: String,
    val recoveryTag: String,
    val requestIntentSha256: String,
    val bindingSha256: String,
) {
    init {
        if (
            schemaVersion != BINDING_SCHEMA_VERSION || provider != LEASE_PROVIDER ||
            authority != LEASE_AUTHORITY || !leaseNonce.matches(NONCE) ||
            !journalRootPathSha256.matches(SHA256) || !buildIntentSha256.matches(SHA256) ||
            !operationId.matches(SHA256) || !requestIntentSha256.matches(SHA256) ||
            !bindingSha256.matches(SHA256)
        ) leaseFail("hosted toolchain image-build lease binding has invalid identities")
        val expectedBuildIntent = sha256(canonical(buildIntentDocument(recipe)))
        if (buildIntentSha256 != expectedBuildIntent) {
            leaseFail("hosted toolchain image-build lease build-intent hash is invalid")
        }
        val expectedOperation = sha256(
            canonical(
                operationIdDocument(
                    leaseNonce,
                    journalRootPathSha256,
                    buildIntentSha256,
                ),
            ),
        )
        if (operationId != expectedOperation) {
            leaseFail("hosted toolchain image-build lease operation id is invalid")
        }
        if (recoveryTag != recoveryTag(operationId) || !recoveryTag.matches(RECOVERY_TAG)) {
            leaseFail("hosted toolchain image-build lease recovery tag is invalid")
        }
        val expectedRequestSha256 = sha256(canonical(buildRequestIntentDocument(recipe, recoveryTag, operationId)))
        if (requestIntentSha256 != expectedRequestSha256) {
            leaseFail("hosted toolchain image-build lease request-intent hash is invalid")
        }
        if (bindingSha256 != sha256(canonicalBytes(includeSelfHash = false))) {
            leaseFail("hosted toolchain image-build lease binding self hash is invalid")
        }
    }

    fun canonicalBytes(): ByteArray = canonicalBytes(includeSelfHash = true)

    private fun canonicalBytes(includeSelfHash: Boolean): ByteArray = canonical(
        bindingDocument(
            leaseNonce,
            journalRootPathSha256,
            recipe,
            buildIntentSha256,
            operationId,
            recoveryTag,
            requestIntentSha256,
            if (includeSelfHash) bindingSha256 else null,
        ),
    )

    fun requireInputs(expectedRootPathSha256: String, expectedRecipe: ToolchainRecipePins) {
        if (
            journalRootPathSha256 != expectedRootPathSha256 ||
            recipe != expectedRecipe
        ) leaseFail("hosted toolchain image-build lease is bound to different retained inputs")
    }

    companion object {
        fun create(
            journalRootPathSha256: String,
            recipe: ToolchainRecipePins,
        ): ToolchainImageBuildLeaseBinding {
            val leaseNonce = randomNonce()
            val buildIntentSha256 = sha256(canonical(buildIntentDocument(recipe)))
            val operationId = sha256(
                canonical(operationIdDocument(leaseNonce, journalRootPathSha256, buildIntentSha256)),
            )
            val recoveryTag = recoveryTag(operationId)
            val requestIntentSha256 = sha256(
                canonical(buildRequestIntentDocument(recipe, recoveryTag, operationId)),
            )
            val provisional = bindingDocument(
                leaseNonce,
                journalRootPathSha256,
                recipe,
                buildIntentSha256,
                operationId,
                recoveryTag,
                requestIntentSha256,
                null,
            )
            return ToolchainImageBuildLeaseBinding(
                BINDING_SCHEMA_VERSION,
                LEASE_PROVIDER,
                LEASE_AUTHORITY,
                leaseNonce,
                journalRootPathSha256,
                recipe,
                buildIntentSha256,
                operationId,
                recoveryTag,
                requestIntentSha256,
                sha256(canonical(provisional)),
            )
        }

        fun parseCanonical(bytes: ByteArray): ToolchainImageBuildLeaseBinding = translateLeaseFailures(
            "parse hosted toolchain image-build lease binding",
        ) {
            val root = OracleJson.parseCanonical(bytes, LEASE_JSON_LIMITS) as? JsonObject
                ?: leaseFail("hosted toolchain image-build lease binding must be an object")
            root.requireExactKeys(BINDING_FIELDS, "hosted toolchain image-build lease binding")
            if (root.requiredObject("acpBoundary") != STATIC_ACP_BOUNDARY) {
                leaseFail("hosted toolchain image-build lease has a different ACP boundary")
            }
            if (root.requiredObject("pythonBoundary") != STATIC_PYTHON_BOUNDARY) {
                leaseFail("hosted toolchain image-build lease has a different Python boundary")
            }
            if (root.requiredObject("claims") != FALSE_CLAIMS) {
                leaseFail("hosted toolchain image-build lease has non-false claims")
            }
            if (root.requiredObject("buildRequestIntent") != buildRequestIntentDocument(
                    ToolchainRecipePins.parse(root.requiredObject("recipe")),
                    root.requiredString("recoveryTag"),
                    root.requiredObject("recoveryLeaseLabel").requiredString("value"),
                )
            ) leaseFail("hosted toolchain image-build lease request intent is not exact")
            val label = root.requiredObject("recoveryLeaseLabel")
            label.requireExactKeys(RECOVERY_LABEL_FIELDS, "hosted toolchain image-build recovery label")
            if (label.requiredString("key") != RECOVERY_LEASE_LABEL_KEY) {
                leaseFail("hosted toolchain image-build lease label key is invalid")
            }
            val binding = ToolchainImageBuildLeaseBinding(
                root.requiredInt("schemaVersion"),
                root.requiredString("provider"),
                root.requiredString("authority"),
                root.requiredString("leaseNonce"),
                root.requiredString("journalRootPathSha256"),
                ToolchainRecipePins.parse(root.requiredObject("recipe")),
                root.requiredString("buildIntentSha256"),
                root.requiredString("operationId"),
                root.requiredString("recoveryTag"),
                root.requiredString("requestIntentSha256"),
                root.requiredString("bindingSha256"),
            )
            if (label.requiredString("value") != binding.operationId) {
                leaseFail("hosted toolchain image-build lease label value is invalid")
            }
            binding
        }
    }
}

private fun buildIntentDocument(recipe: ToolchainRecipePins): JsonObject = JsonObject(
    mapOf(
        "buildRequestPolicy" to FIXED_BUILD_REQUEST_POLICY,
        "provider" to JsonPrimitive(BUILD_INTENT_PROVIDER),
        "recipe" to recipe.json(),
        "schemaVersion" to JsonPrimitive(BUILD_INTENT_SCHEMA_VERSION),
    ),
)

private fun operationIdDocument(
    leaseNonce: String,
    journalRootPathSha256: String,
    buildIntentSha256: String,
): JsonObject = JsonObject(
    mapOf(
        "buildIntentSha256" to JsonPrimitive(buildIntentSha256),
        "journalRootPathSha256" to JsonPrimitive(journalRootPathSha256),
        "leaseNonce" to JsonPrimitive(leaseNonce),
        "provider" to JsonPrimitive(OPERATION_ID_PROVIDER),
        "schemaVersion" to JsonPrimitive(OPERATION_ID_SCHEMA_VERSION),
    ),
)

private fun buildRequestIntentDocument(
    recipe: ToolchainRecipePins,
    recoveryTag: String,
    operationId: String,
): JsonObject = JsonObject(
    mapOf(
        "buildArguments" to EMPTY_OBJECT,
        "buildCancelLocator" to buildCancelLocatorDocument(operationId),
        "buildId" to JsonPrimitive(operationId),
        "buildIdQuery" to JsonObject(
            mapOf(BUILD_ID_QUERY_KEY to JsonPrimitive(operationId)),
        ),
        "contentLength" to JsonPrimitive(recipe.deterministicTarBytes),
        "contentSha256" to JsonPrimitive(recipe.deterministicTarSha256),
        "labels" to JsonObject(
            mapOf(
                CONTENT_SHA256_LABEL_KEY to JsonPrimitive(recipe.deterministicTarSha256),
                RECOVERY_LEASE_LABEL_KEY to JsonPrimitive(operationId),
            ),
        ),
        "policy" to FIXED_BUILD_REQUEST_POLICY,
        "provider" to JsonPrimitive(REQUEST_INTENT_PROVIDER),
        "schemaVersion" to JsonPrimitive(REQUEST_INTENT_SCHEMA_VERSION),
        "tags" to kotlinx.serialization.json.JsonArray(listOf(JsonPrimitive(recoveryTag))),
    ),
)

private fun buildCancelLocatorDocument(buildId: String): JsonObject = JsonObject(
    mapOf(
        "buildId" to JsonPrimitive(buildId),
        "method" to JsonPrimitive("POST"),
        "queryKey" to JsonPrimitive(BUILD_CANCEL_QUERY_KEY),
        "requestTarget" to JsonPrimitive(buildCancelRequestTarget(buildId)),
        "response200Meaning" to JsonPrimitive("request-returned-not-quiescence-or-image-absence"),
        "response200ProvesBuildTermination" to JsonPrimitive(false),
        "registrationRaceRequiresIndependentFence" to JsonPrimitive(true),
        "unknownIdMayReturn200" to JsonPrimitive(true),
    ),
)

private fun bindingDocument(
    leaseNonce: String,
    journalRootPathSha256: String,
    recipe: ToolchainRecipePins,
    buildIntentSha256: String,
    operationId: String,
    recoveryTag: String,
    requestIntentSha256: String,
    bindingSha256: String?,
): JsonObject = JsonObject(
    buildMap {
        put("acpBoundary", STATIC_ACP_BOUNDARY)
        put("authority", JsonPrimitive(LEASE_AUTHORITY))
        bindingSha256?.let { put("bindingSha256", JsonPrimitive(it)) }
        put("buildIntentSha256", JsonPrimitive(buildIntentSha256))
        put("buildRequestIntent", buildRequestIntentDocument(recipe, recoveryTag, operationId))
        put("claims", FALSE_CLAIMS)
        put("journalRootPathSha256", JsonPrimitive(journalRootPathSha256))
        put("leaseNonce", JsonPrimitive(leaseNonce))
        put("operationId", JsonPrimitive(operationId))
        put("provider", JsonPrimitive(LEASE_PROVIDER))
        put("pythonBoundary", STATIC_PYTHON_BOUNDARY)
        put("recipe", recipe.json())
        put(
            "recoveryLeaseLabel",
            JsonObject(
                mapOf(
                    "key" to JsonPrimitive(RECOVERY_LEASE_LABEL_KEY),
                    "value" to JsonPrimitive(operationId),
                ),
            ),
        )
        put("recoveryTag", JsonPrimitive(recoveryTag))
        put("requestIntentSha256", JsonPrimitive(requestIntentSha256))
        put("schemaVersion", JsonPrimitive(BINDING_SCHEMA_VERSION))
    },
)

private class ToolchainImageBuildLeaseTransition private constructor(
    val schemaVersion: Int,
    val provider: String,
    val authority: String,
    val operationId: String,
    val bindingSha256: String,
    val sequence: Int,
    val phase: LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase,
    val previousTransitionSha256: String,
    val transitionSha256: String,
) {
    val fileName: String
        get() = transitionFileName(sequence)

    init {
        if (
            schemaVersion != TRANSITION_SCHEMA_VERSION || provider != LEASE_PROVIDER ||
            authority != LEASE_AUTHORITY || !operationId.matches(SHA256) ||
            !bindingSha256.matches(SHA256) || sequence !in 0 until MAXIMUM_TRANSITIONS ||
            !previousTransitionSha256.matches(SHA256) || !transitionSha256.matches(SHA256)
        ) leaseFail("hosted toolchain image-build lease transition has invalid identities")
        if (sequence == 0) {
            if (
                phase != LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERED ||
                previousTransitionSha256 != ZERO_SHA256
            ) leaseFail("hosted toolchain image-build recovered transition has an invalid position")
        } else if (previousTransitionSha256 == ZERO_SHA256) {
            leaseFail("hosted toolchain image-build lease transition has no predecessor")
        }
        if (transitionSha256 != sha256(canonicalBytes(includeSelfHash = false))) {
            leaseFail("hosted toolchain image-build lease transition self hash is invalid")
        }
    }

    fun canonicalBytes(): ByteArray = canonicalBytes(includeSelfHash = true)

    private fun canonicalBytes(includeSelfHash: Boolean): ByteArray = canonical(
        transitionDocument(
            operationId,
            bindingSha256,
            sequence,
            phase,
            previousTransitionSha256,
            if (includeSelfHash) transitionSha256 else null,
        ),
    )

    companion object {
        fun initial(binding: ToolchainImageBuildLeaseBinding): ToolchainImageBuildLeaseTransition = create(
            binding,
            0,
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERED,
            ZERO_SHA256,
        )

        fun next(
            binding: ToolchainImageBuildLeaseBinding,
            previous: ToolchainImageBuildLeaseTransition,
            phase: LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase,
        ): ToolchainImageBuildLeaseTransition {
            if (phase !in allowedNextPhases(previous.phase)) {
                leaseFail(
                    "hosted toolchain image-build lease phase ${previous.phase.wireName} " +
                        "cannot advance to ${phase.wireName}",
                )
            }
            return create(binding, previous.sequence + 1, phase, previous.transitionSha256)
        }

        private fun create(
            binding: ToolchainImageBuildLeaseBinding,
            sequence: Int,
            phase: LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase,
            previousTransitionSha256: String,
        ): ToolchainImageBuildLeaseTransition {
            val provisional = transitionDocument(
                binding.operationId,
                binding.bindingSha256,
                sequence,
                phase,
                previousTransitionSha256,
                null,
            )
            return ToolchainImageBuildLeaseTransition(
                TRANSITION_SCHEMA_VERSION,
                LEASE_PROVIDER,
                LEASE_AUTHORITY,
                binding.operationId,
                binding.bindingSha256,
                sequence,
                phase,
                previousTransitionSha256,
                sha256(canonical(provisional)),
            )
        }

        fun parseCanonical(bytes: ByteArray): ToolchainImageBuildLeaseTransition = translateLeaseFailures(
            "parse hosted toolchain image-build lease transition",
        ) {
            val root = OracleJson.parseCanonical(bytes, LEASE_JSON_LIMITS) as? JsonObject
                ?: leaseFail("hosted toolchain image-build lease transition must be an object")
            root.requireExactKeys(TRANSITION_FIELDS, "hosted toolchain image-build lease transition")
            if (root.requiredObject("claims") != FALSE_CLAIMS) {
                leaseFail("hosted toolchain image-build lease transition has non-false claims")
            }
            if (root.requiredObject("facts") != EMPTY_OBJECT) {
                leaseFail("hosted toolchain image-build lease transition accepts no facts")
            }
            val phaseName = root.requiredString("phase")
            val phase = LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.entries.singleOrNull {
                it.wireName == phaseName
            } ?: leaseFail("hosted toolchain image-build lease transition has an unknown phase")
            ToolchainImageBuildLeaseTransition(
                root.requiredInt("schemaVersion"),
                root.requiredString("provider"),
                root.requiredString("authority"),
                root.requiredString("operationId"),
                root.requiredString("bindingSha256"),
                root.requiredInt("sequence"),
                phase,
                root.requiredString("previousTransitionSha256"),
                root.requiredString("transitionSha256"),
            )
        }
    }
}

private fun transitionDocument(
    operationId: String,
    bindingSha256: String,
    sequence: Int,
    phase: LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase,
    previousTransitionSha256: String,
    transitionSha256: String?,
): JsonObject = JsonObject(
    buildMap {
        put("authority", JsonPrimitive(LEASE_AUTHORITY))
        put("bindingSha256", JsonPrimitive(bindingSha256))
        put("claims", FALSE_CLAIMS)
        put("facts", EMPTY_OBJECT)
        put("operationId", JsonPrimitive(operationId))
        put("phase", JsonPrimitive(phase.wireName))
        put("previousTransitionSha256", JsonPrimitive(previousTransitionSha256))
        put("provider", JsonPrimitive(LEASE_PROVIDER))
        put("schemaVersion", JsonPrimitive(TRANSITION_SCHEMA_VERSION))
        put("sequence", JsonPrimitive(sequence))
        transitionSha256?.let { put("transitionSha256", JsonPrimitive(it)) }
    },
)

private class ToolchainImageBuildLeaseHistory private constructor(
    val binding: ToolchainImageBuildLeaseBinding,
    transitions: List<ToolchainImageBuildLeaseTransition>,
    bindingSnapshot: DescriptorBoundStateSnapshot,
    transitionSnapshots: List<DescriptorBoundStateSnapshot>,
) {
    val transitions = transitions.toList()
    private val bindingBytes = bindingSnapshot.bytes
    private val bindingIdentity = bindingSnapshot.identity
    private val transitionBytes = transitionSnapshots.map { it.bytes }
    private val transitionIdentities = transitionSnapshots.map { it.identity }

    init {
        if (transitionSnapshots.size != this.transitions.size) {
            leaseFail("hosted toolchain image-build lease history snapshot is incomplete")
        }
        if (!bindingBytes.contentEquals(binding.canonicalBytes())) {
            leaseFail("hosted toolchain image-build lease binding snapshot is not canonical")
        }
        this.transitions.forEachIndexed { index, transition ->
            if (!transitionBytes[index].contentEquals(transition.canonicalBytes())) {
                leaseFail("hosted toolchain image-build lease transition snapshot is not canonical")
            }
        }
    }

    val latest: ToolchainImageBuildLeaseTransition
        get() = transitions.lastOrNull()
            ?: leaseFail("hosted toolchain image-build lease has no durable phase")
    val phase: LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase
        get() = latest.phase

    fun hasExactDurableState(other: ToolchainImageBuildLeaseHistory): Boolean =
        binding.canonicalBytes().contentEquals(other.binding.canonicalBytes()) &&
            bindingBytes.contentEquals(other.bindingBytes) && bindingIdentity == other.bindingIdentity &&
            transitions.size == other.transitions.size &&
            transitions.indices.all { index ->
                transitions[index].canonicalBytes().contentEquals(other.transitions[index].canonicalBytes()) &&
                    transitionBytes[index].contentEquals(other.transitionBytes[index]) &&
                    transitionIdentities[index] == other.transitionIdentities[index]
            }

    companion object {
        fun validatePrefix(
            binding: ToolchainImageBuildLeaseBinding,
            transitions: List<ToolchainImageBuildLeaseTransition>,
            bindingSnapshot: DescriptorBoundStateSnapshot,
            transitionSnapshots: List<DescriptorBoundStateSnapshot>,
        ): ToolchainImageBuildLeaseHistory {
            if (transitions.size > MAXIMUM_TRANSITIONS) {
                leaseFail("hosted toolchain image-build lease has too many transitions")
            }
            var previous: ToolchainImageBuildLeaseTransition? = null
            transitions.forEachIndexed { index, actual ->
                val expected = if (index == 0) {
                    ToolchainImageBuildLeaseTransition.initial(binding)
                } else {
                    ToolchainImageBuildLeaseTransition.next(binding, checkNotNull(previous), actual.phase)
                }
                if (
                    actual.fileName != transitionFileName(index) ||
                    !actual.canonicalBytes().contentEquals(expected.canonicalBytes())
                ) leaseFail("hosted toolchain image-build lease transition chain is invalid")
                previous = actual
            }
            return ToolchainImageBuildLeaseHistory(
                binding,
                transitions,
                bindingSnapshot,
                transitionSnapshots,
            )
        }
    }
}

private class OpenedToolchainImageBuildLease private constructor(
    val journal: ToolchainImageBuildDescriptorJournal,
    val binding: ToolchainImageBuildLeaseBinding,
    val history: ToolchainImageBuildLeaseHistory,
)

private class ToolchainImageBuildJournalRoot private constructor(
    private val path: Path,
    private val parentPath: Path,
    private val parent: LinuxDescriptor,
    private val rootName: String,
    val descriptor: LinuxDescriptor,
) : AutoCloseable {
    private var closed = false
    private var poisoned = false

    @Synchronized
    fun requireBound() {
        check(!closed) { "hosted toolchain image-build lease journal root is closed" }
        check(!poisoned) { "hosted toolchain image-build lease journal root is poisoned" }
        try {
            requireRootBinding()
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun requireRootBinding() {
        requireTrustedParent(LinuxFilesystemSyscalls.identity(parent.fd), parent.identity)
        if (!Files.isSameFile(parentPath, LinuxFilesystemSyscalls.descriptorPath(parent))) {
            leaseFail("hosted toolchain image-build lease journal parent pathname changed")
        }
        val currentRoot = LinuxFilesystemSyscalls.identity(descriptor.fd)
        requirePinnedManagedDirectory(
            currentRoot,
            descriptor.identity,
            "hosted toolchain image-build lease journal root",
        )
        val selected = try {
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, rootName)
        } catch (failure: Exception) {
            leaseFail("hosted toolchain image-build lease journal root was detached: ${failure.message}")
        }
        selected.use {
            if (!sameDirectory(LinuxFilesystemSyscalls.identity(selected.fd), currentRoot)) {
                leaseFail("hosted toolchain image-build lease journal root changed identity")
            }
        }
        if (!Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(descriptor))) {
            leaseFail("hosted toolchain image-build lease journal root pathname changed")
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        runCatching { LinuxFilesystemSyscalls.unlock(descriptor) }.exceptionOrNull()?.let { failure = it }
        runCatching { descriptor.close() }.exceptionOrNull()?.let { closeFailure ->
            failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
        }
        runCatching { parent.close() }.exceptionOrNull()?.let { closeFailure ->
            failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(path: Path): ToolchainImageBuildJournalRoot {
            if (
                !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || path.toRealPath() != path ||
                path.parent == null
            ) leaseFail("hosted toolchain image-build lease root must be a canonical non-root directory")
            LinuxFilesystemSyscalls.requireSupported(path)
            val parentPath = path.parent
            if (parentPath.toRealPath() != parentPath) {
                leaseFail("hosted toolchain image-build lease root parent must be canonical")
            }
            val parent = LinuxFilesystemSyscalls.openRoot(parentPath)
            val root = try {
                LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, path.fileName.toString())
            } catch (failure: Throwable) {
                runCatching { parent.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
            var locked = false
            try {
                requireTrustedParent(LinuxFilesystemSyscalls.identity(parent.fd), parent.identity)
                requirePinnedManagedDirectory(
                    LinuxFilesystemSyscalls.identity(root.fd),
                    root.identity,
                    "hosted toolchain image-build lease journal root",
                )
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(root)) {
                    leaseFail("hosted toolchain image-build lease journal root is already locked")
                }
                locked = true
                LinuxFilesystemSyscalls.synchronize(root)
                LinuxFilesystemSyscalls.synchronize(parent)
                return ToolchainImageBuildJournalRoot(
                    path,
                    parentPath,
                    parent,
                    path.fileName.toString(),
                    root,
                ).also { it.requireBound() }
            } catch (failure: Throwable) {
                if (locked) {
                    runCatching { LinuxFilesystemSyscalls.unlock(root) }
                        .exceptionOrNull()?.let(failure::addSuppressed)
                }
                runCatching { root.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                runCatching { parent.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private class ToolchainImageBuildDescriptorJournal private constructor(
    private val expectedRootPathSha256: String,
    private val expectedRecipe: ToolchainRecipePins,
    private val authority: ToolchainImageBuildJournalRoot,
) : AutoCloseable {
    private val directory: LinuxDescriptor
        get() = authority.descriptor
    private var closed = false
    private var poisoned = false

    @Synchronized
    fun createFresh(): ToolchainImageBuildLeaseHistory = boundOperation {
        if (entryNames().isNotEmpty()) {
            leaseFail("fresh hosted toolchain image-build lease requires an empty journal")
        }
        val binding = ToolchainImageBuildLeaseBinding.create(expectedRootPathSha256, expectedRecipe)
        DescriptorBoundAtomicStateFile.publishNoReplace(
            directory,
            BINDING_FILE,
            binding.canonicalBytes(),
            MAXIMUM_RECORD_BYTES,
        )
        var current = loadPrefix()
            ?: leaseFail("fresh hosted toolchain image-build lease binding publication disappeared")
        if (current.transitions.isNotEmpty()) {
            leaseFail("fresh hosted toolchain image-build lease acquired a preexisting transition")
        }
        val initial = ToolchainImageBuildLeaseTransition.initial(current.binding)
        DescriptorBoundAtomicStateFile.publishNoReplace(
            directory,
            initial.fileName,
            initial.canonicalBytes(),
            MAXIMUM_RECORD_BYTES,
        )
        current = loadPrefix()
            ?: leaseFail("fresh hosted toolchain image-build recovered transition disappeared")
        requirePhased(current)
    }

    fun recover(): ToolchainImageBuildLeaseHistory = boundOperation {
        if (entryNames().isEmpty()) {
            leaseFail("hosted toolchain image-build recovery requires an existing journal")
        }
        completeExactPendingPublicationBound()
        var current = loadPrefix()
            ?: leaseFail("hosted toolchain image-build recovery lost its existing journal")
        if (current.transitions.isEmpty()) {
            val initial = ToolchainImageBuildLeaseTransition.initial(current.binding)
            DescriptorBoundAtomicStateFile.publishNoReplace(
                directory,
                initial.fileName,
                initial.canonicalBytes(),
                MAXIMUM_RECORD_BYTES,
            )
            current = loadPrefix()
                ?: leaseFail("hosted toolchain image-build recovered transition disappeared")
        }
        requirePhased(current)
    }

    @Synchronized
    fun append(
        expected: ToolchainImageBuildLeaseHistory,
        target: LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase,
    ): ToolchainImageBuildLeaseHistory = boundOperation {
        val current = requirePhased(
            loadPrefix() ?: leaseFail("hosted toolchain image-build lease journal is empty"),
        )
        if (!expected.hasExactDurableState(current)) {
            leaseFail("hosted toolchain image-build lease changed before append")
        }
        if (current.phase == target) {
            leaseFail("hosted toolchain image-build lease phase ${target.wireName} cannot be appended twice")
        }
        val next = ToolchainImageBuildLeaseTransition.next(current.binding, current.latest, target)
        DescriptorBoundAtomicStateFile.publishNoReplace(
            directory,
            next.fileName,
            next.canonicalBytes(),
            MAXIMUM_RECORD_BYTES,
        )
        requirePhased(
            loadPrefix() ?: leaseFail("hosted toolchain image-build lease transition disappeared"),
        ).also { completed ->
            if (completed.phase != target) {
                leaseFail("hosted toolchain image-build lease did not reach ${target.wireName}")
            }
        }
    }

    /** Reloads and compares exact immutable state without publishing or completing it. */
    @Synchronized
    fun requireCurrent(expected: ToolchainImageBuildLeaseHistory): Unit = boundOperation {
        val current = requirePhased(
            loadPrefix() ?: leaseFail("hosted toolchain image-build lease journal is empty"),
        )
        if (!expected.hasExactDurableState(current)) {
            leaseFail("hosted toolchain image-build lease changed after it was loaded")
        }
    }

    /** Completes at most one exact immutable publication and never invents recovery bytes. */
    @Synchronized
    fun completeExactPendingPublication() = boundOperation {
        completeExactPendingPublicationBound()
    }

    private fun completeExactPendingPublicationBound() {
        val names = entryNames()
        val pendingNames = names.filter(::isAtomicStateName)
        if (pendingNames.size > 1) {
            leaseFail("hosted toolchain image-build lease has multiple pending publications")
        }
        val pendingName = pendingNames.singleOrNull()
        if (pendingName == null) {
            loadPrefix()
            // Covers death after rename but before the final directory fsync.
            LinuxFilesystemSyscalls.synchronize(directory)
            return
        }
        val targetName = atomicTargetName(pendingName)
        if (targetName in names) {
            leaseFail("hosted toolchain image-build lease has a target and its pending publication")
        }
        if (targetName == BINDING_FILE) {
            if (names != listOf(pendingName)) {
                leaseFail("pending hosted toolchain image-build lease binding has residue")
            }
            inspectRequired(pendingName).use { pending ->
                val binding = ToolchainImageBuildLeaseBinding.parseCanonical(pending.bytes)
                binding.requireInputs(expectedRootPathSha256, expectedRecipe)
                completePending(targetName, pending)
            }
        } else {
            val prefix = loadPrefix(allowedAtomicTarget = targetName)
                ?: leaseFail("pending hosted toolchain image-build lease transition has no binding")
            val expectedSequence = prefix.transitions.size
            if (targetName != transitionFileName(expectedSequence)) {
                leaseFail("pending hosted toolchain image-build lease transition is not contiguous")
            }
            inspectRequired(pendingName).use { pending ->
                val actual = ToolchainImageBuildLeaseTransition.parseCanonical(pending.bytes)
                val exact = if (expectedSequence == 0) {
                    ToolchainImageBuildLeaseTransition.initial(prefix.binding)
                } else {
                    ToolchainImageBuildLeaseTransition.next(prefix.binding, prefix.latest, actual.phase)
                }
                if (
                    actual.fileName != targetName ||
                    !actual.canonicalBytes().contentEquals(exact.canonicalBytes())
                ) leaseFail("pending hosted toolchain image-build lease transition is not exact")
                completePending(targetName, pending)
            }
        }
        loadPrefix() ?: leaseFail("hosted toolchain image-build cold completion lost its journal")
    }

    private fun completePending(targetName: String, pending: DescriptorBoundStateInspection) {
        DescriptorBoundAtomicStateFile.completeExistingTemporaryNoReplace(
            directory,
            targetName,
            pending,
            MAXIMUM_RECORD_BYTES,
        )
    }

    private fun loadPrefix(
        allowedAtomicTarget: String? = null,
    ): ToolchainImageBuildLeaseHistory? {
        val names = entryNames()
        if (names.isEmpty()) return null
        val allowedAtomicName = allowedAtomicTarget?.let(DescriptorBoundAtomicStateFile::temporaryName)
        val atomicNames = names.filter(::isAtomicStateName)
        if (atomicNames.any { it != allowedAtomicName }) {
            leaseFail("hosted toolchain image-build lease requires exact cold recovery")
        }
        if (names.any { name ->
                name != BINDING_FILE && !name.matches(TRANSITION_FILE_NAME) && name != allowedAtomicName
            }
        ) leaseFail("hosted toolchain image-build lease journal contains an unowned entry")
        val bindingSnapshot = DescriptorBoundAtomicStateFile.readOrNull(
            directory,
            BINDING_FILE,
            MAXIMUM_RECORD_BYTES,
        ) ?: leaseFail("hosted toolchain image-build lease journal is missing its binding")
        val binding = ToolchainImageBuildLeaseBinding.parseCanonical(bindingSnapshot.bytes)
        binding.requireInputs(expectedRootPathSha256, expectedRecipe)
        val transitionNames = names.filter(TRANSITION_FILE_NAME::matches).sorted()
        val transitionSnapshots = ArrayList<DescriptorBoundStateSnapshot>(transitionNames.size)
        val transitions = transitionNames.map { name ->
            val snapshot = DescriptorBoundAtomicStateFile.readOrNull(
                directory,
                name,
                MAXIMUM_RECORD_BYTES,
            ) ?: leaseFail("hosted toolchain image-build lease transition disappeared")
            transitionSnapshots += snapshot
            ToolchainImageBuildLeaseTransition.parseCanonical(snapshot.bytes).also { transition ->
                if (transition.fileName != name) {
                    leaseFail("hosted toolchain image-build lease transition occupies the wrong name")
                }
            }
        }
        return ToolchainImageBuildLeaseHistory.validatePrefix(
            binding,
            transitions,
            bindingSnapshot,
            transitionSnapshots,
        )
    }

    private fun entryNames(): List<String> {
        val names = LinuxFilesystemSyscalls.directoryEntryNames(
            directory,
            MAXIMUM_JOURNAL_ENTRIES + 1,
        ).sorted()
        if (names.size > MAXIMUM_JOURNAL_ENTRIES) {
            leaseFail("hosted toolchain image-build lease journal exceeds its entry bound")
        }
        return names
    }

    private fun inspectRequired(name: String): DescriptorBoundStateInspection =
        DescriptorBoundAtomicStateFile.inspectOrNull(directory, name, MAXIMUM_RECORD_BYTES)
            ?: leaseFail("hosted toolchain image-build lease entry disappeared: $name")

    private fun requirePhased(
        history: ToolchainImageBuildLeaseHistory,
    ): ToolchainImageBuildLeaseHistory {
        if (history.transitions.isEmpty()) {
            leaseFail("hosted toolchain image-build lease is missing its recovered phase")
        }
        return history
    }

    private inline fun <T> boundOperation(action: () -> T): T {
        checkOpen()
        return try {
            authority.requireBound()
            val result = action()
            authority.requireBound()
            result
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun checkOpen() {
        check(!closed) { "hosted toolchain image-build lease journal is closed" }
        check(!poisoned) { "hosted toolchain image-build lease journal is poisoned" }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        authority.close()
    }
}

private fun allowedNextPhases(
    phase: LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase,
): Set<LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase> = when (phase) {
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERED -> setOf(
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_LOCATORS_ABSENT,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
    )
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_LOCATORS_ABSENT -> setOf(
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_POST_ARMED,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
    )
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_POST_ARMED -> setOf(
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_OUTCOME_AMBIGUOUS,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_AUTHENTICATED,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.ORPHAN_IMAGE_IDENTIFIED,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.BUILD_TERMINATED_NO_IMAGE,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
    )
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_OUTCOME_AMBIGUOUS -> setOf(
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_FENCE_REQUIRED,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
    )
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_FENCE_REQUIRED -> setOf(
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.BUILD_TERMINATED_NO_IMAGE,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
    )
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_AUTHENTICATED,
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.ORPHAN_IMAGE_IDENTIFIED,
    -> setOf(
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_DELETE_ARMED,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
    )
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.BUILD_TERMINATED_NO_IMAGE -> setOf(
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.ORPHAN_IMAGE_IDENTIFIED,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_ABSENCE_PROVED,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
    )
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_DELETE_ARMED -> setOf(
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_ABSENCE_PROVED,
        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
    )
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_ABSENCE_PROVED,
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
    -> emptySet()
}

private val RECOVERED_ARMED_ALLOWED_TARGETS = setOf(
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_OUTCOME_AMBIGUOUS,
    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
)

private fun atomicTargetName(pendingName: String): String {
    if (pendingName == DescriptorBoundAtomicStateFile.temporaryName(BINDING_FILE)) return BINDING_FILE
    val match = ATOMIC_TRANSITION_FILE_NAME.matchEntire(pendingName)
        ?: leaseFail("hosted toolchain image-build lease has an unknown pending publication")
    return "transition-${match.groupValues[1]}.json"
}

private fun transitionFileName(sequence: Int): String {
    if (sequence !in 0 until MAXIMUM_TRANSITIONS) {
        leaseFail("hosted toolchain image-build lease transition sequence is out of range")
    }
    return "transition-${sequence.toString().padStart(4, '0')}.json"
}

private fun isAtomicStateName(name: String): Boolean = name.startsWith('.') && name.endsWith(".atomic")

private fun requireExactRawPath(path: Path) {
    if (!path.isAbsolute || path.normalize() != path || path.parent == null) {
        leaseFail("hosted toolchain image-build lease root path must already be absolute and normalized")
    }
}

private fun pathCommitment(path: Path): String = sha256(path.toString().toByteArray(Charsets.UTF_8))

private fun recoveryTag(operationId: String): String {
    if (!operationId.matches(SHA256)) leaseFail("hosted toolchain image-build operation id is invalid")
    return RECOVERY_TAG_PREFIX + operationId
}

private fun buildCancelRequestTarget(buildId: String): String {
    if (!buildId.matches(SHA256)) leaseFail("hosted toolchain image-build BuildKit build ID is invalid")
    return "$BUILD_CANCEL_REQUEST_PATH?$BUILD_CANCEL_QUERY_KEY=$buildId"
}

private fun randomNonce(): String {
    val bytes = ByteArray(NONCE_BYTES)
    SECURE_RANDOM.nextBytes(bytes)
    val encoded = CharArray(bytes.size * 2)
    bytes.forEachIndexed { index, byte ->
        val value = byte.toInt() and 0xff
        encoded[index * 2] = HEX[value ushr 4]
        encoded[index * 2 + 1] = HEX[value and 0x0f]
    }
    return encoded.concatToString()
}

private fun requirePinnedManagedDirectory(
    actual: LinuxFileIdentity,
    expected: LinuxFileIdentity,
    label: String,
) {
    val uid = currentUid()
    if (
        !sameDirectory(actual, expected) || actual.uid != uid ||
        actual.mode.permissions != OWNER_DIRECTORY_MODE
    ) leaseFail("$label is not a pinned owner-only directory")
}

private fun requireTrustedParent(actual: LinuxFileIdentity, expected: LinuxFileIdentity) {
    val uid = currentUid()
    if (
        !sameDirectory(actual, expected) || actual.uid !in setOf(0, uid) ||
        actual.mode.permissions and GROUP_OR_OTHER_WRITE_MODE != 0
    ) leaseFail("hosted toolchain image-build lease root has an untrusted parent")
}

private fun sameDirectory(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.uid == second.uid && first.gid == second.gid &&
        first.isDirectory && second.isDirectory &&
        !first.isRegularFile && !second.isRegularFile &&
        !first.isSymbolicLink && !second.isSymbolicLink

private fun currentUid(): Int =
    (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()

private fun canonical(document: JsonObject): ByteArray =
    OracleJson.canonicalBytes(document, LEASE_JSON_LIMITS)

private fun sha256(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)

private fun JsonObject.requireExactKeys(expected: Set<String>, label: String) {
    if (keys != expected) leaseFail("$label fields are not exact")
}

private fun JsonObject.requiredObject(name: String): JsonObject = this[name] as? JsonObject
    ?: leaseFail("hosted toolchain image-build lease field is not an object: $name")

private fun JsonObject.requiredString(name: String): String {
    val value = this[name] as? JsonPrimitive
        ?: leaseFail("hosted toolchain image-build lease field is not a string: $name")
    if (!value.isString) leaseFail("hosted toolchain image-build lease field is not a string: $name")
    return value.content
}

private fun JsonObject.requiredInt(name: String): Int {
    val value = this[name] as? JsonPrimitive
        ?: leaseFail("hosted toolchain image-build lease field is not an integer: $name")
    if (value.isString) leaseFail("hosted toolchain image-build lease field is not an integer: $name")
    return value.intOrNull
        ?: leaseFail("hosted toolchain image-build lease field is not an integer: $name")
}

private fun JsonObject.requiredLong(name: String): Long {
    val value = this[name] as? JsonPrimitive
        ?: leaseFail("hosted toolchain image-build lease field is not an integer: $name")
    if (value.isString) leaseFail("hosted toolchain image-build lease field is not an integer: $name")
    return value.longOrNull
        ?: leaseFail("hosted toolchain image-build lease field is not an integer: $name")
}

private inline fun <T> translateLeaseFailures(label: String, action: () -> T): T = try {
    action()
} catch (failure: LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception) {
    throw failure
} catch (failure: Exception) {
    throw LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception(
        "$label failed: ${failure.message ?: failure::class.java.simpleName}",
        failure,
    )
}

private fun leaseFail(message: String): Nothing =
    throw LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception(message)

private const val BINDING_SCHEMA_VERSION = 2
private const val BUILD_INTENT_SCHEMA_VERSION = 2
private const val OPERATION_ID_SCHEMA_VERSION = 2
private const val REQUEST_INTENT_SCHEMA_VERSION = 2
private const val TRANSITION_SCHEMA_VERSION = 2
private const val LEASE_PROVIDER =
    "kotlin-llvm-behavior-hosted-toolchain-image-build-lease-v2"
private const val BUILD_INTENT_PROVIDER =
    "kotlin-llvm-behavior-hosted-toolchain-image-build-intent-v2"
private const val OPERATION_ID_PROVIDER =
    "kotlin-llvm-behavior-hosted-toolchain-image-build-operation-id-v2"
private const val REQUEST_INTENT_PROVIDER =
    "kotlin-llvm-behavior-hosted-toolchain-image-build-request-intent-v2"
private const val LEASE_AUTHORITY =
    "recipe-bound-fact-free-llvm-behavior-hosted-toolchain-image-build-lease"

private const val ACP_ROLE = "first-class-candidate-producer-operator"
private const val ACP_ORACLE_ACCESS = "none"
private const val RECOVERY_TAG_PREFIX = "decomp-llvm-behavior-hosted-toolchain:lease-"
private const val RECOVERY_LEASE_LABEL_KEY =
    "dev.decompengine.llvm-behavior-hosted-toolchain-image-build-lease"
private const val CONTENT_SHA256_LABEL_KEY =
    "dev.decompengine.llvm-behavior-hosted-toolchain-build-context-sha256"
private const val BUILD_ID_QUERY_KEY = "buildid"
private const val BUILD_CANCEL_QUERY_KEY = "id"
private const val BUILD_CANCEL_REQUEST_PATH = "/v1.55/build/cancel"

private const val PINNED_REPRODUCTION_LOCK_SHA256 =
    "14a383bc5792b7ace786cbbd8964383469c1ffa5a4bb06a99e38c71518643f4f"
private const val PINNED_BUILD_RECORD_SHA256 =
    "415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005"
private const val PINNED_DOCKERFILE_SHA256 =
    "97e2d13915806242c14489b5a8b1417bd0478f3a11dc05e76888ba2ab43b1291"
private const val PINNED_DOCKERFILE_BYTES = 1_638L
private const val PINNED_DETERMINISTIC_TAR_SHA256 =
    "c47e1f8a2c70576c6aad1af2e68865c3d458da7288ea9ecc21dde4c3e364f20e"
private const val PINNED_DETERMINISTIC_TAR_BYTES = 3_584L
private const val PINNED_BASE_IMAGE_REFERENCE =
    "ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517"
private const val PINNED_PLATFORM = "linux/amd64"
private const val PINNED_SOURCE_DATE_EPOCH = "1779182222"

private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val GROUP_OR_OTHER_WRITE_MODE = 0x12 // 0022
private const val MAXIMUM_RECORD_BYTES = 64 * 1024
private const val MAXIMUM_TRANSITIONS = 9
private const val MAXIMUM_JOURNAL_ENTRIES = 1 + MAXIMUM_TRANSITIONS + 1
private const val BINDING_FILE = "binding.json"
private const val NONCE_BYTES = 32
private const val HEX = "0123456789abcdef"
private val SECURE_RANDOM = SecureRandom()
private val ZERO_SHA256 = "0".repeat(64)
private val SHA256 = Regex("[0-9a-f]{64}")
private val NONCE = Regex("[0-9a-f]{64}")
private val RECOVERY_TAG = Regex("[a-z0-9][a-z0-9_.-]*/?[a-z0-9_.-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
private val TRANSITION_FILE_NAME = Regex("transition-[0-9]{4}\\.json")
private val ATOMIC_TRANSITION_FILE_NAME = Regex("\\.transition-([0-9]{4})\\.json\\.atomic")

private val LEASE_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_RECORD_BYTES,
    maximumCanonicalBytes = MAXIMUM_RECORD_BYTES,
    maximumDepth = 8,
    maximumNodes = 512,
    maximumStringBytes = 8192,
    maximumTotalStringBytes = 48 * 1024,
    maximumNumberCharacters = 20,
)

private val EMPTY_OBJECT = JsonObject(emptyMap())

private val FIXED_BUILD_REQUEST_POLICY = JsonObject(
    mapOf(
        "apiVersion" to JsonPrimitive("1.55"),
        "builderVersion" to JsonPrimitive("2"),
        "buildIdQueryParameter" to JsonPrimitive(BUILD_ID_QUERY_KEY),
        "cacheImports" to JsonPrimitive(false),
        "cacheExports" to JsonPrimitive(false),
        "contentType" to JsonPrimitive("application/x-tar"),
        "dockerfile" to JsonPrimitive("Dockerfile"),
        "extraHosts" to JsonPrimitive(false),
        "forceRemoveIntermediateContainers" to JsonPrimitive(true),
        "method" to JsonPrimitive("POST"),
        "networkAccess" to JsonPrimitive("engine-builder-default-required-for-reviewed-apt-and-curl"),
        "networkMode" to JsonPrimitive("default"),
        "noCache" to JsonPrimitive(true),
        "outputsSupplied" to JsonPrimitive(false),
        "platform" to JsonPrimitive(PINNED_PLATFORM),
        "pull" to JsonPrimitive(false),
        "quiet" to JsonPrimitive(false),
        "registryAuthentication" to JsonPrimitive(false),
        "remoteContext" to JsonPrimitive(false),
        "removeIntermediateContainers" to JsonPrimitive(true),
        "requestTarget" to JsonPrimitive("/v1.55/build"),
        "requestTransfer" to JsonPrimitive("fixed-content-length-no-transfer-encoding"),
        "secrets" to JsonPrimitive(false),
        "session" to JsonPrimitive(false),
        "ssh" to JsonPrimitive(false),
        "target" to JsonPrimitive(false),
    ),
)

private val STATIC_ACP_BOUNDARY = JsonObject(
    mapOf(
        "imageBuildAuthority" to JsonPrimitive(false),
        "input" to JsonPrimitive(false),
        "oracleAccess" to JsonPrimitive(ACP_ORACLE_ACCESS),
        "role" to JsonPrimitive(ACP_ROLE),
    ),
)

private val STATIC_PYTHON_BOUNDARY = JsonObject(
    mapOf(
        "oracleOrControlAuthority" to JsonPrimitive(false),
        "packagePresence" to JsonPrimitive("reviewed-recipe-installs-python3"),
    ),
)

private val FALSE_CLAIMS = JsonObject(
    mapOf(
        "admissionAuthority" to JsonPrimitive(false),
        "buildExecuted" to JsonPrimitive(false),
        "buildIdRegistered" to JsonPrimitive(false),
        "buildQuiescenceProved" to JsonPrimitive(false),
        "cancelSucceeded" to JsonPrimitive(false),
        "cleanupExecuted" to JsonPrimitive(false),
        "containmentAuthority" to JsonPrimitive(false),
        "createAuthority" to JsonPrimitive(false),
        "engineAccepted" to JsonPrimitive(false),
        "imageIdentityBound" to JsonPrimitive(false),
        "imageBuildAuthority" to JsonPrimitive(false),
        "observationAuthority" to JsonPrimitive(false),
        "oracleAuthority" to JsonPrimitive(false),
        "parsedFactsAccepted" to JsonPrimitive(false),
        "postIssued" to JsonPrimitive(false),
        "publicationAuthority" to JsonPrimitive(false),
        "recoveryLocatorsObserved" to JsonPrimitive(false),
        "releaseAuthority" to JsonPrimitive(false),
        "runnerAccepted" to JsonPrimitive(false),
        "scoringAuthority" to JsonPrimitive(false),
        "startAuthority" to JsonPrimitive(false),
    ),
)

private val RECIPE_FIELDS = setOf(
    "baseImageReference",
    "buildRecordSha256",
    "deterministicTarBytes",
    "deterministicTarSha256",
    "dockerfileBytes",
    "dockerfileSha256",
    "platform",
    "reproductionLockSha256",
    "sourceDateEpoch",
)

private val RECOVERY_LABEL_FIELDS = setOf("key", "value")

private val BINDING_FIELDS = setOf(
    "acpBoundary",
    "authority",
    "bindingSha256",
    "buildIntentSha256",
    "buildRequestIntent",
    "claims",
    "journalRootPathSha256",
    "leaseNonce",
    "operationId",
    "provider",
    "pythonBoundary",
    "recipe",
    "recoveryLeaseLabel",
    "recoveryTag",
    "requestIntentSha256",
    "schemaVersion",
)

private val TRANSITION_FIELDS = setOf(
    "authority",
    "bindingSha256",
    "claims",
    "facts",
    "operationId",
    "phase",
    "previousTransitionSha256",
    "provider",
    "schemaVersion",
    "sequence",
    "transitionSha256",
)

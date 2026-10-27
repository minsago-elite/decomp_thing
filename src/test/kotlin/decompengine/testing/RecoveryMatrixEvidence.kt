package decompengine.testing

import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.FileAttribute
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.extension.AfterEachCallback
import org.junit.jupiter.api.extension.BeforeEachCallback
import org.junit.jupiter.api.extension.ExtensionContext

/** Observed benign-fixture facts only; not worker, containment, or execution authority. */
class RecoveryMatrixEvidence : BeforeEachCallback, AfterEachCallback {
    override fun beforeEach(context: ExtensionContext) {
        check(active.get() == null) { "a recovery fixture context was not released" }
        require(context.requiredTestMethod.parameterCount == 0) { "unsupported recovery test signature" }
        active.set(CaseContext(context.requiredTestClass.name, context.requiredTestMethod.name + "()"))
    }

    override fun afterEach(context: ExtensionContext) {
        try {
            val current = checkNotNull(active.get()) { "recovery fixture context is missing" }
            check(current.className == context.requiredTestClass.name &&
                current.method == context.requiredTestMethod.name + "()") { "recovery fixture context changed test identity" }
            check(!current.captureFailed) { "recovery fixture configuration capture failed" }
            println(RECOVERY_CONTEXT_PREFIX + current.snapshot())
        } finally {
            active.remove()
        }
    }

    companion object {
        private val active = ThreadLocal<CaseContext>()

        internal fun snapshot(): JsonObject =
            checkNotNull(active.get()) { "fixture creation requires its JUnit test thread" }.snapshot()

        internal fun create(parent: Path, prefix: String, attributes: Array<out FileAttribute<*>>): Path {
            val current = checkNotNull(active.get()) { "fixture creation requires its JUnit test thread" }
            check(current.roots.size < MAXIMUM_FIXTURE_ROOTS) { "recovery fixture root count exceeds its bound" }
            val repository = Path.of("").toRealPath()
            val canonicalParent = requireRecoveryRepositoryParent(repository, parent)
            val directory = Files.createTempDirectory(canonicalParent, prefix, *attributes)
            try {
                val store = Files.getFileStore(directory)
                val blockSize = try {
                    store.blockSize.also { require(it > 0) { "invalid fixture filesystem block size" } }
                } catch (_: UnsupportedOperationException) {
                    null
                }
                current.roots += buildJsonObject {
                    put("ordinal", current.roots.size + 1)
                    put("provider", publicFact(directory.fileSystem.provider().javaClass.name, 160))
                    put("scheme", publicFact(directory.fileSystem.provider().scheme, 32))
                    put("type", publicFact(store.type(), 64))
                    put("blockSizeBytes", blockSize?.let(::JsonPrimitive) ?: JsonNull)
                    put("blockSizeStatus", if (blockSize == null) "UNSUPPORTED" else "CAPTURED")
                    put("readOnly", store.isReadOnly)
                    put("supportsPosix", store.supportsFileAttributeView("posix"))
                    put("supportsUnix", store.supportsFileAttributeView("unix"))
                }
                return directory
            } catch (failure: Throwable) {
                // A test may catch an expected application exception; failed observation
                // must still refuse the case instead of emitting NOT_EXERCISED.
                current.captureFailed = true
                // Only delete the empty directory this call just created, never descendants.
                try { Files.delete(directory) } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
                throw failure
            }
        }
    }

    private class CaseContext(val className: String, val method: String) {
        init {
            require(className.length in 1..512 && method.length in 1..1024) {
                "recovery test identity exceeds its bound"
            }
        }
        val roots = ArrayList<JsonObject>()
        var captureFailed = false
        private val runtime = buildJsonObject {
            put("javaRuntimeVersion", publicFact(Runtime.version().toString(), 128))
            put("javaVendor", publicFact(System.getProperty("java.vendor"), 128))
            put("javaVmName", publicFact(System.getProperty("java.vm.name"), 128))
            put("osName", publicFact(System.getProperty("os.name"), 128))
            put("osVersion", publicFact(System.getProperty("os.version"), 128))
            put("osArch", publicFact(System.getProperty("os.arch"), 128))
        }

        fun snapshot() = buildJsonObject {
            put("schemaVersion", 1)
            put("scope", "benign-recovery-fixture-runtime")
            put("caseClass", className)
            put("caseMethod", method)
            put("runtime", runtime)
            put("fixtureRoots", JsonArray(roots.toList()))
            put("filesystemDisposition", if (roots.isEmpty()) "NOT_EXERCISED" else "OBSERVED")
        }
    }
}

internal const val RECOVERY_CONTEXT_PREFIX = "web-job-recovery-context-v1 "
private const val MAXIMUM_FIXTURE_ROOTS = 256

private fun publicFact(value: String?, maximum: Int): String {
    require(value != null && value.isNotEmpty() && value.length <= maximum &&
        value.all { it.code in 32..126 && it != '/' && it != '\\' }) {
        "fixture runtime or filesystem fact is missing or outside its public text bound"
    }
    return value
}

internal fun requireRecoveryRepositoryParent(repository: Path, parent: Path): Path {
    val requested = parent.toAbsolutePath().normalize()
    val logicalRepository = Path.of("").toAbsolutePath().normalize()
    require(requested.startsWith(repository) || requested.startsWith(logicalRepository)) {
        "recovery fixture parent is outside the repository"
    }
    val canonical = requested.toRealPath()
    require(canonical.startsWith(repository)) { "recovery fixture parent resolves outside the repository" }
    return canonical
}

private fun recoveryScratchParent(): Path {
    var directory = Path.of("").toRealPath()
    for (component in listOf("build", "test-tmp", "recovery-matrix")) {
        directory = directory.resolve(component)
        try { Files.createDirectory(directory) } catch (_: FileAlreadyExistsException) { /* Validate below. */ }
        require(Files.isDirectory(directory, NOFOLLOW_LINKS) && !Files.isSymbolicLink(directory)) {
            "recovery fixture scratch parent must be a real directory"
        }
    }
    return directory
}

internal fun recoveryMatrixTempDirectory(prefix: String, vararg attributes: FileAttribute<*>): Path =
    RecoveryMatrixEvidence.create(recoveryScratchParent(), prefix, attributes)

internal fun recoveryMatrixTempDirectory(parent: Path, prefix: String, vararg attributes: FileAttribute<*>): Path =
    RecoveryMatrixEvidence.create(parent, prefix, attributes)

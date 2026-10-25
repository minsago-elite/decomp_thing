package decompengine.oracle.reference

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Base64
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import org.tukaani.xz.SingleXZInputStream

internal class ReferenceCorpusProfileException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class ReferenceCorpusArtifactIdentity(val guestPath: String, val bytes: Long, val sha256: String)

internal class ReferenceCorpusBatch internal constructor(val id: String, artifactRoles: Collection<String>) {
    val artifactRoles: Set<String> = Collections.unmodifiableSet(LinkedHashSet(artifactRoles))
}

internal class ReferenceCorpusInput internal constructor(val path: String, content: ByteArray) {
    private val stored = content.copyOf()
    val content: ByteArray get() = stored.copyOf()
    val bytes: Long get() = stored.size.toLong()
    val sha256: String = OracleArtifacts.sha256(stored)
}

internal class ReferenceCorpusCase internal constructor(
    val id: String,
    arguments: List<String>,
    environment: Map<String, String>,
    inputs: List<ReferenceCorpusInput>,
    stdin: ByteArray,
    val batchId: String,
    categories: List<String>,
) {
    val arguments: List<String> = immutableList(arguments)
    val environment: Map<String, String> = Collections.unmodifiableMap(LinkedHashMap(environment))
    val inputs: List<ReferenceCorpusInput> = immutableList(inputs)
    private val storedStdin = stdin.copyOf()
    val stdin: ByteArray get() = storedStdin.copyOf()
    val categories: List<String> = immutableList(categories)
}

internal class ReferenceCorpusIdentitySubstitution internal constructor(
    val id: String,
    val token: String,
    patterns: List<String>,
    val where: String,
    val permitted: String,
    val alternateBinding: String,
) {
    val patterns: List<String> = immutableList(patterns)
}

internal data class ReferenceCorpusLimits(
    val wallClockMillisPerInvocation: Long,
    val maximumStdoutBytes: Long,
    val maximumStderrBytes: Long,
    val maximumArtifactBytes: Long,
    val maximumAggregateOutputBytes: Long,
)

/** Validated immutable input definition only; parsing this value grants no execution authority. */
internal class ReferenceCorpusDefinition private constructor(
    val id: String,
    val imageConfigSha256: String,
    artifacts: Map<String, ReferenceCorpusArtifactIdentity>,
    val executableRole: String,
    batches: Map<String, ReferenceCorpusBatch>,
    val alternateBasename: String,
    cases: List<ReferenceCorpusCase>,
    identitySubstitutions: List<ReferenceCorpusIdentitySubstitution>,
    val limits: ReferenceCorpusLimits,
    canonical: ByteArray,
) {
    val artifacts: Map<String, ReferenceCorpusArtifactIdentity> = immutableMap(artifacts)
    val executableIdentity: ReferenceCorpusArtifactIdentity get() = artifacts.getValue(executableRole)
    val executablePath: String get() = executableIdentity.guestPath
    val batches: Map<String, ReferenceCorpusBatch> = immutableMap(batches)
    val cases: List<ReferenceCorpusCase> = immutableList(cases)
    val identitySubstitutions: List<ReferenceCorpusIdentitySubstitution> = immutableList(identitySubstitutions)
    private val encoded = canonical.copyOf()
    val canonicalBytes: ByteArray get() = encoded.copyOf()

    fun batch(batchId: String): ReferenceCorpusBatch = batches[batchId]
        ?: throw IllegalArgumentException("unknown reference batch")

    fun artifactRolesForBatch(batchId: String): Set<String> = batch(batchId).artifactRoles

    fun alternateSubstitutionValues(invokedAs: String): Map<String, String> {
        require(invokedAs.startsWith('/') && Path.of(invokedAs).normalize().toString() == invokedAs &&
            Path.of(invokedAs).fileName.toString() == alternateBasename) { "alternate executable identity differs" }
        return immutableMap(identitySubstitutions.mapNotNull { rule ->
            when (rule.alternateBinding) {
                "executable-basename" -> rule.id to alternateBasename
                "executable-argv0" -> rule.id to invokedAs
                else -> null
            }
        }.toMap())
    }

    /** ASCII policy patterns operate on an octet-preserving view; unmatched bytes are never decoded lossily. */
    fun substitute(input: ByteArray, values: Map<String, String>): ByteArray {
        require(values.keys.all { key -> identitySubstitutions.any { it.id == key } }) { "unknown identity substitution" }
        require(values.values.all { it.length <= 4096 && '\u0000' !in it && '\n' !in it && '\r' !in it })
        var lines = input.toString(Charsets.ISO_8859_1).split('\n')
        for (rule in identitySubstitutions) {
            val value = values[rule.id]?.toByteArray(Charsets.UTF_8)?.toString(Charsets.ISO_8859_1) ?: continue
            for (pattern in rule.patterns) {
                val regex = Regex(pattern)
                lines = lines.map { line ->
                    regex.replace(line) { match ->
                        val group = checkNotNull(match.groups[1])
                        val start = group.range.first - match.range.first
                        val end = group.range.last + 1 - match.range.first
                        match.value.substring(0, start) + value + match.value.substring(end)
                    }
                }
            }
        }
        return lines.joinToString("\n").toByteArray(Charsets.ISO_8859_1)
    }

    companion object {
        fun parse(canonicalBytes: ByteArray): ReferenceCorpusDefinition = profileTranslate {
            val root = OracleJson.parseCanonical(canonicalBytes, PROFILE_JSON_LIMITS).obj("reference profile")
            root.fields("schemaVersion", "id", "imageConfigSha256", "artifactIdentities", "executableRole", "batches",
                "alternateBasename", "limits", "identitySubstitutions", "cases")
            require(root.number("schemaVersion") == 1L) { "unsupported reference profile version" }
            val id = root.string("id").identifier("profile id")
            val image = root.string("imageConfigSha256").digest("image config")
            val artifacts = root.obj("artifactIdentities").map { (role, value) ->
                role.identifier("artifact role") to parseArtifactIdentity(value.obj("artifact identity"))
            }.toMap()
            require(artifacts.size in 1..16 && artifacts.values.map { it.guestPath }.distinct().size == artifacts.size) {
                "artifact registry is empty, too large or has overlapping guest paths"
            }
            val executableRole = root.string("executableRole").identifier("executable role")
            require(executableRole in artifacts) { "executable is absent from the artifact registry" }
            val parsedBatches = root.array("batches").map { item ->
                val batch = item.obj("batch")
                batch.fields("id", "artifactRoles")
                val roles = batch.strings("artifactRoles", 16)
                require(roles.size == roles.distinct().size && roles.all { it in artifacts } && executableRole in roles) {
                    "batch must include the executable and only registered artifact roles"
                }
                ReferenceCorpusBatch(batch.string("id").identifier("batch id"), roles)
            }
            require(parsedBatches.size in 1..16 && parsedBatches.map { it.id }.distinct().size == parsedBatches.size)
            val batches = parsedBatches.associateBy { it.id }
            val alternate = root.string("alternateBasename").identifier("alternate basename")
            val limitObject = root.obj("limits")
            limitObject.fields("wallClockMillisPerInvocation", "maximumStdoutBytes", "maximumStderrBytes",
                "maximumArtifactBytes", "maximumAggregateOutputBytes")
            val limits = ReferenceCorpusLimits(limitObject.number("wallClockMillisPerInvocation"),
                limitObject.number("maximumStdoutBytes"), limitObject.number("maximumStderrBytes"),
                limitObject.number("maximumArtifactBytes"), limitObject.number("maximumAggregateOutputBytes"))
            require(limits.wallClockMillisPerInvocation in 1_000L..60_000L && limits.wallClockMillisPerInvocation % 1000L == 0L)
            require(limits.maximumStdoutBytes in 1L..1024 * 1024 && limits.maximumStderrBytes in 1L..1024 * 1024)
            require(limits.maximumArtifactBytes in 1L..4L * 1024 * 1024)
            require(limits.maximumAggregateOutputBytes in maxOf(limits.maximumStdoutBytes, limits.maximumStderrBytes)..16L * 1024 * 1024)
            val substitutions = root.array("identitySubstitutions").map { value ->
                val rule = value.obj("substitution")
                rule.fields("id", "token", "patterns", "where", "permitted", "alternateBinding")
                val patterns = rule.strings("patterns", 16)
                require(patterns.isNotEmpty() && patterns.all { pattern ->
                    pattern.length in 1..512 && pattern.all { it.code in 32..126 } &&
                        Regex(pattern).toPattern().matcher("").groupCount() == 1
                }) { "identity substitution must have one bounded ASCII capture group" }
                ReferenceCorpusIdentitySubstitution(rule.string("id").identifier("substitution id"),
                    rule.string("token").boundedText(4096), patterns, rule.string("where").boundedText(4096),
                    rule.string("permitted").boundedText(4096), rule.string("alternateBinding").also {
                        require(it in setOf("executable-basename", "executable-argv0", "unchanged")) { "unknown alternate identity binding" }
                    })
            }
            require(substitutions.size <= 8 && substitutions.map { it.id }.distinct().size == substitutions.size)
            val cases = root.array("cases").map { value ->
                val case = value.obj("case")
                case.fields("id", "arguments", "environment", "inputs", "stdin", "batchId", "categories")
                val arguments = case.strings("arguments", 64).map { it.boundedText(4096) }
                val environment = case.obj("environment").mapValues { (key, value) ->
                    require(key.matches(Regex("[A-Z][A-Z0-9_]{0,63}"))) { "invalid environment name" }
                    value.stringValue("environment value").boundedText(4096)
                }
                require(environment.size in 1..32 && "PATH" in environment) { "explicit bounded PATH is required" }
                val inputs = case.array("inputs").map { item ->
                    val input = item.obj("input")
                    input.fields("path", "base64", "bytes", "sha256")
                    ReferenceCorpusInput(input.string("path").relativePath(), decodeBlob(input, 64 * 1024))
                }
                require(inputs.size <= 64 && inputs.map { it.path }.distinct().size == inputs.size)
                require(inputs.sumOf { it.bytes } <= 256 * 1024L) { "input bytes exceed per-case bound" }
                val stdin = case.obj("stdin")
                stdin.fields("base64", "bytes", "sha256")
                ReferenceCorpusCase(case.string("id").identifier("case id"), arguments, environment, inputs,
                    decodeBlob(stdin, 64 * 1024), case.string("batchId").also { require(it in batches) { "case batch is not registered" } },
                    case.strings("categories", 16).map { it.identifier("category") })
            }
            require(cases.size in 1..64 && cases.map { it.id }.distinct().size == cases.size)
            require(cases.map { it.batchId }.toSet() == batches.keys) { "reference batches must have cases" }
            require(parsedBatches.flatMap { it.artifactRoles }.toSet() == artifacts.keys) { "reference artifacts must be used by a batch" }
            require(cases.sumOf { it.inputs.sumOf { input -> input.bytes } + it.stdin.size } <= 1024 * 1024L)
            ReferenceCorpusDefinition(id, image, artifacts, executableRole, batches, alternate, cases, substitutions, limits, canonicalBytes)
        }
    }
}

internal data class ReferenceCorpusSourceBinding(val id: String, val path: Path, val bytes: Long, val sha256: String)

/** A bounded, immutable projection definition. Parsing alone grants no runtime authority. */
internal class ReferenceNativeRuntimeSelection private constructor(
    val imageConfigSha256: String,
    treePrefixes: List<String>,
    configurationTreeRoots: List<String>,
    configurationNodes: List<String>,
    canonicalBytes: ByteArray,
) {
    val treePrefixes: List<String> = immutableList(treePrefixes)
    val configurationTreeRoots: List<String> = immutableList(configurationTreeRoots)
    val configurationNodes: List<String> = immutableList(configurationNodes)
    private val stored = canonicalBytes.copyOf()
    val canonicalBytes: ByteArray get() = stored.copyOf()
    val sha256: String = OracleArtifacts.sha256(stored)

    fun selectsConfiguration(path: String): Boolean = path in configurationNodes ||
        configurationTreeRoots.any { path == it || path.startsWith("$it/") }

    companion object {
        fun parse(canonicalBytes: ByteArray): ReferenceNativeRuntimeSelection = profileTranslate {
            val root = OracleJson.parseCanonical(canonicalBytes, PROFILE_JSON_LIMITS).obj("native runtime selection")
            root.fields("schemaVersion", "imageConfigSha256", "treePrefixes", "configurationTreeRoots", "configurationNodes")
            require(root.number("schemaVersion") == 1L) { "unsupported native runtime selection version" }
            fun paths(name: String, maximum: Int): List<String> = root.strings(name, maximum).also { paths ->
                require(paths == paths.distinct().sorted()) { "native runtime selection paths must be sorted and unique" }
                paths.forEach { path ->
                    require(path.startsWith('/') && path != "/" && path.length <= 4096 &&
                        path.all { it.code in 33..126 && it != '\\' } &&
                        path.split('/').drop(1).all { it.isNotEmpty() && it != "." && it != ".." } &&
                        path.split('/').size <= 64 && Path.of(path).normalize().toString() == path) {
                        "native runtime selection path is invalid"
                    }
                }
            }
            val trees = paths("treePrefixes", 5)
            require(trees == listOf("/bin", "/lib", "/lib64", "/sbin", "/usr")) {
                "native runtime selection must retain the complete Linux tool and ABI trees"
            }
            val configurationTrees = paths("configurationTreeRoots", 1024)
            val configurationNodes = paths("configurationNodes", 2048)
            require("/etc" in configurationNodes && configurationTrees.all { it.startsWith("/etc/") } &&
                configurationNodes.all { it == "/etc" || it.startsWith("/etc/") }) {
                "native runtime configuration selection must be explicit beneath /etc"
            }
            require(configurationTrees.none { tree -> configurationTrees.any { it != tree && tree.startsWith("$it/") } } &&
                configurationNodes.none { node -> configurationTrees.any { node == it || node.startsWith("$it/") } }) {
                "native runtime configuration selection overlaps"
            }
            (configurationTrees + configurationNodes).forEach { selected ->
                var ancestor = Path.of(selected).parent
                while (ancestor != null && ancestor != Path.of("/")) {
                    require(ancestor.toString() in configurationNodes) { "native runtime configuration ancestor is absent" }
                    ancestor = ancestor.parent
                }
            }
            ReferenceNativeRuntimeSelection(root.string("imageConfigSha256").digest("native runtime image config"),
                trees, configurationTrees, configurationNodes, canonicalBytes)
        }
    }
}

internal class ReferenceCorpusArtifact internal constructor(
    val role: String,
    val sourcePath: Path,
    val guestPath: String,
    val bytes: Long,
    val sha256: String,
    val sourceBytes: Long,
    val sourceSha256: String,
    val encoding: String,
    content: ByteArray,
) {
    private val stored = content.copyOf()
    val content: ByteArray get() = stored.copyOf()
}

/**
 * Retained authority for exact reference inputs. Only registrations embedded in this authenticated
 * application classpath can be selected; caller digests, parsed documents and approval flags are
 * never accepted. Execution/containment authority remains with the separate retained coordinator.
 */
internal class AuthenticatedReferenceCorpusProfile private constructor(
    val registrationId: String,
    val profilePath: Path,
    val definition: ReferenceCorpusDefinition,
    val nativeRuntimeSelection: ReferenceNativeRuntimeSelection,
    private val guards: List<StableControlFile>,
    inputBindings: List<ReferenceCorpusSourceBinding>,
    artifacts: List<ReferenceCorpusArtifact>,
) : AutoCloseable {
    val inputBindings: List<ReferenceCorpusSourceBinding> = immutableList(inputBindings)
    val originalArtifacts: List<ReferenceCorpusArtifact> = immutableList(artifacts)
    val executable: ReferenceCorpusArtifact get() = artifact(definition.executableRole)
    val profileSha256: String = OracleArtifacts.sha256(definition.canonicalBytes)
    val canonicalBytes: ByteArray get() = definition.canonicalBytes
    val imageConfigSha256: String get() = definition.imageConfigSha256
    private var closed = false

    fun artifactRolesForBatch(batchId: String): Set<String> = definition.artifactRolesForBatch(batchId)

    fun artifact(role: String): ReferenceCorpusArtifact = originalArtifacts.singleOrNull { it.role == role }
        ?: throw IllegalArgumentException("unknown reference artifact role")

    @Synchronized
    fun requireCurrent(label: String = "reference profile") {
        check(!closed) { "reference profile is closed" }
        guards.forEach { it.verifyUnchanged(label) }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        guards.asReversed().forEach { guard ->
            runCatching(guard::close).exceptionOrNull()?.let { next ->
                if (failure == null) failure = next else failure!!.addSuppressed(next)
            }
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(profileRoot: Path, registrationId: String): AuthenticatedReferenceCorpusProfile = profileTranslate {
            require(registrationId.matches(Regex("[a-z0-9][a-z0-9-]{0,63}"))) { "invalid reference registration id" }
            val resource = "/oracle-reference-profiles/$registrationId.json"
            val registrationBytes = AuthenticatedReferenceCorpusProfile::class.java.getResourceAsStream(resource)?.use {
                it.readNBytes(MAXIMUM_PROFILE_BYTES + 1)
            } ?: throw ReferenceCorpusProfileException("reference registration is not embedded in the application")
            require(registrationBytes.size <= MAXIMUM_PROFILE_BYTES)
            val registration = OracleJson.parseCanonical(registrationBytes, PROFILE_JSON_LIMITS).obj("registration")
            registration.fields("schemaVersion", "id", "profileBinding", "nativeRuntimeSelectionBinding", "sourceLockBinding", "bindings", "artifacts")
            require(registration.number("schemaVersion") == 2L && registration.string("id") == registrationId)
            require(profileRoot.isAbsolute && profileRoot.normalize() == profileRoot && profileRoot.toRealPath() == profileRoot)
            require(Files.isDirectory(profileRoot, LinkOption.NOFOLLOW_LINKS))
            val opened = ArrayList<StableControlFile>()
            try {
                val bindings = registration.array("bindings").map { value ->
                    val item = value.obj("binding")
                    item.fields("id", "path", "bytes", "sha256")
                    val id = item.string("id").identifier("binding id")
                    val path = profileRoot.resolve(item.string("path").relativePath())
                    val expectedBytes = item.number("bytes")
                    val expectedSha = item.string("sha256").digest("binding digest")
                    require(expectedBytes in 1L..MAXIMUM_ARTIFACT_BYTES)
                    val guard = StableControlFile.open(path, expectedBytes, "reference binding $id")
                    opened += guard
                    require(guard.size == expectedBytes && guard.authenticatedSha256 == expectedSha) {
                        "reference binding $id differs from the embedded registration"
                    }
                    ReferenceCorpusSourceBinding(id, path, expectedBytes, expectedSha) to guard
                }
                require(bindings.size in 1..32 && bindings.map { it.first.id }.distinct().size == bindings.size &&
                    bindings.map { it.first.path }.distinct().size == bindings.size)
                val byId = bindings.associateBy { it.first.id }
                fun binding(id: String) = byId[id] ?: throw ReferenceCorpusProfileException("unknown registration binding $id")
                fun content(id: String, maximum: Int = MAXIMUM_PROFILE_BYTES): ByteArray {
                    val (_, guard) = binding(id)
                    require(guard.size <= maximum) { "reference metadata exceeds its bound" }
                    return guard.readExactly(0, guard.size.toInt(), "reference binding $id")
                }
                fun document(id: String) = OracleJson.parse(content(id), PROFILE_JSON_LIMITS).obj("reference $id")
                val profileId = registration.string("profileBinding")
                val definition = ReferenceCorpusDefinition.parse(content(profileId))
                val selection = ReferenceNativeRuntimeSelection.parse(content(registration.string("nativeRuntimeSelectionBinding")))
                require(selection.imageConfigSha256 == definition.imageConfigSha256) { "native runtime selection image differs from the reference profile" }
                val sourceId = registration.string("sourceLockBinding")
                val sourceBinding = binding(sourceId).first
                val source = document(sourceId)
                val sourceRevision = source.obj("revision").string("commit")
                val sourceVersion = source.obj("oracle").string("version")
                var oracleIdentity: JsonObject? = null
                val artifacts = registration.array("artifacts").map { value ->
                    val spec = value.obj("artifact registration")
                    spec.fields("role", "binding", "manifestBinding", "buildBinding", "variant", "encoding")
                    val role = spec.string("role").identifier("artifact role")
                    val identity = definition.artifacts[role] ?: throw ReferenceCorpusProfileException("artifact role is not in the profile")
                    val artifactBinding = binding(spec.string("binding")).first
                    val manifest = document(spec.string("manifestBinding"))
                    val buildBinding = binding(spec.string("buildBinding")).first
                    val build = document(buildBinding.id)
                    val oracle = manifest.obj("oracle")
                    require(oracle.string("sourceRevision") == sourceRevision && oracle.string("version") == sourceVersion)
                    if (oracleIdentity == null) oracleIdentity = oracle else require(oracleIdentity == oracle) {
                        "reference artifacts do not share the exact oracle source identity"
                    }
                    val buildOracle = build.obj("oracle")
                    require(buildOracle.string("sourceRevision") == sourceRevision && buildOracle.string("version") == sourceVersion &&
                        buildOracle.string("sourceLockSha256") == sourceBinding.sha256) { "reference build/source identity differs" }
                    authenticateManifestInput(manifest.obj("inputs").obj("sourceLock"), sourceBinding, profileRoot)
                    authenticateManifestInput(manifest.obj("inputs").obj("buildRecord"), buildBinding, profileRoot)
                    val artifact = manifest.obj("artifacts").obj(spec.string("variant"))
                    require(artifact.number("bytes") == identity.bytes && artifact.string("sha256") == identity.sha256) {
                        "reference artifact differs from its manifest"
                    }
                    val encoding = spec.string("encoding")
                    val sourceBytes = content(artifactBinding.id, MAXIMUM_ARTIFACT_BYTES.toInt())
                    val decoded = when (encoding) {
                        "raw" -> sourceBytes
                        "xz" -> decodeReferenceXz(sourceBytes, identity.bytes)
                        else -> throw ReferenceCorpusProfileException("unsupported reference artifact encoding")
                    }
                    require(decoded.size.toLong() == identity.bytes && OracleArtifacts.sha256(decoded) == identity.sha256) {
                        "decoded reference artifact differs from its manifest"
                    }
                    ReferenceCorpusArtifact(role, artifactBinding.path, identity.guestPath, identity.bytes, identity.sha256,
                        artifactBinding.bytes, artifactBinding.sha256, encoding, decoded)
                }
                require(artifacts.size in 1..16 && artifacts.size == artifacts.map { it.role }.distinct().size &&
                    artifacts.map { it.role }.toSet() == definition.artifacts.keys) { "registered artifact roles differ from the profile" }
                opened.forEach { it.verifyUnchanged("reference profile admitted") }
                AuthenticatedReferenceCorpusProfile(registrationId, binding(profileId).first.path, definition, selection,
                    immutableList(opened), bindings.map { it.first }, artifacts)
            } catch (failure: Throwable) {
                opened.asReversed().forEach { runCatching(it::close).exceptionOrNull()?.let(failure::addSuppressed) }
                throw failure
            }
        }
    }
}

private fun authenticateManifestInput(input: JsonObject, binding: ReferenceCorpusSourceBinding, root: Path) {
    require(input.number("bytes") == binding.bytes && input.string("sha256") == binding.sha256 &&
        input.string("path").relativePath() == root.relativize(binding.path).toString()) {
        "reference manifest input differs from its retained binding"
    }
}

/** Bounded decoding alone is not an authenticated artifact or execution authority. */
internal fun decodeReferenceXz(compressed: ByteArray, expectedBytes: Long): ByteArray {
    require(expectedBytes in 1L..MAXIMUM_ARTIFACT_BYTES)
    val source = ByteArrayInputStream(compressed)
    val decoded = SingleXZInputStream(source, 128 * 1024).use { xz ->
        val bytes = xz.readNBytes(expectedBytes.toInt() + 1)
        require(bytes.size.toLong() == expectedBytes && xz.read() == -1) { "artifact expanded bytes differ from their fixed bound" }
        bytes
    }
    require(source.available() == 0) { "reference archive has trailing bytes or multiple streams" }
    return decoded
}

private fun parseArtifactIdentity(value: JsonObject): ReferenceCorpusArtifactIdentity {
    value.fields("guestPath", "bytes", "sha256")
    val path = value.string("guestPath")
    require(path.startsWith('/') && path != "/" && path.length <= 4096 && '\u0000' !in path &&
        Path.of(path).normalize().toString() == path && path.split('/').drop(1).all { it.isNotEmpty() && it != "." && it != ".." })
    val bytes = value.number("bytes")
    require(bytes in 1L..MAXIMUM_ARTIFACT_BYTES)
    return ReferenceCorpusArtifactIdentity(path, bytes, value.string("sha256").digest("artifact digest"))
}

private fun decodeBlob(value: JsonObject, maximum: Int): ByteArray {
    val expected = value.number("bytes")
    require(expected in 0L..maximum.toLong())
    val encoded = value.string("base64")
    require(encoded.length <= ((maximum + 2L) / 3 * 4))
    val decoded = Base64.getDecoder().decode(encoded)
    require(decoded.size.toLong() == expected && Base64.getEncoder().encodeToString(decoded) == encoded &&
        OracleArtifacts.sha256(decoded) == value.string("sha256").digest("blob digest")) { "reference blob identity differs" }
    return decoded
}

private fun JsonElement.obj(label: String): JsonObject = this as? JsonObject ?: error("$label must be an object")
private fun JsonObject.obj(name: String): JsonObject = getValue(name).obj(name)
private fun JsonObject.array(name: String): JsonArray = getValue(name) as? JsonArray ?: error("$name must be an array")
private fun JsonElement.stringValue(label: String): String = (this as? JsonPrimitive)?.takeIf { it.isString }?.content
    ?: error("$label must be a string")
private fun JsonObject.string(name: String): String = getValue(name).stringValue(name)
private fun JsonObject.number(name: String): Long = (getValue(name) as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull
    ?: error("$name must be an integer")
private fun JsonObject.strings(name: String, maximum: Int): List<String> = array(name).also { require(it.size <= maximum) }
    .map { it.stringValue(name) }
private fun JsonObject.fields(vararg names: String) { require(keys == names.toSet()) { "reference object fields differ" } }
private fun String.identifier(label: String): String = also { require(matches(Regex("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"))) { "$label is invalid" } }
private fun String.digest(label: String): String = also { require(matches(Regex("[0-9a-f]{64}"))) { "$label is invalid" } }
private fun String.boundedText(maximum: Int): String = also { require(length <= maximum && '\u0000' !in this) }
private fun String.relativePath(): String = also {
    require(isNotEmpty() && length <= 4096 && !startsWith('/') && '\u0000' !in this && '\\' !in this &&
        split('/').all { part -> part.isNotEmpty() && part != "." && part != ".." }) { "reference relative path is invalid" }
}
private fun <T> immutableList(values: Collection<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
private fun <K, V> immutableMap(values: Map<K, V>): Map<K, V> = Collections.unmodifiableMap(LinkedHashMap(values))
private inline fun <T> profileTranslate(action: () -> T): T = try { action() } catch (failure: ReferenceCorpusProfileException) {
    throw failure
} catch (failure: Exception) {
    throw ReferenceCorpusProfileException(failure.message ?: "reference profile authentication failed", failure)
}

private const val MAXIMUM_PROFILE_BYTES = 512 * 1024
private const val MAXIMUM_ARTIFACT_BYTES = 64L * 1024 * 1024
private val PROFILE_JSON_LIMITS = StrictJsonLimits(maximumInputBytes = MAXIMUM_PROFILE_BYTES,
    maximumCanonicalBytes = MAXIMUM_PROFILE_BYTES, maximumNodes = 32_768, maximumStringBytes = 256 * 1024,
    maximumTotalStringBytes = 384 * 1024)

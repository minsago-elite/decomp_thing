package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.reference.AdmittedReferenceNativeRuntime
import decompengine.oracle.reference.AuthenticatedReferenceCorpusProfile
import decompengine.oracle.reference.ReferenceRuntimeFileBinding
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

/** A reference declaration made by an installed owner, never a candidate execution receipt. */
internal object GccOrchestrationReferenceDeclaration {
    const val FILE_NAME = "orchestration-declaration.json"
    const val MAXIMUM_BYTES = 2 * 1024 * 1024
    private const val CONTRACT = "orchestration-contract"
    private const val REFERENCE = "orchestration-reference"
    private const val DRIVER = "/oracle/install/bin/gcc"
    private val caseIds = listOf("compile-to-assembly", "compile-to-object", "compile-pipe", "compile-save-temps",
        "assemble-only", "preprocess-and-assemble", "link-single", "link-multiple-sources", "link-mixed-c-and-assembly",
        "link-default-output", "failure-compile", "failure-assemble-source", "failure-assemble-after-compile", "failure-link-undefined-symbol")
    private val producedCases = setOf("link-single", "link-multiple-sources", "link-mixed-c-and-assembly", "link-default-output")
    private val argumentEquivalence = strings(mapOf(
        "assemble" to "insert -v immediately after argv[0]",
        "compile" to "insert -v after the first -quiet unless -fpreprocessed; insert -version immediately before -o",
        "failure" to "observed phases form a nonempty prefix; successful cases include all planned phases",
        "link" to "byte-identical argv", "preprocess" to "insert -v after the first -quiet"))
    private val programEnvironment = strings(mapOf("LC_ALL" to "C", "PATH" to "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SOURCE_DATE_EPOCH" to "1786060800", "TZ" to "UTC"))
    private val driverEnvironment = JsonObject(programEnvironment + strings(mapOf(
        "COMPILER_PATH" to "/oracle/install/libexec/gcc/x86_64-pc-linux-gnu/16.2.0:/usr/local/libexec/gcc/x86_64-linux-gnu/16.2.0",
        "C_INCLUDE_PATH" to "/usr/local/lib/gcc/x86_64-linux-gnu/16.2.0/include",
        "LIBRARY_PATH" to "/usr/local/lib/gcc/x86_64-linux-gnu/16.2.0:/usr/lib/x86_64-linux-gnu")))
    private val limits = StrictJsonLimits(maximumInputBytes = MAXIMUM_BYTES, maximumCanonicalBytes = MAXIMUM_BYTES,
        maximumDepth = 48, maximumNodes = 200_000, maximumStringBytes = 512 * 1024,
        maximumTotalStringBytes = MAXIMUM_BYTES, maximumNumberCharacters = 20)

    fun declare(profile: AuthenticatedReferenceCorpusProfile, runtime: AdmittedReferenceNativeRuntime): ByteArray {
        require(profile.registrationId == GccMetadataReferenceProfile.REGISTRATION_ID)
        profile.requireCurrent("before orchestration declaration")
        runtime.requireCurrent("before orchestration declaration")
        val contractBytes = profile.registeredInput(CONTRACT, MAXIMUM_BYTES)
        val referenceBytes = profile.registeredInput(REFERENCE, MAXIMUM_BYTES)
        val description = validateDocuments(contractBytes, referenceBytes)
        val contract = description.contract
        val provenance = contract.obj("provenance")
        fun bound(record: JsonObject, id: String) {
            val binding = profile.inputBindings.single { it.id == id }
            require(record.text("path") == binding.path.fileName.toString() && record.integer("bytes") == binding.bytes &&
                record.text("sha256") == binding.sha256) { "orchestration provenance differs from its retained profile input" }
        }
        bound(provenance.obj("reference"), REFERENCE)
        for ((role, manifestId, buildId) in listOf(Triple("driverManifest", "driver-manifest", "driver-build"),
            Triple("frontendManifest", "frontend-manifest", "frontend-build"))) {
            val declared = provenance.obj(role)
            bound(declared, manifestId)
            bound(declared.obj("inputs").obj("sourceLock"), "source-lock")
            bound(declared.obj("inputs").obj("buildRecord"), buildId)
            val manifest = OracleJson.parse(profile.registeredInput(manifestId, MAXIMUM_BYTES), limits).objectValue()
            require(provenance.obj("source") == manifest.obj("oracle")) { "orchestration source identity differs from its original manifest" }
        }
        val driver = profile.artifact("driver")
        require(contract.obj("driver") == fileIdentity(driver.guestPath, driver.bytes, driver.sha256))
        val frontend = profile.artifact("frontend")
        val compiler = contract.obj("phaseTools").obj("compile")
        require(compiler.text("path") == frontend.guestPath && compiler.integer("bytes") == frontend.bytes &&
            compiler.text("sha256") == frontend.sha256) { "orchestration frontend differs from the original artifact" }
        require(contract.obj("runtime").text("imageConfig") == "sha256:${profile.imageConfigSha256}")
        runtime.verifyDeclaredFiles(description.runtimeFiles)
        val runtimeBytes = runtime.canonicalBytes
        val admitted = OracleJson.parseCanonical(runtimeBytes).objectValue()
        require(admitted.text("profileSha256") == profile.profileSha256)
        val receipt = OracleJson.canonicalBytes(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("gcc-orchestration-reference-declaration-v1"),
            "scope" to JsonPrimitive("authenticated-reference-phase-and-invocation-declaration"),
            "registrationId" to JsonPrimitive(profile.registrationId), "profileSha256" to JsonPrimitive(profile.profileSha256),
            "contractSha256" to JsonPrimitive(OracleArtifacts.sha256(contractBytes)),
            "referenceSha256" to JsonPrimitive(OracleArtifacts.sha256(referenceBytes)),
            "invocationPolicySha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(contract.getValue("invocationPolicy")))),
            "nativeRuntimeSha256" to JsonPrimitive(runtime.identitySha256), "nativeRuntime" to admitted,
            "historicalReferenceProvenance" to provenance, "declaredRuntime" to contract.getValue("runtime"),
            "phaseStartupDependencies" to contract.getValue("phaseStartupDependencies"),
            "selectedRuntimeFiles" to JsonArray(description.runtimeFiles.map { file -> JsonObject(mapOf(
                "path" to JsonPrimitive(file.path), "resolvedPath" to JsonPrimitive(file.resolvedPath),
                "bytes" to JsonPrimitive(file.bytes), "sha256" to JsonPrimitive(file.sha256))) }),
            "cases" to contract.getValue("cases"), "declaredCaseCount" to JsonPrimitive(caseIds.size),
            "declaredProducedProgramCount" to JsonPrimitive(producedCases.size),
            "declarationAuthenticated" to JsonPrimitive(true), "phaseExecutionPerformed" to JsonPrimitive(false),
            "reconstructedExecution" to JsonPrimitive(false), "producedProgramExecution" to JsonPrimitive(false),
            "candidateQualified" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "recordedProducedArtifactsAreMounted" to JsonPrimitive(false),
            "kernelObjectScope" to JsonPrimitive("recorded vDSO name only; no kernel-owned byte identity or new execution claim"),
        )), limits)
        profile.requireCurrent("after orchestration declaration")
        runtime.requireCurrent("after orchestration declaration")
        return receipt
    }

    /** Shape/coherence result only. It cannot create an admitted runtime or declaration receipt. */
    internal class Description(val contract: JsonObject, runtimeFiles: List<ReferenceRuntimeFileBinding>) {
        val runtimeFiles: List<ReferenceRuntimeFileBinding> = java.util.List.copyOf(runtimeFiles)
    }

    internal fun validateDocuments(contractBytes: ByteArray, referenceBytes: ByteArray): Description {
        val contract = OracleJson.parseCanonical(contractBytes, limits).objectValue()
        val reference = OracleJson.parse(referenceBytes, limits).objectValue()
        contract.fields("acceptanceBoundary", "cases", "driver", "invocationPolicy", "issue", "kind", "phaseStartupDependencies",
            "phaseTools", "provenance", "runtime", "schemaVersion", "scope")
        require(contract.integer("schemaVersion") == 2L && contract.integer("issue") == 712L &&
            contract.text("kind") == "gcc-orchestration-identity-contract-v2" && contract.text("scope") == "closed-original-driver-reference-invocations")
        reference.fields("schemaVersion", "issue", "id", "status", "scope", "toolchain", "oracleDriver", "oracleFrontend",
            "referenceInvocationPolicy", "capture", "normalizations", "cases", "productionGates", "analysisBoundary")
        require(reference.integer("schemaVersion") == 2L && reference.integer("issue") == 712L &&
            reference.text("id") == "gcc-16-2-0-orchestration-phase-reference" && reference.text("status") == "captured" &&
            reference.text("scope") == "real-driver-phase-orchestration")
        val provenance = contract.obj("provenance")
        provenance.fields("driverManifest", "frontendManifest", "policySource", "reference", "runtimeProbe", "source")
        val referenceIdentity = provenance.obj("reference")
        referenceIdentity.fields("path", "bytes", "sha256")
        require(referenceIdentity == JsonObject(fileIdentity("orchestration-phase-reference.json", referenceBytes.size.toLong(),
            OracleArtifacts.sha256(referenceBytes)))) { "orchestration contract does not bind the independent reference bytes" }
        val policySource = provenance.obj("policySource")
        policySource.fields("path", "bytes", "sha256")
        require(policySource.text("path") == "scripts/capture-gcc-preprocessing-reference.py" && policySource.integer("bytes") in 1L..MAXIMUM_BYTES.toLong())
        policySource.digest("sha256")
        val probe = provenance.obj("runtimeProbe")
        probe.fields("path", "sha256")
        require(probe.text("path") == "oracle/gcc/reference_runtime_probe.py")
        probe.digest("sha256")
        provenance.obj("source").fields("id", "version", "sourceRevision")
        for (name in listOf("driverManifest", "frontendManifest")) {
            val manifest = provenance.obj(name)
            manifest.fields("path", "bytes", "sha256", "inputs")
            manifest.digest("sha256")
            manifest.obj("inputs").fields("sourceLock", "buildRecord")
            for (input in manifest.obj("inputs").values) input.objectValue().also {
                it.fields("path", "bytes", "sha256"); it.digest("sha256"); require(it.integer("bytes") > 0)
            }
        }
        require(probe == reference.obj("referenceInvocationPolicy").obj("runtimeProbe"))
        val toolchain = reference.obj("toolchain")
        require(contract.obj("runtime") == JsonObject(listOf("image", "imageConfig", "platform", "sandbox").associateWith { toolchain.getValue(it) }))
        require(contract.obj("driver") == toolchain.obj("driver") && contract.obj("driver").text("path") == DRIVER)
        val tools = contract.obj("phaseTools")
        tools.fields("assemble", "compile", "link", "linkEditor", "ltoPlugin", "ltoWrapper")
        val toolFields = mapOf(
            "assemble" to listOf("invokedAs", "lookup", "path", "resolvedPath", "role", "sha256", "version"),
            "compile" to listOf("bytes", "path", "resolvedPath", "role", "sha256", "source"),
            "link" to listOf("path", "resolvedPath", "role", "sha256"),
            "linkEditor" to listOf("invokedBy", "lookup", "path", "resolvedPath", "role", "sha256", "version"),
            "ltoPlugin" to listOf("loadedBy", "path", "resolvedPath", "role", "sha256"),
            "ltoWrapper" to listOf("path", "resolvedPath", "role", "sha256"))
        toolFields.forEach { (role, fields) -> tools.obj(role).fields(*fields.toTypedArray()) }
        contract.obj("driver").fields("path", "bytes", "sha256")
        require(tools == toolchain.obj("phaseTools"))
        val closures = contract.obj("phaseStartupDependencies")
        require(closures == toolchain.obj("runtimeClosure"))
        val toolIdentities = tools.values.map { it.objectValue() } + contract.obj("driver")
        require(closures.keys == toolIdentities.map { it.text("path") }.toSet() && closures.size == 7)
        val runtimeFiles = linkedMapOf<String, ReferenceRuntimeFileBinding>()
        fun file(value: JsonObject) {
            val binding = ReferenceRuntimeFileBinding(value.text("path"), value.text("resolvedPath"), value.integer("bytes"), value.digest("sha256"))
            require(binding.bytes in 1..1024L * 1024 * 1024)
            val previous = runtimeFiles.putIfAbsent(binding.path, binding)
            require(previous == null || previous == binding) { "startup closures disagree on a runtime file identity" }
        }
        toolIdentities.forEach { identity -> validateClosure(closures.obj(identity.text("path")), identity, true, ::file) }
        val policy = contract.obj("invocationPolicy")
        policy.fields("argumentEquivalence", "caseOrder", "mode", "temporaryNames", "undeclaredCaseOrArgument")
        require(policy.text("mode") == "closed" && policy.text("undeclaredCaseOrArgument") == "reject" &&
            policy.obj("argumentEquivalence") == argumentEquivalence && policy.strings("caseOrder") == caseIds)
        require(policy.obj("temporaryNames") == reference.obj("normalizations").obj("temporary-file-names"))
        require(policy.obj("temporaryNames").text("pattern") == "/tmp/cc[A-Za-z0-9]{6}(\\.[A-Za-z0-9]+)?")
        val declaredCases = contract.array("cases").map { it.objectValue() }
        val observedCases = reference.array("cases").map { it.objectValue() }
        require(declaredCases.map { it.text("id") } == caseIds && observedCases.map { it.text("id") } == caseIds)
        declaredCases.zip(observedCases).forEach { (declared, observed) ->
            val id = declared.text("id")
            declared.fields(*(listOf("driverInvocation", "id", "phaseInvocations", "referenceObservationSha256") +
                if (id in producedCases) listOf("producedProgram") else emptyList()).toTypedArray())
            observed.fields("id", "categories", "arguments", "environment", "inputs", "observed", "repetitions", "normalizations")
            require(observed.integer("repetitions") == 2L && observed.strings("normalizations") == listOf("temporary-file-names"))
            require(observed.obj("environment") == driverEnvironment)
            val driverArguments = observed.strings("arguments")
            require(driverArguments.size in 1..512 && driverArguments.all { it.length <= 4096 && '\u0000' !in it })
            val inputs = observed.array("inputs").map { it.objectValue().also { input ->
                input.fields("path", "bytes", "sha256")
                val path = input.text("path")
                require(path.matches(Regex("[A-Za-z0-9_.-]{1,128}")) && path != "." && path != ".." && input.integer("bytes") in 1L..MAXIMUM_BYTES.toLong())
                input.digest("sha256")
            } }
            require(inputs.map { it.text("path") }.distinct().size == inputs.size && inputs.size in 1..16)
            require(declared.obj("driverInvocation") == JsonObject(mapOf("argv" to JsonArray((listOf(DRIVER) + driverArguments).map(::JsonPrimitive)),
                "cwd" to JsonPrimitive("/w"), "environment" to driverEnvironment, "inputs" to observed.getValue("inputs"))))
            val observation = observed.obj("observed")
            observation.fields(*(listOf("plan", "executedPhases", "execution") + if (id in producedCases) listOf("programBehavior") else emptyList()).toTypedArray())
            require(declared.digest("referenceObservationSha256") == OracleArtifacts.sha256(OracleJson.canonicalBytes(observation, limits)))
            val plan = observation.obj("plan")
            plan.fields("exitCode", "stderr", "phases")
            require(plan.integer("exitCode") == 0L)
            val trace = observation.obj("executedPhases")
            trace.fields("source", "exitCode", "stderrSha256", "stderr", "phases")
            val execution = observation.obj("execution")
            execution.fields("exitCode", "stdout", "stderr", "artifacts")
            require(execution.integer("exitCode") in 0L..255L)
            require(trace.integer("exitCode") == execution.integer("exitCode"))
            val failed = execution.integer("exitCode") != 0L
            require(failed == id.startsWith("failure-"))
            val planned = plan.array("phases").map { it.objectValue() }
            val traced = trace.array("phases").map { it.objectValue() }
            require(planned == parsePhases(blob(plan.obj("stderr")), tools, true))
            require(traced == parsePhases(blob(trace.obj("stderr")), tools, false))
            require(trace.digest("stderrSha256") == trace.obj("stderr").digest("sha256"))
            validatePhases(planned, traced, tools, failed)
            fun annotated(rows: List<JsonObject>) = JsonArray(rows.mapIndexed { index, phase ->
                JsonObject(phase + mapOf("index" to JsonPrimitive(index), "toolSha256" to phaseTool(phase, tools).getValue("sha256")))
            })
            require(declared.obj("phaseInvocations") == JsonObject(mapOf("planned" to annotated(planned), "verbose" to annotated(traced))))
            blob(execution.obj("stdout")); blob(execution.obj("stderr"))
            val artifacts = execution.array("artifacts").map { it.objectValue().also { artifact ->
                artifact.fields("path", "bytes", "sha256", "base64", "text")
                require(artifact.text("path").matches(Regex("[A-Za-z0-9_.-]{1,128}")) && artifact.text("path") !in listOf(".", ".."))
                blob(artifact, true)
            } }
            require(artifacts.map { it.text("path") }.distinct().size == artifacts.size)
            if (id in producedCases) {
                val produced = observation.obj("programBehavior")
                produced.fields("program", "invocation", "runtime", "exitCode", "stdout", "stderr")
                require(produced.integer("exitCode") in 0L..255L)
                val name = produced.text("program")
                require(name == if (id == "link-default-output") "a.out" else "prog")
                val artifact = artifacts.single { it.text("path") == name }
                val programPath = "/w/$name"
                require(produced.obj("invocation") == JsonObject(mapOf("argv" to JsonArray(listOf(JsonPrimitive(programPath))),
                    "cwd" to JsonPrimitive("/w"), "environment" to programEnvironment)))
                validateClosure(produced.obj("runtime"), fileIdentity(programPath, artifact.integer("bytes"), artifact.digest("sha256")), false, ::file)
                blob(produced.obj("stdout")); blob(produced.obj("stderr"))
                require(declared.obj("producedProgram") == JsonObject(mapOf("invocation" to produced.getValue("invocation"),
                    "startupDependencies" to produced.getValue("runtime"), "exitCode" to produced.getValue("exitCode"),
                    "stdoutSha256" to produced.obj("stdout").getValue("sha256"), "stderrSha256" to produced.obj("stderr").getValue("sha256"))))
            }
        }
        return Description(contract, runtimeFiles.values.sortedBy { it.path })
    }

    private fun validateClosure(closure: JsonObject, identity: JsonObject, includeElf: Boolean, consume: (JsonObject) -> Unit) {
        closure.fields("elf", "interpreter", "kernelObjects", "libraries", "needed")
        val elf = closure.obj("elf")
        elf.fields("path", "resolvedPath", "bytes", "sha256")
        require(elf.text("path") == identity.text("path") && elf.digest("sha256") == identity.digest("sha256"))
        require(elf.getValue("resolvedPath") == (identity["resolvedPath"] ?: identity.getValue("path")))
        identity["bytes"]?.let { require(elf.getValue("bytes") == it) }
        require(elf.integer("bytes") > 0)
        if (includeElf) consume(elf)
        val libraries = closure.array("libraries").map { it.objectValue().also { library ->
            library.fields("bytes", "name", "path", "resolvedPath", "sha256")
            require(library.text("name").matches(Regex("[A-Za-z0-9_.+-]{1,256}")))
            consume(library)
        } }
        val names = libraries.map { it.text("name") }
        require(names.distinct().size == names.size && closure.strings("needed").all { it in names })
        require(closure.strings("kernelObjects") == listOf("linux-vdso.so.1"))
        if (closure.getValue("interpreter") != JsonNull) closure.obj("interpreter").also {
            it.fields("path", "resolvedPath", "bytes", "sha256"); consume(it)
        }
    }

    internal fun validatePhases(planned: List<JsonObject>, traced: List<JsonObject>, tools: JsonObject, failed: Boolean) {
        require(planned.isNotEmpty() && traced.isNotEmpty() && planned.size <= 64 && traced.size <= planned.size)
        require(failed || planned.size == traced.size) { "successful reference omits a declared phase" }
        (planned + traced).forEach { phaseTool(it, tools) }
        planned.zip(traced).forEach { (expected, actual) ->
            require(listOf("phase", "tool", "stdoutPipedToNextPhase").all { expected[it] == actual[it] })
            val argv = expected.strings("argv").toMutableList()
            when (expected.text("phase")) {
                "assemble" -> argv.add(1, "-v")
                "compile", "preprocess" -> {
                    if ("-fpreprocessed" !in argv) { val quiet = argv.indexOf("-quiet"); require(quiet >= 0); argv.add(quiet + 1, "-v") }
                    if (expected.text("phase") == "compile") { val output = argv.indexOf("-o"); require(output >= 0); argv.add(output, "-version") }
                }
                "link" -> Unit
                else -> error("undeclared phase")
            }
            require(actual.strings("argv") == argv) { "phase arguments differ outside closed positional verbosity additions" }
        }
    }

    private fun phaseTool(phase: JsonObject, tools: JsonObject): JsonObject {
        phase.fields("phase", "tool", "argv", "stdoutPipedToNextPhase")
        val role = when (phase.text("phase")) { "compile", "preprocess" -> "compile"; "assemble" -> "assemble"; "link" -> "link"; else -> error("undeclared phase role") }
        val identity = tools.obj(role)
        val argv = phase.strings("argv")
        require(argv.isNotEmpty() && argv.size <= 512 && argv.all { it.length <= 4096 && '\u0000' !in it })
        require(phase.text("tool") == argv[0] && argv[0] in listOfNotNull(identity.text("path"), identity["invokedAs"]?.stringValue()))
        require((phase.getValue("stdoutPipedToNextPhase") as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull != null)
        return identity
    }

    private fun parsePhases(bytes: ByteArray, tools: JsonObject, strict: Boolean): List<JsonObject> {
        val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        val known = linkedMapOf<String, String>()
        listOf("compile", "assemble", "link").forEach { role -> val tool = tools.obj(role); known[tool.text("path")] = role; tool["invokedAs"]?.let { known[it.stringValue()] = role } }
        return text.lineSequence().filter { it.startsWith(' ') && it.isNotBlank() }.mapNotNull { line ->
            val piped = line.endsWith(" |")
            val argv = try { shellWords(if (piped) line.dropLast(2) else line) } catch (failure: IllegalArgumentException) { if (strict) throw failure else return@mapNotNull null }
            val role = argv.firstOrNull()?.let(known::get)
            if (role == null) { require(!strict) { "undeclared command in reference plan" }; return@mapNotNull null }
            JsonObject(mapOf("phase" to JsonPrimitive(if (role == "compile" && "-E" in argv) "preprocess" else role),
                "tool" to JsonPrimitive(argv[0]), "argv" to JsonArray(argv.map(::JsonPrimitive)), "stdoutPipedToNextPhase" to JsonPrimitive(piped)))
        }.toList()
    }

    /** POSIX word decoding of retained text only: no expansion, evaluation or process launch. */
    internal fun shellWords(line: String): List<String> {
        val words = ArrayList<String>(); val word = StringBuilder(); var quote: Char? = null; var started = false; var index = 0
        while (index < line.length) {
            val c = line[index++]
            when {
                quote == '\'' -> if (c == '\'') quote = null else word.append(c)
                c == '\\' -> {
                    require(index < line.length) { "unfinished retained command escape" }
                    val next = line[index++]
                    if (quote == '"' && next !in listOf('$', '`', '"', '\\', '\n')) word.append('\\')
                    if (next != '\n') word.append(next)
                    started = true
                }
                quote == '"' -> if (c == '"') quote = null else word.append(c)
                c == '\'' || c == '"' -> { quote = c; started = true }
                c in " \t\r\n" -> if (started) { words += word.toString(); word.setLength(0); started = false }
                else -> { word.append(c); started = true }
            }
        }
        require(quote == null) { "unfinished retained command quote" }
        if (started) words += word.toString()
        return words
    }

    private fun blob(value: JsonObject, artifact: Boolean = false): ByteArray {
        value.fields(*(listOf("base64", "bytes", "sha256", "text") + if (artifact) listOf("path") else emptyList()).toTypedArray())
        val encoded = value.text("base64")
        val bytes = Base64.getDecoder().decode(encoded)
        require(Base64.getEncoder().encodeToString(bytes) == encoded && bytes.size.toLong() == value.integer("bytes") &&
            OracleArtifacts.sha256(bytes) == value.digest("sha256")) { "recorded bytes differ from their declared identity" }
        value.text("text") // Advisory display is retained by the independently fixed reference, never compared as raw bytes.
        return bytes
    }

    private fun fileIdentity(path: String, bytes: Long, sha256: String) = JsonObject(mapOf("path" to JsonPrimitive(path), "bytes" to JsonPrimitive(bytes), "sha256" to JsonPrimitive(sha256)))
    private fun strings(values: Map<String, String>) = JsonObject(values.mapValues { JsonPrimitive(it.value) })
    private fun JsonElement.objectValue() = this as? JsonObject ?: error("orchestration field must be an object")
    private fun JsonElement.stringValue() = (this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("orchestration field must be a string")
    private fun JsonObject.obj(key: String) = getValue(key).objectValue()
    private fun JsonObject.array(key: String) = getValue(key) as? JsonArray ?: error("orchestration field must be an array")
    private fun JsonObject.text(key: String) = getValue(key).stringValue()
    private fun JsonObject.integer(key: String) = (getValue(key) as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull ?: error("orchestration field must be an integer")
    private fun JsonObject.strings(key: String) = array(key).map { it.stringValue() }
    private fun JsonObject.digest(key: String) = text(key).also { require(it.matches(Regex("[0-9a-f]{64}"))) { "orchestration digest is invalid" } }
    private fun JsonObject.fields(vararg expected: String) { require(keys == expected.toSet()) { "orchestration fields differ from the closed schema" } }
}

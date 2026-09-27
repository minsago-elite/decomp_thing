package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFactLimits
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFactScanner
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFacts
import decompengine.oracle.fulltree.DwarfInterfaceFactState
import decompengine.oracle.fulltree.DwarfInterfaceFunctionFacts
import decompengine.oracle.fulltree.FullTreeControlLimits
import decompengine.oracle.fulltree.FullTreeElfCoreLayout
import decompengine.oracle.fulltree.FullTreeElfExecutableRange
import decompengine.oracle.fulltree.FullTreeElfLayout
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** A bounded evidence publication, not an ABI oracle, scored model, or release capability. */
internal class GccDriverDwarfInterfaceArtifact internal constructor(bytes: ByteArray) {
    private val encoded = bytes.copyOf()
    val sha256: String = gccInterfaceSha256(encoded)
    fun canonicalBytes(): ByteArray = encoded.copyOf()
}

/** Checked driver truth inputs are deliberately independent of compiler-engine runtime profiles. */
internal object GccDriverDwarfInterfaceEvidence {
    const val EVIDENCE_NAME = "evidence.json"
    const val QUALIFICATION_NAME = "qualification.json"
    const val MAXIMUM_EVIDENCE_BYTES = 64 * 1024 * 1024
    private const val PREFIX = "oracle/gcc/16.2.0/"
    private const val ORACLE_ID = "gcc-driver-16.2.0"
    private const val SOURCE_REVISION = "78d4ac73dd391005b895a6148cd9831e28e1208b"
    private const val FULL_SHA256 = "8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b"
    private const val STRIPPED_SHA256 = "3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4"
    private val EXECUTABLE_RANGES = listOf(FullTreeElfExecutableRange(0x3000UL, 0x10eac9UL))
    private val CONTROL_JSON_LIMITS = StrictJsonLimits(
        maximumInputBytes = 16 * 1024 * 1024, maximumCanonicalBytes = 16 * 1024 * 1024,
        maximumNodes = 1_000_000, maximumTotalStringBytes = 16 * 1024 * 1024,
    )
    internal val EVIDENCE_JSON_LIMITS = StrictJsonLimits(
        maximumInputBytes = MAXIMUM_EVIDENCE_BYTES, maximumCanonicalBytes = MAXIMUM_EVIDENCE_BYTES,
        maximumNodes = 1_000_000, maximumTotalStringBytes = MAXIMUM_EVIDENCE_BYTES,
    )
    private val SCAN_LIMITS = BoundedDwarfInterfaceFactLimits(maximumArtifactBytes = 20_713_760)
    private val CONTROL_LIMITS = FullTreeControlLimits(
        maximumRichArtifactBytes = 20_713_760,
        maximumDwarfSectionBytes = 32L * 1024 * 1024,
        maximumDwarfScratchBytes = 64L * 1024 * 1024,
        maximumDwarfMetadataBytes = 64L * 1024 * 1024,
        maximumDwarfAttributeBytes = 1024 * 1024,
        maximumDwarfParseSteps = 100_000_000,
        maximumCompilationUnits = 10_000,
    )
    private data class Pin(val path: String, val bytes: Long, val sha256: String)
    private val controls = linkedMapOf(
        "targetAbi" to Pin("oracle/targets/sysv-amd64-v1.json", 901,
            "d251d5e6a0edc17655c355fb8fd757d557f064a6e67095ad53c8ca1e7569a343"),
        "sourceLock" to Pin(PREFIX + "source-lock.json", 3_953,
            "e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc"),
        "buildRecord" to Pin(PREFIX + "build-record.json", 3_910,
            "f91a68ffde054b9598cba8506bbf6b3b373b35b8680fddb54f76bffa9db23637"),
        "toolchainReproduction" to Pin(PREFIX + "toolchain-reproduction.json", 1_568,
            "5c2c159d7287305159a220a1260f6ff6bffe9ec78bb1cbe2fb24f85b68a7d4de"),
        "toolchainRecipe" to Pin(PREFIX + "build-toolchain.Dockerfile", 3_345,
            "8b0af79ba3426f49ba599eb0c7eea433c62ac5bb6ab5e7797f7d09d978f43543"),
        "artifactManifest" to Pin(PREFIX + "oracle-manifest.json", 60_269,
            "c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9"),
        "functionOracle" to Pin(PREFIX + "function-recovery-oracle.json", 12_558_460,
            "b49b8a72a96580bd8727d9dc530753f40f78185a656f472ebe83a7a1f6fc9aae"),
        "reviewedExclusions" to Pin(PREFIX + "function-recovery-exclusions.json", 21_251,
            "71039d9d5462c54b920d3ebe2cd2aff855faf211389a4e86bab3158bca742031"),
    )
    private val artifacts = linkedMapOf(
        "rich" to Pin(PREFIX + "artifacts/gcc-driver.full", 20_713_760, FULL_SHA256),
        "stripped" to Pin(PREFIX + "artifacts/gcc-driver.stripped", 2_349_296, STRIPPED_SHA256),
    )

    fun capture(
        repositoryRoot: Path,
        scratchParent: Path,
        checkpoint: (String) -> Unit = {},
    ): GccDriverDwarfInterfaceArtifact {
        val root = repositoryRoot.toAbsolutePath().normalize()
        val scratch = scratchParent.toAbsolutePath().normalize()
        require(root.toRealPath() == root && scratch.toRealPath() == scratch) { "GCC interface paths contain indirection" }
        require(scratch.startsWith(root) && scratch != root) { "GCC interface scratch must be inside the repository" }
        require((controls.values + artifacts.values).none { pin ->
            val input = root.resolve(pin.path)
            input.startsWith(scratch) || scratch.startsWith(input)
        }) { "GCC interface scratch overlaps a retained input" }
        val guards = linkedMapOf<String, StableControlFile>()
        var failure: Throwable? = null
        try {
            fun retain(role: String, pin: Pin): StableControlFile =
                StableControlFile.openWithCheckpoint(root.resolve(pin.path), pin.bytes, "GCC driver $role", checkpoint).also { guard ->
                    guards[role] = guard
                    require(guard.size == pin.bytes && guard.authenticatedSha256 == pin.sha256) {
                        "GCC driver $role differs from its checked identity"
                    }
                    guard.verifyUnchanged("checked GCC driver $role")
                }
            val documents = controls.mapNotNull { (role, pin) ->
                val guard = retain(role, pin)
                if (role == "toolchainRecipe") null else {
                    val bytes = guard.readExactly(0, guard.size.toInt(), "GCC driver $role")
                    require(gccInterfaceSha256(bytes) == pin.sha256) { "GCC driver $role changed while reading" }
                    role to OracleJson.parse(bytes, CONTROL_JSON_LIMITS).jsonObject
                }
            }.toMap()
            validateControls(documents)
            val layouts = artifacts.mapValues { (role, pin) ->
                val guard = retain(role, pin)
                FullTreeElfLayout.scanLayout(guard, "checked GCC driver $role", checkpoint = checkpoint).also(::validateLayout)
            }
            require(layouts.getValue("rich") == layouts.getValue("stripped")) {
                "checked GCC driver twins have different executable layouts"
            }
            checkpoint("before scanning checked GCC driver interfaces")
            guards.forEach { (role, guard) -> guard.verifyUnchanged("before GCC driver interface scan: $role") }
            val facts = BoundedDwarfInterfaceFactScanner.scan(
                guards.getValue("rich"), scratch, CONTROL_LIMITS, SCAN_LIMITS, checkpoint,
            )
            require(facts.inputSha256 == FULL_SHA256 && facts.inputBytes == artifacts.getValue("rich").bytes &&
                facts.elfType == "ET_EXEC" && facts.imageBase == 0x400000UL &&
                facts.executableRanges == EXECUTABLE_RANGES && facts.dwarfPresent && facts.functions.isNotEmpty()) {
                "GCC driver interface facts differ from the retained rich artifact"
            }
            val document = publication(documents, facts)
            val bytes = OracleJson.canonicalBytes(document, EVIDENCE_JSON_LIMITS)
            checkpoint("before publishing checked GCC driver interfaces")
            guards.forEach { (role, guard) -> guard.verifyUnchanged("after GCC driver interface publication: $role") }
            return GccDriverDwarfInterfaceArtifact(bytes)
        } catch (caught: Throwable) {
            failure = caught
            throw caught
        } finally {
            var closeFailure: Throwable? = null
            guards.values.toList().asReversed().forEach { guard ->
                try { guard.close() } catch (caught: Throwable) {
                    if (closeFailure == null) closeFailure = caught else if (closeFailure !== caught) closeFailure!!.addSuppressed(caught)
                }
            }
            closeFailure?.let { caught ->
                if (failure == null) throw caught
                if (failure !== caught) failure.addSuppressed(caught)
            }
        }
    }

    private fun validateLayout(layout: FullTreeElfCoreLayout) {
        require(layout.elfClass == 2 && layout.byteOrder == 1 && layout.elfType == "ET_EXEC" &&
            layout.machine == 62 && layout.osAbi == 3 && layout.abiVersion == 0 &&
            layout.imageBase == 0x400000UL && layout.executableRanges == EXECUTABLE_RANGES) {
            "GCC driver ELF identity or executable ranges differ from the checked target"
        }
    }

    private fun validateControls(documents: Map<String, JsonObject>) {
        val target = documents.getValue("targetAbi")
        require(target.text("id") == "sysv-amd64-elf-v1" && target.obj("target").let {
            it.text("architecture") == "x86_64" && it.text("endianness") == "little" &&
                it.getValue("addressBits") == JsonPrimitive(64) && it.text("objectFormat") == "ELF"
        }) { "GCC driver target ABI differs from its ELF target" }
        val source = documents.getValue("sourceLock")
        val build = documents.getValue("buildRecord")
        val manifest = documents.getValue("artifactManifest")
        val toolchain = documents.getValue("toolchainReproduction")
        val oracle = documents.getValue("functionOracle")
        val exclusions = documents.getValue("reviewedExclusions")
        require(listOf(source, build, manifest).all { it.obj("oracle").text("id") == ORACLE_ID } &&
            source.obj("revision").text("commit") == SOURCE_REVISION &&
            build.obj("oracle").text("sourceRevision") == SOURCE_REVISION &&
            manifest.obj("oracle").text("sourceRevision") == SOURCE_REVISION &&
            build.obj("oracle").text("sourceLockSha256") == controls.getValue("sourceLock").sha256) {
            "GCC driver source and build controls disagree"
        }
        for (role in listOf("sourceLock", "buildRecord")) {
            val retained = controls.getValue(role)
            val input = manifest.obj("inputs").obj(role)
            require(input.text("path") == retained.path.removePrefix(PREFIX) &&
                input.text("sha256") == retained.sha256 && input.getValue("bytes") == JsonPrimitive(retained.bytes)) {
                "GCC driver manifest does not bind $role"
            }
        }
        require(toolchain.obj("recordedOrigin").text("buildRecordSha256") == controls.getValue("buildRecord").sha256 &&
            toolchain.obj("recordedOrigin").text("imageDigest") == build.obj("environment").obj("container").text("digest") &&
            toolchain.obj("recipe").text("dockerfileSha256") == controls.getValue("toolchainRecipe").sha256 &&
            toolchain.obj("recipe").text("dockerfile") == "build-toolchain.Dockerfile") {
            "GCC driver toolchain controls disagree"
        }
        require(oracle.text("scope") == "production" && oracle.obj("oracle").text("id") == ORACLE_ID &&
            oracle.obj("oracle").text("artifactManifestSha256") == controls.getValue("artifactManifest").sha256 &&
            exclusions.text("richArtifactSha256") == FULL_SHA256) { "GCC driver function controls disagree" }
        for ((role, pin) in artifacts) {
            val manifestRole = if (role == "rich") "full" else role
            val artifact = manifest.obj("artifacts").obj(manifestRole)
            val functionArtifact = oracle.obj("artifacts").obj(role)
            require(artifact.text("sha256") == pin.sha256 && artifact.getValue("bytes") == JsonPrimitive(pin.bytes) &&
                artifact.text("path") == pin.path.removePrefix(PREFIX) &&
                build.obj("outputs").text(manifestRole) == pin.path.removePrefix(PREFIX) &&
                functionArtifact.text("inputSha256") == pin.sha256 && functionArtifact.text("elfType") == "ET_EXEC" &&
                functionArtifact.text("elfImageBase") == "0x400000" &&
                functionArtifact.getValue("executableRvaRanges") == rangeJson()) { "GCC driver $role controls disagree" }
        }
        val functions = oracle.getValue("functions").jsonArray.map { it.jsonObject }
        require(functions.size == 12_844 && functions.map { it.text("id") }.distinct().size == functions.size &&
            functions.count { it.getValue("exclusion") == JsonNull } == 3_284 &&
            functions.count { it.getValue("rva") == JsonNull } == 9_420) { "GCC driver function denominator drifted" }
        val physicalExclusions = functions.filter { it.getValue("rva") != JsonNull && it.getValue("exclusion") != JsonNull }
        val reviewed = exclusions.getValue("exclusions").jsonArray.map { it.jsonObject }
        require(physicalExclusions.size == 140 && reviewed.size == 140 &&
            physicalExclusions.associate { it.text("rva") to it.obj("exclusion").text("reason") } ==
            reviewed.associate { it.text("rva") to it.text("reason") }) { "GCC driver reviewed exclusions drifted" }
    }

    private fun publication(documents: Map<String, JsonObject>, facts: BoundedDwarfInterfaceFacts): JsonObject {
        val mapping = mapFunctions(documents.getValue("functionOracle").getValue("functions").jsonArray, facts.functions)
        return JsonObject(linkedMapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("gcc-driver-dwarf-interface-evidence-v1"),
            "oracleId" to JsonPrimitive(ORACLE_ID),
            "sourceRevision" to JsonPrimitive(SOURCE_REVISION),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "productionVerified" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "configuration" to JsonObject(mapOf(
                "mapping" to JsonPrimitive("exact-executable-rich-rva-only"),
                "nameMatching" to JsonPrimitive(false),
                "abiNormalization" to JsonPrimitive("not-implemented"),
                "globalFacts" to JsonPrimitive("not-produced"),
                "maximumEvidenceBytes" to JsonPrimitive(MAXIMUM_EVIDENCE_BYTES),
                "scanner" to JsonPrimitive(BoundedDwarfInterfaceFactScanner.PRODUCER),
                "scannerLimits" to SCAN_LIMITS.toJson(),
                "controlLimits" to JsonObject(mapOf(
                    "maximumRichArtifactBytes" to JsonPrimitive(CONTROL_LIMITS.maximumRichArtifactBytes),
                    "maximumDwarfSectionBytes" to JsonPrimitive(CONTROL_LIMITS.maximumDwarfSectionBytes),
                    "maximumDwarfScratchBytes" to JsonPrimitive(CONTROL_LIMITS.maximumDwarfScratchBytes),
                    "maximumDwarfMetadataBytes" to JsonPrimitive(CONTROL_LIMITS.maximumDwarfMetadataBytes),
                    "maximumDwarfAttributeBytes" to JsonPrimitive(CONTROL_LIMITS.maximumDwarfAttributeBytes),
                    "maximumDwarfParseSteps" to JsonPrimitive(CONTROL_LIMITS.maximumDwarfParseSteps),
                    "maximumCompilationUnits" to JsonPrimitive(CONTROL_LIMITS.maximumCompilationUnits),
                    "maximumAbbreviationDeclarationsPerUnit" to JsonPrimitive(CONTROL_LIMITS.maximumAbbreviationDeclarationsPerUnit),
                    "maximumAbbreviationAttributesPerUnit" to JsonPrimitive(CONTROL_LIMITS.maximumAbbreviationAttributesPerUnit),
                )),
            )),
            "inputs" to JsonObject((controls + artifacts).mapValues { (_, pin) -> JsonObject(mapOf(
                "path" to JsonPrimitive(pin.path), "bytes" to JsonPrimitive(pin.bytes), "sha256" to JsonPrimitive(pin.sha256),
            )) }),
            "targetAbi" to documents.getValue("targetAbi"),
            "coverage" to mapping.getValue("coverage"),
            "functions" to mapping.getValue("functions"),
            "unmatchedRawCandidateDieLocators" to mapping.getValue("unmatchedRawCandidateDieLocators"),
            "reviewedExclusions" to documents.getValue("reviewedExclusions"),
            "rawDwarfFacts" to facts.toJson(),
            "unresolved" to JsonArray(listOf(
                "raw-DWARF-source-facts-are-not-normalized-ABI-signatures",
                "absent-attributes-do-not-establish-void-types-or-default-calling-conventions",
                "global-ABI-denominator-and-scoring-remain-outstanding",
                "no-candidate-comparison-or-release-qualification",
            ).map(::JsonPrimitive)),
        ))
    }

    /** Pure projection for fixture checks; this cannot mint an authenticated publication. */
    internal fun mapFunctions(oracleFunctions: JsonArray, facts: List<DwarfInterfaceFunctionFacts>): JsonObject {
        val byRva = facts.filter { it.executable && it.rva != null }.groupBy { requireNotNull(it.rva) }
        val matched = hashSetOf<String>()
        var scored = 0
        var excluded = 0
        var missing = 0
        var ambiguous = 0
        var unique = 0
        var knownReturn = 0
        var knownParameters = 0
        var knownConvention = 0
        var knownVariadic = 0
        val records = oracleFunctions.map { item ->
            val function = item.jsonObject
            val rva = function.getValue("rva").takeUnless { it == JsonNull }?.jsonPrimitive?.content
                ?.removePrefix("0x")?.toULong(16)
            val candidates = rva?.let { byRva[it].orEmpty() }.orEmpty().sortedBy { it.locator }
            val ids = candidates.map { it.locator }
            require(ids.distinct().size == ids.size) { "raw GCC interface candidates repeat a DIE at one RVA" }
            matched += ids
            val isExcluded = function.getValue("exclusion") != JsonNull
            if (isExcluded) excluded++ else {
                require(rva != null) { "scored GCC function lacks a physical RVA" }
                scored++
                when (candidates.size) {
                    0 -> missing++
                    1 -> {
                        unique++
                        val candidate = candidates.single()
                        if (candidate.returnType.state == DwarfInterfaceFactState.KNOWN) knownReturn++
                        if (candidate.parameterList.state == DwarfInterfaceFactState.KNOWN) knownParameters++
                        if (candidate.callingConvention.state == DwarfInterfaceFactState.KNOWN) knownConvention++
                        if (candidate.variadic.state == DwarfInterfaceFactState.KNOWN) knownVariadic++
                    }
                    else -> ambiguous++
                }
            }
            JsonObject(function + mapOf(
                "candidateDieLocators" to JsonArray(ids.map(::JsonPrimitive)),
                "dwarfMatch" to JsonPrimitive(when {
                    rva == null -> "no-physical-rva"
                    candidates.isEmpty() -> "missing-dwarf"
                    candidates.size > 1 -> "ambiguous-dwarf-candidates"
                    else -> "unique-raw-dwarf-candidate"
                }),
                "normalizedAbiSignature" to JsonNull,
                "abiStatus" to JsonPrimitive(if (isExcluded) "excluded" else "unresolved"),
            ))
        }
        require(scored == missing + ambiguous + unique) { "GCC interface coverage lost a scored function" }
        return JsonObject(mapOf(
            "coverage" to JsonObject(mapOf(
                "oracleRecords" to JsonPrimitive(records.size), "scoredPhysicalFunctions" to JsonPrimitive(scored),
                "excludedRecords" to JsonPrimitive(excluded), "missingDwarfFunctions" to JsonPrimitive(missing),
                "ambiguousDwarfFunctions" to JsonPrimitive(ambiguous), "uniqueRawDwarfFunctions" to JsonPrimitive(unique),
                "addressMatchedDwarfFunctions" to JsonPrimitive(unique + ambiguous),
                "uniqueWithKnownRawReturnType" to JsonPrimitive(knownReturn),
                "uniqueWithKnownRawParameterList" to JsonPrimitive(knownParameters),
                "uniqueWithKnownRawCallingConvention" to JsonPrimitive(knownConvention),
                "uniqueWithKnownRawVariadicFact" to JsonPrimitive(knownVariadic),
                "fullyNormalizedAbiSignatures" to JsonPrimitive(0),
            )),
            "functions" to JsonArray(records),
            "unmatchedRawCandidateDieLocators" to JsonArray(facts.map { it.locator }.distinct().filterNot(matched::contains)
                .sorted().map(::JsonPrimitive)),
        ))
    }

    private fun rangeJson() = JsonArray(EXECUTABLE_RANGES.map { JsonObject(mapOf(
        "start" to JsonPrimitive("0x${it.start.toString(16)}"),
        "endExclusive" to JsonPrimitive("0x${it.endExclusive.toString(16)}"),
    )) })
    private fun JsonObject.text(name: String) = getValue(name).jsonPrimitive.content
    private fun JsonObject.obj(name: String) = getValue(name).jsonObject
}

private fun gccInterfaceSha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(bytes).joinToString("") { "%02x".format(it) }

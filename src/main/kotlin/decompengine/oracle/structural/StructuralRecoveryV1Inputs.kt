package decompengine.oracle.structural

import java.math.BigInteger
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

object StructuralRecoveryV1Inputs {
    fun loadTargetAbi(
        path: Path,
        limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits(),
    ): StructuralTargetAbiV1 {
        val (snapshot, root) = readStructuralDocument(path, "target ABI descriptor", "target-abi", limits)
        root.requireObject(
            "target ABI descriptor",
            setOf("schemaVersion", "id", "target", "callingConventions", "abiClasses", "scalarWidthsBits"),
        )
        requireSchemaVersion(root, "target ABI descriptor")
        val id = root.field("id", "target ABI descriptor")
            .requireIdentifier("target ABI descriptor.id", limits)
        val target = root.field("target", "target ABI descriptor").requireObject(
            "target ABI descriptor.target",
            setOf("architecture", "endianness", "addressBits", "objectFormat"),
        )
        target.field("architecture", "target ABI descriptor.target")
            .requireIdentifier("target ABI descriptor.target.architecture", limits)
        val endianness = target.field("endianness", "target ABI descriptor.target")
            .requireString("target ABI descriptor.target.endianness", 128)
        if (endianness !in setOf("little", "big")) structuralFail("target ABI descriptor endianness is invalid")
        val addressBits = target.field("addressBits", "target ABI descriptor.target")
            .requireInt("target ABI descriptor.target.addressBits", 8, 64)
        val objectFormat = target.field("objectFormat", "target ABI descriptor.target")
            .requireIdentifier("target ABI descriptor.target.objectFormat", limits)

        val classes = linkedSetOf<String>()
        root.field("abiClasses", "target ABI descriptor")
            .requireArray("target ABI descriptor.abiClasses", limits.maximumAbiClasses, 1)
            .forEachIndexed { index, raw ->
                val name = raw.requireString("target ABI descriptor.abiClasses[$index]", 128)
                if (!classes.add(name)) structuralFail("duplicate ABI class: $name")
            }

        val conventions = linkedSetOf<String>()
        val aliases = linkedMapOf<String, String>()
        root.field("callingConventions", "target ABI descriptor").requireArray(
            "target ABI descriptor.callingConventions",
            limits.maximumCallingConventions,
            1,
        ).forEachIndexed { index, raw ->
            val itemPath = "target ABI descriptor.callingConventions[$index]"
            val item = raw.requireObject(
                itemPath,
                setOf(
                    "id",
                    "aliases",
                    "integerArgumentRegisters",
                    "floatingArgumentRegisters",
                    "integerReturnRegisters",
                    "floatingReturnRegisters",
                    "stackAlignmentBytes",
                    "redZoneBytes",
                    "variadicRegisterCountRegister",
                ),
            )
            val convention = item.field("id", itemPath).requireString("$itemPath.id", 128)
            if (convention in conventions || convention in aliases) structuralFail("duplicate calling convention: $convention")
            conventions += convention
            aliases[convention] = convention
            item.field("aliases", itemPath).requireArray("$itemPath.aliases", 128).forEachIndexed { aliasIndex, rawAlias ->
                val alias = rawAlias.requireString("$itemPath.aliases[$aliasIndex]", 128)
                if (alias in aliases || alias in conventions) structuralFail("duplicate calling-convention alias: $alias")
                aliases[alias] = convention
            }
            listOf(
                "integerArgumentRegisters",
                "floatingArgumentRegisters",
                "integerReturnRegisters",
                "floatingReturnRegisters",
            ).forEach { key ->
                val seen = hashSetOf<String>()
                item.field(key, itemPath).requireArray("$itemPath.$key", limits.maximumRegisters)
                    .forEachIndexed { registerIndex, rawRegister ->
                        val register = rawRegister.requireString("$itemPath.$key[$registerIndex]", 128)
                        if (!seen.add(register)) structuralFail("duplicate register in $itemPath.$key: $register")
                    }
            }
            item.field("stackAlignmentBytes", itemPath).requireInt("$itemPath.stackAlignmentBytes", 1, 4096)
            item.field("redZoneBytes", itemPath).requireInt("$itemPath.redZoneBytes", 0, 65_536)
            item.field("variadicRegisterCountRegister", itemPath)
                .requireNullableString("$itemPath.variadicRegisterCountRegister", 128)
        }

        val widths = root.field("scalarWidthsBits", "target ABI descriptor").requireObject(
            "target ABI descriptor.scalarWidthsBits",
            setOf("pointer", "size", "ptrdiff", "boolean"),
        )
        widths.forEach { (key, value) -> value.requireInt("target ABI descriptor.scalarWidthsBits.$key", 1, 1024) }
        val maximumAddress = if (addressBits == 64) ULong.MAX_VALUE else (1UL shl addressBits) - 1UL
        return StructuralTargetAbiV1(
            snapshot,
            root,
            id,
            addressBits,
            maximumAddress,
            objectFormat,
            conventions.toSet(),
            aliases.toMap(),
            classes.toSet(),
        )
    }

    /** Validates the upstream function-oracle semantics used to bind a boundary report; it never re-scores models. */
    fun loadFunctionOracle(
        path: Path,
        limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits(),
    ): StructuralFunctionOracleV1 {
        val (snapshot, root) = readStructuralDocument(path, "function oracle", "function-recovery-oracle", limits)
        root.requireObject(
            "function oracle",
            setOf("schemaVersion", "scope", "oracle", "artifacts", "scoringPolicy", "functions"),
        )
        requireSchemaVersion(root, "function oracle")
        val scope = root.field("scope", "function oracle").requireString("function oracle.scope", 32)
        if (scope !in setOf("fixture", "production")) structuralFail("function oracle.scope must be fixture or production")
        val header = root.field("oracle", "function oracle").requireObject(
            "function oracle.oracle",
            setOf("id", "source", "artifactManifestSha256"),
        )
        val id = header.field("id", "function oracle.oracle")
            .requireString("function oracle.oracle.id", limits.maximumIdentifierCharacters)
        if (header.field("source", "function oracle.oracle") != JsonPrimitive("dwarf-and-symbols")) {
            structuralFail("function oracle.oracle.source must be dwarf-and-symbols")
        }
        val manifestElement = header.field("artifactManifestSha256", "function oracle.oracle")
        val manifest = if (manifestElement == JsonNull) null else manifestElement.requireSha256(
            "function oracle.oracle.artifactManifestSha256",
        )
        if (scope == "production" && manifest == null) structuralFail("production function oracle must bind an artifact manifest")
        if (scope == "fixture" && manifest != null) structuralFail("fixture function oracle cannot claim an artifact manifest")

        val artifacts = linkedMapOf<String, StructuralFunctionArtifactV1>()
        val artifactRecords = root.field("artifacts", "function oracle")
            .requireObject("function oracle.artifacts", setOf("rich", "stripped"))
        listOf("rich", "stripped").forEach { twin ->
            val itemPath = "function oracle.artifacts.$twin"
            val item = artifactRecords.field(twin, "function oracle.artifacts").requireObject(
                itemPath,
                setOf("inputSha256", "elfType", "elfImageBase", "executableRvaRanges"),
            )
            val elfType = item.field("elfType", itemPath).requireString("$itemPath.elfType", 16)
            if (elfType !in setOf("ET_EXEC", "ET_DYN")) structuralFail("$itemPath.elfType is invalid")
            val ranges = arrayListOf<Pair<ULong, ULong>>()
            item.field("executableRvaRanges", itemPath).requireArray("$itemPath.executableRvaRanges", 256, 1)
                .forEachIndexed { index, raw ->
                    val rangePath = "$itemPath.executableRvaRanges[$index]"
                    val range = raw.requireObject(rangePath, setOf("start", "endExclusive"))
                    val start = range.field("start", rangePath).requireAddress("$rangePath.start", ULong.MAX_VALUE)
                    val end = range.field("endExclusive", rangePath).requireAddress("$rangePath.endExclusive", ULong.MAX_VALUE)
                    if (start >= end) structuralFail("$rangePath must be a non-empty increasing range")
                    if (ranges.isNotEmpty() && start < ranges.last().second) {
                        structuralFail("$itemPath.executableRvaRanges must be sorted and non-overlapping")
                    }
                    ranges += start to end
                }
            artifacts[twin] = StructuralFunctionArtifactV1(
                inputSha256 = item.field("inputSha256", itemPath).requireSha256("$itemPath.inputSha256"),
                elfType = elfType,
                elfImageBase = item.field("elfImageBase", itemPath).requireAddress("$itemPath.elfImageBase", ULong.MAX_VALUE),
                executableRvaRanges = ranges,
            )
        }
        if (artifacts.getValue("rich").inputSha256 == artifacts.getValue("stripped").inputSha256) {
            structuralFail("rich and stripped artifact hashes must differ")
        }
        val richArtifact = artifacts.getValue("rich")
        val strippedArtifact = artifacts.getValue("stripped")
        if (richArtifact.elfType != strippedArtifact.elfType || richArtifact.elfImageBase != strippedArtifact.elfImageBase ||
            richArtifact.executableRvaRanges != strippedArtifact.executableRvaRanges
        ) structuralFail("rich and stripped artifact metadata must match")
        val policy = root.field("scoringPolicy", "function oracle")
            .requireObject("function oracle.scoringPolicy", setOf("nearMissBytes"))
        val nearMissBytes = policy.field("nearMissBytes", "function oracle.scoringPolicy")
            .requireInt("function oracle.scoringPolicy.nearMissBytes", 1, 4096)

        data class FunctionRecord(
            val id: String,
            val rva: ULong?,
            val aliases: JsonArray,
            val exclusion: JsonObject?,
        )
        val functions = arrayListOf<FunctionRecord>()
        val identifiers = hashSetOf<String>()
        val scoredRvas = hashSetOf<ULong>()
        val excludedRvas = hashSetOf<ULong>()
        val evidenceKinds = hashSetOf<String>()
        val scoredIds = hashSetOf<String>()
        root.field("functions", "function oracle").requireArray(
            "function oracle.functions",
            minOf(20_000, limits.maximumEntities),
            1,
        ).forEachIndexed { index, raw ->
            val itemPath = "function oracle.functions[$index]"
            val item = raw.requireObject(itemPath, setOf("id", "rva", "aliases", "exclusion"))
            val functionId = item.field("id", itemPath).requireString("$itemPath.id", limits.maximumIdentifierCharacters)
            if (!identifiers.add(functionId)) structuralFail("duplicate function oracle id: $functionId")
            val aliases = arrayListOf<JsonObject>()
            val aliasNames = hashSetOf<String>()
            item.field("aliases", itemPath).requireArray("$itemPath.aliases", 256, 1).forEachIndexed { aliasIndex, rawAlias ->
                val aliasPath = "$itemPath.aliases[$aliasIndex]"
                val alias = rawAlias.requireObject(aliasPath, setOf("name", "evidence", "availability"))
                val name = alias.field("name", aliasPath).requireString("$aliasPath.name", 4096)
                if (!aliasNames.add(name)) structuralFail("$itemPath.aliases contains a duplicate name")
                val availability = alias.field("availability", aliasPath)
                    .requireObject("$aliasPath.availability", setOf("rich", "stripped"))
                listOf("rich", "stripped").forEach { twin ->
                    if (availability.field(twin, "$aliasPath.availability").requireString("$aliasPath.availability.$twin", 32) !in
                        setOf("surviving", "removed", "not-observable")
                    ) structuralFail("$aliasPath.availability.$twin is invalid")
                }
                val evidence = arrayListOf<JsonObject>()
                val evidenceIdentities = hashSetOf<Pair<String, String>>()
                alias.field("evidence", aliasPath).requireArray("$aliasPath.evidence", 256, 1).forEachIndexed { evidenceIndex, rawEvidence ->
                    val evidencePath = "$aliasPath.evidence[$evidenceIndex]"
                    val evidenceItem = rawEvidence.requireObject(evidencePath, setOf("kind", "locator"))
                    val kind = evidenceItem.field("kind", evidencePath).requireString("$evidencePath.kind", 64)
                    if (kind !in setOf("dwarf-subprogram", "elf-symbol")) structuralFail("$evidencePath.kind is invalid")
                    val locator = evidenceItem.field("locator", evidencePath)
                        .requireString("$evidencePath.locator", limits.maximumTextCharacters)
                    if (!evidenceIdentities.add(kind to locator)) structuralFail("$aliasPath.evidence contains duplicates")
                    evidenceKinds += kind
                    evidence += JsonObject(mapOf("kind" to JsonPrimitive(kind), "locator" to JsonPrimitive(locator)))
                }
                aliases += JsonObject(
                    mapOf(
                        "name" to JsonPrimitive(name),
                        "availability" to availability,
                        "evidence" to JsonArray(evidence.sortedWith { left, right ->
                            compareCodePoints(left.getValue("kind").requireString("evidence.kind", 64), right.getValue("kind").requireString("evidence.kind", 64))
                                .takeIf { it != 0 }
                                ?: compareCodePoints(
                                    left.getValue("locator").requireString("evidence.locator", limits.maximumTextCharacters),
                                    right.getValue("locator").requireString("evidence.locator", limits.maximumTextCharacters),
                                )
                        }),
                    ),
                )
            }
            val rvaElement = item.field("rva", itemPath)
            val rva = if (rvaElement == JsonNull) null else rvaElement.requireAddress("$itemPath.rva", ULong.MAX_VALUE)
            val exclusionElement = item.field("exclusion", itemPath)
            val exclusion = if (exclusionElement == JsonNull) null else exclusionElement.requireObject(
                "$itemPath.exclusion",
                setOf("kind", "reason"),
            )
            if (exclusion == null) {
                if (rva == null) structuralFail("scoreable $itemPath must have an RVA")
                aliases.forEach { alias ->
                    val availability = alias.getValue("availability") as JsonObject
                    if (availability.getValue("rich") != JsonPrimitive("surviving") ||
                        availability.getValue("stripped") == JsonPrimitive("not-observable")
                    ) structuralFail("scoreable aliases have invalid twin availability")
                }
                if (richArtifact.executableRvaRanges.none { (start, end) -> rva >= start && rva < end }) {
                    structuralFail("scoreable $itemPath.rva is outside executable ranges")
                }
                if (!scoredRvas.add(rva)) structuralFail("multiple scoreable functions share an RVA")
                scoredIds += functionId
            } else {
                val kind = exclusion.field("kind", "$itemPath.exclusion").requireString("$itemPath.exclusion.kind", 64)
                if (kind !in setOf("compiler-generated", "inlined")) structuralFail("$itemPath.exclusion.kind is invalid")
                exclusion.field("reason", "$itemPath.exclusion").requireString(
                    "$itemPath.exclusion.reason",
                    limits.maximumTextCharacters,
                )
                if (kind == "inlined" && rva != null) structuralFail("inlined $itemPath must use a null RVA")
                if (kind == "compiler-generated" && rva == null) structuralFail("compiler-generated $itemPath must identify an RVA")
                if (rva != null) {
                    if (richArtifact.executableRvaRanges.none { (start, end) -> rva >= start && rva < end }) {
                        structuralFail("excluded $itemPath.rva is outside executable ranges")
                    }
                    if (!excludedRvas.add(rva)) structuralFail("multiple exclusions share an RVA")
                }
            }
            functions += FunctionRecord(
                functionId,
                rva,
                JsonArray(aliases.sortedWith { left, right ->
                    compareCodePoints(left.getValue("name").requireString("alias.name", 4096), right.getValue("name").requireString("alias.name", 4096))
                }),
                exclusion,
            )
        }
        if ((scoredRvas intersect excludedRvas).isNotEmpty()) structuralFail("scoreable and excluded functions share an RVA")
        if (scoredRvas.isEmpty()) structuralFail("function oracle must contain at least one scoreable function")
        if (evidenceKinds != setOf("dwarf-subprogram", "elf-symbol")) {
            structuralFail("function oracle must retain both DWARF and ELF-symbol evidence")
        }
        val sortedFunctions = functions.sortedWith { left, right ->
            (left.rva == null).compareTo(right.rva == null).takeIf { it != 0 }
                ?: (left.rva ?: 0UL).compareTo(right.rva ?: 0UL).takeIf { it != 0 }
                ?: compareCodePoints(left.id, right.id)
        }
        val scoreableByTwin = listOf("rich", "stripped").associateWith { twin ->
            sortedFunctions.filter { it.exclusion == null }.associate { function ->
                val aliases = function.aliases.map { rawAlias ->
                    val alias = rawAlias as JsonObject
                    val availability = alias.getValue("availability") as JsonObject
                    JsonObject(
                        mapOf(
                            "name" to alias.getValue("name"),
                            "availability" to availability.getValue(twin),
                            "evidence" to alias.getValue("evidence"),
                        ),
                    )
                }
                function.id to StructuralFunctionScoreRecordV1(
                    checkNotNull(function.rva),
                    JsonArray(aliases),
                )
            }
        }
        val excluded = sortedFunctions.filter { it.exclusion != null }.map { function ->
            val exclusion = checkNotNull(function.exclusion)
            JsonObject(
                mapOf(
                    "oracleId" to JsonPrimitive(function.id),
                    "rva" to (function.rva?.let { JsonPrimitive("0x${it.toString(16)}") } ?: JsonNull),
                    "aliases" to function.aliases,
                    "kind" to exclusion.getValue("kind"),
                    "reason" to exclusion.getValue("reason"),
                ),
            )
        }
        return StructuralFunctionOracleV1(
            snapshot,
            root,
            id,
            scope,
            manifest,
            nearMissBytes,
            artifacts.toMap(),
            scoredIds.toSet(),
            scoreableByTwin,
            JsonArray(excluded),
        )
    }

    fun loadStructuralOracle(
        path: Path,
        target: StructuralTargetAbiV1,
        limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits(),
    ): StructuralOracleV1 {
        val (snapshot, root) = readStructuralDocument(path, "structural oracle", "structural-oracle", limits)
        root.requireObject(
            "structural oracle",
            setOf("schemaVersion", "scope", "oracle", "artifact", "targetAbi", "normalizationProfile", "entities"),
        )
        requireSchemaVersion(root, "structural oracle")
        val scope = root.field("scope", "structural oracle").requireString("structural oracle.scope", 32)
        if (scope !in setOf("fixture", "production")) structuralFail("structural oracle.scope is invalid")
        val oracle = root.field("oracle", "structural oracle").requireObject(
            "structural oracle.oracle",
            setOf("id", "producer", "artifactManifestSha256", "boundaryOracle"),
        )
        oracle.field("id", "structural oracle.oracle").requireIdentifier("structural oracle.oracle.id", limits)
        validateToolIdentity(oracle.field("producer", "structural oracle.oracle"), "structural oracle.oracle.producer", limits)
        val manifest = oracle.field("artifactManifestSha256", "structural oracle.oracle")
        if (scope == "production") manifest.requireSha256("structural oracle.oracle.artifactManifestSha256")
        else if (manifest != JsonNull) structuralFail("fixture structural oracle cannot claim an artifact manifest")
        val boundary = oracle.field("boundaryOracle", "structural oracle.oracle").requireObject(
            "structural oracle.oracle.boundaryOracle",
            setOf("id", "artifactManifestSha256"),
        )
        boundary.field("id", "structural oracle.oracle.boundaryOracle")
            .requireIdentifier("structural oracle.oracle.boundaryOracle.id", limits)
        val boundaryManifest = boundary.field("artifactManifestSha256", "structural oracle.oracle.boundaryOracle")
        if (scope == "production") {
            if (boundaryManifest.requireSha256("structural oracle.oracle.boundaryOracle.artifactManifestSha256") !=
                manifest.requireSha256("structural oracle.oracle.artifactManifestSha256")
            ) structuralFail("production structural and boundary oracles use different manifests")
        } else if (boundaryManifest != JsonNull) {
            structuralFail("fixture boundary oracle cannot claim an artifact manifest")
        }
        val artifact = root.field("artifact", "structural oracle").requireObject(
            "structural oracle.artifact",
            setOf("id", "inputSha256", "sizeBytes", "imageBase"),
        )
        artifact.field("id", "structural oracle.artifact").requireIdentifier("structural oracle.artifact.id", limits)
        artifact.field("inputSha256", "structural oracle.artifact").requireSha256("structural oracle.artifact.inputSha256")
        artifact.field("sizeBytes", "structural oracle.artifact").requireInteger(
            "structural oracle.artifact.sizeBytes",
            BigInteger.ONE,
        )
        artifact.field("imageBase", "structural oracle.artifact")
            .requireAddress("structural oracle.artifact.imageBase", target.maximumAddress)
        validateTargetBinding(root.field("targetAbi", "structural oracle"), "structural oracle.targetAbi", target)
        validateNormalizationProfile(root.field("normalizationProfile", "structural oracle"), "structural oracle.normalizationProfile")
        validateEntities(root.field("entities", "structural oracle"), "structural oracle.entities", false, target, limits)
        return StructuralOracleV1(snapshot, root)
    }

    fun loadBoundaryMapping(
        path: Path,
        twin: String,
        target: StructuralTargetAbiV1,
        functionOracle: StructuralFunctionOracleV1,
        limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits(),
    ): StructuralBoundaryMappingV1 {
        if (twin !in setOf("rich", "stripped")) structuralFail("boundary mapping twin must be rich or stripped")
        val (snapshot, root) = readStructuralDocument(
            path,
            "function-boundary score report",
            "function-recovery-score",
            limits,
        )
        root.requireObject("function-boundary score report", setOf("schemaVersion", "oracle", "policy", "twins"))
        requireSchemaVersion(root, "function-boundary score report")
        val oracle = root.field("oracle", "function-boundary score report").requireObject(
            "function-boundary score report.oracle",
            setOf(
                "id",
                "scope",
                "source",
                "artifactManifestSha256",
                "verification",
                "functionRecordCount",
                "scoredFunctionCount",
                "exclusions",
                "excludedFunctions",
            ),
        )
        oracle.field("id", "function-boundary score report.oracle")
            .requireIdentifier("function-boundary score report.oracle.id", limits)
        val scope = oracle.field("scope", "function-boundary score report.oracle")
            .requireString("function-boundary score report.oracle.scope", 32)
        if (scope !in setOf("fixture", "production")) structuralFail("function-boundary score report oracle scope is invalid")
        if (oracle.field("source", "function-boundary score report.oracle")
                .requireString("function-boundary score report.oracle.source", 128) != "dwarf-and-symbols"
        ) structuralFail("function-boundary score report oracle source is invalid")
        if (oracle.field("id", "function-boundary score report.oracle") != JsonPrimitive(functionOracle.id) ||
            scope != functionOracle.scope ||
            oracle.field("artifactManifestSha256", "function-boundary score report.oracle") !=
            (functionOracle.artifactManifestSha256?.let { JsonPrimitive(it) } ?: JsonNull)
        ) structuralFail("function-boundary score report is not bound to the supplied function oracle")
        val expectedVerification = if (functionOracle.scope == "fixture") {
            JsonObject(
                mapOf(
                    "status" to JsonPrimitive("fixture-non-production"),
                    "artifactManifestVerified" to JsonPrimitive(false),
                    "programModelProvenance" to JsonPrimitive("fixture-inputs"),
                    "productionVerified" to JsonPrimitive(false),
                ),
            )
        } else {
            JsonObject(
                mapOf(
                    "status" to JsonPrimitive("artifact-verified-model-unattested"),
                    "artifactManifestVerified" to JsonPrimitive(true),
                    "programModelProvenance" to JsonPrimitive("unattested-schema-v1"),
                    "productionVerified" to JsonPrimitive(false),
                ),
            )
        }
        if (oracle.field("verification", "function-boundary score report.oracle") != expectedVerification) {
            structuralFail("function-boundary verification context is inconsistent with the supplied function oracle")
        }
        val policy = root.field("policy", "function-boundary score report").requireObject(
            "function-boundary score report.policy",
            setOf("addressNormalization", "nearMissBytes", "nearMissMatching", "nameComparison", "exclusionHandling", "limits"),
        )
        val nearBytes = policy.field("nearMissBytes", "function-boundary score report.policy")
            .requireInt("function-boundary score report.policy.nearMissBytes", 1, 4096)
        if (nearBytes != functionOracle.nearMissBytes) {
            structuralFail("function-boundary near-miss policy does not match the supplied function oracle")
        }

        val excludedOracleIds = linkedSetOf<String>()
        oracle.field("excludedFunctions", "function-boundary score report.oracle")
            .requireArray("function-boundary score report.oracle.excludedFunctions", limits.maximumEntities)
            .forEachIndexed { index, raw ->
                val itemPath = "function-boundary score report.oracle.excludedFunctions[$index]"
                val item = raw.requireObject(itemPath, setOf("oracleId", "rva", "aliases", "kind", "reason"))
                val oracleId = item.field("oracleId", itemPath).requireIdentifier("$itemPath.oracleId", limits)
                if (!excludedOracleIds.add(oracleId)) structuralFail("function-boundary exclusions contain a duplicate oracle ID")
                item["rva"]?.takeUnless { it == JsonNull }?.requireAddress("$itemPath.rva", target.maximumAddress)
                item.field("aliases", itemPath).requireArray("$itemPath.aliases", 256, 1)
                if (item.field("kind", itemPath).requireString("$itemPath.kind", 64) !in setOf("compiler-generated", "inlined")) {
                    structuralFail("$itemPath.kind is invalid")
                }
                item.field("reason", itemPath).requireString("$itemPath.reason", limits.maximumTextCharacters)
            }
        if (oracle.field("excludedFunctions", "function-boundary score report.oracle") !=
            functionOracle.expectedExcludedFunctions
        ) structuralFail("function-boundary exclusions do not match the supplied function oracle")
        val exclusions = oracle.field("exclusions", "function-boundary score report.oracle").requireObject(
            "function-boundary score report.oracle.exclusions",
            setOf("compiler-generated", "inlined"),
        )
        val expectedExclusionCounts = functionOracle.expectedExcludedFunctions
            .map { (it as JsonObject).field("kind", "function exclusion").requireString("function exclusion.kind", 64) }
            .groupingBy { it }
            .eachCount()
        listOf("compiler-generated", "inlined").forEach { kind ->
            if (exclusions.field(kind, "function-boundary score report.oracle.exclusions")
                    .requireInt("function-boundary score report.oracle.exclusions.$kind") !=
                expectedExclusionCounts.getOrDefault(kind, 0)
            ) structuralFail("function-boundary exclusion counts do not match the supplied function oracle")
        }
        val recordCount = oracle.field("functionRecordCount", "function-boundary score report.oracle")
            .requireInt("function-boundary score report.oracle.functionRecordCount", 1)
        val scoredCount = oracle.field("scoredFunctionCount", "function-boundary score report.oracle")
            .requireInt("function-boundary score report.oracle.scoredFunctionCount", 1)
        if (recordCount != scoredCount + excludedOracleIds.size) {
            structuralFail("function-boundary oracle record and exclusion counts disagree")
        }
        if (recordCount != (functionOracle.document.field("functions", "function oracle") as JsonArray).size ||
            scoredCount != functionOracle.scoredFunctionIds.size
        ) structuralFail("function-boundary oracle counts do not match the supplied function oracle")

        val twins = root.field("twins", "function-boundary score report").requireObject(
            "function-boundary score report.twins",
            setOf("rich", "stripped"),
        )
        validateAllBoundaryOracleProjections(twins, functionOracle, target, limits)
        val selectedPath = "function-boundary score report.twins.$twin"
        val selected = twins.field(twin, "function-boundary score report.twins").requireObject(
            selectedPath,
            setOf(
                "artifact",
                "boundaries",
                "nameRecovery",
                "nearMatchAssignment",
                "exactMatches",
                "nearMisses",
                "falsePositives",
                "falseNegatives",
                "ignoredExcludedRecoveries",
            ),
        )
        val selectedArtifact = selected.field("artifact", selectedPath)
        val projection = projectBoundaryArtifact(selectedArtifact, "$selectedPath.artifact", target)
        val upstreamArtifact = functionOracle.artifacts.getValue(twin)
        val projectedArtifact = selectedArtifact as JsonObject
        if (projection.inputSha256 != upstreamArtifact.inputSha256 ||
            projectedArtifact.field("elfType", "$selectedPath.artifact").requireString("$selectedPath.artifact.elfType", 16) !=
            upstreamArtifact.elfType ||
            projectedArtifact.field("elfImageBase", "$selectedPath.artifact").requireAddress(
                "$selectedPath.artifact.elfImageBase",
                target.maximumAddress,
            ) != upstreamArtifact.elfImageBase ||
            projection.ranges != upstreamArtifact.executableRvaRanges
        ) structuralFail("function-boundary artifact projection does not match the supplied function oracle")
        val assignment = selected.field("nearMatchAssignment", selectedPath).requireObject(
            "$selectedPath.nearMatchAssignment",
            setOf(
                "objective",
                "stableTieBreak",
                "nameIndependent",
                "hasAlternativeOptimalMatching",
                "optimalCandidateEdgeCount",
                "alternativeOptimalEdges",
            ),
        )
        if (!assignment.field("nameIndependent", "$selectedPath.nearMatchAssignment")
                .requireBoolean("$selectedPath.nearMatchAssignment.nameIndependent")
        ) structuralFail("function-boundary selected mapping is not name-independent")
        val objective = assignment.field("objective", "$selectedPath.nearMatchAssignment").requireObject(
            "$selectedPath.nearMatchAssignment.objective",
            setOf("maximumCardinality", "minimumTotalDistanceBytes"),
        )
        val objectiveCardinality = objective.field("maximumCardinality", "$selectedPath.nearMatchAssignment.objective")
            .requireInt("function-boundary near objective cardinality")
        val objectiveDistance = objective.field("minimumTotalDistanceBytes", "$selectedPath.nearMatchAssignment.objective")
            .requireLong("function-boundary near objective distance")

        val oracleToRecovered = linkedMapOf<String, String>()
        val recoveredToOracle = linkedMapOf<String, String>()
        val oracleFunctionIds = linkedSetOf<String>()
        val recoveredFunctionIds = linkedSetOf<String>()
        var nearDistance = 0L
        val categoryCounts = linkedMapOf<String, Int>()
        listOf("exactMatches", "nearMisses").forEach { category ->
            val records = selected.field(category, selectedPath).requireArray("$selectedPath.$category", limits.maximumEntities)
            records.forEachIndexed { index, raw ->
                val itemPath = "$selectedPath.$category[$index]"
                val item = raw.requireObject(
                    itemPath,
                    setOf(
                        "oracleId",
                        "oracleRva",
                        "oracleAliases",
                        "recoveredId",
                        "recoveredRva",
                        "recoveredName",
                        "recoveredStatus",
                        "deltaBytes",
                        "matchKind",
                        "nameResult",
                        "matchedAlias",
                        "matchedAliasAvailability",
                        "nameCategoryResults",
                    ),
                )
                val oracleId = item.field("oracleId", itemPath).requireIdentifier("$itemPath.oracleId", limits)
                val recoveredId = item.field("recoveredId", itemPath).requireIdentifier("$itemPath.recoveredId", limits)
                if (oracleId in excludedOracleIds) structuralFail("function-boundary selected mapping overlaps the excluded oracle universe")
                val oracleRva = item.field("oracleRva", itemPath).requireAddress("$itemPath.oracleRva", target.maximumAddress)
                val upstreamFunction = functionOracle.scoreableFunctionsByTwin.getValue(twin)[oracleId]
                    ?: structuralFail("function-boundary mapping references an ID absent from the supplied function oracle")
                if (oracleRva != upstreamFunction.rva || item.field("oracleAliases", itemPath) != upstreamFunction.aliases) {
                    structuralFail("function-boundary oracle detail does not match the supplied function oracle")
                }
                val recoveredRva = item.field("recoveredRva", itemPath).requireAddress("$itemPath.recoveredRva", target.maximumAddress)
                val expectedDelta = recoveredRva.toBigInteger().subtract(oracleRva.toBigInteger())
                val delta = item.field("deltaBytes", itemPath).requireInteger(
                    "$itemPath.deltaBytes",
                    UNSIGNED_64_MAXIMUM.negate(),
                    UNSIGNED_64_MAXIMUM,
                )
                if (delta != expectedDelta) structuralFail("$itemPath.deltaBytes does not match its RVAs")
                val expectedKind = if (category == "exactMatches") "exact" else "near"
                if (item.field("matchKind", itemPath).requireString("$itemPath.matchKind", 32) != expectedKind) {
                    structuralFail("$itemPath.matchKind is inconsistent with its category")
                }
                if (expectedKind == "exact" && delta != BigInteger.ZERO) structuralFail("$itemPath is not an exact-address match")
                if (expectedKind == "near" && (delta == BigInteger.ZERO || delta.abs() > BigInteger.valueOf(nearBytes.toLong()))) {
                    structuralFail("$itemPath is outside the near-match policy")
                }
                if (oracleId in oracleToRecovered || recoveredId in recoveredToOracle) {
                    structuralFail("function-boundary selected mapping is not one-to-one")
                }
                oracleToRecovered[oracleId] = recoveredId
                recoveredToOracle[recoveredId] = oracleId
                oracleFunctionIds += oracleId
                recoveredFunctionIds += recoveredId
                if (oracleToRecovered.size > limits.maximumMappings) structuralFail("function-boundary mapping exceeds the mapping limit")
                if (expectedKind == "near") nearDistance = Math.addExact(nearDistance, delta.abs().toLong())
            }
            categoryCounts[category] = records.size
        }

        val falseNegatives = selected.field("falseNegatives", selectedPath)
            .requireArray("$selectedPath.falseNegatives", limits.maximumEntities)
        falseNegatives.forEachIndexed { index, raw ->
            val itemPath = "$selectedPath.falseNegatives[$index]"
            val item = raw.requireObject(itemPath, setOf("oracleId", "oracleRva", "oracleAliases"))
            val id = item.field("oracleId", itemPath).requireIdentifier("$itemPath.oracleId", limits)
            val rva = item.field("oracleRva", itemPath).requireAddress("$itemPath.oracleRva", target.maximumAddress)
            val upstreamFunction = functionOracle.scoreableFunctionsByTwin.getValue(twin)[id]
                ?: structuralFail("function-boundary false negative is absent from the supplied function oracle")
            if (rva != upstreamFunction.rva || item.field("oracleAliases", itemPath) != upstreamFunction.aliases) {
                structuralFail("function-boundary false-negative detail does not match the supplied function oracle")
            }
            if (id in oracleFunctionIds || id in excludedOracleIds) structuralFail("function-boundary oracle universe is not partitioned")
            oracleFunctionIds += id
        }
        val falsePositives = selected.field("falsePositives", selectedPath)
            .requireArray("$selectedPath.falsePositives", limits.maximumEntities)
        falsePositives.forEachIndexed { index, raw ->
            val itemPath = "$selectedPath.falsePositives[$index]"
            val item = raw.requireObject(itemPath, setOf("recoveredId", "recoveredRva", "recoveredName", "recoveredStatus"))
            val id = item.field("recoveredId", itemPath).requireIdentifier("$itemPath.recoveredId", limits)
            item.field("recoveredRva", itemPath).requireAddress("$itemPath.recoveredRva", target.maximumAddress)
            item.field("recoveredName", itemPath).requireString("$itemPath.recoveredName", limits.maximumTextCharacters)
            if (item.field("recoveredStatus", itemPath).requireString("$itemPath.recoveredStatus", 32) !in
                setOf("recovered", "partial", "failed", "synthetic")
            ) structuralFail("$itemPath.recoveredStatus is invalid")
            if (!recoveredFunctionIds.add(id)) structuralFail("function-boundary recovered universe is not partitioned")
        }
        val ignoredRecoveredIds = linkedSetOf<String>()
        val ignored = selected.field("ignoredExcludedRecoveries", selectedPath)
            .requireArray("$selectedPath.ignoredExcludedRecoveries", limits.maximumEntities)
        ignored.forEachIndexed { index, raw ->
            val itemPath = "$selectedPath.ignoredExcludedRecoveries[$index]"
            val item = raw.requireObject(
                itemPath,
                setOf(
                    "recoveredId",
                    "recoveredRva",
                    "recoveredName",
                    "recoveredStatus",
                    "oracleId",
                    "exclusionKind",
                    "exclusionReason",
                ),
            )
            val recoveredId = item.field("recoveredId", itemPath).requireIdentifier("$itemPath.recoveredId", limits)
            val oracleId = item.field("oracleId", itemPath).requireIdentifier("$itemPath.oracleId", limits)
            item.field("recoveredRva", itemPath).requireAddress("$itemPath.recoveredRva", target.maximumAddress)
            if (oracleId !in excludedOracleIds ||
                item.field("exclusionKind", itemPath).requireString("$itemPath.exclusionKind", 64) != "compiler-generated"
            ) structuralFail("ignored recovery is not backed by a reviewed exclusion")
            if (recoveredId in recoveredFunctionIds || !ignoredRecoveredIds.add(recoveredId)) {
                structuralFail("ignored recovery overlaps the scored recovered universe")
            }
        }
        if (oracleFunctionIds.size != scoredCount) structuralFail("function-boundary scored oracle universe count disagrees")
        if (oracleFunctionIds != functionOracle.scoredFunctionIds) {
            structuralFail("function-boundary scored oracle universe does not match the supplied function oracle")
        }
        if (objectiveCardinality != categoryCounts.getValue("nearMisses")) {
            structuralFail("function-boundary near-assignment cardinality disagrees")
        }
        if (objectiveDistance != nearDistance) structuralFail("function-boundary near-assignment distance disagrees")
        val boundaries = selected.field("boundaries", selectedPath).requireObject(
            "$selectedPath.boundaries",
            setOf(
                "referenceCount",
                "rawRecoveredCount",
                "scoredRecoveredCount",
                "ignoredExcludedCount",
                "exactMatches",
                "nearMisses",
                "truePositives",
                "falsePositives",
                "falseNegatives",
                "precision",
                "recall",
                "f1",
                "exactAddressRate",
                "nearMissRate",
                "nearMissDistanceBytes",
            ),
        )
        val expectedCounts = mapOf(
            "referenceCount" to oracleFunctionIds.size.toLong(),
            "scoredRecoveredCount" to recoveredFunctionIds.size.toLong(),
            "ignoredExcludedCount" to ignoredRecoveredIds.size.toLong(),
            "exactMatches" to categoryCounts.getValue("exactMatches").toLong(),
            "nearMisses" to categoryCounts.getValue("nearMisses").toLong(),
            "truePositives" to oracleToRecovered.size.toLong(),
            "falsePositives" to falsePositives.size.toLong(),
            "falseNegatives" to falseNegatives.size.toLong(),
            "nearMissDistanceBytes" to nearDistance,
        )
        expectedCounts.forEach { (key, expected) ->
            if (boundaries.field(key, "$selectedPath.boundaries").requireLong("$selectedPath.boundaries.$key") != expected) {
                structuralFail("function-boundary boundaries.$key disagrees with records")
            }
        }
        val rawRecovered = boundaries.field("rawRecoveredCount", "$selectedPath.boundaries")
            .requireLong("$selectedPath.boundaries.rawRecoveredCount")
        if (rawRecovered != recoveredFunctionIds.size.toLong() + ignoredRecoveredIds.size.toLong()) {
            structuralFail("function-boundary raw recovered count disagrees")
        }
        return StructuralBoundaryMappingV1(
            snapshot,
            functionOracle.snapshot,
            root,
            twin,
            StructuralRecoveryV1Contract.BOUNDARY_PROJECTION_ADAPTER_ID,
            StructuralRecoveryV1Contract.BOUNDARY_PROJECTION_ADAPTER_VERSION,
            projection.objectFormat,
            projection.inputSha256,
            projection.modelImageBase,
            projection.ranges,
            oracleToRecovered.toMap(),
            recoveredToOracle.toMap(),
            oracleFunctionIds.toSet(),
            recoveredFunctionIds.toSet(),
            excludedOracleIds.toSet(),
            ignoredRecoveredIds.toSet(),
        )
    }

    fun loadFixtureIdentityMap(
        path: Path,
        oracle: StructuralOracleV1,
        limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits(),
    ): StructuralIdentityMapV1 {
        val attested = loadAttestedFixture(path, "structural identity map", "structural-identity-map", limits)
        val root = attested.document
        root.requireObject("structural identity map", setOf("schemaVersion", "scope", "map", "mappings", "attestation"))
        requireSchemaVersion(root, "structural identity map")
        val header = root.field("map", "structural identity map").requireObject(
            "structural identity map.map",
            setOf("id", "oracleId", "oracleSha256", "recoveredModelId"),
        )
        header.field("id", "structural identity map.map").requireIdentifier("structural identity map.map.id", limits)
        val oracleHeader = oracle.document.field("oracle", "structural oracle") as JsonObject
        if (header.field("oracleId", "structural identity map.map").requireIdentifier("structural identity map.map.oracleId", limits) !=
            oracleHeader.field("id", "structural oracle.oracle").requireIdentifier("structural oracle.oracle.id", limits)
        ) structuralFail("identity map oracle ID does not match the structural oracle")
        if (header.field("oracleSha256", "structural identity map.map").requireSha256("structural identity map.map.oracleSha256") !=
            oracle.snapshot.sha256
        ) structuralFail("identity map oracle digest does not match the structural oracle")
        header.field("recoveredModelId", "structural identity map.map")
            .requireIdentifier("structural identity map.map.recoveredModelId", limits)
        val recoveredToOracle = linkedMapOf<StructuralEntityKey, String>()
        val oracleToRecovered = linkedMapOf<StructuralEntityKey, String>()
        root.field("mappings", "structural identity map")
            .requireArray("structural identity map.mappings", limits.maximumMappings)
            .forEachIndexed { index, raw ->
                val itemPath = "structural identity map.mappings[$index]"
                val item = raw.requireObject(itemPath, setOf("kind", "oracleId", "recoveredId", "evidence"))
                val kind = item.field("kind", itemPath).requireString("$itemPath.kind", 32)
                if (kind !in setOf("global", "type")) structuralFail("$itemPath.kind must be global or type")
                val oracleId = item.field("oracleId", itemPath).requireIdentifier("$itemPath.oracleId", limits)
                val recoveredId = item.field("recoveredId", itemPath).requireIdentifier("$itemPath.recoveredId", limits)
                validateMappingEvidence(item.field("evidence", itemPath), "$itemPath.evidence", limits)
                val recoveredKey = StructuralEntityKey(kind, recoveredId)
                val oracleKey = StructuralEntityKey(kind, oracleId)
                if (recoveredKey in recoveredToOracle || oracleKey in oracleToRecovered) {
                    structuralFail("structural identity map must be one-to-one")
                }
                recoveredToOracle[recoveredKey] = oracleId
                oracleToRecovered[oracleKey] = recoveredId
            }
        return StructuralIdentityMapV1(attested.snapshot, root, recoveredToOracle.toMap(), oracleToRecovered.toMap())
    }

    fun loadFixtureRecoveredStructure(
        path: Path,
        target: StructuralTargetAbiV1,
        oracle: StructuralOracleV1,
        boundary: StructuralBoundaryMappingV1,
        identityMap: StructuralIdentityMapV1,
        limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits(),
    ): RecoveredStructureV1 {
        val attested = loadAttestedFixture(path, "recovered structure", "recovered-structure", limits)
        val root = attested.document
        root.requireObject("recovered structure", setOf("schemaVersion", "scope", "model", "provenance", "entities", "attestation"))
        requireSchemaVersion(root, "recovered structure")
        val model = root.field("model", "recovered structure").requireObject("recovered structure.model", setOf("id"))
        val modelId = model.field("id", "recovered structure.model").requireIdentifier("recovered structure.model.id", limits)
        val mapHeader = identityMap.document.field("map", "structural identity map") as JsonObject
        if (modelId != mapHeader.field("recoveredModelId", "structural identity map.map")
                .requireIdentifier("structural identity map.map.recoveredModelId", limits)
        ) structuralFail("recovered model ID does not match the identity map")
        val provenance = root.field("provenance", "recovered structure").requireObject(
            "recovered structure.provenance",
            setOf("inputBinary", "exporter", "loader", "targetAbi", "normalizationProfile", "boundaryScore", "identityMap"),
        )
        val input = provenance.field("inputBinary", "recovered structure.provenance").requireObject(
            "recovered structure.provenance.inputBinary",
            setOf("sha256", "sizeBytes"),
        )
        val inputSha = input.field("sha256", "recovered structure.provenance.inputBinary")
            .requireSha256("recovered structure.provenance.inputBinary.sha256")
        val inputSize = input.field("sizeBytes", "recovered structure.provenance.inputBinary")
            .requireInteger("recovered structure.provenance.inputBinary.sizeBytes", BigInteger.ONE)
        val oracleArtifact = oracle.document.field("artifact", "structural oracle") as JsonObject
        if (inputSha != oracleArtifact.field("inputSha256", "structural oracle.artifact")
                .requireSha256("structural oracle.artifact.inputSha256") ||
            inputSize != oracleArtifact.field("sizeBytes", "structural oracle.artifact")
                .requireInteger("structural oracle.artifact.sizeBytes", BigInteger.ONE)
        ) structuralFail("recovered input-binary provenance does not match the oracle artifact")
        validateToolIdentity(provenance.field("exporter", "recovered structure.provenance"), "recovered structure.provenance.exporter", limits)
        val loader = provenance.field("loader", "recovered structure.provenance").requireObject(
            "recovered structure.provenance.loader",
            setOf("id", "version", "executableSha256", "configurationSha256", "imageBase"),
        )
        validateToolIdentity(
            JsonObject(loader.filterKeys { it != "imageBase" }),
            "recovered structure.provenance.loader",
            limits,
        )
        val loaderBase = loader.field("imageBase", "recovered structure.provenance.loader")
            .requireAddress("recovered structure.provenance.loader.imageBase", target.maximumAddress)
        if (loaderBase != oracleArtifact.field("imageBase", "structural oracle.artifact")
                .requireAddress("structural oracle.artifact.imageBase", target.maximumAddress)
        ) structuralFail("recovered loader image base does not match the oracle artifact")
        validateTargetBinding(provenance.field("targetAbi", "recovered structure.provenance"), "recovered structure.provenance.targetAbi", target)
        val recoveredProfile = validateNormalizationProfile(
            provenance.field("normalizationProfile", "recovered structure.provenance"),
            "recovered structure.provenance.normalizationProfile",
        )
        val oracleProfile = validateNormalizationProfile(
            oracle.document.field("normalizationProfile", "structural oracle"),
            "structural oracle.normalizationProfile",
        )
        if (recoveredProfile != oracleProfile) structuralFail("recovered normalization profile does not match the structural oracle")
        val boundaryBinding = provenance.field("boundaryScore", "recovered structure.provenance").requireObject(
            "recovered structure.provenance.boundaryScore",
            setOf("sha256", "twin", "projectionAdapter"),
        )
        if (boundaryBinding.field("sha256", "recovered structure.provenance.boundaryScore")
                .requireSha256("recovered structure.provenance.boundaryScore.sha256") != boundary.snapshot.sha256
        ) structuralFail("recovered boundary-score provenance does not match the selected report")
        if (boundaryBinding.field("twin", "recovered structure.provenance.boundaryScore")
                .requireString("recovered structure.provenance.boundaryScore.twin", 32) != boundary.twin
        ) structuralFail("recovered boundary-score twin does not match the selected mapping")
        val adapter = boundaryBinding.field("projectionAdapter", "recovered structure.provenance.boundaryScore").requireObject(
            "recovered structure.provenance.boundaryScore.projectionAdapter",
            setOf("id", "version"),
        )
        val expectedAdapter = JsonObject(
            mapOf(
                "id" to JsonPrimitive(boundary.projectionAdapterId),
                "version" to JsonPrimitive(boundary.projectionAdapterVersion),
            ),
        )
        if (adapter != expectedAdapter) structuralFail("recovered boundary-score projection adapter does not match the selected mapping")
        val mapBinding = provenance.field("identityMap", "recovered structure.provenance")
            .requireObject("recovered structure.provenance.identityMap", setOf("sha256"))
        if (mapBinding.field("sha256", "recovered structure.provenance.identityMap")
                .requireSha256("recovered structure.provenance.identityMap.sha256") != identityMap.snapshot.sha256
        ) structuralFail("recovered identity-map provenance does not match the supplied mapping")
        val boundaryOracle = (oracle.document.field("oracle", "structural oracle") as JsonObject)
            .field("boundaryOracle", "structural oracle.oracle") as JsonObject
        val reportOracle = boundary.document.field("oracle", "function-boundary score report") as JsonObject
        if (reportOracle.field("id", "function-boundary score report.oracle") !=
            boundaryOracle.field("id", "structural oracle.oracle.boundaryOracle")
        ) structuralFail("selected boundary report uses a different boundary oracle")
        if (reportOracle.field("artifactManifestSha256", "function-boundary score report.oracle") !=
            boundaryOracle.field("artifactManifestSha256", "structural oracle.oracle.boundaryOracle")
        ) structuralFail("selected boundary report uses a different artifact manifest")
        if (reportOracle.field("scope", "function-boundary score report.oracle") !=
            oracle.document.field("scope", "structural oracle")
        ) structuralFail("selected boundary report uses a different evidence scope")
        if (boundary.inputSha256 != inputSha) structuralFail("selected boundary report uses a different input binary")
        if (boundary.modelImageBase != loaderBase) structuralFail("selected boundary report uses a different loader image base")
        if (boundary.objectFormat != target.objectFormat) structuralFail("selected boundary report uses a different object format")
        validateEntities(root.field("entities", "recovered structure"), "recovered structure.entities", true, target, limits)
        return RecoveredStructureV1(attested.snapshot, root, attested.payloadSha256)
    }

    private data class AttestedFixture(
        val snapshot: StructuralSnapshot,
        val document: JsonObject,
        val payloadSha256: String,
    )

    private fun loadAttestedFixture(
        path: Path,
        label: String,
        schema: String,
        limits: StructuralRecoveryV1Limits,
    ): AttestedFixture {
        val (snapshot, document) = readStructuralDocument(path, label, schema, limits)
        if (document.field("scope", label).requireString("$label.scope", 32) != "fixture") {
            structuralFail("$label is production-scoped; a trusted adapter-replay verifier is required")
        }
        val attestation = document.field("attestation", label).requireObject(
            "$label.attestation",
            setOf("kind", "payloadSha256", "evidenceSha256", "verifier"),
        )
        if (attestation.field("kind", "$label.attestation").requireString("$label.attestation.kind", 64) != "fixture-digest") {
            structuralFail("$label fixture must use fixture-digest attestation")
        }
        if (attestation.field("evidenceSha256", "$label.attestation") != JsonNull) {
            structuralFail("$label fixture cannot claim an authenticated replay-evidence digest")
        }
        val verifier = attestation.field("verifier", "$label.attestation")
            .requireObject("$label.attestation.verifier", setOf("id", "version"))
        verifier.field("id", "$label.attestation.verifier").requireIdentifier("$label.attestation.verifier.id", limits)
        verifier.field("version", "$label.attestation.verifier").requireIdentifier("$label.attestation.verifier.version", limits)
        val payloadSha256 = fixturePayloadSha256(document, limits.maximumJsonInputBytes)
        if (attestation.field("payloadSha256", "$label.attestation").requireSha256("$label.attestation.payloadSha256") !=
            payloadSha256
        ) structuralFail("$label fixture payload digest does not verify")
        return AttestedFixture(snapshot, document, payloadSha256)
    }
}

private data class BoundaryProjection(
    val objectFormat: String,
    val inputSha256: String,
    val modelImageBase: ULong,
    val ranges: List<Pair<ULong, ULong>>,
)

private fun validateAllBoundaryOracleProjections(
    twins: JsonObject,
    functionOracle: StructuralFunctionOracleV1,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
) {
    listOf("rich", "stripped").forEach { twin ->
        val path = "function-boundary score report.twins.$twin"
        val result = twins.field(twin, "function-boundary score report.twins") as JsonObject
        val artifactValue = result.field("artifact", path)
        val projection = projectBoundaryArtifact(artifactValue, "$path.artifact", target)
        val projectedArtifact = artifactValue as JsonObject
        val upstreamArtifact = functionOracle.artifacts.getValue(twin)
        if (projection.inputSha256 != upstreamArtifact.inputSha256 ||
            projectedArtifact.field("elfType", "$path.artifact").requireString("$path.artifact.elfType", 16) !=
            upstreamArtifact.elfType ||
            projectedArtifact.field("elfImageBase", "$path.artifact")
                .requireAddress("$path.artifact.elfImageBase", target.maximumAddress) != upstreamArtifact.elfImageBase ||
            projection.ranges != upstreamArtifact.executableRvaRanges
        ) structuralFail("$path artifact is not bound to the supplied function oracle")
        val seen = hashSetOf<String>()
        listOf("exactMatches", "nearMisses").forEach { category ->
            result.field(category, path).requireArray("$path.$category", limits.maximumEntities).forEachIndexed { index, raw ->
                validateUpstreamBoundaryFunction(
                    raw as JsonObject,
                    "$path.$category[$index]",
                    twin,
                    functionOracle,
                    target,
                    limits,
                    seen,
                )
            }
        }
        result.field("falseNegatives", path).requireArray("$path.falseNegatives", limits.maximumEntities)
            .forEachIndexed { index, raw ->
                validateUpstreamBoundaryFunction(
                    raw as JsonObject,
                    "$path.falseNegatives[$index]",
                    twin,
                    functionOracle,
                    target,
                    limits,
                    seen,
                )
            }
        if (seen != functionOracle.scoredFunctionIds) {
            structuralFail("$path oracle universe is not the supplied function oracle universe")
        }
    }
}

private fun validateUpstreamBoundaryFunction(
    item: JsonObject,
    path: String,
    twin: String,
    functionOracle: StructuralFunctionOracleV1,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
    seen: MutableSet<String>,
) {
    val id = item.field("oracleId", path).requireIdentifier("$path.oracleId", limits)
    if (!seen.add(id)) structuralFail("function-boundary oracle universe contains a duplicate ID")
    val upstream = functionOracle.scoreableFunctionsByTwin.getValue(twin)[id]
        ?: structuralFail("$path is absent from the supplied function oracle")
    if (item.field("oracleRva", path).requireAddress("$path.oracleRva", target.maximumAddress) != upstream.rva ||
        item.field("oracleAliases", path) != upstream.aliases
    ) structuralFail("$path does not match the supplied function oracle")
}

private fun projectBoundaryArtifact(
    value: JsonElement,
    path: String,
    target: StructuralTargetAbiV1,
): BoundaryProjection {
    val item = value.requireObject(
        path,
        setOf(
            "inputSha256",
            "elfType",
            "elfImageBase",
            "modelImageBase",
            "modelImageBaseEvidence",
            "modelImageBaseValidation",
            "executableRvaRanges",
        ),
    )
    if (target.objectFormat != "ELF") structuralFail("the selected function-boundary adapter object format does not match the target descriptor")
    val input = item.field("inputSha256", path).requireSha256("$path.inputSha256")
    if (item.field("elfType", path).requireString("$path.elfType", 32) !in setOf("ET_EXEC", "ET_DYN")) {
        structuralFail("$path.elfType is invalid")
    }
    item.field("elfImageBase", path).requireAddress("$path.elfImageBase", target.maximumAddress)
    val modelBase = item.field("modelImageBase", path).requireAddress("$path.modelImageBase", target.maximumAddress)
    val ranges = arrayListOf<Pair<ULong, ULong>>()
    item.field("executableRvaRanges", path).requireArray("$path.executableRvaRanges", 256, 1)
        .forEachIndexed { index, raw ->
            val rangePath = "$path.executableRvaRanges[$index]"
            val range = raw.requireObject(rangePath, setOf("start", "endExclusive"))
            val start = range.field("start", rangePath).requireAddress("$rangePath.start", target.maximumAddress)
            val end = range.field("endExclusive", rangePath).requireAddress("$rangePath.endExclusive", target.maximumAddress)
            if (end <= start) structuralFail("$rangePath is empty or reversed")
            if (ranges.isNotEmpty() && start < ranges.last().second) structuralFail("$path.executableRvaRanges overlap or are unsorted")
            ranges += start to end
        }
    return BoundaryProjection("ELF", input, modelBase, ranges.toList())
}

internal fun validateTargetBinding(value: JsonElement, path: String, target: StructuralTargetAbiV1) {
    val binding = value.requireObject(path, setOf("id", "sha256"))
    if (binding.field("id", path).requireString("$path.id", 4096) != target.id ||
        binding.field("sha256", path).requireSha256("$path.sha256") != target.snapshot.sha256
    ) structuralFail("$path does not match the supplied target ABI descriptor")
}

internal fun validateEvidence(value: JsonElement, path: String, limits: StructuralRecoveryV1Limits) {
    val seen = hashSetOf<Pair<String, String>>()
    value.requireArray(path, limits.maximumEvidencePerFact, 1).forEachIndexed { index, raw ->
        val itemPath = "$path[$index]"
        val item = raw.requireObject(itemPath, setOf("kind", "locator"))
        val kind = item.field("kind", itemPath).requireString("$itemPath.kind", 128)
        val locator = item.field("locator", itemPath).requireString("$itemPath.locator", limits.maximumTextCharacters)
        if (!seen.add(kind to locator)) structuralFail("duplicate evidence in $path")
    }
}

private fun validateMappingEvidence(value: JsonElement, path: String, limits: StructuralRecoveryV1Limits) {
    value.requireArray(path, limits.maximumEvidencePerFact, 1).forEachIndexed { index, raw ->
        val itemPath = "$path[$index]"
        val item = raw.requireObject(itemPath, setOf("kind", "oracleLocator", "recoveredLocator", "verifier"))
        item.field("kind", itemPath).requireString("$itemPath.kind", 128)
        item.field("oracleLocator", itemPath).requireString("$itemPath.oracleLocator", limits.maximumTextCharacters)
        item.field("recoveredLocator", itemPath).requireString("$itemPath.recoveredLocator", limits.maximumTextCharacters)
        item.field("verifier", itemPath).requireString("$itemPath.verifier", limits.maximumTextCharacters)
    }
}

internal fun validateEntities(
    value: JsonElement,
    path: String,
    recovered: Boolean,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
) {
    val seenEntities = hashSetOf<StructuralEntityKey>()
    var factCount = 0
    value.requireArray(path, limits.maximumEntities, 1).forEachIndexed { index, raw ->
        val itemPath = "$path[$index]"
        val item = raw.requireObject(itemPath, setOf("kind", "id", "facts"))
        val kind = item.field("kind", itemPath).requireString("$itemPath.kind", 32)
        if (kind !in setOf("function", "global", "type")) structuralFail("$itemPath.kind is invalid")
        val id = item.field("id", itemPath).requireIdentifier("$itemPath.id", limits)
        if (!seenEntities.add(StructuralEntityKey(kind, id))) structuralFail("duplicate entity identity: $kind/$id")
        val facts = item.field("facts", itemPath).requireArray("$itemPath.facts", limits.maximumFactsPerEntity, 1)
        factCount = Math.addExact(factCount, facts.size)
        if (factCount > limits.maximumFacts) structuralFail("$path exceeds the global fact limit")
        val seenFactIds = hashSetOf<String>()
        val seenSlots = hashSetOf<Pair<String, String>>()
        facts.forEachIndexed { factIndex, rawFact ->
            val factPath = "$itemPath.facts[$factIndex]"
            val validated = validateFact(rawFact, factPath, recovered, kind, target, limits)
            if (!seenFactIds.add(validated.id)) structuralFail("duplicate fact ID in $itemPath: ${validated.id}")
            if (!seenSlots.add(validated.dimension to validated.slot)) {
                structuralFail("duplicate fact slot in $itemPath: ${validated.dimension}/${validated.slot}")
            }
        }
    }
}

private data class ValidatedFact(val id: String, val dimension: String, val slot: String)

private fun validateFact(
    value: JsonElement,
    path: String,
    recovered: Boolean,
    entityKind: String,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
): ValidatedFact {
    val stateKey = if (recovered) "state" else "observability"
    val item = value.requireObject(path, setOf("id", "slot", "dimension", "evidence", "value", stateKey))
    val id = item.field("id", path).requireIdentifier("$path.id", limits)
    val dimension = item.field("dimension", path).requireString("$path.dimension", 128)
    if (dimension !in StructuralRecoveryV1Contract.DIMENSIONS) structuralFail("$path.dimension is unsupported")
    if (StructuralRecoveryV1Contract.DIMENSION_ENTITY_KIND[dimension] != entityKind) {
        structuralFail("$path.dimension is incompatible with $entityKind entities")
    }
    val slot = validateSlot(dimension, item.field("slot", path), "$path.slot", target, limits)
    validateEvidence(item.field("evidence", path), "$path.evidence", limits)
    val state = item.field(stateKey, path).requireString("$path.$stateKey", 64)
    val allowed = if (recovered) setOf("recovered", "recovered-unknown") else setOf("observable", "oracle-unobservable")
    if (state !in allowed) structuralFail("$path.$stateKey is invalid")
    val expectsValue = state == "recovered" || state == "observable"
    val factValue = item.field("value", path)
    if (expectsValue != (factValue != JsonNull)) structuralFail("$path.value must be present exactly for a concrete $stateKey")
    if (factValue != JsonNull) validateStructuralValue(factValue, "$path.value", dimension, target, limits)
    return ValidatedFact(id, dimension, slot)
}

internal fun validateStructuralValue(
    value: JsonElement,
    path: String,
    dimension: String,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
): JsonObject {
    val item = value.requireObject(path, setOf("source", "abi"))
    val source = item.field("source", path)
    when {
        dimension == "function.variadic" -> source.requireBoolean("$path.source")
        dimension in StructuralRecoveryV1Contract.INTEGER_SOURCE_DIMENSIONS -> {
            val minimum = if (dimension == "type.enum.enumerator-value") SIGNED_64_MAGNITUDE_MAXIMUM.negate() else BigInteger.ZERO
            source.requireInteger("$path.source", minimum, UNSIGNED_64_MAXIMUM)
        }
        dimension in StructuralRecoveryV1Contract.STRING_SOURCE_DIMENSIONS -> {
            val sourceText = source.requireString("$path.source", limits.maximumTextCharacters)
            validateNormalizedSource(sourceText, "$path.source", dimension, target)
        }
        else -> structuralFail("unsupported structural dimension: $dimension")
    }
    val abi = validateAbiProjection(item.field("abi", path), "$path.abi", target, limits)
    when {
        dimension == "function.calling-convention" -> {
            if (abi == null || abi.field("callingConvention", "$path.abi") == JsonNull) {
                structuralFail("$path.abi must identify a calling convention")
            }
            val sourceConvention = target.conventionAliases[(source as JsonPrimitive).content.removePrefix("convention:")]
                ?: structuralFail("$path.source is absent from the target descriptor's convention vocabulary")
            if (sourceConvention != abi.field("callingConvention", "$path.abi").requireString("$path.abi.callingConvention", 128)) {
                structuralFail("$path.source and ABI calling convention are inconsistent")
            }
            requireProjectionShape(abi, path, allowCallingConvention = true)
        }
        dimension == "function.variadic" -> {
            if (abi == null || abi.field("variadic", "$path.abi") == JsonNull) structuralFail("$path.abi must carry variadic state")
            if (source.requireBoolean("$path.source") != abi.field("variadic", "$path.abi").requireBoolean("$path.abi.variadic")) {
                structuralFail("$path.source and ABI variadic state are inconsistent")
            }
            requireProjectionShape(abi, path, allowVariadic = true)
        }
        dimension in StructuralRecoveryV1Contract.TYPE_REFERENCE_DIMENSIONS -> {
            if (abi == null || abi.field("classes", "$path.abi").requireArray("$path.abi.classes", limits.maximumAbiClasses).isEmpty()) {
                structuralFail("$path.abi must carry at least one ABI class")
            }
            requireProjectionShape(abi, path, allowClasses = true, allowSize = true, allowAlignment = true)
        }
        dimension == "type.aggregate.size-bits" -> {
            if (abi == null || abi.field("sizeBits", "$path.abi") != source) structuralFail("$path.abi.sizeBits must equal the source size")
            requireProjectionShape(abi, path, allowSize = true)
        }
        dimension == "type.aggregate.alignment-bits" -> {
            if (abi == null || abi.field("alignmentBits", "$path.abi") != source) {
                structuralFail("$path.abi.alignmentBits must equal the source alignment")
            }
            requireProjectionShape(abi, path, allowAlignment = true)
        }
        abi != null -> structuralFail("$path.abi is forbidden for a dimension without an explicit ABI equivalence relation")
    }
    return item
}

private fun validateAbiProjection(
    value: JsonElement,
    path: String,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
): JsonObject? {
    if (value == JsonNull) return null
    val item = value.requireObject(path, setOf("callingConvention", "classes", "sizeBits", "alignmentBits", "variadic"))
    val convention = item.field("callingConvention", path).requireNullableString("$path.callingConvention", 128)
    if (convention != null && convention !in target.callingConventions) {
        structuralFail("$path.callingConvention is absent from the target descriptor")
    }
    val classes = item.field("classes", path).requireArray("$path.classes", limits.maximumAbiClasses)
    classes.forEachIndexed { index, raw ->
        if (raw.requireString("$path.classes[$index]", 128) !in target.abiClasses) {
            structuralFail("$path.classes[$index] is absent from the target descriptor")
        }
    }
    listOf("sizeBits", "alignmentBits").forEach { key ->
        item.field(key, path).takeUnless { it == JsonNull }?.requireInteger("$path.$key", BigInteger.ONE)
    }
    item.field("variadic", path).takeUnless { it == JsonNull }?.requireBoolean("$path.variadic")
    if (convention == null && classes.isEmpty() && item.field("sizeBits", path) == JsonNull &&
        item.field("alignmentBits", path) == JsonNull && item.field("variadic", path) == JsonNull
    ) structuralFail("$path must carry at least one ABI datum")
    return item
}

private fun requireProjectionShape(
    abi: JsonObject,
    path: String,
    allowCallingConvention: Boolean = false,
    allowClasses: Boolean = false,
    allowSize: Boolean = false,
    allowAlignment: Boolean = false,
    allowVariadic: Boolean = false,
) {
    val unexpected = arrayListOf<String>()
    if (!allowCallingConvention && abi["callingConvention"] != JsonNull) unexpected += "callingConvention"
    if (!allowClasses && (abi["classes"] as JsonArray).isNotEmpty()) unexpected += "classes"
    if (!allowSize && abi["sizeBits"] != JsonNull) unexpected += "sizeBits"
    if (!allowAlignment && abi["alignmentBits"] != JsonNull) unexpected += "alignmentBits"
    if (!allowVariadic && abi["variadic"] != JsonNull) unexpected += "variadic"
    if (unexpected.isNotEmpty()) structuralFail("$path.abi carries fields irrelevant to this dimension: $unexpected")
}

private fun validateNormalizedSource(
    source: String,
    path: String,
    dimension: String,
    target: StructuralTargetAbiV1,
) {
    val contract = StructuralRecoveryV1Contract
    val valid = when {
        dimension == "function.prototype" -> contract.PROTOTYPE_SOURCE.matches(source)
        dimension == "function.calling-convention" ->
            contract.CONVENTION_SOURCE.matches(source) && source.removePrefix("convention:") in target.conventionAliases
        dimension in contract.TYPE_REFERENCE_DIMENSIONS -> contract.TYPE_SOURCE.matches(source)
        dimension == "call.internal" -> contract.FUNCTION_SOURCE.matches(source)
        dimension == "call.external" -> contract.EXTERNAL_SOURCE.matches(source)
        dimension == "call.indirect" -> contract.INDIRECT_SOURCE.matches(source)
        dimension == "global.reference" -> contract.GLOBAL_SOURCE.matches(source)
        dimension == "global.storage" -> {
            val matches = contract.STORAGE_SOURCE.matches(source)
            if (matches && (source.startsWith("static-rva:") || source.startsWith("tls-offset:"))) {
                JsonPrimitive(source.substringAfter(':')).requireAddress(path, target.maximumAddress)
            }
            matches
        }
        dimension == "global.linkage" -> source in contract.LINKAGE_SOURCES
        dimension == "type.aggregate.kind" -> source in contract.AGGREGATE_KIND_SOURCES
        else -> structuralFail("$path has no string normalization rule")
    }
    if (!valid) structuralFail("$path violates the closed normalization for $dimension")
}

internal fun validateSlot(
    dimension: String,
    value: JsonElement,
    path: String,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
): String {
    val slot = value.requireString(path, limits.maximumIdentifierCharacters)
    val fixed = mapOf(
        "function.prototype" to "prototype",
        "function.calling-convention" to "calling-convention",
        "function.variadic" to "variadic",
        "function.return-abi-class" to "return",
        "global.storage" to "storage",
        "global.linkage" to "linkage",
        "global.type" to "type",
        "type.aggregate.kind" to "aggregate-kind",
        "type.aggregate.size-bits" to "aggregate-size",
        "type.aggregate.alignment-bits" to "aggregate-alignment",
        "type.enum.underlying-abi-class" to "enum-underlying",
        "type.typedef.target" to "typedef-target",
    )
    if (dimension in fixed && slot != fixed[dimension]) structuralFail("$path must be '${fixed[dimension]}'")
    if (dimension == "function.parameter-abi-class" && !StructuralRecoveryV1Contract.PARAMETER_SLOT.matches(slot)) {
        structuralFail("$path must identify a canonical parameter index")
    }
    if (dimension.startsWith("call.")) {
        val match = StructuralRecoveryV1Contract.CALL_SLOT.matchEntire(slot)
            ?: structuralFail("$path must identify a canonical call site and endpoint kind")
        if ("call.${match.groupValues[2]}" != dimension) structuralFail("$path must identify a canonical call site and endpoint kind")
        JsonPrimitive(match.groupValues[1]).requireAddress(path, target.maximumAddress)
    }
    if (dimension == "global.reference") {
        val match = StructuralRecoveryV1Contract.GLOBAL_REFERENCE_SLOT.matchEntire(slot)
            ?: structuralFail("$path must identify a canonical reference site")
        JsonPrimitive(match.groupValues[1]).requireAddress(path, target.maximumAddress)
    }
    if (dimension.startsWith("type.aggregate.member-")) {
        val match = StructuralRecoveryV1Contract.MEMBER_SLOT.matchEntire(slot)
        val expected = if (dimension.endsWith("offset-bits")) "offset" else "type"
        if (match == null || match.groupValues[2] != expected) structuralFail("$path must identify a canonical aggregate member slot")
    }
    if (dimension == "type.enum.enumerator-value" && !StructuralRecoveryV1Contract.ENUMERATOR_SLOT.matches(slot)) {
        structuralFail("$path must identify a canonical enumerator slot")
    }
    return slot
}

private fun ULong.toBigInteger(): BigInteger = BigInteger(toString())

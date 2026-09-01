package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemaException
import decompengine.oracle.core.OracleSchemas
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream
import org.apache.commons.compress.compressors.xz.XZCompressorOutputStream
import org.junit.jupiter.api.Assumptions.assumeTrue

class FullTreeSourceHeaderDependenciesTest {
    @Test
    fun `authenticated fixture preserves module and source-only populations without an empty graph claim`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createDependencyFixture(directory.resolve("complete"))

            val first = assessDependencies(fixture)
            val second = assessDependencies(fixture)
            assertContentEquals(first.canonicalBytes, second.canonicalBytes)
            assertEquals(first.reportSha256, second.reportSha256)
            assertEquals(fixtureSha256(fixture.planning), first.planningInventoryArtifactSha256)
            assertEquals(fixtureSha256(fixture.sourceArchive), first.sourceArchiveSha256)
            assertEquals(first.canonicalSourceHeaderManifestSha256, second.canonicalSourceHeaderManifestSha256)
            assertEquals(first.canonicalSourceHeaderPaths, second.canonicalSourceHeaderPaths)
            assertTrue(first.canonicalSourceHeaderPaths.isEmpty())
            assertTrue(first.canonicalSourceHeaderManifestSha256.matches(Regex("[0-9a-f]{64}")))
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (first.canonicalSourceHeaderPaths as MutableList<String>).add("source/forged.h")
            }

            val document = dependencyDocument(first)
            assertEquals(
                "planning-only-non-authoritative",
                document.controlObject("authority").controlString("status"),
            )
            assertFalse(document.controlObject("authority").getValue("releaseEligible").toString().toBoolean())
            assertFalse(
                document.controlObject("authority").getValue("cleanCompilationProven").toString().toBoolean(),
            )
            val graph = document.controlObject("moduleGraph")
            assertEquals(
                "withheld-until-authenticated-compiler-resolution-and-header-ownership",
                graph.controlString("status"),
            )
            assertFalse(graph.getValue("edgePopulationKnown").toString().toBoolean())
            assertTrue("edges" !in graph)

            val counts = document.controlObject("counts")
            assertEquals(2L, counts.controlLong("sourceModules"))
            assertEquals(1L, counts.controlLong("handwrittenSourceModulesParsed"))
            assertEquals(1L, counts.controlLong("generatedSourceModulesUnavailable"))
            assertEquals(3L, counts.controlLong("sourceOnlyUnits"))
            assertEquals(2, document.controlArray("modules").size)
            assertEquals(3, document.controlArray("sourceOnly").size)
            assertTrue(
                document.controlArray("sourceOnly").controlObjects("source-only records").all {
                    it.controlString("ownershipStatus") == "excluded-non-owning"
                },
            )
            val generated = document.controlArray("modules").controlObjects("modules")
                .single { it.controlString("sourceKind") == "generated" }
            assertEquals("unavailable-generated-source", generated.controlString("sourceStatus"))
            assertEquals(JsonNull, generated["dependencyFacts"])
            assertTrue(document.controlArray("modules").controlObjects("modules").none {
                it.controlString("moduleId") == "core"
            })
        }

    @Test
    fun `authenticated source header manifest includes eligible regular archive files`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createDependencyFixtureWithSourceHeaders(directory.resolve("with-header"))

            val assessment = assessDependencies(fixture)

            assertEquals(listOf("source/clang/include/fixture.h"), assessment.canonicalSourceHeaderPaths)
            assertEquals(
                "0bbcb99f8f2797a547f8949d044d6181350601a0d5be0451bd8e7dd02f8d0ded",
                assessment.canonicalSourceHeaderManifestSha256,
            )
            assertEquals(fixtureSha256(fixture.sourceArchive), assessment.sourceArchiveSha256)
            assertEquals(fixtureSha256(fixture.planning), assessment.planningInventoryArtifactSha256)
        }

    @Test
    fun `directive parser separates local candidates unresolved conditional macro and nonstandard facts`() {
        val source = listOf(
            "/* #include \"commented.h\" */",
            "const char *payload = R\"tag(",
            "#include \"raw-string.h\"",
            ")tag\";",
            "#include \"local.h\"",
            "#include \"../shared.h\"",
            "#include <llvm/ADT/X.h>",
            "#include <dup.h>",
            "#include \"missing.h\"",
            "#include \"../../../../outside.h\"",
            "#include HEADER_MACRO",
            "#include_next <next.h>",
            "#import \"objc.h\"",
            "#if FEATURE",
            "#include \"conditional.h\"",
            "#endif",
            "#incl\\",
            "ude \"continued.h\"",
            "#include \"unterminated",
        ).joinToString("\n", postfix = "\n").toByteArray()
        val (balanced, directives) = parseSourceHeaderDependencyDirectives(
            "source/clang/lib/Driver/main.cpp",
            source,
        )
        assertTrue(balanced)
        assertEquals(12, directives.size)
        val resolved = resolveSourceHeaderDependencyDirectives(
            currentArchivePath = "clang/lib/Driver/main.cpp",
            structureBalanced = balanced,
            directives = directives,
            regularArchivePaths = setOf(
                "clang/lib/Driver/main.cpp",
                "clang/lib/Driver/local.h",
                "clang/lib/Driver/continued.h",
                "clang/lib/shared.h",
                "llvm/include/llvm/ADT/X.h",
                "clang/include/dup.h",
                "llvm/include/dup.h",
            ),
        )

        assertEquals(
            mapOf(
                SourceHeaderDependencyStatus.RESOLVED_LOCAL to 3,
                SourceHeaderDependencyStatus.UNIQUE_ARCHIVE_CANDIDATE to 1,
                SourceHeaderDependencyStatus.AMBIGUOUS_ARCHIVE_CANDIDATE to 1,
                SourceHeaderDependencyStatus.UNRESOLVED_ARCHIVE to 2,
                SourceHeaderDependencyStatus.CONDITIONAL to 1,
                SourceHeaderDependencyStatus.MACRO to 1,
                SourceHeaderDependencyStatus.NONSTANDARD to 2,
                SourceHeaderDependencyStatus.MALFORMED to 1,
            ),
            resolved.groupingBy { it.status }.eachCount(),
        )
        assertEquals(
            listOf("source/llvm/include/llvm/ADT/X.h"),
            resolved.single { it.status == SourceHeaderDependencyStatus.UNIQUE_ARCHIVE_CANDIDATE }.targets,
        )
        assertEquals(
            listOf("source/clang/include/dup.h", "source/llvm/include/dup.h"),
            resolved.single { it.status == SourceHeaderDependencyStatus.AMBIGUOUS_ARCHIVE_CANDIDATE }.targets,
        )
        assertTrue(resolved.none { directive ->
            directive.raw.spelling in setOf("commented.h", "raw-string.h")
        })
    }

    @Test
    fun `unbalanced conditional structure withholds every directive and preserves multiplicity`() {
        val bytes = """
            #include "first.h"
            #include "first.h"
            #if OPEN
            #include "inside.h"
        """.trimIndent().toByteArray()
        val (balanced, directives) = parseSourceHeaderDependencyDirectives("source/clang/lib/file.cpp", bytes)
        assertFalse(balanced)
        assertEquals(3, directives.size)
        val resolved = resolveSourceHeaderDependencyDirectives(
            "clang/lib/file.cpp",
            balanced,
            directives,
            setOf("clang/lib/file.cpp", "clang/lib/first.h", "clang/lib/inside.h"),
        )
        assertEquals(3, resolved.size)
        assertTrue(resolved.all { it.status == SourceHeaderDependencyStatus.CONDITIONAL })
        assertTrue(resolved.all { it.targets.isEmpty() })
    }

    @Test
    fun `parser and candidate lowering bounds fail closed`() {
        assertFailsWith<FullTreeSourceHeaderDependencyException> {
            parseSourceHeaderDependencyDirectives(
                "source/clang/lib/file.cpp",
                "#include \"too-long.h\"".toByteArray(),
                maximumLogicalLineBytes = 8,
            )
        }
        assertFailsWith<FullTreeSourceHeaderDependencyException> {
            parseSourceHeaderDependencyDirectives(
                "source/clang/lib/file.cpp",
                "#include \"one.h\"\n#include \"two.h\"\n".toByteArray(),
                maximumDirectives = 1,
            )
        }
        assertFailsWith<FullTreeSourceHeaderDependencyException> {
            parseSourceHeaderDependencyDirectives(
                "source/clang/lib/file.cpp",
                byteArrayOf('#'.code.toByte(), 0, '\n'.code.toByte()),
            )
        }
        val (_, directives) = parseSourceHeaderDependencyDirectives(
            "source/clang/lib/file.cpp",
            "#include <shared.h>\n".toByteArray(),
        )
        assertFailsWith<FullTreeSourceHeaderDependencyException> {
            resolveSourceHeaderDependencyDirectives(
                "clang/lib/file.cpp",
                true,
                directives,
                setOf("clang/include/shared.h", "llvm/include/shared.h"),
                maximumCandidatesPerDirective = 1,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            FullTreeSourceHeaderDependencyLimits(maximumCandidatesPerDirective = 65)
        }
    }

    @Test
    fun `lowered archive bounds symbolic links aliases and schema overclaims fail closed`(): Unit =
        inControlTemporaryDirectory { directory ->
            val bounded = createDependencyFixture(directory.resolve("bounded"))
            assertFailsWith<FullTreeSourceHeaderDependencyException> {
                assessDependencies(
                    bounded,
                    FullTreeSourceHeaderDependencyLimits(maximumParsedFileBytes = 1),
                )
            }

            val linked = createDependencyFixture(directory.resolve("linked"))
            val aliasRoot = directory.resolve("aliases")
            Files.createDirectories(aliasRoot)
            Files.setPosixFilePermissions(aliasRoot, PosixFilePermissions.fromString("rwx------"))
            val alias = aliasRoot.resolve("source.tar.xz")
            Files.createSymbolicLink(alias, linked.control.sourceArchive)
            assertFailsWith<FullTreeSourceHeaderDependencyException> {
                assessDependencies(linked.copy(sourceArchive = alias))
            }
            assertFailsWith<FullTreeSourceHeaderDependencyException> {
                assessDependencies(linked.copy(sourceArchive = linked.control.scope))
            }

            val valid = dependencyDocument(assessDependencies(linked))
            val overclaim = JsonObject(
                valid + ("moduleGraph" to JsonObject(
                    valid.controlObject("moduleGraph") + ("edgePopulationKnown" to JsonPrimitive(true)),
                )),
            )
            assertFailsWith<OracleSchemaException> {
                OracleSchemas.validate("full-tree-source-header-dependencies", overclaim)
            }

            val forgedModules = valid.controlArray("modules").map { element ->
                val module = element as JsonObject
                if (module.controlString("sourceKind") == "generated") {
                    JsonObject(module + ("sourceStatus" to JsonPrimitive("authenticated-archive-parsed")))
                } else {
                    module
                }
            }
            assertFailsWith<OracleSchemaException> {
                OracleSchemas.validate(
                    "full-tree-source-header-dependencies",
                    JsonObject(valid + ("modules" to JsonArray(forgedModules))),
                )
            }

            val duplicatePath = JsonPrimitive("source/clang/lib/duplicate.h")
            val duplicateListModules = valid.controlArray("modules").map { element ->
                val module = element as JsonObject
                if (module.controlString("sourceKind") == "handwritten") {
                    val facts = module.controlObject("dependencyFacts")
                    JsonObject(
                        module + ("dependencyFacts" to JsonObject(
                            facts + ("resolvedLocalFiles" to JsonArray(listOf(duplicatePath, duplicatePath))),
                        )),
                    )
                } else {
                    module
                }
            }
            assertFailsWith<OracleSchemaException> {
                OracleSchemas.validate(
                    "full-tree-source-header-dependencies",
                    JsonObject(valid + ("modules" to JsonArray(duplicateListModules))),
                )
            }
        }

    @Test
    fun `JVM construction and public API accept only raw paths and lowering limits`() {
        val implementation = Class.forName(
            "decompengine.oracle.fulltree.FullTreeSourceHeaderDependencies\$ValidatedAssessment",
        )
        assertTrue(implementation.declaredConstructors.isNotEmpty())
        implementation.declaredConstructors.forEach { constructor ->
            val unsupported = constructor.parameterTypes.filterNot { type ->
                type == Path::class.java ||
                    type == FullTreeSourceHeaderDependencyLimits::class.java ||
                    type.name == "kotlin.jvm.internal.DefaultConstructorMarker"
            }
            assertTrue(unsupported.isEmpty(), "unexpected constructor inputs: $unsupported")
            assertFalse(constructor.parameterTypes.any { it == ByteArray::class.java })
            assertFalse(constructor.parameterTypes.any { JsonObject::class.java.isAssignableFrom(it) })
            assertFalse(constructor.parameterTypes.any {
                AuthenticatedFullTreePlanningRegistry::class.java.isAssignableFrom(it)
            })
        }
        FullTreeSourceHeaderDependencies::class.java.declaredMethods
            .filter { Modifier.isPublic(it.modifiers) && it.name == "assess" }
            .forEach { method ->
                assertTrue(method.parameterTypes.all {
                    it == Path::class.java || it == FullTreeSourceHeaderDependencyLimits::class.java
                })
            }
    }

    @Test
    fun `locked LLVM source archive reproduces exact dependency populations`() {
        val archive = System.getenv("DECOMP_LLVM_SOURCE_ARCHIVE")
            ?.takeIf(String::isNotBlank)?.let(Path::of)
        assumeTrue(archive != null && Files.isRegularFile(archive), "set DECOMP_LLVM_SOURCE_ARCHIVE")
        val profile = Path.of("oracle/llvm/22.1.6").toAbsolutePath().normalize()
        val assessment = FullTreeSourceHeaderDependencies.assess(
            requireNotNull(archive),
            profile.resolve("full-tree-scope.json"),
            profile.resolve("source-lock.json"),
            profile.resolve("oracle-manifest.json"),
            profile.resolve("build-record.json"),
            profile.resolve("full-tree-inventory.json"),
            profile.resolve("full-tree-source-inventory.json"),
            profile.resolve("full-tree-planning-inventory.json"),
        )
        val document = dependencyDocument(assessment)
        val counts = document.controlObject("counts")

        assertEquals(
            JsonObject(
                mapOf(
                    "ambiguousArchiveCandidateDirectives" to JsonPrimitive(59),
                    "conditionalDirectives" to JsonPrimitive(24_831),
                    "dependencyFilesWithFacts" to JsonPrimitive(4_904),
                    "directives" to JsonPrimitive(87_423),
                    "generatedSourceModulesUnavailable" to JsonPrimitive(1),
                    "handwrittenSourceModulesParsed" to JsonPrimitive(2_149),
                    "indexedRelevantRegularFiles" to JsonPrimitive(108_590),
                    "macroDirectives" to JsonPrimitive(0),
                    "malformedDirectives" to JsonPrimitive(0),
                    "nonstandardDirectives" to JsonPrimitive(77),
                    "parsedBytes" to JsonPrimitive(207_334_974),
                    "parsedFiles" to JsonPrimitive(11_053),
                    "resolvedLocalDirectives" to JsonPrimitive(7_570),
                    "resolvedLocalFileEdges" to JsonPrimitive(6_040),
                    "sharedHeaders" to JsonPrimitive(300),
                    "sourceModules" to JsonPrimitive(2_150),
                    "sourceOnlyUnits" to JsonPrimitive(2_325),
                    "uniqueArchiveCandidateDirectives" to JsonPrimitive(47_391),
                    "uniqueArchiveCandidateFileReferences" to JsonPrimitive(46_881),
                    "unresolvedArchiveDirectives" to JsonPrimitive(7_495),
                    "workUnits" to JsonPrimitive(401_564),
                ),
            ),
            counts,
        )
        val archiveEvidence = document.controlObject("archive")
        assertEquals(167_043_464L, archiveEvidence.controlLong("compressedBytes"))
        assertEquals(2_161_858_560L, archiveEvidence.controlLong("expandedBytes"))
        assertEquals(184_819L, archiveEvidence.controlLong("memberCount"))
        assertEquals(169_003L, archiveEvidence.controlLong("regularFileCount"))
        assertEquals(REAL_SOURCE_HEADER_COUNT, assessment.canonicalSourceHeaderPaths.size)
        assertEquals(REAL_SOURCE_HEADER_MANIFEST_SHA256, assessment.canonicalSourceHeaderManifestSha256)
        assertEquals(
            assessment.canonicalSourceHeaderPaths.sortedWith(FULL_TREE_CODE_POINT_ORDER),
            assessment.canonicalSourceHeaderPaths,
        )
        assertEquals(REAL_PARITY_OUTPUT_SHA256, OracleArtifacts.sha256(assessment.canonicalBytes))
        assertEquals(REAL_PARITY_REPORT_SHA256, assessment.reportSha256)
        assertEquals(REAL_PARITY_OUTPUT_BYTES, assessment.canonicalBytes.size)
    }

    private companion object {
        const val REAL_PARITY_OUTPUT_SHA256 =
            "8650d4c302d9071b6ad1aa08c45a0bb35037ff2951ae63200536a7e9c34e3798"
        const val REAL_PARITY_REPORT_SHA256 =
            "33abce3226fc60143c5d4586689f2e43db0ab14e10acaf4288c062899ff329bf"
        const val REAL_PARITY_OUTPUT_BYTES = 14_218_981
        const val REAL_SOURCE_HEADER_COUNT = 6_579
        const val REAL_SOURCE_HEADER_MANIFEST_SHA256 =
            "a508d401c9904e2a18b52bb6f1e77cf06d0944e5ced8888c4c010f196e2310fc"
    }
}

internal data class DependencyFixture(
    val control: FullTreeControlFixture,
    val planning: Path,
    val sourceArchive: Path = control.sourceArchive,
)

private fun createDependencyFixture(root: Path): DependencyFixture {
    Files.createDirectories(root)
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
    val control = createFullTreeControlFixture(root.resolve("control"))
    val planning = root.resolve("planning.json")
    FullTreePlanningInventoryControl.generateAndPublish(
        control.scope,
        control.sourceLock,
        control.manifest,
        control.buildRecord,
        control.inventory,
        control.sourceInventory,
        planning,
    )
    return DependencyFixture(control, planning)
}

internal fun createDependencyFixtureWithSourceHeaders(
    root: Path,
    headerNames: List<String> = listOf("fixture.h"),
): DependencyFixture {
    val fixture = createDependencyFixture(root)
    addFixtureSourceHeaders(fixture.control.sourceArchive, headerNames)

    val archiveSha256 = fixtureSha256(fixture.control.sourceArchive)
    val archiveBytes = Files.size(fixture.control.sourceArchive)
    val sourceLock = parseControlObject(fixture.control.sourceLock)
    val source = sourceLock.controlObject("source")
    val archive = source.controlObject("archive")
    writeControlObject(
        fixture.control.sourceLock,
        JsonObject(
            sourceLock + ("source" to JsonObject(
                source + ("archive" to JsonObject(
                    archive + mapOf(
                        "bytes" to JsonPrimitive(archiveBytes),
                        "sha256" to JsonPrimitive(archiveSha256),
                    ),
                )),
            )),
        ),
    )
    val sourceLockSha256 = fixtureSha256(fixture.control.sourceLock)
    val buildRecord = parseControlObject(fixture.control.buildRecord)
    writeControlObject(
        fixture.control.buildRecord,
        JsonObject(
            buildRecord + ("oracle" to JsonObject(
                buildRecord.controlObject("oracle") +
                    ("sourceLockSha256" to JsonPrimitive(sourceLockSha256)),
            )),
        ),
    )
    val manifest = parseControlObject(fixture.control.manifest)
    val manifestInputs = manifest.controlObject("inputs")
    writeControlObject(
        fixture.control.manifest,
        JsonObject(
            manifest + ("inputs" to JsonObject(
                manifestInputs + mapOf(
                    "buildRecord" to JsonObject(
                        manifestInputs.controlObject("buildRecord") + mapOf(
                            "bytes" to JsonPrimitive(Files.size(fixture.control.buildRecord)),
                            "sha256" to JsonPrimitive(fixtureSha256(fixture.control.buildRecord)),
                        ),
                    ),
                    "sourceLock" to JsonObject(
                        manifestInputs.controlObject("sourceLock") + mapOf(
                            "bytes" to JsonPrimitive(Files.size(fixture.control.sourceLock)),
                            "sha256" to JsonPrimitive(sourceLockSha256),
                        ),
                    ),
                ),
            )),
        ),
    )
    val artifactManifestSha256 = fixtureSha256(fixture.control.manifest)
    val scope = parseControlObject(fixture.control.scope)
    writeControlObject(
        fixture.control.scope,
        JsonObject(
            scope + ("oracle" to JsonObject(
                scope.controlObject("oracle") +
                    mapOf(
                        "artifactManifestSha256" to JsonPrimitive(artifactManifestSha256),
                        "sourceLockSha256" to JsonPrimitive(sourceLockSha256),
                    ),
            )),
        ),
    )
    val authenticatedScope = FullTreeScopeControl.load(
        fixture.control.scope,
        fixture.control.sourceLock,
        fixture.control.manifest,
    )
    FullTreeInventoryControl.generateAndPublish(
        fixture.control.richArtifact,
        authenticatedScope,
        fixture.control.inventory,
        maximumWorkers = 1,
    )
    FullTreeSourceInventoryControl.generateAndPublish(
        fixture.control.sourceArchive,
        authenticatedScope,
        fixture.control.buildRecord,
        fixture.control.inventory,
        fixture.control.sourceInventory,
        maximumWorkers = 1,
    )
    FullTreePlanningInventoryControl.generateAndPublish(
        fixture.control.scope,
        fixture.control.sourceLock,
        fixture.control.manifest,
        fixture.control.buildRecord,
        fixture.control.inventory,
        fixture.control.sourceInventory,
        fixture.planning,
    )
    return fixture
}

private fun addFixtureSourceHeaders(archivePath: Path, headerNames: List<String>) {
    require(headerNames.isNotEmpty() && headerNames.distinct().size == headerNames.size)
    val expanded = XZCompressorInputStream(
        ByteArrayInputStream(Files.readAllBytes(archivePath)),
    ).use { it.readAllBytes() }
    val prefixBytes = fixtureTarPrefixBytes(expanded)
    val entries = headerNames.map { name ->
        require(name.matches(Regex("[A-Za-z0-9][A-Za-z0-9._+-]*")))
        canonicalFixtureTarEntry(
            "llvm-project-22.1.6.src/clang/include/$name",
            0x1b4,
            "#pragma once\n".toByteArray(),
        )
    }
    val unpaddedBytes = entries.fold(prefixBytes) { total, entry -> Math.addExact(total, entry.size) }
    var terminatorBytes = (10_240 - unpaddedBytes % 10_240) % 10_240
    if (terminatorBytes < 1_024) terminatorBytes += 10_240
    require(terminatorBytes in 1_024..10_752 && terminatorBytes % 512 == 0)
    val encoded = ByteArrayOutputStream()
    XZCompressorOutputStream(encoded).use { compressed ->
        compressed.write(expanded, 0, prefixBytes)
        entries.forEach(compressed::write)
        compressed.write(ByteArray(terminatorBytes))
    }
    Files.write(archivePath, encoded.toByteArray())
    Files.setPosixFilePermissions(archivePath, PosixFilePermissions.fromString("rw-r--r--"))
}

private fun fixtureTarPrefixBytes(expanded: ByteArray): Int {
    var offset = 0
    while (true) {
        require(offset <= expanded.size - 512)
        if ((offset until offset + 512).all { expanded[it] == 0.toByte() }) return offset
        val size = expanded.copyOfRange(offset + 124, offset + 136)
        require(size.last() == 0.toByte())
        val payloadBytes = size.copyOfRange(0, size.lastIndex)
            .toString(Charsets.US_ASCII)
            .toLong(8)
        val paddedPayloadBytes = Math.multiplyExact(Math.addExact(payloadBytes, 511) / 512, 512)
        offset = Math.toIntExact(Math.addExact(offset.toLong() + 512, paddedPayloadBytes))
    }
}

private fun canonicalFixtureTarEntry(name: String, mode: Int, bytes: ByteArray): ByteArray {
    val header = ByteArray(512)
    require(name.toByteArray(Charsets.US_ASCII).size <= 100)
    putFixtureTarText(header, 0, 100, name)
    putFixtureTarOctal(header, 100, 8, mode.toLong())
    putFixtureTarOctal(header, 108, 8, 0)
    putFixtureTarOctal(header, 116, 8, 0)
    putFixtureTarOctal(header, 124, 12, bytes.size.toLong())
    putFixtureTarOctal(header, 136, 12, 0)
    header.fill(0x20, 148, 156)
    header[156] = '0'.code.toByte()
    putFixtureTarText(header, 257, 6, "ustar")
    putFixtureTarText(header, 263, 2, "00", terminate = false)
    putFixtureTarText(header, 265, 32, "root")
    putFixtureTarText(header, 297, 32, "root")
    putFixtureTarOctal(header, 329, 8, 0)
    putFixtureTarOctal(header, 337, 8, 0)
    putFixtureTarOctal(header, 148, 8, header.sumOf { it.toInt() and 0xff }.toLong())
    return ByteArrayOutputStream().use { output ->
        output.write(header)
        output.write(bytes)
        output.write(ByteArray((512 - bytes.size % 512) % 512))
        output.toByteArray()
    }
}

private fun putFixtureTarText(
    target: ByteArray,
    offset: Int,
    length: Int,
    value: String,
    terminate: Boolean = true,
) {
    val bytes = value.toByteArray(Charsets.US_ASCII)
    require(bytes.size <= length - if (terminate) 1 else 0)
    bytes.copyInto(target, offset)
}

private fun putFixtureTarOctal(target: ByteArray, offset: Int, length: Int, value: Long) {
    val encoded = value.toString(8).padStart(length - 1, '0').toByteArray(Charsets.US_ASCII)
    require(encoded.size == length - 1)
    encoded.copyInto(target, offset)
    target[offset + length - 1] = 0
}

private fun assessDependencies(
    fixture: DependencyFixture,
    limits: FullTreeSourceHeaderDependencyLimits = FullTreeSourceHeaderDependencyLimits(),
): FullTreeSourceHeaderDependencyAssessment = FullTreeSourceHeaderDependencies.assess(
    fixture.sourceArchive,
    fixture.control.scope,
    fixture.control.sourceLock,
    fixture.control.manifest,
    fixture.control.buildRecord,
    fixture.control.inventory,
    fixture.control.sourceInventory,
    fixture.planning,
    limits,
)

private fun dependencyDocument(assessment: FullTreeSourceHeaderDependencyAssessment): JsonObject =
    OracleJson.parseCanonical(
        assessment.canonicalBytes,
        controlJsonLimits(DEPENDENCY_MAXIMUM_SERIALIZED_BYTES),
    ) as JsonObject

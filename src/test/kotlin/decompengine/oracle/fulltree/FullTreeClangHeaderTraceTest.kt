package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class FullTreeClangHeaderTraceTest {
    @Test
    fun `structured direct-per-file trace projects project and external facts exactly`() {
        val bytes = """
            {
              "version":"2.0.0",
              "dependencies":[
                {
                  "source":"/oracle/source/clang/lib/Lex/Lexer.cpp",
                  "includes":[
                    {"location":"virtual:name:400:7","file":"/oracle/source/clang/include/clang/Lex/Lexer.h"},
                    {"location":"/oracle/source/clang/lib/Lex/Lexer.cpp:8:1","file":"/oracle/build/include/llvm/Config/llvm-config.h"},
                    {"location":"/oracle/source/clang/lib/Lex/Lexer.cpp:9:1","file":"/usr/include/stddef.h"}
                  ],
                  "imports":[]
                },
                {
                  "source":"/oracle/source/clang/include/clang/Lex/Lexer.h",
                  "includes":[
                    {"location":"/oracle/source/clang/include/clang/Lex/Lexer.h:3:2","file":"/oracle/source/llvm/include/llvm/ADT/StringRef.h"}
                  ],
                  "imports":[
                    {"location":"/oracle/source/clang/include/clang/Lex/Lexer.h:4:1","module":"Builtin","file":"/oracle/build/module.modulemap"}
                  ]
                }
              ]
            }
        """.trimIndent().toByteArray()

        val trace = parse(bytes)

        assertEquals(OracleArtifacts.sha256(bytes), trace.inputSha256)
        assertEquals(2, trace.dependencyFileCount)
        assertEquals(listOf("/usr/include/stddef.h"), trace.externalFiles)
        assertEquals(
            listOf(
                FullTreeClangIncludeOccurrence(
                    "source/clang/include/clang/Lex/Lexer.h",
                    "/oracle/source/clang/include/clang/Lex/Lexer.h",
                    3,
                    2,
                    "source/llvm/include/llvm/ADT/StringRef.h",
                ),
                FullTreeClangIncludeOccurrence(
                    "source/clang/lib/Lex/Lexer.cpp",
                    "virtual:name",
                    400,
                    7,
                    "source/clang/include/clang/Lex/Lexer.h",
                ),
                FullTreeClangIncludeOccurrence(
                    "source/clang/lib/Lex/Lexer.cpp",
                    "/oracle/source/clang/lib/Lex/Lexer.cpp",
                    8,
                    1,
                    "generated/include/llvm/Config/llvm-config.h",
                ),
            ),
            trace.includeOccurrences,
        )
        assertEquals(
            listOf(
                FullTreeClangExternalIncludeOccurrence(
                    "source/clang/lib/Lex/Lexer.cpp",
                    "/oracle/source/clang/lib/Lex/Lexer.cpp",
                    9,
                    1,
                    "/usr/include/stddef.h",
                ),
            ),
            trace.externalIncludeOccurrences,
        )
        assertEquals(
            listOf(
                FullTreeClangModuleImport(
                    "source/clang/include/clang/Lex/Lexer.h",
                    "/oracle/source/clang/include/clang/Lex/Lexer.h",
                    4,
                    1,
                    "Builtin",
                    "/oracle/build/module.modulemap",
                    "generated/module.modulemap",
                ),
            ),
            trace.moduleImports,
        )
        assertEquals(
            listOf(
                "generated/include/llvm/Config/llvm-config.h",
                "generated/module.modulemap",
                "source/clang/include/clang/Lex/Lexer.h",
                "source/clang/lib/Lex/Lexer.cpp",
                "source/llvm/include/llvm/ADT/StringRef.h",
            ),
            trace.projectFiles,
        )
    }

    @Test
    fun `empty output is bound to expected TU while impossible empty JSON records fail`() {
        val first = parse(byteArrayOf(), "source/clang/lib/Empty.cpp")
        val second = parse(byteArrayOf(), "source/clang/lib/Other.cpp")
        assertEquals(0, first.dependencyFileCount)
        assertTrue(first.includeOccurrences.isEmpty())
        assertNotEquals(first.canonicalFactsSha256, second.canonicalFactsSha256)

        val impossible = """
            {"version":"2.0.0","dependencies":[{
              "source":"/oracle/source/clang/lib/Lex/Lexer.cpp","includes":[],"imports":[]
            }]}
        """.trimIndent().toByteArray()
        assertFailsWith<FullTreeClangHeaderTraceException> { parse(impossible) }
        assertFailsWith<FullTreeClangHeaderTraceException> {
            parse("""{"version":"2.0.0","dependencies":[]}""".toByteArray())
        }
    }

    @Test
    fun `record order does not affect canonical facts and duplicate occurrences remain`() {
        val main = record(
            "/oracle/source/clang/lib/Lex/Lexer.cpp",
            listOf(
                include("/oracle/source/clang/lib/Lex/Lexer.cpp:1:1", "/oracle/source/clang/include/X.h"),
                include("/oracle/source/clang/lib/Lex/Lexer.cpp:1:1", "/oracle/source/clang/include/X.h"),
            ),
        )
        val header = record(
            "/oracle/source/clang/include/X.h",
            listOf(include("/oracle/source/clang/include/X.h:2:1", "/usr/include/a.h")),
        )
        val first = document(listOf(main, header)).toByteArray()
        val second = document(listOf(header, main)).toByteArray()
        val firstTrace = parse(first)
        val secondTrace = parse(second)

        assertNotEquals(firstTrace.inputSha256, secondTrace.inputSha256)
        assertEquals(firstTrace.canonicalFactsSha256, secondTrace.canonicalFactsSha256)
        assertEquals(firstTrace.includeOccurrences, secondTrace.includeOccurrences)
        assertEquals(2, firstTrace.includeOccurrences.count { it.dependencyPath.endsWith("/X.h") })
    }

    @Test
    fun `ordinary physical locations canonicalize across authenticated root mappings`() {
        val firstBytes = document(
            listOf(
                record(
                    "/first/source/clang/lib/Lex/Lexer.cpp",
                    listOf(
                        include(
                            "/first/source/clang/lib/Lex/Lexer.cpp:1:1",
                            "/first/build/X.h",
                        ),
                    ),
                ),
            ),
        ).toByteArray()
        val secondBytes = firstBytes.decodeToString()
            .replace("/first/source", "/second/source")
            .replace("/first/build", "/second/build")
            .toByteArray()
        val first = FullTreeClangHeaderTraceParser.parse(
            firstBytes,
            listOf(
                FullTreeClangTraceRoot("/first/source", "source"),
                FullTreeClangTraceRoot("/first/build", "generated"),
            ),
            "source/clang/lib/Lex/Lexer.cpp",
        )
        val second = FullTreeClangHeaderTraceParser.parse(
            secondBytes,
            listOf(
                FullTreeClangTraceRoot("/second/source", "source"),
                FullTreeClangTraceRoot("/second/build", "generated"),
            ),
            "source/clang/lib/Lex/Lexer.cpp",
        )
        assertNotEquals(first.inputSha256, second.inputSha256)
        assertEquals(first.canonicalFactsSha256, second.canonicalFactsSha256)
    }

    @Test
    fun `schema path source and root confusion fail closed`() {
        val valid = document(
            listOf(
                record(
                    "/oracle/source/clang/lib/Lex/Lexer.cpp",
                    listOf(include("/oracle/source/clang/lib/Lex/Lexer.cpp:1:1", "/oracle/build/X.h")),
                ),
            ),
        )
        listOf(
            valid.replace("\"version\":\"2.0.0\"", "\"version\":\"1.0.0\""),
            valid.replace("\"imports\":[]", "\"imports\":[],\"extra\":false"),
            valid.replace("/oracle/build/X.h", "/oracle\\build\\X.h"),
            valid.replace(
                "\"source\":\"/oracle/source/clang/lib/Lex/Lexer.cpp\"",
                "\"source\":\"\"",
            ),
            valid.replace(":1:1", ":1:0"),
        ).forEach { malformed ->
            assertFailsWith<FullTreeClangHeaderTraceException> { parse(malformed.toByteArray()) }
        }

        assertFailsWith<FullTreeClangHeaderTraceException> {
            FullTreeClangHeaderTraceParser.parse(
                byteArrayOf(),
                listOf(
                    FullTreeClangTraceRoot("/oracle/root", "source"),
                    FullTreeClangTraceRoot("/oracle/root", "generated"),
                ),
                "source/clang/lib/Lex/Lexer.cpp",
            )
        }
    }

    @Test
    fun `outside-root consumers and lexical resource paths remain classified evidence`() {
        val outside = document(
            listOf(
                record(
                    "/usr/include/gentoo/maybe-stddefs.h",
                    listOf(
                        include(
                            "/usr/include/gentoo/maybe-stddefs.h:1:1",
                            "/usr/lib/llvm/22/bin/../../../../lib/clang/22/include/stddef.h",
                        ),
                    ),
                ),
            ),
        ).toByteArray()
        val trace = parse(outside)
        assertEquals(
            listOf(
                "/usr/include/gentoo/maybe-stddefs.h",
                "/usr/lib/llvm/22/bin/../../../../lib/clang/22/include/stddef.h",
            ),
            trace.externalFiles,
        )
        assertEquals(1, trace.externalConsumerIncludeOccurrences.size)
        assertEquals(
            "/usr/lib/llvm/22/bin/../../../../lib/clang/22/include/stddef.h",
            trace.externalConsumerIncludeOccurrences.single().observedDependencyPath,
        )
        assertTrue(trace.projectFiles.isEmpty())

        val normalizedProject = document(
            listOf(
                record(
                    "/oracle/source/clang/lib/Lex/Lexer.cpp",
                    listOf(
                        include(
                            "/oracle/source/clang/lib/Lex/Lexer.cpp:1:1",
                            "/oracle/build/subdirectory/../X.h",
                        ),
                    ),
                ),
            ),
        ).toByteArray()
        val noncanonical = parse(normalizedProject)
        assertTrue(noncanonical.includeOccurrences.isEmpty())
        assertEquals(
            "/oracle/build/subdirectory/../X.h",
            noncanonical.externalIncludeOccurrences.single().observedDependencyPath,
        )

        val relative = parse(
            document(
                listOf(
                    record(
                        "source/clang/lib/Lex/Lexer.cpp",
                        listOf(include("source/clang/lib/Lex/Lexer.cpp:1:1", "generated/X.h")),
                    ),
                ),
            ).toByteArray(),
        )
        assertEquals(
            listOf("generated/X.h", "source/clang/lib/Lex/Lexer.cpp"),
            relative.externalFiles,
        )
        assertEquals(1, relative.externalConsumerIncludeOccurrences.size)
        assertNotEquals(relative.canonicalFactsSha256, parse(normalizedProject).canonicalFactsSha256)
    }

    @Test
    fun `presumed filenames remain opaque and allow empty labels and line zero`() {
        fun withLocation(location: String): FullTreeClangHeaderTrace = parse(
            document(
                listOf(
                    record(
                        "/oracle/source/clang/lib/Lex/Lexer.cpp",
                        listOf(include(location, "/oracle/build/X.h")),
                    ),
                ),
            ).toByteArray(),
        )

        val empty = withLocation(":0:1")
        assertEquals("", empty.includeOccurrences.single().presumedLocationFile)
        assertEquals(0, empty.includeOccurrences.single().line)
        val rootLabel = withLocation("/oracle/source:1:1")
        assertEquals("/oracle/source", rootLabel.includeOccurrences.single().presumedLocationFile)
        assertNotEquals(
            withLocation("/oracle/source/foo:1:1").canonicalFactsSha256,
            withLocation("source/foo:1:1").canonicalFactsSha256,
        )
    }

    @Test
    fun `raw external entities and independent limits fail closed`() {
        val twoExternalIncludes = document(
            listOf(
                record(
                    "/oracle/source/clang/lib/Lex/Lexer.cpp",
                    listOf(
                        include("/oracle/source/clang/lib/Lex/Lexer.cpp:1:1", "/usr/include/a.h"),
                        include("/oracle/source/clang/lib/Lex/Lexer.cpp:2:1", "/usr/include/b.h"),
                    ),
                ),
            ),
        ).toByteArray()
        assertFailsWith<FullTreeClangHeaderTraceException> {
            parse(twoExternalIncludes, limits = FullTreeClangHeaderTraceLimits(maximumIncludeOccurrences = 1))
        }

        val twoDependencies = document(
            listOf(
                record(
                    "/oracle/source/clang/lib/Lex/Lexer.cpp",
                    listOf(include("/oracle/source/clang/lib/Lex/Lexer.cpp:1:1", "/oracle/build/X.h")),
                ),
                record(
                    "/oracle/source/clang/include/X.h",
                    listOf(include("/oracle/source/clang/include/X.h:1:1", "/oracle/build/Y.h")),
                ),
            ),
        ).toByteArray()
        assertFailsWith<FullTreeClangHeaderTraceException> {
            parse(twoDependencies, limits = FullTreeClangHeaderTraceLimits(maximumDependencyFiles = 1))
        }
        assertFailsWith<FullTreeClangHeaderTraceException> {
            parse(twoDependencies, limits = FullTreeClangHeaderTraceLimits(maximumWorkUnits = 1))
        }
        assertFailsWith<FullTreeClangHeaderTraceException> {
            parse(twoDependencies, limits = FullTreeClangHeaderTraceLimits(maximumPathBytes = 8))
        }
    }

    @Test
    fun `returned collections cannot be mutated after fact digest binding`() {
        val trace = parse(
            document(
                listOf(
                    record(
                        "/oracle/source/clang/lib/Lex/Lexer.cpp",
                        listOf(
                            include("/oracle/source/clang/lib/Lex/Lexer.cpp:1:1", "/oracle/build/A.h"),
                            include("/oracle/source/clang/lib/Lex/Lexer.cpp:2:1", "/oracle/build/B.h"),
                        ),
                    ),
                ),
            ).toByteArray(),
        )
        @Suppress("UNCHECKED_CAST")
        val mutable = trace.includeOccurrences as MutableList<FullTreeClangIncludeOccurrence>
        assertFailsWith<UnsupportedOperationException> { mutable.removeAt(0) }
        @Suppress("UNCHECKED_CAST")
        val files = trace.projectFiles as MutableList<String>
        assertFailsWith<UnsupportedOperationException> { files.add("source/forged.h") }
    }

    private fun parse(
        bytes: ByteArray,
        expected: String = "source/clang/lib/Lex/Lexer.cpp",
        limits: FullTreeClangHeaderTraceLimits = FullTreeClangHeaderTraceLimits(),
    ): FullTreeClangHeaderTrace = FullTreeClangHeaderTraceParser.parse(bytes, roots(), expected, limits)

    private fun roots(): List<FullTreeClangTraceRoot> = listOf(
        FullTreeClangTraceRoot("/oracle/source", "source"),
        FullTreeClangTraceRoot("/oracle/build", "generated"),
    )

    private fun include(location: String, file: String): String =
        """{"location":"$location","file":"$file"}"""

    private fun record(source: String, includes: List<String>): String =
        """{"source":"$source","includes":[${includes.joinToString(",")}],"imports":[]}"""

    private fun document(records: List<String>): String =
        """{"version":"2.0.0","dependencies":[${records.joinToString(",")}]}"""
}

package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class FullTreeClangHeaderTraceTest {
    @Test
    fun `structured direct-per-file trace projects source and generated edges exactly`() {
        val bytes = """
            {
              "version":"2.0.0",
              "dependencies":[
                {
                  "source":"/oracle/source/clang/lib/Lex/Lexer.cpp",
                  "includes":[
                    {
                      "location":"/oracle/source/clang/lib/Lex/Lexer.cpp:7:1",
                      "file":"/oracle/source/clang/include/clang/Lex/Lexer.h"
                    },
                    {
                      "location":"/oracle/source/clang/lib/Lex/Lexer.cpp:8:1",
                      "file":"/oracle/build/include/llvm/Config/llvm-config.h"
                    },
                    {
                      "location":"/oracle/source/clang/lib/Lex/Lexer.cpp:9:1",
                      "file":"/usr/include/stddef.h"
                    }
                  ],
                  "imports":[]
                },
                {
                  "source":"/oracle/source/clang/include/clang/Lex/Lexer.h",
                  "includes":[
                    {
                      "location":"/oracle/source/clang/include/clang/Lex/Lexer.h:3:2",
                      "file":"/oracle/source/llvm/include/llvm/ADT/StringRef.h"
                    }
                  ],
                  "imports":[
                    {
                      "location":"/oracle/source/clang/include/clang/Lex/Lexer.h:4:1",
                      "module":"Builtin",
                      "file":"/oracle/build/module.modulemap"
                    }
                  ]
                },
                {
                  "source":"/usr/include/stddef.h",
                  "includes":[],
                  "imports":[]
                }
              ]
            }
        """.trimIndent().toByteArray()

        val trace = FullTreeClangHeaderTraceParser.parse(bytes, roots())

        assertEquals(OracleArtifacts.sha256(bytes), trace.inputSha256)
        assertEquals(3, trace.dependencyFileCount)
        assertEquals(2, trace.externalFileCount)
        assertEquals(
            listOf(
                FullTreeClangIncludeOccurrence(
                    "source/clang/lib/Lex/Lexer.cpp",
                    7,
                    1,
                    "source/clang/include/clang/Lex/Lexer.h",
                ),
                FullTreeClangIncludeOccurrence(
                    "source/clang/lib/Lex/Lexer.cpp",
                    8,
                    1,
                    "generated/include/llvm/Config/llvm-config.h",
                ),
                FullTreeClangIncludeOccurrence(
                    "source/clang/include/clang/Lex/Lexer.h",
                    3,
                    2,
                    "source/llvm/include/llvm/ADT/StringRef.h",
                ),
            ),
            trace.includeOccurrences,
        )
        assertEquals(
            listOf(
                FullTreeClangModuleImport(
                    "source/clang/include/clang/Lex/Lexer.h",
                    4,
                    1,
                    "Builtin",
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
    fun `trace rejects schema drift path confusion duplicate sources and location mismatch`() {
        val valid = trace(
            source = "/oracle/source/clang/lib/Lex/Lexer.cpp",
            location = "/oracle/source/clang/lib/Lex/Lexer.cpp:1:1",
            file = "/oracle/source/clang/include/clang/Lex/Lexer.h",
        )
        listOf(
            valid.replace("\"version\":\"2.0.0\"", "\"version\":\"1.0.0\""),
            valid.replace("\"imports\":[]", "\"imports\":[],\"extra\":false"),
            valid.replace("/oracle/source/clang/lib/Lex/Lexer.cpp:1:1", "/oracle/source/clang/lib/Other.cpp:1:1"),
            valid.replace("/oracle/source/clang/include", "/oracle/source/clang/../clang/include"),
            """{"version":"2.0.0","dependencies":[${valid.substringAfter("[+").substringBeforeLast("]}")}] }""",
        ).take(4).forEach { malformed ->
            assertFailsWith<FullTreeClangHeaderTraceException> {
                FullTreeClangHeaderTraceParser.parse(malformed.toByteArray(), roots())
            }
        }

        val record = valid.substringAfter("\"dependencies\":[").substringBeforeLast("]}")
        val duplicate = """{"version":"2.0.0","dependencies":[$record,$record]}"""
        assertFailsWith<FullTreeClangHeaderTraceException> {
            FullTreeClangHeaderTraceParser.parse(duplicate.toByteArray(), roots())
        }
    }

    @Test
    fun `root overlap entity and work limits fail closed`() {
        val bytes = trace(
            source = "/oracle/source/a.cpp",
            location = "/oracle/source/a.cpp:1:1",
            file = "/oracle/build/a.h",
        ).toByteArray()
        assertFailsWith<FullTreeClangHeaderTraceException> {
            FullTreeClangHeaderTraceParser.parse(
                bytes,
                listOf(
                    FullTreeClangTraceRoot("/oracle", "source"),
                    FullTreeClangTraceRoot("/oracle/build", "generated"),
                ),
            )
        }
        assertFailsWith<FullTreeClangHeaderTraceException> {
            FullTreeClangHeaderTraceParser.parse(
                bytes,
                roots(),
                FullTreeClangHeaderTraceLimits(maximumIncludeOccurrences = 1, maximumWorkUnits = 1),
            )
        }
        assertFailsWith<FullTreeClangHeaderTraceException> {
            FullTreeClangHeaderTraceParser.parse(
                bytes,
                roots(),
                FullTreeClangHeaderTraceLimits(maximumDependencyFiles = 1, maximumPathBytes = 8),
            )
        }
        assertTrue(
            FullTreeClangHeaderTraceLimits::class.java.declaredConstructors.all { constructor ->
                constructor.parameterTypes.none { it == Function::class.java || it == Any::class.java }
            },
        )
    }

    private fun roots(): List<FullTreeClangTraceRoot> = listOf(
        FullTreeClangTraceRoot("/oracle/source", "source"),
        FullTreeClangTraceRoot("/oracle/build", "generated"),
    )

    private fun trace(source: String, location: String, file: String): String =
        """{"version":"2.0.0","dependencies":[{"source":"$source","includes":[{"location":"$location","file":"$file"}],"imports":[]}]}"""
}

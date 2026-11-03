package decompengine.project

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class GeneratedCSourceHeaderPolicyTest {
    @Test
    fun `conventional guards literal project headers and fixture system headers are admitted`() {
        val inputs = mapOf(
            "src/modules/parser.c" to """
                #include <stddef.h>
                #include <stdint.h>
                #include "modules/parser.h"
                int parser(void) { const char *s = \"#include <not-a-header>\"; return (int)sizeof(*s); }
            """.trimIndent().toByteArray(),
            "include/modules/parser.h" to """
                #ifndef DECOMP_MODULES_PARSER_H
                #define DECOMP_MODULES_PARSER_H
                #include <stddef.h>
                typedef size_t parser_size;
                #endif /* DECOMP_MODULES_PARSER_H */
            """.trimIndent().toByteArray(),
        )
        GeneratedCSourceHeaderPolicy.requireAllowed("src/modules/parser.c", inputs)
    }

    @Test
    fun `every source and captured header rejects off snapshot and computed reads deterministically`() {
        val baseline = mapOf(
            "src/modules/parser.c" to "int parser(void) { return 0; }\n".toByteArray(),
            "include/modules/parser.h" to "#ifndef PARSER_H\n#define PARSER_H\n#endif\n".toByteArray(),
        )
        val cases = listOf(
            "#include \"/tmp/transient.h\"\nint parser(void) { return 0; }",
            "#include \"../../tmp/transient.h\"\nint parser(void) { return 0; }",
            "#define H \"modules/parser.h\"\n#include H\nint parser(void) { return 0; }",
            "#include HEADER\nint parser(void) { return 0; }",
            "#include_next <stddef.h>\nint parser(void) { return 0; }",
            "#if __has_include(\"/tmp/transient.h\")\nint parser(void) { return 0; }\n#endif",
            "#if __has_include_next(<stddef.h>)\nint parser(void) { return 0; }\n#endif",
            "int parser(void) { _Pragma(\"GCC poison fopen\") return 0; }",
            "#pragma GCC dependency \"/tmp/transient.h\"\nint parser(void) { return 0; }",
            "#embed \"/tmp/transient.bin\"\nint parser(void) { return 0; }",
            "int parser(void) { __asm__(\".include \\\"/tmp/transient.s\\\"\"); return 0; }",
            """int parser(void) { __asm__("\056incbin \"/tmp/transient.bin\""); return 0; }""",
            "int parser(void) { __asm__(\".incbin \\\"/tmp/transient.bin\\\"\"); return 0; }",
        )
        for (source in cases) {
            val inputs = baseline + ("src/modules/parser.c" to source.toByteArray())
            val first = assertFailsWith<IllegalArgumentException> {
                GeneratedCSourceHeaderPolicy.requireAllowed("src/modules/parser.c", inputs)
            }
            val second = assertFailsWith<IllegalArgumentException> {
                GeneratedCSourceHeaderPolicy.requireAllowed("src/modules/parser.c", inputs)
            }
            assertEquals(first.message, second.message, source)
        }
        val transitive = baseline + ("include/modules/parser.h" to
            "#ifndef PARSER_H\n#define PARSER_H\n#include \"/tmp/transient.h\"\n#endif\n".toByteArray())
        assertTrue(assertFailsWith<IllegalArgumentException> {
            GeneratedCSourceHeaderPolicy.requireAllowed("src/modules/parser.c", transitive)
        }.message.orEmpty().contains("include/modules/parser.h"))
    }

    @Test
    fun `comments strings splices trigraphs digraphs and header names cannot hide reads`() {
        val good = mapOf(
            "src/modules/parser.c" to """
                /* #include \"/tmp/no.h\" */
                const char *text = \"_Pragma(\\\"x\\\") #include <missing.h>\";
                int parser(void) { return text[0]; }
            """.trimIndent().toByteArray(),
            "include/modules/parser.h" to "#ifndef P\n#define P\n#endif\n".toByteArray(),
        )
        GeneratedCSourceHeaderPolicy.requireAllowed("src/modules/parser.c", good)
        for (directive in listOf(
            "#incl\\\nude \"/tmp/transient.h\"",
            "??=include <../../tmp/transient.h>",
            "%:include MACRO_HEADER",
        )) {
            val inputs = good + ("src/modules/parser.c" to "$directive\nint parser(void) { return 0; }".toByteArray())
            assertFailsWith<IllegalArgumentException> {
                GeneratedCSourceHeaderPolicy.requireAllowed("src/modules/parser.c", inputs)
            }
        }
    }
}

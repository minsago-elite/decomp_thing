package decompengine.testing

/**
 * Finds process launches in Kotlin test sources and classifies whether each one can start a JDK executable (#2001).
 *
 * Comments are dropped and every string literal becomes one token, so launcher paths quoted in comments or in
 * string fixture data never count as launches. A literal becomes [JDK_EXECUTABLE] when it names a JDK tool (`java`,
 * `…/bin/javap`, …), [JAVA_HOME] when it is `"java.home"`, [WRAPPER] when it names a command wrapper that can
 * exec a JVM (`unshare`, `prlimit`, `timeout`, …), [PERF_FLAG] when it contains `-XX:-UsePerfData`, and [STRING]
 * otherwise. Each `ProcessBuilder(…)`, `Runtime.getRuntime().exec(…)` or `ProcessExecutor(…)` call is judged by its
 * own argument list only.
 */
object JdkLaunchScan {
    const val JDK_EXECUTABLE = "LIT_JDK_EXECUTABLE"
    const val JAVA_HOME = "LIT_JAVA_HOME"
    const val WRAPPER = "LIT_WRAPPER"
    const val PERF_FLAG = "LIT_PERF_FLAG"
    const val STRING = "LIT_STRING"

    enum class Kind {
        /** Arguments come from `ChildJvm.command(…)` or `ChildJvm.toolCommand(…)`. */
        CHILD_JVM,
        /** Arguments name the JDK directly (`java.home`, a JDK tool literal, or the current process's command). */
        DIRECT_JDK,
        /** The executable is a non-JDK, non-wrapper string literal. */
        NON_JDK_LITERAL,
        /** A command built elsewhere, in a file that references a JDK launcher: it may start a JVM. */
        OPAQUE_IN_JDK_FILE,
        /** A command built elsewhere, in a file with no JDK launcher reference. */
        NON_JDK,
    }

    data class Site(val line: Int, val kind: Kind)

    data class Scan(val sites: List<Site>, val namesPerfFlag: Boolean, val code: String)

    private val jdkTool = Regex("""^(?:.*/)?(java|javap|javac|jar|jshell|jdeps|jlink|keytool|jcmd|jps|jstack|jfr|jpackage|jarsigner|jrunscript|serialver)$""")
    private val wrapper = Regex("""^(?:.*/)?(unshare|prlimit|timeout|env|nice|setsid|bwrap|systemd-run|sh|bash|taskset|stdbuf|strace|nohup|chrt|ionice|xargs|su|sudo|doas|runuser)$""")
    private val launch = Regex("""\bProcessBuilder\s*\(|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessExecutor\s*\(""")
    private val jdkReference = Regex("""\b$JAVA_HOME\b|\b$JDK_EXECUTABLE\b|\.info\s*\(\s*\)\s*\.\s*command\s*\(\s*\)""")
    private val childJvm = Regex("""\bChildJvm\s*\.\s*(command|toolCommand)\s*\(""")
    private val literalExecutable = Regex("""^\s*(?:(?:listOf|arrayOf|mutableListOf)\s*\(\s*)?$STRING\b""")
    private val perfFlag = Regex("""\b$PERF_FLAG\b|\bChildJvm\s*\.\s*NO_PERF_DATA\b|\bChildJvm\s*\.\s*(command|toolCommand|options|toolOptions)\s*\(""")

    fun scan(source: String): Scan {
        val code = Lexer(source).code()
        val jdkFile = jdkReference.containsMatchIn(code)
        val sites = launch.findAll(code).map { match ->
            val arguments = arguments(code, match.range.last + 1)
            val kind = when {
                childJvm.containsMatchIn(arguments) -> Kind.CHILD_JVM
                jdkReference.containsMatchIn(arguments) -> Kind.DIRECT_JDK
                literalExecutable.containsMatchIn(arguments) -> Kind.NON_JDK_LITERAL
                jdkFile -> Kind.OPAQUE_IN_JDK_FILE
                else -> Kind.NON_JDK
            }
            Site(code.substring(0, match.range.first).count { it == '\n' } + 1, kind)
        }.toList()
        return Scan(sites, perfFlag.containsMatchIn(code), code)
    }

    private fun arguments(code: String, start: Int): String {
        var depth = 1
        var index = start
        while (index < code.length && depth > 0) {
            when (code[index]) {
                '(' -> depth++
                ')' -> depth--
            }
            index++
        }
        return code.substring(start, maxOf(start, index - 1))
    }

    private fun classify(literal: String): String = when {
        wrapper.matches(literal) -> WRAPPER
        jdkTool.matches(literal) -> JDK_EXECUTABLE
        literal == "java.home" -> JAVA_HOME
        "-XX:-UsePerfData" in literal -> PERF_FLAG
        else -> STRING
    }

    /** Kotlin comments, strings (with templates), characters and backquoted names; newlines are preserved. */
    private class Lexer(private val source: String) {
        private val output = StringBuilder()
        private val n = source.length

        fun code(): String {
            var i = 0
            while (i < n) {
                val c = source[i]
                when {
                    source.startsWith("//", i) -> { while (i < n && source[i] != '\n') i++ }
                    source.startsWith("/*", i) -> i = blockComment(i)
                    c == '`' -> {
                        val end = source.indexOf('`', i + 1).let { if (it < 0) n else it + 1 }
                        output.append("IDENT").append("\n".repeat(source.substring(i, end).count { it == '\n' }))
                        i = end
                    }
                    c == '\'' -> { i = character(i); output.append("'c'") }
                    c == '"' -> {
                        val (end, raw) = string(i)
                        output.append(' ').append(classify(raw)).append(' ')
                            .append("\n".repeat(source.substring(i, end).count { it == '\n' }))
                        i = end
                    }
                    else -> { output.append(c); i++ }
                }
            }
            return output.toString()
        }

        private fun blockComment(start: Int): Int {
            var depth = 0
            var i = start
            while (i < n) {
                when {
                    source.startsWith("/*", i) -> { depth++; i += 2 }
                    source.startsWith("*/", i) -> { depth--; i += 2; if (depth == 0) return i }
                    else -> { if (source[i] == '\n') output.append('\n'); i++ }
                }
            }
            return n
        }

        private fun character(start: Int): Int {
            var i = start + 1
            i += if (i < n && source[i] == '\\') 2 else 1
            while (i < n && source[i] != '\'' && source[i] != '\n') i++
            return minOf(n, i + 1)
        }

        /** Returns the index after the literal and its raw text (templates included verbatim). */
        private fun string(start: Int): Pair<Int, String> {
            val raw = source.startsWith("\"\"\"", start)
            var i = start + if (raw) 3 else 1
            val text = StringBuilder()
            while (i < n) {
                if (raw && source.startsWith("\"\"\"", i)) {
                    var end = i
                    while (end < n && source[end] == '"') end++
                    text.append(source, i, end - 3)
                    return end to text.toString()
                }
                val c = source[i]
                when {
                    !raw && c == '\\' -> { text.append(source, i, minOf(n, i + 2)); i += 2 }
                    !raw && c == '"' -> return i + 1 to text.toString()
                    !raw && c == '\n' -> return i to text.toString()
                    source.startsWith("\${", i) -> { val end = template(i + 2); text.append(source, i, end); i = end }
                    else -> { text.append(c); i++ }
                }
            }
            return n to text.toString()
        }

        private fun template(start: Int): Int {
            var depth = 1
            var i = start
            while (i < n) {
                when (source[i]) {
                    '"' -> { i = string(i).first; continue }
                    '\'' -> { i = character(i); continue }
                    '{' -> depth++
                    '}' -> { depth--; if (depth == 0) return i + 1 }
                }
                i++
            }
            return n
        }
    }
}

package decompengine.testing

/**
 * Finds process launches in Kotlin test sources and classifies whether each one can start a JDK executable (#2001).
 *
 * Comments are dropped and every string literal becomes a placeholder token whose text stays available, so launcher
 * paths quoted in comments or string fixture data never count as launches. Each `ProcessBuilder(…)`,
 * `Runtime.getRuntime().exec(…)` or `ProcessExecutor(…)` call is judged by its executable expression: the first
 * argument (unwrapped from `listOf`/`arrayOf`/`mutableListOf` and a leading spread), or the first word of a single
 * string passed to `exec`. Command wrappers (`unshare`, `prlimit`, `timeout`, …) are looked through to the rest of
 * their arguments. Each site carries a stable [Site.anchor]: file, enclosing function and executable snippet.
 */
object JdkLaunchScan {
    enum class Kind {
        /** The command comes from `ChildJvm.command(…)` or `ChildJvm.toolCommand(…)`. */
        CHILD_JVM,
        /** The executable is visibly a JDK tool (`java.home`, a JDK tool literal, or the current process's command). */
        DIRECT_JDK,
        /** The executable is a non-JDK string literal. */
        NON_JDK_LITERAL,
        /** The executable is built elsewhere, in a file that references a JDK launcher, or is a wrapper of such. */
        OPAQUE_IN_JDK_FILE,
        /** The executable is built elsewhere, in a file with no JDK launcher reference. */
        NON_JDK,
    }

    data class Site(val line: Int, val kind: Kind, val function: String, val executable: String) {
        /** Stable identity for review exceptions: survives unrelated edits and line shifts. */
        fun anchor(file: String): String = "$file :: $function :: $executable"
    }

    data class Scan(val sites: List<Site>, val namesPerfFlag: Boolean, val code: String)

    private val jdkTool = Regex("""^(?:.*/)?(java|javap|javac|jar|jshell|jdeps|jlink|keytool|jcmd|jps|jstack|jfr|jpackage|jarsigner|jrunscript|serialver)$""")
    private val wrapper = Regex("""^(?:.*/)?(unshare|prlimit|timeout|env|nice|setsid|bwrap|systemd-run|sh|bash|taskset|stdbuf|strace|nohup|chrt|ionice|xargs|su|sudo|doas|runuser)$""")
    private val launch = Regex("""\bProcessBuilder\s*\(|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessExecutor\s*\(""")
    private val literal = Regex("""\bLIT(\d+)_\b""")
    private val javaHome = Regex("""getProperty\s*\(\s*LIT(\d+)_\s*\)""")
    private val currentCommand = Regex("""\.info\s*\(\s*\)\s*\.\s*command\s*\(\s*\)""")
    private val childJvm = Regex("""\bChildJvm\s*\.\s*(command|toolCommand)\s*\(""")
    private val collection = Regex("""^(?:listOf|arrayOf|mutableListOf|arrayListOf)\s*\(""")
    private val function = Regex("""\bfun\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?(`[^`]*`|\w+)\s*\(""")

    fun scan(source: String): Scan {
        val lexed = Lexer(source).lex()
        val code = lexed.code
        val literals = lexed.literals
        fun raw(token: MatchResult) = literals[token.groupValues[1].toInt()]
        fun referencesJdk(text: String): Boolean =
            literal.findAll(text).any { jdkTool.matches(raw(it)) } ||
                javaHome.findAll(text).any { raw(it) == "java.home" } || currentCommand.containsMatchIn(text)
        val jdkFile = referencesJdk(code)
        val functions = function.findAll(code).map { it.range.first to it.groupValues[1] }.toList()

        /** The nearest `val`/`var` definition of [name] before [position] (else the first after it), as its RHS. */
        fun definition(name: String, position: Int): Pair<String, Int>? {
            val matches = Regex("""\b(?:val|var)\s+${Regex.escape(name)}\b\s*(?::[^=\n]+)?=\s*""").findAll(code).toList()
            val chosen = matches.lastOrNull { it.range.first < position } ?: matches.firstOrNull() ?: return null
            return statement(code, chosen.range.last + 1) to chosen.range.first
        }

        fun classify(arguments: List<String>, isExec: Boolean, position: Int, depth: Int): Kind {
            val first = arguments.firstOrNull() ?: return Kind.NON_JDK
            if (childJvm.containsMatchIn(first)) return Kind.CHILD_JVM
            val elements = splitTopLevel(unwrap(first))
            val head = elements.firstOrNull().orEmpty()
            val literalHead = literalPath.find(head)?.takeIf { callChain.matches(head.substring(it.range.last + 1)) }
                ?.let { literals[it.groupValues[1].toInt()] }
            val word = literalHead?.let { if (isExec && arguments.size == 1) it.trim().substringBefore(' ') else it }
            if (word != null && wrapper.matches(word)) {
                // A wrapper execs the rest of its arguments; judge those instead.
                val rest = elements.drop(1) + arguments.drop(1)
                return when {
                    rest.any(childJvm::containsMatchIn) -> Kind.CHILD_JVM
                    rest.any { referencesJdk(it) || (depth < 4 && classify(listOf(it), false, position, depth + 1) == Kind.DIRECT_JDK) } ->
                        Kind.DIRECT_JDK
                    jdkFile -> Kind.OPAQUE_IN_JDK_FILE
                    else -> Kind.NON_JDK
                }
            }
            if (word != null) return if (jdkTool.matches(word)) Kind.DIRECT_JDK else Kind.NON_JDK_LITERAL
            if (referencesJdk(head)) return Kind.DIRECT_JDK
            val name = identifier.find(head)?.groupValues?.get(1)
            if (name != null && depth < 4) definition(name, position)?.let { (rhs, at) ->
                return classify(listOf(rhs), false, at, depth + 1)
            }
            return if (jdkFile) Kind.OPAQUE_IN_JDK_FILE else Kind.NON_JDK
        }

        val sites = launch.findAll(code).map { match ->
            val arguments = splitTopLevel(enclosedArguments(code, match.range.last + 1))
            val kind = classify(arguments, match.value.contains("exec"), match.range.first, 0)
            Site(code.substring(0, match.range.first).count { it == '\n' } + 1, kind,
                functions.lastOrNull { it.first < match.range.first }?.second ?: "<top level>",
                display(arguments.firstOrNull().orEmpty(), literals))
        }.toList()
        val perf = literals.any { "-XX:-UsePerfData" in it } ||
            Regex("""\bChildJvm\s*\.\s*(NO_PERF_DATA|command|toolCommand|options|toolOptions)\b""").containsMatchIn(code)
        return Scan(sites, perf, code)
    }

    private val literalPath = Regex("""^(?:(?:Path\s*\.\s*of|Paths\s*\.\s*get|File)\s*\(\s*)?LIT(\d+)_\s*\)?""")
    private val callChain = Regex("""(?:\s*\.\s*\w+\s*\(\s*\))*\s*""")
    private val identifier = Regex("""^(?:(?:checkNotNull|requireNotNull)\s*\(\s*)?([A-Za-z_]\w*)\s*\)?(?:\s*\.\s*\w+\s*\(\s*\))*\s*$""")

    /** The expression starting at [start], up to the first newline or `;` outside brackets. */
    private fun statement(code: String, start: Int): String {
        var depth = 0
        var index = start
        while (index < code.length) {
            val c = code[index]
            if (c == '(' || c == '[' || c == '{') depth++
            else if (c == ')' || c == ']' || c == '}') { if (depth == 0) break; depth-- }
            else if ((c == '\n' || c == ';') && depth == 0) break
            index++
        }
        return code.substring(start, index).trim()
    }

    /** `listOf(a, b) + c` → `a, b`; `*expr` → `expr`; anything else unchanged. */
    private fun unwrap(expression: String): String {
        var text = expression.trim().removePrefix("*").trim()
        collection.find(text)?.let { text = enclosedArguments(text, it.range.last + 1).trim() }
        return text
    }

    /** A short, stable rendering of the executable expression: the first element, literals restored. */
    private fun display(expression: String, literals: List<String>): String {
        val trimmed = expression.trim()
        val shown = if (trimmed.startsWith("*") || collection.containsMatchIn(trimmed)) {
            splitTopLevel(unwrap(trimmed)).firstOrNull().orEmpty()
        } else {
            trimmed
        }
        return Regex("""\s*\bLIT(\d+)_\b\s*""").replace(shown) { "\"" + literals[it.groupValues[1].toInt()] + "\"" }
            .replace(Regex("""\s+"""), " ").let { if (it.length > 60) it.take(60) + "…" else it }
    }

    private fun enclosedArguments(code: String, start: Int): String {
        var depth = 1
        var index = start
        while (index < code.length && depth > 0) {
            when (code[index]) { '(', '[', '{' -> depth++; ')', ']', '}' -> depth-- }
            index++
        }
        return code.substring(start, maxOf(start, index - 1))
    }

    private fun splitTopLevel(arguments: String): List<String> {
        val parts = mutableListOf<String>()
        var depth = 0
        var start = 0
        arguments.forEachIndexed { index, c ->
            when (c) {
                '(', '[', '{' -> depth++
                ')', ']', '}' -> depth--
                ',' -> if (depth == 0) { parts += arguments.substring(start, index); start = index + 1 }
            }
        }
        parts += arguments.substring(start)
        return parts.map(String::trim).filter(String::isNotEmpty)
    }

    private class Lexed(val code: String, val literals: List<String>)

    /** Kotlin comments, strings (with templates), characters and backquoted names; newlines are preserved. */
    private class Lexer(private val source: String) {
        private val output = StringBuilder()
        private val literals = mutableListOf<String>()
        private val n = source.length

        fun lex(): Lexed {
            var i = 0
            while (i < n) {
                val c = source[i]
                when {
                    source.startsWith("//", i) -> { while (i < n && source[i] != '\n') i++ }
                    source.startsWith("/*", i) -> i = blockComment(i)
                    c == '`' -> {
                        val end = source.indexOf('`', i + 1).let { if (it < 0) n else it + 1 }
                        output.append(source.substring(i, end).replace(Regex("""["'\n]"""), "_"))
                        i = end
                    }
                    c == '\'' -> { i = character(i); output.append("'c'") }
                    c == '"' -> {
                        val (end, raw) = string(i)
                        output.append(" LIT").append(literals.size).append("_ ")
                            .append("\n".repeat(source.substring(i, end).count { it == '\n' }))
                        literals += raw
                        i = end
                    }
                    else -> { output.append(c); i++ }
                }
            }
            return Lexed(output.toString(), literals)
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

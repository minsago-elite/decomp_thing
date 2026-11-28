package decompengine.testing

/**
 * Finds process launches in Kotlin test sources and classifies whether each one can start a JDK executable (#2001).
 *
 * This is a best-effort lint that keeps test-launched JVMs on [ChildJvm]; the runtime system-temp isolation check
 * is the real guard. It errs towards [Kind.OPAQUE_IN_JDK_FILE], which needs a reviewed anchor, whenever it cannot
 * see the executable.
 *
 * - Comments are dropped and every string literal becomes a placeholder whose text stays available, so launcher
 *   paths in comments or string fixtures never count as launches.
 * - Each `ProcessBuilder(…)`, `Runtime.getRuntime().exec(…)` or `ProcessExecutor(…)` call is expanded to its argv:
 *   the vararg arguments, a spread or a `listOf`/`arrayOf` collection, or, for `exec` with one scalar argument,
 *   the string split on `StringTokenizer`'s default delimiters (space, tab, newline, CR, form feed).
 * - Only the executable position is judged. For `env`, `timeout`, `prlimit`, `unshare` and `setsid` it skips that
 *   wrapper's options (and `env` assignments, `timeout`'s duration) and judges the wrapped executable. Any other
 *   wrapper, or a wrapper form outside those rules, is opaque.
 * - An identifier is followed only through a single `val` declaration in the file, with no `var`, parameter,
 *   lambda parameter or loop variable of the same name anywhere in it. Kotlin scopes are not modelled, so any
 *   ambiguity is opaque. Templates in an executable literal are opaque.
 * - `listOf(…) + more`, calls, and anything else not listed here are not followed.
 * - [Site.anchor] is the file, the lexically innermost enclosing `fun` (block or expression body) and the full
 *   normalized first launch argument.
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
        val owners = functionBodies(code)

        /**
         * The right-hand side of the single `val` that declares [name], or null when the name is declared more than
         * once, declared with `var`, or also bound as a parameter, lambda parameter or loop variable anywhere in the
         * file. Kotlin scoping is not modelled; ambiguity makes the caller treat the site as opaque.
         */
        fun definition(name: String): String? {
            val escaped = Regex.escape(name)
            val declarations = Regex("""\b(?:val|var)\s+$escaped\b""").findAll(code).toList()
            if (declarations.size != 1 || code.startsWith("var", declarations.single().range.first)) return null
            val shadowed = Regex("""[(,]\s*(?:vararg\s+|(?:private\s+|internal\s+)?(?:val|var)\s+)?$escaped\s*:|""" +
                """[{,]\s*$escaped\s*(?:,[^-{}]*)?->|\bfor\s*\(\s*$escaped\b""").containsMatchIn(code)
            if (shadowed) return null
            val assignment = Regex("""\bval\s+$escaped\b\s*(?::[^=\n]+)?=\s*""").find(code) ?: return null
            return statement(code, assignment.range.last + 1)
        }

        /** The text of a string literal [expression] (bare, `Path.of`/`File` wrapped, or a unique `val` alias). */
        fun literalValue(expression: String, depth: Int): String? {
            val head = expression.trim()
            literalPath.find(head)?.takeIf { callChain.matches(head.substring(it.range.last + 1)) }
                ?.let { return literals[it.groupValues[1].toInt()] }
            val name = identifier.find(head)?.groupValues?.get(1) ?: return null
            return if (depth < 4) definition(name)?.let { literalValue(it, depth + 1) } else null
        }

        /**
         * argv elements of a list-valued expression: `+` operands in order, each a `listOf`/`arrayOf` collection,
         * a unique `val` alias of one, or a single element. An element the scan cannot see stays as its expression
         * and is judged opaque if anything depends on it.
         */
        fun expand(expression: String, depth: Int): List<String> {
            val text = expression.trim().removePrefix("*").trim()
            if (childJvm.containsMatchIn(text)) return listOf(text)
            return splitTopLevel(text, '+').flatMap { operand ->
                val match = collection.find(operand)
                when {
                    match != null && closingParen(operand, match.range.last + 1) == operand.length - 1 ->
                        splitTopLevel(operand.substring(match.range.last + 1, operand.length - 1))
                    depth < 4 && identifier.find(operand)?.groupValues?.get(1) == operand ->
                        definition(operand)?.takeIf { literalValue(it, depth + 1) == null }?.let { expand(it, depth + 1) }
                            ?: listOf(operand)
                    else -> listOf(operand)
                }
            }
        }

        /** The full argv of a launch, as far as the scan can see it. */
        fun argv(arguments: List<String>, isExec: Boolean): List<String> {
            if (isExec && arguments.size == 1) {
                // exec(String) splits its command line like java.util.StringTokenizer's default delimiters.
                literalValue(arguments.single(), 0)?.let { line ->
                    return java.util.StringTokenizer(line).toList().map { "\u0000" + it }
                }
            }
            if (arguments.size == 1) return expand(arguments.single(), 0)
            return arguments.flatMap { argument -> if (argument.trim().startsWith("*")) expand(argument, 0) else listOf(argument) }
        }

        /** The executable word of an argv element: a resolved literal, or null when it is not a visible literal. */
        fun word(element: String): String? =
            if (element.startsWith("\u0000")) element.substring(1) else literalValue(element, 0)

        fun classifyArgv(elements: List<String>, depth: Int): Kind {
            val opaque = if (jdkFile) Kind.OPAQUE_IN_JDK_FILE else Kind.NON_JDK
            val executable = elements.firstOrNull() ?: return opaque
            if (childJvm.containsMatchIn(executable)) return Kind.CHILD_JVM
            val name = word(executable)
            if (name == null) {
                if (referencesJdk(executable)) return Kind.DIRECT_JDK
                // A unique `val` alias of a JDK path expression (for example `Path.of(System.getProperty("java.home"), …)`).
                val alias = identifier.find(executable.removePrefix("*").trim())?.groupValues?.get(1)?.let(::definition)
                return if (alias != null && referencesJdk(alias)) Kind.DIRECT_JDK else opaque
            }
            if (jdkTool.matches(name)) return Kind.DIRECT_JDK
            if ('$' in name) return opaque // a template decides the executable at run time
            val wrapped = wrapperName.find(name)?.groupValues?.get(1) ?: return if (wrapper.matches(name)) opaque else Kind.NON_JDK_LITERAL
            val index = executableIndex(wrapped, elements.drop(1).map(::word)) ?: return opaque
            return if (depth < 4) classifyArgv(elements.drop(1 + index), depth + 1) else opaque
        }

        val sites = launch.findAll(code).map { match ->
            val arguments = splitTopLevel(enclosedArguments(code, match.range.last + 1))
            val first = arguments.firstOrNull().orEmpty()
            val kind = when {
                childJvm.containsMatchIn(first) -> Kind.CHILD_JVM
                else -> classifyArgv(argv(arguments, match.value.contains("exec")), 0)
            }
            val owner = owners.filter { (range, _) -> match.range.first in range }.minByOrNull { it.first.last - it.first.first }
            Site(code.substring(0, match.range.first).count { it == '\n' } + 1, kind, owner?.second ?: "<top level>",
                normalized(first, literals))
        }.toList()
        val perf = literals.any { "-XX:-UsePerfData" in it } ||
            Regex("""\bChildJvm\s*\.\s*(NO_PERF_DATA|command|toolCommand|options|toolOptions)\b""").containsMatchIn(code)
        return Scan(sites, perf, code)
    }

    private val wrapperName = Regex("""^(?:.*/)?(env|timeout|prlimit|unshare|setsid)$""")
    private val unshareValueOptions = setOf("--propagation", "-S", "--setuid", "-G", "--setgid", "-R", "--root",
        "-w", "--wd", "--map-user", "--map-group", "--map-users", "--map-groups", "--monotonic", "--boottime")

    /**
     * The position of the wrapped executable among a wrapper's [arguments] (their literal words, null when not a
     * visible literal), or null for any form not modelled here: the caller then treats the site as opaque.
     */
    private fun executableIndex(wrapper: String, arguments: List<String?>): Int? {
        var index = 0
        fun at(i: Int) = arguments.getOrNull(i)
        when (wrapper) {
            "env" -> while (true) {
                val argument = at(index) ?: return null
                when {
                    argument == "--" -> return index + 1
                    argument in setOf("-u", "--unset", "-C", "--chdir") -> index += 2
                    argument == "-S" || argument.startsWith("--split-string") || argument.startsWith("-S") -> return null
                    argument.startsWith("-") -> index++
                    Regex("""^[A-Za-z_][A-Za-z0-9_]*=.*""").matches(argument) -> index++
                    else -> return index
                }
            }
            "timeout" -> {
                while (true) {
                    val argument = at(index) ?: return null
                    when {
                        argument == "--" -> { index++; break }
                        argument in setOf("-s", "--signal", "-k", "--kill-after") -> index += 2
                        argument.startsWith("-") -> index++
                        else -> break
                    }
                }
                at(index) ?: return null // the duration
                return index + 1
            }
            "prlimit" -> while (true) {
                val argument = at(index) ?: return null
                when {
                    argument == "--" -> return index + 1
                    argument.startsWith("--") -> index++
                    argument.startsWith("-") -> return null
                    else -> return index
                }
            }
            "unshare" -> while (true) {
                val argument = at(index) ?: return null
                when {
                    argument == "--" -> return index + 1
                    argument in unshareValueOptions -> index += 2
                    argument.startsWith("-") -> index++
                    else -> return index
                }
            }
            "setsid" -> while (true) {
                val argument = at(index) ?: return null
                when {
                    argument == "--" -> return index + 1
                    argument.startsWith("-") -> index++
                    else -> return index
                }
            }
        }
        return null
    }

    /**
     * Owner of every position: each `fun` mapped to its body (a braced block, or an expression body up to the end
     * of its statement). The innermost body containing a launch owns it, so a local function declared earlier in
     * the same scope does not.
     */
    private fun functionBodies(code: String): List<Pair<IntRange, String>> = function.findAll(code).mapNotNull { match ->
        val parametersEnd = closingParen(code, match.range.last + 1)
        // The body starts on the same line as the parameter list's end: `{` for a block, `=` for an expression.
        val lineEnd = code.indexOf('\n', parametersEnd).let { if (it < 0) code.length else it }
        val signatureTail = code.substring(parametersEnd + 1, lineEnd)
        val opener = signatureTail.indexOfFirst { it == '{' || it == '=' }.takeIf { it >= 0 } ?: return@mapNotNull null
        val bodyStart = parametersEnd + 1 + opener
        val end = if (code[bodyStart] == '{') closingParen(code, bodyStart + 1) else statementEnd(code, bodyStart + 1)
        (match.range.first..end) to match.groupValues[1]
    }.toList()

    /** Index of the bracket closing the one just before [start]. */
    private fun closingParen(code: String, start: Int): Int {
        var depth = 1
        var index = start
        while (index < code.length) {
            when (code[index]) { '(', '[', '{' -> depth++; ')', ']', '}' -> { depth--; if (depth == 0) return index } }
            index++
        }
        return code.length - 1
    }

    private val literalPath = Regex("""^(?:(?:Path\s*\.\s*of|Paths\s*\.\s*get|File)\s*\(\s*)?LIT(\d+)_\s*\)?""")
    private val callChain = Regex("""(?:\s*\.\s*\w+\s*\(\s*\))*\s*""")
    private val identifier = Regex("""^(?:(?:checkNotNull|requireNotNull)\s*\(\s*)?([A-Za-z_]\w*)\s*\)?(?:\s*\.\s*\w+\s*\(\s*\))*\s*$""")

    /** The expression starting at [start], up to the first newline or `;` outside brackets. */
    private fun statement(code: String, start: Int): String = code.substring(start, statementEnd(code, start)).trim()

    /** Index just past the expression starting at [start]; a newline right after `=` continues the expression. */
    private fun statementEnd(code: String, start: Int): Int {
        var depth = 0
        var index = start
        while (index < code.length && code[index].isWhitespace()) index++
        while (index < code.length) {
            val c = code[index]
            if (c == '(' || c == '[' || c == '{') depth++
            else if (c == ')' || c == ']' || c == '}') { if (depth == 0) break; depth-- }
            else if ((c == '\n' || c == ';') && depth == 0) break
            index++
        }
        return index
    }

    /** The full first launch argument with literals restored and whitespace collapsed: the anchor's executable. */
    private fun normalized(expression: String, literals: List<String>): String =
        Regex("""\s*\bLIT(\d+)_\b\s*""").replace(expression.trim()) { "\"" + literals[it.groupValues[1].toInt()] + "\"" }
            .replace(Regex("""\s+"""), " ")

    private fun enclosedArguments(code: String, start: Int): String {
        var depth = 1
        var index = start
        while (index < code.length && depth > 0) {
            when (code[index]) { '(', '[', '{' -> depth++; ')', ']', '}' -> depth-- }
            index++
        }
        return code.substring(start, maxOf(start, index - 1))
    }

    private fun splitTopLevel(arguments: String, separator: Char = ','): List<String> {
        val parts = mutableListOf<String>()
        var depth = 0
        var start = 0
        arguments.forEachIndexed { index, c ->
            when (c) {
                '(', '[', '{' -> depth++
                ')', ']', '}' -> depth--
                separator -> if (depth == 0) { parts += arguments.substring(start, index); start = index + 1 }
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

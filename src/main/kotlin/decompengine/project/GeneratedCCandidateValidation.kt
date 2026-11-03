package decompengine.project

/** Attribution reads retained C syntax, so preprocessing must not hide or rename its definitions. */
internal fun generatedCAttributionPreprocessorIssue(source: String, allowIncludes: Boolean = true): String? =
    GeneratedCCandidateValidation.preprocessorAttributionIssue(source, allowIncludes)

/** Generated-C source checks. Invocation and release acceptance remain in orchestration. */
internal object GeneratedCCandidateValidation {
    private val declarationContexts = GeneratedCDeclarationContextCache()
    private val literalSystemInclude = Regex("<[^<>\\r\\n]+>")
    fun assess(
        module: PlannedModule,
        model: RecoveredProgramModel,
        generator: String,
        source: String,
    ): List<ModuleReconstructionIssue> {
        val lexical = attributionLexicalView(source)
        preprocessorAttributionIssue(lexical)?.let { reason ->
            return (module.functionIds + module.globalIds).map { id ->
                ModuleReconstructionIssue(
                    "unsupported-preprocessor-attribution",
                    "candidate definition attribution for $id requires unconditional retained syntax: $reason",
                    listOf(id),
                )
            }
        }
        val issues = mutableListOf<ModuleReconstructionIssue>()
        val declarationContext = declarationContexts.forTypes(model.types)
        val codeOnly = lexical.code
        // The compiler gate resolves type names; spelling-only checks reject valid
        // identifiers and explicitly defined typedefs.
        module.functionIds.forEach { id ->
            val function = model.functions.single { it.id == id }
            if (!source.contains(id)) {
                issues += ModuleReconstructionIssue(
                    "missing-function-provenance",
                    "candidate source does not attribute ${function.id}",
                    listOf(function.id),
                )
            }
            val body = findFunctionBody(lexical.syntax, lexical.code, safeCName(function.name))
            if (body == null) {
                issues += ModuleReconstructionIssue(
                    "missing-function-definition",
                    "candidate source does not define ${safeCName(function.name)} for ${function.id}",
                    listOf(function.id),
                )
            } else if (
                generator != "recovered-c" &&
                (genericReturnBody(body) || isGeneratedCPlaceholderBody(function, body, declarationContext)) &&
                !recoveredEvidenceIsTrivial(function, declarationContext)
            ) {
                issues += ModuleReconstructionIssue(
                    "generic-return-placeholder",
                    "candidate implementation for ${function.id} is indistinguishable from the evidence-only return stub",
                    listOf(function.id),
                )
            }
        }
        module.globalIds.forEach { id ->
            val global = model.globals.single { it.id == id }
            if (!source.contains(id)) {
                issues += ModuleReconstructionIssue(
                    "missing-global-provenance",
                    "candidate source does not attribute $id",
                    listOf(id),
                )
            }
            if (!hasGlobalDefinition(codeOnly, safeCName(global.name)) && !generatedCGlobalDefinition(lexical.syntax, safeCName(global.name))) {
                issues += ModuleReconstructionIssue(
                    "missing-global-definition",
                    "candidate source does not define ${safeCName(global.name)} for $id",
                    listOf(id),
                )
            }
        }
        return issues.distinctBy { Triple(it.code, it.message, it.entityIds.sorted()) }
    }

    private fun findFunctionBody(source: String, code: String, functionName: String): String? {
        val candidates = Regex("\\b${Regex.escape(functionName)}\\s*\\(").findAll(code)
        candidates.forEach { candidate ->
            val parameterStart = code.indexOf('(', candidate.range.first)
            val parameterEnd = matchingDelimiter(code, parameterStart, '(', ')') ?: return@forEach
            var bodyStart = parameterEnd + 1
            while (bodyStart < code.length && code[bodyStart].isWhitespace()) bodyStart++
            if (bodyStart >= code.length || code[bodyStart] != '{') return@forEach
            val bodyEnd = matchingDelimiter(code, bodyStart, '{', '}') ?: return@forEach
            return source.substring(bodyStart + 1, bodyEnd)
        }
        return generatedCFunctionBody(source, functionName)
    }

    private fun matchingDelimiter(source: String, start: Int, open: Char, close: Char): Int? {
        var depth = 0
        var index = start
        var quoted: Char? = null
        var escaped = false
        var lineComment = false
        var blockComment = false
        while (index < source.length) {
            val character = source[index]
            val next = source.getOrNull(index + 1)
            when {
                lineComment -> if (character == '\n') lineComment = false
                blockComment -> if (character == '*' && next == '/') {
                    blockComment = false
                    index++
                }
                quoted != null -> when {
                    escaped -> escaped = false
                    character == '\\' -> escaped = true
                    character == quoted -> quoted = null
                }
                character == '/' && next == '/' -> {
                    lineComment = true
                    index++
                }
                character == '/' && next == '*' -> {
                    blockComment = true
                    index++
                }
                character == '"' || character == '\'' -> quoted = character
                character == open -> depth++
                character == close -> {
                    depth--
                    if (depth == 0) return index
                }
            }
            index++
        }
        return null
    }

    private fun genericReturnBody(body: String): Boolean = isGeneratedCSimpleReturnBody(body)

    private fun recoveredEvidenceIsTrivial(function: RecoveredFunction, context: GeneratedCDeclarationContext): Boolean =
        function.decompiledC?.let { recovered ->
            val lexical = attributionLexicalView(recovered)
            if (preprocessorAttributionIssue(lexical) != null) return@let false
            findFunctionBody(lexical.syntax, lexical.code, function.name)?.let { genericReturnBody(it) || isGeneratedCPlaceholderBody(function, it, context) }
                ?: Regex("\\{\\s*return(?:\\s+0)?\\s*;\\s*}", RegexOption.DOT_MATCHES_ALL).findAll(lexical.code).any { match ->
                    // Masking identifies real braces, but can erase a returned literal. Judge
                    // triviality from the retained body rather than its masked expression.
                    genericReturnBody(lexical.syntax.substring(match.range.first + 1, match.range.last))
                }
        } == true

    /** A linear lexical guard, not a preprocessor: even a known-looking #if condition is rejected. */
    internal fun preprocessorAttributionIssue(source: String, allowIncludes: Boolean = true): String? =
        preprocessorAttributionIssue(attributionLexicalView(source), allowIncludes)

    private fun preprocessorAttributionIssue(lexical: AttributionLexicalView, allowIncludes: Boolean = true): String? {
        if (lexical.spliceOutsideLiteral) {
            return "escaped physical lines require preprocessing before definition attribution"
        }
        for (line in lexical.code.lineSequence()) {
            val text = line.trimStart()
            val markerLength = when {
                text.startsWith('#') -> 1
                text.startsWith("%:") -> 2
                text.startsWith("??=") -> 3
                else -> continue
            }
            val directive = text.drop(markerLength).trimStart()
            if (!allowIncludes) return "preprocessing directives are unsupported in recovered type declarations"
            if (directive.isEmpty()) continue // A null directive cannot alter a definition.
            val name = directive.takeWhile { it.isLetterOrDigit() || it == '_' }
            if (name != "include") return "preprocessing directive #${name.ifEmpty { "<unknown>" }} is unsupported"
            // Quoted header names are masked with the other literals. System header names stay
            // visible between angle brackets; a remaining identifier is a macro include operand.
            val operand = directive.drop(name.length).trim()
            if (operand.isNotEmpty() && !literalSystemInclude.matches(operand)) {
                return "macro-dependent include operands are unsupported"
            }
        }
        return null
    }

    private data class AttributionLexicalView(val syntax: String, val code: String, val spliceOutsideLiteral: Boolean = false)

    /**
     * Mask literal continuations before interpreting escapes, as C translation phase two does.
     * A splice leaves the escape state unchanged: a preceding backslash can still escape a quote
     * after the joined line. Keep raw offsets and source bytes for the declaration tokenizer:
     * joining physical lines could otherwise manufacture a new phase-one trigraph on a second pass.
     * Comments and literals are masked so their text cannot establish declarations.
     */
    private fun attributionLexicalView(source: String): AttributionLexicalView {
        val code = StringBuilder(source.length)
        var index = 0
        var lineComment = false
        var blockComment = false
        var quoted: Char? = null
        var escaped = false
        var directive = false
        while (index < source.length) {
            val character = source[index]
            val next = source.getOrNull(index + 1)
            val spliceEnd = generatedCPhysicalLineSpliceEnd(source, index)
            if (spliceEnd != null) {
                if (quoted == null || directive) return AttributionLexicalView(source, "", spliceOutsideLiteral = true)
                repeat(spliceEnd - index) { code.append(' ') }
                index = spliceEnd
                continue
            }
            // Phase one also makes a non-spliced trigraph a backslash. Retain its
            // bytes in the syntax view, but interpret the resulting escape state.
            if (quoted != null && source.startsWith("??/", index)) {
                code.append("   ")
                escaped = !escaped
                index += 3
                continue
            }
            if (!blockComment && quoted == null && (character == '\r' || character == '\n')) directive = false
            if (!lineComment && !blockComment && quoted == null &&
                (character == '#' || source.startsWith("%:", index) || source.startsWith("??=", index))) directive = true
            when {
                lineComment -> {
                    code.append(if (character == '\n' || character == '\r') character else ' ')
                    if (character == '\n' || character == '\r') lineComment = false
                }
                blockComment -> {
                    code.append(if (character == '\n' || character == '\r') character else ' ')
                    if (character == '*' && next == '/') {
                        code.append(' ')
                        index++
                        blockComment = false
                    }
                }
                quoted != null -> {
                    code.append(if (character == '\n' || character == '\r') character else ' ')
                    when {
                        escaped -> escaped = false
                        character == '\\' -> escaped = true
                        character == quoted -> quoted = null
                    }
                }
                character == '/' && next == '/' -> {
                    code.append("  ")
                    index++
                    lineComment = true
                }
                character == '/' && next == '*' -> {
                    code.append("  ")
                    index++
                    blockComment = true
                }
                character == '"' || character == '\'' -> {
                    code.append(' ')
                    quoted = character
                }
                else -> code.append(character)
            }
            index++
        }
        return AttributionLexicalView(source, code.toString())
    }

    /**
     * Recognize a top-level C declarator for [name]. References in function bodies, parameters,
     * array bounds, and other globals' initializers do not qualify as definitions.
     */
    private fun hasGlobalDefinition(code: String, name: String): Boolean {
        val occurrences = Regex("\\b${Regex.escape(name)}\\b").findAll(code).iterator()
        if (!occurrences.hasNext()) return false
        var occurrence = occurrences.next()
        var braceDepth = 0
        var parenthesisDepth = 0
        var bracketDepth = 0
        var statementStart = 0
        var declaratorStart = 0
        for (index in code.indices) {
            if (index == occurrence.range.first) {
                if (braceDepth == 0 && bracketDepth == 0) {
                    val prefix = code.substring(statementStart, occurrence.range.first)
                    val declaratorPrefix = code.substring(declaratorStart, occurrence.range.first)
                    val functionPointerDeclarator =
                        parenthesisDepth == 1 && declaratorPrefix.trimEnd().endsWith("(*")
                    val declarationPrefix = parenthesisDepth == 0 || functionPointerDeclarator
                    val hasType = Regex("[A-Za-z_]\\w*").containsMatchIn(prefix)
                    val isExternalOrTypedef = Regex("\\b(extern|typedef)\\b").containsMatchIn(prefix)
                    val suffix = code.substring(occurrence.range.last + 1).trimStart()
                    val declaratorSuffix = when {
                        functionPointerDeclarator -> suffix.startsWith(')')
                        suffix.startsWith('(') -> false
                        suffix.isEmpty() -> true
                        else -> suffix.first() in setOf(';', '=', ',', '[')
                    }
                    if (
                        declarationPrefix &&
                        hasType &&
                        !isExternalOrTypedef &&
                        '=' !in declaratorPrefix &&
                        declaratorSuffix
                    ) {
                        return true
                    }
                }
                if (!occurrences.hasNext()) break
                occurrence = occurrences.next()
            }
            when (code[index]) {
                '{' -> braceDepth++
                '}' -> {
                    if (braceDepth > 0) braceDepth--
                    if (braceDepth == 0) statementStart = index + 1
                }
                '(' -> parenthesisDepth++
                ')' -> if (parenthesisDepth > 0) parenthesisDepth--
                '[' -> bracketDepth++
                ']' -> if (bracketDepth > 0) bracketDepth--
                ';' -> if (braceDepth == 0 && parenthesisDepth == 0 && bracketDepth == 0) {
                    statementStart = index + 1
                    declaratorStart = statementStart
                }
                ',' -> if (braceDepth == 0 && parenthesisDepth == 0 && bracketDepth == 0) {
                    declaratorStart = index + 1
                }
            }
        }
        return false
    }

}

/**
 * Closed input-affecting source policy for the authenticated module compiler snapshot.
 * This deliberately does not interpret the C program or ask the compiler what it read: it
 * admits only literal includes whose target is in the supplied immutable inventory, plus the
 * reviewed standard headers retained by the registered generated-C runtime.
 */
internal object GeneratedCSourceHeaderPolicy {
    private val systemHeaders = setOf("stddef.h", "stdint.h", "stdio.h", "stdlib.h", "string.h")
    private val directive = Regex("^\\s*(?:#|%:)\\s*([A-Za-z_][A-Za-z_0-9]*)(.*)$")
    private val guardName = Regex("^\\s*([A-Za-z_][A-Za-z_0-9]*)\\s*$")
    private val includeOperand = Regex("^\\s*(?:\"([^\"\\\\\\r\\n]+)\"|<([^<>\\r\\n]+)>)\\s*$")

    fun requireAllowed(sourcePath: String, files: Map<String, ByteArray>, progress: () -> Unit = {}) {
        requireAllowedStreaming(sourcePath, files.keys, { path -> files.getValue(path) }, progress)
    }

    /**
     * Validate an authenticated inventory without retaining all of its bytes at once. The
     * inventory is supplied separately from [read] so callers can keep membership bound to the
     * request manifest while reading one pinned file at a time.
     */
    fun requireAllowedStreaming(
        sourcePath: String,
        authenticatedPaths: Collection<String>,
        read: (String) -> ByteArray,
        progress: () -> Unit = {},
    ) {
        require(sourcePath in authenticatedPaths) { "generated-C policy source is absent from authenticated snapshot" }
        require(authenticatedPaths.size in 1..ContainedModuleCompilerRequest.MAXIMUM_INPUTS) {
            "generated-C policy inventory exceeds its bound"
        }
        val normalizedFiles = authenticatedPaths.map(::normalizeInventoryPath).toSet()
        require(normalizedFiles.size == authenticatedPaths.size) { "generated-C policy inventory has ambiguous paths" }
        for (path in normalizedFiles.sorted()) {
            checkScanProgress(progress, 0)
            val bytes = read(path)
            require(bytes.size <= ContainedModuleCompilerRequest.MAXIMUM_INPUT_FILE_BYTES) {
                "generated-C policy input exceeds its bound: $path"
            }
            val text = try {
                bytes.toString(Charsets.UTF_8).also { decoded ->
                    require(decoded.toByteArray(Charsets.UTF_8).contentEquals(bytes)) { "generated-C policy input is not valid UTF-8: $path" }
                }
            } catch (failure: IllegalArgumentException) {
                throw IllegalArgumentException("generated-C policy input is not valid UTF-8: $path", failure)
            }
            require('\u0000' !in text && !text.startsWith('\uFEFF')) {
                "generated-C policy input contains unsupported encoding markers: $path"
            }
            validateTranslationUnit(path, text, normalizedFiles, progress)
        }
    }

    private fun validateTranslationUnit(path: String, source: String, inventory: Set<String>, progress: () -> Unit) {
        rejectMalformedOrContinuedDirectives(path, source, progress)
        val logical = phaseOneAndTwo(source, progress)
        val clean = removeComments(logical, progress)
        val code = maskLiterals(clean, progress)
        if (Regex("\\b(?:_Pragma|__has_include(?:_next)?|__has_include_next)\\b").containsMatchIn(code)) {
            reject(path, "unsupported preprocessing operator")
        }
        checkInlineAssembler(path, code, progress)

        var guard: String? = null
        var guardDefined = false
        var guardClosed = false
        var directiveCount = 0
        var seenAnyContent = false
        clean.lineSequence().forEach { line ->
            checkScanProgress(progress, line.length)
            if (guardClosed && line.isNotBlank()) reject(path, "source follows include guard")
            val match = directive.find(line)
            if (match == null) {
                if (line.trimStart().startsWith('#') || line.trimStart().startsWith("%:")) {
                    reject(path, "malformed preprocessing directive")
                }
                if (line.isNotBlank()) seenAnyContent = true
                return@forEach
            }
            directiveCount++
            val name = match.groupValues[1]
            val operand = match.groupValues[2].trim()
            when (name) {
                "" -> Unit
                "include" -> {
                    if (guardClosed || (guard != null && !guardDefined)) reject(path, "include is outside a closed conventional guard")
                    val include = includeOperand.matchEntire(operand) ?: reject(path, "computed or malformed include operand")
                    val quoted = include.groupValues[1].takeIf { it.isNotEmpty() }
                    val angled = include.groupValues[2].takeIf { it.isNotEmpty() }
                    val nameText = quoted ?: angled ?: reject(path, "empty include operand")
                    if (nameText.startsWith('/') || nameText.contains('\\') || nameText.split('/').any { it == ".." || it.isEmpty() || it == "." }) {
                        reject(path, "absolute or traversing include is unsupported")
                    }
                    val candidates = buildList {
                        if (quoted != null) {
                            val parent = path.substringBeforeLast('/', "")
                            add(if (parent.isEmpty()) nameText else "$parent/$nameText")
                        }
                        add("include/$nameText")
                    }
                    if (candidates.none { it in inventory } && nameText !in systemHeaders) {
                        reject(path, "include is outside the authenticated snapshot: $nameText")
                    }
                }
                "ifndef" -> {
                    if (!path.endsWith(".h") || guard != null || guardDefined || guardClosed || directiveCount != 1 || seenAnyContent) {
                        reject(path, "unsupported conditional preprocessing directive")
                    }
                    guard = guardName.matchEntire(operand)?.groupValues?.get(1)
                        ?: reject(path, "malformed conventional include guard")
                }
                "define" -> {
                    val expected = guard
                    if (expected != null && !guardDefined && !guardClosed && operand == expected) {
                        guardDefined = true
                    } else if (guard == null && path.endsWith(".h") && !guardClosed &&
                        Regex("[A-Za-z_][A-Za-z_0-9]*(?:\\s+(?:[0-9]+[uUlL]*|0[xX][0-9A-Fa-f]+[uUlL]*))?").matches(operand)) {
                        // Numeric object-like constants cannot manufacture preprocessing,
                        // include names, or assembler source after macro expansion.
                    } else reject(path, "unsupported macro definition")
                }
                "endif" -> {
                    if (!guardDefined || guardClosed || operand.isNotEmpty()) reject(path, "unsupported conditional preprocessing directive")
                    guardClosed = true
                }
                else -> reject(path, "unsupported preprocessing directive #$name")
            }
        }
        if (guard != null && (!guardDefined || !guardClosed)) reject(path, "unterminated conventional include guard")
    }

    private fun rejectMalformedOrContinuedDirectives(path: String, source: String, progress: () -> Unit) {
        var index = 0
        var lineStart = true
        var directive = false
        while (index < source.length) {
            checkScanProgress(progress, index)
            val character = source[index]
            val next = source.getOrNull(index + 1)
            if (character == '\r' || character == '\n') {
                directive = false
                lineStart = true
                index++
                if (character == '\r' && source.getOrNull(index) == '\n') index++
                continue
            }
            if (directive) {
                if (character == '\\' && (next == '\r' || next == '\n')) {
                    reject(path, "continued preprocessing directive is unsupported")
                }
                if (character == '/' && next == '*') {
                    index += 2
                    var closed = false
                    while (index < source.length) {
                        checkScanProgress(progress, index)
                        if (source[index] == '\r' || source[index] == '\n') {
                            reject(path, "preprocessing directive comment crosses a physical line")
                        }
                        if (source[index] == '*' && source.getOrNull(index + 1) == '/') {
                            index += 2
                            closed = true
                            break
                        }
                        index++
                    }
                    if (!closed) reject(path, "unterminated preprocessing directive comment")
                    continue
                }
                index++
                continue
            }
            if (lineStart && character.isWhitespace()) {
                index++
                continue
            }
            if (lineStart && (character == '#' || source.startsWith("%:", index) || source.startsWith("??=", index))) {
                directive = true
                lineStart = false
                index += when {
                    character == '#' -> 1
                    source.startsWith("%:", index) -> 2
                    else -> 3
                }
                continue
            }
            lineStart = false
            index++
        }
    }

    /** Reject every GNU inline-assembler token in one bounded lexical pass. */
    private fun checkInlineAssembler(path: String, code: String, progress: () -> Unit) {
        var index = 0
        while (index < code.length) {
            checkScanProgress(progress, index)
            val character = code[index]
            if (character == '_' || character.isLetter()) {
                val start = index++
                while (index < code.length && (code[index] == '_' || code[index].isLetterOrDigit())) index++
                val tokenLength = index - start
                if ((tokenLength == 3 && code.regionMatches(start, "asm", 0, 3)) ||
                    (tokenLength == 5 && code.regionMatches(start, "__asm", 0, 5)) ||
                    (tokenLength == 7 && code.regionMatches(start, "__asm__", 0, 7))) {
                    reject(path, "inline assembler is unsupported")
                }
            } else {
                index++
            }
        }
    }

    private fun phaseOneAndTwo(source: String, progress: () -> Unit): String {
        val trigraphs = mapOf("=" to '#', "/" to '\\', "'" to '^', "(" to '[', ")" to ']', "!" to '|', "<" to '{', ">" to '}', "-" to '~')
        val phaseOne = buildString(source.length) {
            var i = 0
            while (i < source.length) {
                checkScanProgress(progress, i)
                if (source.startsWith("??", i) && i + 2 < source.length && source[i + 2].toString() in trigraphs) {
                    append(trigraphs.getValue(source[i + 2].toString()))
                    i += 3
                } else append(source[i++])
            }
        }
        return buildString(phaseOne.length) {
            var i = 0
            while (i < phaseOne.length) {
                checkScanProgress(progress, i)
                if (phaseOne[i] == '\\' && i + 1 < phaseOne.length && phaseOne[i + 1] == '\n') i += 2
                else if (phaseOne[i] == '\\' && i + 2 < phaseOne.length && phaseOne[i + 1] == '\r' && phaseOne[i + 2] == '\n') i += 3
                else if (phaseOne[i] == '\\' && i + 1 < phaseOne.length && phaseOne[i + 1] == '\r') i += 2
                else append(phaseOne[i++])
            }
        }
    }

    private fun removeComments(source: String, progress: () -> Unit): String = buildString(source.length) {
        var i = 0
        var quote: Char? = null
        var escaped = false
        while (i < source.length) {
            checkScanProgress(progress, i)
            val c = source[i]
            val next = source.getOrNull(i + 1)
            when {
                quote != null -> {
                    append(c)
                    when { escaped -> escaped = false; c == '\\' -> escaped = true; c == quote -> quote = null }
                }
                c == '"' || c == '\'' -> { quote = c; append(c) }
                c == '/' && next == '/' -> {
                    append("  "); i += 2
                    while (i < source.length && source[i] != '\n' && source[i] != '\r') { append(' '); i++ }
                    continue
                }
                c == '/' && next == '*' -> {
                    append("  "); i += 2
                    while (i < source.length && !(source[i] == '*' && source.getOrNull(i + 1) == '/')) { append(if (source[i] == '\n' || source[i] == '\r') source[i] else ' '); i++ }
                    if (i < source.length) { append("  "); i++ }
                }
                else -> append(c)
            }
            i++
        }
    }

    private fun maskLiterals(source: String, progress: () -> Unit): String = buildString(source.length) {
        var quote: Char? = null
        var escaped = false
        source.forEachIndexed { index, c ->
            checkScanProgress(progress, index)
            if (quote == null) {
                if (c == '"' || c == '\'') { quote = c; append(' ') } else append(c)
            } else {
                append(if (c == '\n' || c == '\r') c else ' ')
                when { escaped -> escaped = false; c == '\\' -> escaped = true; c == quote -> quote = null }
            }
        }
    }

    private fun checkScanProgress(progress: () -> Unit, index: Int) {
        if ((index and 0x3ff) == 0) {
            if (Thread.currentThread().isInterrupted) throw InterruptedException("generated-C source policy cancelled")
            progress()
        }
    }

    private fun normalizeInventoryPath(path: String): String {
        require(!path.startsWith('/') && '\\' !in path && path.split('/').none { it.isEmpty() || it == "." || it == ".." })
        return path
    }

    private fun reject(path: String, reason: String): Nothing = throw GeneratedCSourcePolicyRefusal(path, reason)
}

/** A deterministic refusal that callers can distinguish from compiler observations. */
internal class GeneratedCSourcePolicyRefusal(val sourcePath: String, val reason: String) :
    IllegalArgumentException("generated-C source policy refused $sourcePath: $reason")

package decompengine.project

/** Attribution reads retained C syntax, so preprocessing must not hide or rename its definitions. */
internal fun generatedCAttributionPreprocessorIssue(source: String): String? =
    GeneratedCCandidateValidation.preprocessorAttributionIssue(source)

/** Generated-C source checks. Invocation and release acceptance remain in orchestration. */
internal object GeneratedCCandidateValidation {
    private val declarationContexts = GeneratedCDeclarationContextCache()
    private val escapedPhysicalLine = Regex("""(?:\\|\?\?/)[ \t\u000b\f]*(?:\r\n?|\n)""")
    private val literalSystemInclude = Regex("<[^<>\\r\\n]+>")
    fun assess(
        module: PlannedModule,
        model: RecoveredProgramModel,
        generator: String,
        source: String,
    ): List<ModuleReconstructionIssue> {
        generatedCAttributionPreprocessorIssue(source)?.let { reason ->
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
        val codeOnly = codeWithoutCommentsOrLiterals(source)
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
            val body = findFunctionBody(source, safeCName(function.name))
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
            if (!hasGlobalDefinition(codeOnly, safeCName(global.name)) && !generatedCGlobalDefinition(source, safeCName(global.name))) {
                issues += ModuleReconstructionIssue(
                    "missing-global-definition",
                    "candidate source does not define ${safeCName(global.name)} for $id",
                    listOf(id),
                )
            }
        }
        return issues.distinctBy { Triple(it.code, it.message, it.entityIds.sorted()) }
    }

    private fun findFunctionBody(source: String, functionName: String): String? {
        val candidates = Regex("\\b${Regex.escape(functionName)}\\s*\\(").findAll(source)
        candidates.forEach { candidate ->
            val parameterStart = source.indexOf('(', candidate.range.first)
            val parameterEnd = matchingDelimiter(source, parameterStart, '(', ')') ?: return@forEach
            var bodyStart = parameterEnd + 1
            while (bodyStart < source.length && source[bodyStart].isWhitespace()) bodyStart++
            if (bodyStart >= source.length || source[bodyStart] != '{') return@forEach
            val bodyEnd = matchingDelimiter(source, bodyStart, '{', '}') ?: return@forEach
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
            if (generatedCAttributionPreprocessorIssue(recovered) != null) return@let false
            findFunctionBody(recovered, function.name)?.let { genericReturnBody(it) || isGeneratedCPlaceholderBody(function, it, context) }
                ?: Regex("\\{\\s*return(?:\\s+0)?\\s*;\\s*}", RegexOption.DOT_MATCHES_ALL).containsMatchIn(recovered)
        } == true

    /** A linear lexical guard, not a preprocessor: even a known-looking #if condition is rejected. */
    internal fun preprocessorAttributionIssue(source: String): String? {
        // C splices physical lines before recognizing comments or directives. The attribution
        // scanners do not perform that translation, so never let a splice conceal source syntax.
        if (escapedPhysicalLine.containsMatchIn(source)) {
            return "escaped physical lines require preprocessing before definition attribution"
        }
        for (line in codeWithoutCommentsOrLiterals(source).lineSequence()) {
            val text = line.trimStart()
            val markerLength = when {
                text.startsWith('#') -> 1
                text.startsWith("%:") -> 2
                text.startsWith("??=") -> 3
                else -> continue
            }
            val directive = text.drop(markerLength).trimStart()
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

    /**
     * Preserve code layout while hiding tokens that occur only in comments and literals. This keeps
     * acceptance checks from treating diagnostics such as "copied 1 byte" as C type declarations.
     */
    private fun codeWithoutCommentsOrLiterals(source: String): String = buildString(source.length) {
        var index = 0
        var lineComment = false
        var blockComment = false
        var quoted: Char? = null
        var escaped = false
        while (index < source.length) {
            val character = source[index]
            val next = source.getOrNull(index + 1)
            when {
                lineComment -> {
                    append(if (character == '\n' || character == '\r') character else ' ')
                    if (character == '\n' || character == '\r') lineComment = false
                }
                blockComment -> {
                    append(if (character == '\n' || character == '\r') character else ' ')
                    if (character == '*' && next == '/') {
                        append(' ')
                        index++
                        blockComment = false
                    }
                }
                quoted != null -> {
                    append(if (character == '\n' || character == '\r') character else ' ')
                    when {
                        escaped -> escaped = false
                        character == '\\' -> escaped = true
                        character == quoted -> quoted = null
                    }
                }
                character == '/' && next == '/' -> {
                    append("  ")
                    index++
                    lineComment = true
                }
                character == '/' && next == '*' -> {
                    append("  ")
                    index++
                    blockComment = true
                }
                character == '"' || character == '\'' -> {
                    append(' ')
                    quoted = character
                }
                else -> append(character)
            }
            index++
        }
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

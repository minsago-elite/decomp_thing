package decompengine.project

/** Generated-C source checks. Invocation and release acceptance remain in orchestration. */
internal object GeneratedCCandidateValidation {
    fun assess(
        module: PlannedModule,
        model: RecoveredProgramModel,
        generator: String,
        source: String,
    ): List<ModuleReconstructionIssue> {
        val issues = mutableListOf<ModuleReconstructionIssue>()
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
                genericReturnBody(body) &&
                !recoveredEvidenceIsTrivial(function)
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
            if (!hasGlobalDefinition(codeOnly, safeCName(global.name))) {
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
        return null
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

    private fun genericReturnBody(body: String): Boolean {
        val withoutComments = body
            .replace(Regex("/\\*.*?\\*/", setOf(RegexOption.DOT_MATCHES_ALL)), "")
            .replace(Regex("//[^\\r\\n]*"), "")
            .replace(Regex("\\s+"), "")
        return withoutComments == "return0;" || withoutComments == "return;"
    }

    private fun recoveredEvidenceIsTrivial(function: RecoveredFunction): Boolean =
        function.decompiledC?.let { recovered ->
            findFunctionBody(recovered, function.name)?.let(::genericReturnBody)
                ?: Regex("\\{\\s*return(?:\\s+0)?\\s*;\\s*}", RegexOption.DOT_MATCHES_ALL).containsMatchIn(recovered)
        } == true

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
                    append(if (character == '\n') '\n' else ' ')
                    if (character == '\n') lineComment = false
                }
                blockComment -> {
                    append(if (character == '\n') '\n' else ' ')
                    if (character == '*' && next == '/') {
                        append(' ')
                        index++
                        blockComment = false
                    }
                }
                quoted != null -> {
                    append(if (character == '\n') '\n' else ' ')
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
        for (index in code.indices) {
            if (index == occurrence.range.first) {
                if (braceDepth == 0 && bracketDepth == 0) {
                    val prefix = code.substring(statementStart, occurrence.range.first)
                    val functionPointerDeclarator = parenthesisDepth == 1 && prefix.trimEnd().endsWith("(*")
                    val declarationPrefix = parenthesisDepth == 0 || functionPointerDeclarator
                    val hasType = Regex("[A-Za-z_]\\w*").containsMatchIn(prefix)
                    val isExternal = Regex("\\bextern\\b").containsMatchIn(prefix)
                    val suffix = code.substring(occurrence.range.last + 1).trimStart()
                    val declaratorSuffix = when {
                        functionPointerDeclarator -> suffix.startsWith(')')
                        suffix.startsWith('(') -> false
                        suffix.isEmpty() -> true
                        else -> suffix.first() in setOf(';', '=', ',', '[')
                    }
                    if (declarationPrefix && hasType && !isExternal && '=' !in prefix && declaratorSuffix) {
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
                }
            }
        }
        return false
    }

}

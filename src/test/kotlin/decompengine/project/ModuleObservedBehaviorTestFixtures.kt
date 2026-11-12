package decompengine.project

/** Bind valid synthetic observation corpora to the input admitted by a transactional test fixture. */
internal fun bindModuleObservationFixtureToInput(observed: String?, inputSha256: String): String? {
    if (observed == null) return null
    val document = try {
        ModuleObservedBehavior.parse(observed)
    } catch (_: IllegalArgumentException) {
        // Malformed and deliberately wrapped documents must reach the production validator unchanged.
        return observed
    }
    if (document.inputSha256 == inputSha256) return observed

    // Replace only the top-level binding. The digest has fixed width, so whitespace-padded fixtures
    // retain their exact byte size for boundary checks.
    val binding = Regex("""("inputSha256"\s*:\s*")${Regex.escape(document.inputSha256)}(")""")
    val matches = binding.findAll(observed).toList()
    require(matches.size == 1) { "valid observation fixture must have one input digest binding" }
    val match = matches.single()
    return observed.replaceRange(match.range, "${match.groupValues[1]}$inputSha256${match.groupValues[2]}")
}

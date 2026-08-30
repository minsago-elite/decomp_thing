package decompengine.oracle.fulltree

import java.nio.charset.StandardCharsets
import java.nio.file.Path

internal data class FullTreeDwarfCompilationUnit(
    val offset: Long,
    val version: Int,
    val addressSize: Int,
    val rawPath: String,
    val producer: String?,
    val language: Long?,
)

/** Bounded ELF/DWARF reader for the compilation-unit metadata used by inventory v1. */
internal object FullTreeDwarfCompilationUnits {
    fun read(
        artifact: StableControlFile,
        scratchParent: Path,
        scope: kotlinx.serialization.json.JsonObject,
        limits: FullTreeControlLimits,
        checkpoint: (String) -> Unit = {},
    ): List<FullTreeDwarfCompilationUnit> {
        val authenticatedLimit = scope.controlObject("bounds").controlObject("wholeRun")
            .controlLong("compilationUnits")
        val maximumUnits = minOf(authenticatedLimit, limits.maximumCompilationUnits.toLong())
        FullTreeDwarfSections.open(artifact, scratchParent, limits).use { sections ->
            val info = sections.required(".debug_info")
            val abbrev = sections.required(".debug_abbrev")
            val result = arrayListOf<FullTreeDwarfCompilationUnit>()
            var metadataBytes = 0L
            val parseBudget = FullTreeDwarfParseBudget(limits.maximumDwarfParseSteps, checkpoint)
            val headers = FullTreeDwarfCompilationUnitHeaders(info, maximumUnits, parseBudget)
            while (headers.hasNext()) {
                val header = headers.next()
                val cursor = header.dieCursor(info)
                val abbreviationCode = cursor.readUleb128()
                if (abbreviationCode == 0L) {
                    throw FullTreeControlException("DWARF compilation unit has no top-level DIE")
                }
                val declaration = FullTreeDwarfAbbreviations(
                    abbrev,
                    header.abbreviationOffset,
                    limits,
                    parseBudget,
                ).required(abbreviationCode, "DWARF top-level abbreviation")
                val values = LinkedHashMap<Long, FullTreeDwarfFormValue>()
                declaration.attributes.forEach { attribute ->
                    val value = FullTreeDwarfForms.read(
                        cursor,
                        attribute.form,
                        attribute.implicitConstant,
                        header.version,
                        header.addressSize,
                        header.offsetSize,
                        limits,
                    )
                    if (attribute.name in RELEVANT_ATTRIBUTES) values[attribute.name] = value
                }
                val stringOffsetsBase = (values[DW_AT_STR_OFFSETS_BASE] as? FullTreeDwarfNumericValue)?.value
                val name = FullTreeDwarfForms.decodeString(
                    values[DW_AT_NAME]
                        ?: throw FullTreeControlException("DWARF compilation unit lacks DW_AT_name"),
                    sections,
                    stringOffsetsBase,
                    header.offsetSize,
                    limits,
                    "DWARF compilation-unit name",
                )
                val rawPath = if (name.startsWith('/')) {
                    name
                } else {
                    val directory = FullTreeDwarfForms.decodeString(
                        values[DW_AT_COMP_DIR]
                            ?: throw FullTreeControlException("DWARF compilation unit lacks DW_AT_comp_dir"),
                        sections,
                        stringOffsetsBase,
                        header.offsetSize,
                        limits,
                        "DWARF compilation directory",
                    ).trimEnd('/')
                    "$directory/$name"
                }
                val producer = values[DW_AT_PRODUCER]?.let { value ->
                    FullTreeDwarfForms.decodeString(
                        value,
                        sections,
                        stringOffsetsBase,
                        header.offsetSize,
                        limits,
                        "DWARF compilation-unit producer",
                    )
                }
                val language = values[DW_AT_LANGUAGE]?.let { value ->
                    val numeric = value as? FullTreeDwarfNumericValue
                        ?: throw FullTreeControlException("DWARF compilation-unit language is not an integer")
                    if (numeric.value < 0L) {
                        throw FullTreeControlException("DWARF compilation-unit language is invalid")
                    }
                    numeric.value
                }
                metadataBytes = try {
                    Math.addExact(
                        metadataBytes,
                        Math.addExact(
                            Math.addExact(
                                rawPath.toByteArray(StandardCharsets.UTF_8).size.toLong(),
                                producer?.toByteArray(StandardCharsets.UTF_8)?.size?.toLong() ?: 0L,
                            ),
                            MODELED_COMPILATION_UNIT_OVERHEAD_BYTES,
                        ),
                    )
                } catch (failure: ArithmeticException) {
                    throw FullTreeControlException("DWARF compilation-unit metadata size overflows", failure)
                }
                if (metadataBytes > limits.maximumDwarfMetadataBytes) {
                    throw FullTreeControlException("DWARF compilation-unit metadata exceeds its byte bound")
                }
                result += FullTreeDwarfCompilationUnit(
                    offset = header.offset,
                    version = header.version,
                    addressSize = header.addressSize,
                    rawPath = rawPath,
                    producer = producer,
                    language = language,
                )
            }
            return result
        }
    }

    private const val MODELED_COMPILATION_UNIT_OVERHEAD_BYTES = 128L
    private const val DW_AT_NAME = 0x03L
    private const val DW_AT_LANGUAGE = 0x13L
    private const val DW_AT_COMP_DIR = 0x1bL
    private const val DW_AT_PRODUCER = 0x25L
    private const val DW_AT_STR_OFFSETS_BASE = 0x72L
    private val RELEVANT_ATTRIBUTES = setOf(
        DW_AT_NAME,
        DW_AT_LANGUAGE,
        DW_AT_COMP_DIR,
        DW_AT_PRODUCER,
        DW_AT_STR_OFFSETS_BASE,
    )
}

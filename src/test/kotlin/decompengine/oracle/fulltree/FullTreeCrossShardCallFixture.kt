package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal data class FullTreeCrossShardFixtureFunction(
    val name: String,
    val linkageName: String,
    val sourcePath: String,
    val rva: Long,
    val size: Int,
) {
    val functionId: String get() = "function-rva-0x${rva.toString(16)}"
}

internal data class FullTreeCrossShardFixtureCall(
    val name: String,
    val caller: String,
    val addressRva: Long?,
    val targetKind: String,
    val target: String? = null,
    val aliases: List<String> = emptyList(),
    val tailCall: Boolean = false,
    val callPcRva: Long? = if (tailCall) addressRva else null,
    val returnPcRva: Long? = if (tailCall) null else addressRva,
)

internal data class FullTreeCrossShardCallFixture(
    val root: Path,
    val artifact: Path,
    val strippedArtifact: Path,
    val scope: AuthenticatedFullTreeScope,
    val inventoryPath: Path,
    val inventory: JsonObject,
    val functions: Map<String, FullTreeCrossShardFixtureFunction>,
    val calls: List<FullTreeCrossShardFixtureCall>,
    val dieOffsets: Map<String, Long>,
) {
    val shardIds: List<String> = inventory.controlArray("shards").controlObjects("fixture shards")
        .map { it.controlString("id") }
    val functionIds: Map<String, String> = functions.mapValues { it.value.functionId }
    val duplicateCallGroups: List<List<String>> = listOf(listOf("gamma-to-alpha", "gamma-to-alpha-duplicate"))
    val unsupportedSemantics: Set<String> = setOf(
        "relocation-backed-external-or-PLT-target-identities",
        "normalized-semantic-thunk-targets",
        "virtual-slot-identities-and-proven-virtual-targets",
        "multi-target-indirect-proof",
        "source-archive-or-reproducible-build-provenance-for-the-handcrafted-ELF",
    )

    fun shardForFunction(name: String): String = FullTreeScopeControl.shardForSourcePath(
        scope,
        functions.getValue(name).sourcePath,
    )

    fun generateRawCallShards(scratchParent: Path = root): Map<String, FullTreeCallObservationShardGeneration> =
        shardIds.associateWith { shardId ->
            FullTreeCallObservationProducer.generateShard(artifact, inventoryPath, scope, shardId, scratchParent)
        }

    fun generateRawFunctionShards(
        scratchParent: Path = root,
    ): Map<String, FullTreeFunctionObservationShardGeneration> = shardIds.associateWith { shardId ->
        FullTreeFunctionObservationProducer.generateShard(artifact, inventoryPath, scope, shardId, scratchParent)
    }
}

internal fun createFullTreeCrossShardCallFixture(
    root: Path,
    additionalCalls: List<FullTreeCrossShardFixtureCall> = emptyList(),
): FullTreeCrossShardCallFixture {
    Files.createDirectories(root)
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
    val controls = createFullTreeControlFixture(root.resolve("controls"))
    val original = controls.authenticatedScope()
    val fixtureCalls = CrossShardCallElfBytes.calls + additionalCalls
    val fixture = CrossShardCallElfBytes.build(fixtureCalls)
    val artifact = writeElf(root.resolve("cross-shard-calls.elf"), fixture.rich)
    val stripped = writeElf(root.resolve("cross-shard-calls.stripped.elf"), fixture.stripped)
    val originalArtifacts = original.artifactManifest.controlObject("artifacts")
    val reboundArtifacts = JsonObject(originalArtifacts.toMutableMap().apply {
        for ((name, bytes) in listOf("full" to fixture.rich, "stripped" to fixture.stripped)) {
            this[name] = JsonObject(originalArtifacts.controlObject(name).toMutableMap().apply {
                this["bytes"] = JsonPrimitive(bytes.size)
                this["sha256"] = JsonPrimitive(OracleArtifacts.sha256(bytes))
            })
        }
    })
    val manifest = JsonObject(original.artifactManifest.toMutableMap().apply {
        this["artifacts"] = reboundArtifacts
    })
    val manifestSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(manifest))
    val document = JsonObject(original.document.toMutableMap().apply {
        this["oracle"] = JsonObject(original.document.controlObject("oracle").toMutableMap().apply {
            this["artifactManifestSha256"] = JsonPrimitive(manifestSha256)
            this["richArtifactSha256"] = JsonPrimitive(OracleArtifacts.sha256(fixture.rich))
            this["strippedArtifactSha256"] = JsonPrimitive(OracleArtifacts.sha256(fixture.stripped))
        })
    })
    writeControlObject(controls.manifest, manifest)
    writeControlObject(controls.scope, document)
    val scope = controls.authenticatedScope()
    val inventoryPath = root.resolve("cross-shard-inventory.json")
    val inventory = FullTreeInventoryControl.generateAndPublish(
        artifact,
        scope,
        inventoryPath,
        maximumWorkers = 1,
    ).inventory
    check(inventory.controlArray("units").size == 3)
    check(inventory.controlArray("shards").size == 3)
    return FullTreeCrossShardCallFixture(
        root,
        artifact,
        stripped,
        scope,
        inventoryPath,
        inventory,
        CrossShardCallElfBytes.functions,
        fixtureCalls,
        fixture.dieOffsets,
    )
}

private data class CrossShardCallArtifactBytes(
    val rich: ByteArray,
    val stripped: ByteArray,
    val dieOffsets: Map<String, Long>,
)

private data class CrossShardCallDwarfBytes(
    val info: ByteArray,
    val abbreviations: ByteArray,
    val dieOffsets: Map<String, Long>,
)

private data class CrossShardCallSection(
    val name: String,
    val type: Int,
    val bytes: ByteArray,
    val alignment: Int = 1,
    val flags: Long = 0,
    val address: Long = 0,
    val link: Int = 0,
    val info: Int = 0,
    val entrySize: Int = 0,
)

private object CrossShardCallElfBytes {
    private const val IMAGE_BASE = 0x400000L
    private const val TEXT_OFFSET = 0x100
    private const val TEXT_BYTES = 0x400
    private const val ELF_HEADER_BYTES = 64
    private const val PROGRAM_HEADER_BYTES = 56
    private const val SECTION_HEADER_BYTES = 64
    private const val UNIT_HEADER_BYTES = 11

    val functions = listOf(
        FullTreeCrossShardFixtureFunction("alpha", "alpha_entry", "source/clang/lib/Alpha/alpha.c", 0x100, 0x80),
        FullTreeCrossShardFixtureFunction("beta", "_ZN4Beta4callEv", "source/clang/lib/Beta/beta.cc", 0x200, 0x80),
        FullTreeCrossShardFixtureFunction("gamma", "gamma_entry", "source/llvm/lib/Gamma/gamma.c", 0x300, 0x80),
        FullTreeCrossShardFixtureFunction("thunk", "_ZTh0_N4Beta4callEv", "source/llvm/lib/Gamma/gamma.c", 0x380, 0x10),
        FullTreeCrossShardFixtureFunction("callback", "callback_entry", "source/clang/lib/Alpha/alpha.c", 0x3a0, 0x20),
    ).associateBy { it.name }

    val calls = listOf(
        direct("alpha-to-beta", "alpha", 0x105, "beta"),
        direct("alpha-to-thunk", "alpha", 0x10a, "thunk"),
        FullTreeCrossShardFixtureCall(
            "alpha-to-external", "alpha", 0x10c, "external-unresolved", aliases = listOf("fixture_external"),
        ),
        FullTreeCrossShardFixtureCall("alpha-to-callback", "alpha", 0x118, "indirect-proven", "callback"),
        direct("beta-to-gamma", "beta", 0x205, "gamma"),
        FullTreeCrossShardFixtureCall(
            "beta-virtual", "beta", 0x207, "virtual-unresolved", aliases = listOf("virtual_method"),
        ),
        FullTreeCrossShardFixtureCall("beta-ambiguous", "beta", 0x209, "indirect-unresolved"),
        direct("beta-tail-to-alpha", "beta", 0x220, "alpha", tailCall = true),
        direct("gamma-to-alpha", "gamma", 0x305, "alpha"),
        direct("gamma-to-alpha-duplicate", "gamma", 0x305, "alpha"),
        FullTreeCrossShardFixtureCall("gamma-addressless", "gamma", null, "indirect-unresolved"),
        direct("thunk-to-beta", "thunk", 0x380, "beta", tailCall = true),
    )

    fun build(calls: List<FullTreeCrossShardFixtureCall>): CrossShardCallArtifactBytes {
        val dwarf = dwarfSections(calls)
        return CrossShardCallArtifactBytes(
            elf(dwarf),
            elf(null),
            dwarf.dieOffsets,
        )
    }

    private fun direct(
        name: String,
        caller: String,
        address: Long,
        target: String,
        tailCall: Boolean = false,
    ): FullTreeCrossShardFixtureCall = FullTreeCrossShardFixtureCall(
        name,
        caller,
        address,
        "direct-internal",
        target,
        listOf(functions.getValue(target).name, functions.getValue(target).linkageName).sorted(),
        tailCall,
    )

    private fun dwarfSections(calls: List<FullTreeCrossShardFixtureCall>): CrossShardCallDwarfBytes {
        val abbreviations = ByteArrayOutputStream().apply {
            abbreviation(1, 0x11, true, listOf(
                0x03L to FULL_TREE_DW_FORM_STRING,
                0x1bL to FULL_TREE_DW_FORM_STRING,
                0x25L to FULL_TREE_DW_FORM_STRING,
                0x13L to FULL_TREE_DW_FORM_DATA2,
            ))
            abbreviation(2, 0x2e, true, listOf(
                0x03L to FULL_TREE_DW_FORM_STRING,
                0x6eL to FULL_TREE_DW_FORM_STRING,
                0x11L to FULL_TREE_DW_FORM_ADDR,
                0x12L to FULL_TREE_DW_FORM_DATA4,
            ))
            abbreviation(3, 0x2e, false, listOf(
                0x03L to FULL_TREE_DW_FORM_STRING,
                DW_AT_DECLARATION to FULL_TREE_DW_FORM_FLAG_PRESENT,
            ))
            abbreviation(4, 0x2e, false, listOf(
                0x03L to FULL_TREE_DW_FORM_STRING,
                DW_AT_DECLARATION to FULL_TREE_DW_FORM_FLAG_PRESENT,
                0x4cL to FULL_TREE_DW_FORM_DATA1,
            ))
            abbreviation(5, 0x34, false, listOf(0x03L to FULL_TREE_DW_FORM_STRING))
            abbreviation(6, 0x48, false, listOf(
                0x7dL to FULL_TREE_DW_FORM_ADDR,
                0x7fL to FULL_TREE_DW_FORM_REF_ADDR,
            ))
            abbreviation(7, 0x48, false, listOf(
                0x81L to FULL_TREE_DW_FORM_ADDR,
                0x7fL to FULL_TREE_DW_FORM_REF_ADDR,
                0x82L to FULL_TREE_DW_FORM_FLAG_PRESENT,
            ))
            abbreviation(8, 0x48, false, listOf(
                0x7dL to FULL_TREE_DW_FORM_ADDR,
                0x83L to FULL_TREE_DW_FORM_EXPRLOC,
            ))
            abbreviation(9, 0x48, false, listOf(
                0x7dL to FULL_TREE_DW_FORM_ADDR,
                0x83L to FULL_TREE_DW_FORM_EXPRLOC,
                0x7fL to FULL_TREE_DW_FORM_REF_ADDR,
            ))
            abbreviation(10, 0x48, false, emptyList())
            abbreviation(11, 0x48, false, listOf(
                0x81L to FULL_TREE_DW_FORM_ADDR,
                0x7dL to FULL_TREE_DW_FORM_ADDR,
                0x7fL to FULL_TREE_DW_FORM_REF_ADDR,
            ))
            abbreviation(12, 0x48, false, listOf(
                0x81L to FULL_TREE_DW_FORM_ADDR,
                0x7fL to FULL_TREE_DW_FORM_REF_ADDR,
            ))
            write(0)
        }.toByteArray()
        val info = ByteArrayOutputStream()
        val dieOffsets = linkedMapOf<String, Long>()
        val references = mutableListOf<Pair<Int, String>>()
        for ((sourcePath, unitFunctions) in functions.values.groupBy { it.sourcePath }) {
            val unitStart = info.size()
            val dies = ByteArrayOutputStream()
            fun die(code: Int, name: String) {
                check(dieOffsets.put(name, (unitStart + UNIT_HEADER_BYTES + dies.size()).toLong()) == null)
                dies.uleb(code.toLong())
            }
            fun reference(target: String) {
                references += (unitStart + UNIT_HEADER_BYTES + dies.size()) to target
                dies.write(unsigned(0, 4))
            }
            die(1, sourcePath)
            dies.string(sourcePath.substringAfterLast('/'))
            dies.string("/fixture/source-tree/" + sourcePath.removePrefix("source/").substringBeforeLast('/'))
            dies.string("Kotlin authenticated cross-shard call fixture")
            dies.write(unsigned(if (sourcePath.endsWith(".cc")) 0x0004 else 0x000c, 2))
            if (unitFunctions.any { it.name == "alpha" }) {
                die(3, "external-origin")
                dies.string("fixture_external")
            }
            if (unitFunctions.any { it.name == "beta" }) {
                die(4, "virtual-origin")
                dies.string("virtual_method")
                dies.write(1)
                die(5, "callback-origin")
                dies.string("ambiguous_callback")
            }
            for (function in unitFunctions) {
                die(2, function.name)
                dies.string(function.name)
                dies.string(function.linkageName)
                dies.write(unsigned(IMAGE_BASE + function.rva, 8))
                dies.write(unsigned(function.size.toLong(), 4))
                for (call in calls.filter { it.caller == function.name }) {
                    when {
                        call.callPcRva != null -> {
                            require(call.targetKind == "direct-internal")
                            die(if (call.returnPcRva != null) 11 else if (call.tailCall) 7 else 12, call.name)
                            dies.write(unsigned(IMAGE_BASE + call.callPcRva, 8))
                            if (call.returnPcRva != null) dies.write(unsigned(IMAGE_BASE + call.returnPcRva, 8))
                            reference(checkNotNull(call.target))
                        }
                        call.addressRva == null -> die(10, call.name)
                        call.targetKind == "indirect-proven" -> {
                            die(8, call.name)
                            dies.write(unsigned(IMAGE_BASE + call.addressRva, 8))
                            dies.uleb(9)
                            dies.write(0x03)
                            dies.write(unsigned(IMAGE_BASE + functions.getValue(checkNotNull(call.target)).rva, 8))
                        }
                        call.targetKind == "indirect-unresolved" -> {
                            die(9, call.name)
                            dies.write(unsigned(IMAGE_BASE + call.addressRva, 8))
                            dies.uleb(1)
                            dies.write(0x50)
                            reference("callback-origin")
                        }
                        else -> {
                            die(if (call.tailCall) 7 else 6, call.name)
                            dies.write(unsigned(IMAGE_BASE + call.addressRva, 8))
                            reference(when (call.targetKind) {
                                "external-unresolved" -> "external-origin"
                                "virtual-unresolved" -> "virtual-origin"
                                else -> checkNotNull(call.target)
                            })
                        }
                    }
                }
                dies.write(0)
            }
            dies.write(0)
            val body = unsigned(4, 2) + unsigned(0, 4) + byteArrayOf(8) + dies.toByteArray()
            info.write(unsigned(body.size.toLong(), 4))
            info.write(body)
        }
        val result = info.toByteArray()
        for ((offset, target) in references) put(result, offset, dieOffsets.getValue(target), 4)
        return CrossShardCallDwarfBytes(result, abbreviations, dieOffsets.toMap())
    }

    private fun elf(dwarf: CrossShardCallDwarfBytes?): ByteArray {
        val sections = mutableListOf(CrossShardCallSection(
            ".text", 1, text(), alignment = 16, flags = 6, address = IMAGE_BASE + TEXT_OFFSET,
        ))
        val dynamicStrings = byteArrayOf(0) + "alpha_entry\u0000fixture_external\u0000".toByteArray(Charsets.US_ASCII)
        val dynamicSymbols = ByteArray(72).apply {
            put(this, 24, 1, 4)
            this[28] = 0x12
            put(this, 30, 1, 2)
            put(this, 32, IMAGE_BASE + functions.getValue("alpha").rva, 8)
            put(this, 40, functions.getValue("alpha").size.toLong(), 8)
            put(this, 48, 13, 4)
            this[52] = 0x12
        }
        val dynamicOffset = TEXT_OFFSET + TEXT_BYTES
        sections += CrossShardCallSection(
            ".dynsym", 11, dynamicSymbols, alignment = 8, flags = 2, address = IMAGE_BASE + dynamicOffset,
            link = 3, info = 1, entrySize = 24,
        )
        sections += CrossShardCallSection(
            ".dynstr", 3, dynamicStrings, flags = 2, address = IMAGE_BASE + dynamicOffset + dynamicSymbols.size,
        )
        if (dwarf != null) {
            sections += CrossShardCallSection(".debug_info", 1, dwarf.info)
            sections += CrossShardCallSection(".debug_abbrev", 1, dwarf.abbreviations)
            val strings = ByteArrayOutputStream().apply { write(0) }
            val symbols = ByteArrayOutputStream().apply { write(ByteArray(24)) }
            fun symbol(name: String, function: FullTreeCrossShardFixtureFunction?) {
                val nameOffset = strings.size()
                strings.string(name)
                symbols.write(unsigned(nameOffset.toLong(), 4))
                symbols.write(0x12)
                symbols.write(0)
                symbols.write(unsigned(if (function == null) 0 else 1, 2))
                symbols.write(unsigned(function?.let { IMAGE_BASE + it.rva } ?: 0, 8))
                symbols.write(unsigned(function?.size?.toLong() ?: 0, 8))
            }
            for (function in functions.values) {
                symbol(function.name, function)
                symbol(function.linkageName, function)
            }
            symbol("fixture_external", null)
            sections += CrossShardCallSection(
                ".symtab", 2, symbols.toByteArray(), alignment = 8, link = 7, info = 1, entrySize = 24,
            )
            sections += CrossShardCallSection(".strtab", 3, strings.toByteArray())
        }
        val names = ByteArrayOutputStream().apply { write(0) }
        val nameOffsets = (sections.map { it.name } + ".shstrtab").associateWith { name ->
            names.size().also { names.string(name) }
        }
        sections += CrossShardCallSection(".shstrtab", 3, names.toByteArray())
        var cursor = TEXT_OFFSET
        val offsets = sections.map { section ->
            cursor = align(cursor, section.alignment)
            cursor.also { cursor += section.bytes.size }
        }
        val sectionTableOffset = align(cursor, 8)
        val result = ByteArray(sectionTableOffset + (sections.size + 1) * SECTION_HEADER_BYTES)
        byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 2, 1, 1).copyInto(result)
        put(result, 16, 2, 2)
        put(result, 18, 62, 2)
        put(result, 20, 1, 4)
        put(result, 24, IMAGE_BASE + functions.getValue("alpha").rva, 8)
        put(result, 32, ELF_HEADER_BYTES.toLong(), 8)
        put(result, 40, sectionTableOffset.toLong(), 8)
        put(result, 52, ELF_HEADER_BYTES.toLong(), 2)
        put(result, 54, PROGRAM_HEADER_BYTES.toLong(), 2)
        put(result, 56, 3, 2)
        put(result, 58, SECTION_HEADER_BYTES.toLong(), 2)
        put(result, 60, (sections.size + 1).toLong(), 2)
        put(result, 62, sections.size.toLong(), 2)
        programHeader(result, ELF_HEADER_BYTES, 0, IMAGE_BASE, ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES * 3, 4)
        programHeader(result, ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES, TEXT_OFFSET, IMAGE_BASE + TEXT_OFFSET, TEXT_BYTES, 5)
        programHeader(
            result,
            ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES * 2,
            dynamicOffset,
            IMAGE_BASE + dynamicOffset,
            dynamicSymbols.size + dynamicStrings.size,
            4,
        )
        sections.forEachIndexed { index, section ->
            section.bytes.copyInto(result, offsets[index])
            val header = sectionTableOffset + (index + 1) * SECTION_HEADER_BYTES
            put(result, header, nameOffsets.getValue(section.name).toLong(), 4)
            put(result, header + 4, section.type.toLong(), 4)
            put(result, header + 8, section.flags, 8)
            put(result, header + 16, section.address, 8)
            put(result, header + 24, offsets[index].toLong(), 8)
            put(result, header + 32, section.bytes.size.toLong(), 8)
            put(result, header + 40, section.link.toLong(), 4)
            put(result, header + 44, section.info.toLong(), 4)
            put(result, header + 48, section.alignment.toLong(), 8)
            put(result, header + 56, section.entrySize.toLong(), 8)
        }
        return result
    }

    private fun programHeader(result: ByteArray, header: Int, offset: Int, address: Long, size: Int, flags: Int) {
        put(result, header, 1, 4)
        put(result, header + 4, flags.toLong(), 4)
        put(result, header + 8, offset.toLong(), 8)
        put(result, header + 16, address, 8)
        put(result, header + 24, address, 8)
        put(result, header + 32, size.toLong(), 8)
        put(result, header + 40, size.toLong(), 8)
        put(result, header + 48, 0x100, 8)
    }

    private fun text(): ByteArray {
        val result = ByteArray(TEXT_BYTES) { 0x90.toByte() }
        fun branch(address: Int, target: Long, opcode: Int) {
            result[address - TEXT_OFFSET] = opcode.toByte()
            put(result, address - TEXT_OFFSET + 1, target - (address + 5), 4)
        }
        branch(0x100, 0x200, 0xe8)
        branch(0x105, 0x380, 0xe8)
        branch(0x200, 0x300, 0xe8)
        branch(0x220, 0x100, 0xe9)
        branch(0x300, 0x100, 0xe8)
        branch(0x380, 0x200, 0xe9)
        for (address in listOf(0x10a, 0x116, 0x205, 0x207)) {
            result[address - TEXT_OFFSET] = 0xff.toByte()
            result[address - TEXT_OFFSET + 1] = 0xd0.toByte()
        }
        result[0x10c - TEXT_OFFSET] = 0x48
        result[0x10d - TEXT_OFFSET] = 0xb8.toByte()
        put(result, 0x10e - TEXT_OFFSET, IMAGE_BASE + functions.getValue("callback").rva, 8)
        for (address in listOf(0x118, 0x305, 0x3a0)) result[address - TEXT_OFFSET] = 0xc3.toByte()
        return result
    }

    private fun ByteArrayOutputStream.abbreviation(
        code: Int,
        tag: Long,
        children: Boolean,
        attributes: List<Pair<Long, Long>>,
    ) {
        uleb(code.toLong())
        uleb(tag)
        write(if (children) 1 else 0)
        for ((attribute, form) in attributes) {
            uleb(attribute)
            uleb(form)
        }
        write(0)
        write(0)
    }

    private fun ByteArrayOutputStream.uleb(value: Long) {
        var remaining = value
        do {
            val bits = (remaining and 0x7f).toInt()
            remaining = remaining ushr 7
            write(bits or if (remaining == 0L) 0 else 0x80)
        } while (remaining != 0L)
    }

    private fun ByteArrayOutputStream.string(value: String) {
        write(value.toByteArray(Charsets.UTF_8))
        write(0)
    }

    private fun unsigned(value: Long, width: Int): ByteArray =
        ByteArray(width) { index -> (value ushr (index * 8)).toByte() }

    private fun put(bytes: ByteArray, offset: Int, value: Long, width: Int) {
        unsigned(value, width).copyInto(bytes, offset)
    }

    private fun align(value: Int, alignment: Int): Int =
        (value + alignment - 1) / alignment * alignment
}

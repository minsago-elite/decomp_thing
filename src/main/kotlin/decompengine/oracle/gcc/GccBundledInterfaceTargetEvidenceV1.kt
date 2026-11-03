package decompengine.oracle.gcc

import decompengine.oracle.fulltree.FullTreeElfExecutableRange

internal data class GccBundledInterfaceAddressSpaceIdentityV1(
    val name: String, val type: Int, val sizeBits: Int, val addressableUnitSize: Int,
    val overlay: Boolean, val signedOffsets: Boolean,
)

/** Independently derived input/target metadata; construction grants no owned result or ABI authority. */
internal data class GccBundledInterfaceTargetEvidenceV1(
    val profileSha256: String, val profileTarget: String, val inputSha256: String, val inputBytes: Long,
    val imageBase: ULong, val languageId: String, val compilerSpecId: String,
    val defaultAddressSpace: GccBundledInterfaceAddressSpaceIdentityV1,
    val executableRanges: List<FullTreeElfExecutableRange>,
    val engineId: String = "driver",
) {
    init { require(engineId == "driver") { "interface observations require the independently selected driver" } }
}

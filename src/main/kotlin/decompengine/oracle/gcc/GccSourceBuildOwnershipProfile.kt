package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import kotlinx.serialization.json.JsonObject

/** Proposed policy metadata only. Loading this class approves neither the profile nor execution. */
internal class GccSourceBuildOwnershipProfile private constructor(
    metadataPins: Map<String, GccSourceBuildMetadataPin>,
    mandatoryGates: List<String>,
    resourceCeilings: Map<String, Long>,
    private val encoded: ByteArray,
) {
    val metadataPins = OwnershipJson.immutableMap(metadataPins)
    val mandatoryGates = OwnershipJson.immutable(mandatoryGates)
    val resourceCeilings = OwnershipJson.immutableMap(resourceCeilings)
    val canonicalSha256: String = OracleArtifacts.sha256(encoded)
    val approved: Boolean get() = false
    val productionVerified: Boolean get() = false
    fun canonicalBytes(): ByteArray = encoded.copyOf()

    companion object {
        const val SCHEMA = "gcc/source-build-ownership-profile-v1"
        const val SOURCE_REVISION = "78d4ac73dd391005b895a6148cd9831e28e1208b"
        const val ORIGIN_IMAGE = "sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248"
        const val REPRODUCED_IMAGE = "sha256:807f16e03368e1e0ff3c904f21f1a13c260d78a8b7226a52284a2ee68a4d1511"
        const val RICH_SHA256 = "8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b"
        const val STRIPPED_SHA256 = "3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4"
        private val GATES = listOf(
            "signed-source-archive", "toolchain-runtime-and-reproduction-bridge", "collector-kernel-and-completion",
            "exact-rich-stripped-pair", "complete-action-file-object-link-closure", "physical-cu-declaration-use-ownership",
            "independent-kotlin-replay-twice", "hidden-source-oracle-isolation", "independent-semantic-authority-review",
            "required-ci-and-independent-review",
        )
        private val AUTHORITY_FIELDS = setOf("approved", "sourceAuthenticated", "runtimeAuthenticated", "collectorAuthenticated",
            "exactPairReproduced", "closureComplete", "ownershipComplete", "nominalIdentityComplete", "modelBound",
            "sealed", "scored", "productionVerified", "releaseEligible")
        private val CEILINGS = linkedMapOf(
            "maximumProfileBytes" to 65_536L, "maximumMetadataBytes" to 131_072L,
            "maximumTotalMetadataBytes" to 262_144L, "maximumRecordBytes" to 8_388_608L,
            "maximumRecordNodes" to 100_000L, "maximumArgvWords" to 16_384L,
            "maximumEnvironmentEntries" to 4_096L, "maximumResponseDepth" to 16L,
            "maximumPathBytes" to 4_096L, "maximumSourceMembers" to 500_000L,
            "maximumExpandedSourceBytes" to 4_294_967_296L, "maximumBuildWallSeconds" to 7_200L,
            "maximumBuildCpuSeconds" to 28_800L, "maximumBuildRssBytes" to 8_589_934_592L,
            "maximumBuildScratchBytes" to 34_359_738_368L, "maximumLiveDescendants" to 256L,
            "maximumExecs" to 200_000L, "maximumCaptureEvents" to 100_000_000L,
            "maximumRawEventBytes" to 17_179_869_184L, "maximumFileVersionBytes" to 17_179_869_184L,
            "maximumCanonicalRows" to 5_000_000L, "maximumCanonicalNodes" to 64_000_000L,
            "maximumCanonicalBytes" to 2_147_483_648L, "maximumShards" to 256L,
            "maximumVerifierHeapBytes" to 1_073_741_824L, "maximumVerifierRssBytes" to 8_589_934_592L,
            "maximumVerifierScratchBytes" to 17_179_869_184L, "maximumVerifierWork" to 100_000_000L,
            "maximumVerifierWallSeconds" to 3_600L, "maximumPhysicalDies" to 1_000_000L,
            "maximumTypedReferences" to 2_000_000L, "maximumDeclarationUseRows" to 1_000_000L,
            "maximumScopeDepth" to 128L,
        )
        private val CHECKED_PINS = linkedMapOf(
            "sourceLock" to GccSourceBuildMetadataPin("oracle/gcc/16.2.0/source-lock.json", 3_953,
                "e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc"),
            "buildRecord" to GccSourceBuildMetadataPin("oracle/gcc/16.2.0/build-record.json", 3_910,
                "f91a68ffde054b9598cba8506bbf6b3b373b35b8680fddb54f76bffa9db23637"),
            "reproductionLock" to GccSourceBuildMetadataPin("oracle/gcc/16.2.0/toolchain-reproduction.json", 1_568,
                "5c2c159d7287305159a220a1260f6ff6bffe9ec78bb1cbe2fb24f85b68a7d4de"),
            "recipe" to GccSourceBuildMetadataPin("oracle/gcc/16.2.0/build-toolchain.Dockerfile", 3_345,
                "8b0af79ba3426f49ba599eb0c7eea433c62ac5bb6ab5e7797f7d09d978f43543"),
            "artifactManifest" to GccSourceBuildMetadataPin("oracle/gcc/16.2.0/oracle-manifest.json", 60_269,
                "c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9"),
        )

        fun load(bytes: ByteArray, maximumProfileBytes: Int = 65_536): GccSourceBuildOwnershipProfile = ownershipBoundary {
            ownershipRequire(maximumProfileBytes in 1..65_536, "profile byte limit is invalid")
            val root = OwnershipJson.parseObject(bytes, maximumProfileBytes)
            OracleSchemas.validate(SCHEMA, root)
            OwnershipJson.exact(root, setOf("schemaVersion", "schema", "profileId", "status", "sourceRevision", "metadataPins",
                "runtimePolicy", "qualification", "units", "mandatoryGates", "authority", "resourceCeilings"), "profile")
            ownershipRequire(OwnershipJson.number(root, "schemaVersion") == 1L, "schema version differs")
            OwnershipJson.expect(root, "schema", "gcc-source-build-ownership-profile-v1")
            OwnershipJson.expect(root, "profileId", "gcc-driver-16.2.0-source-build-ownership-proposal-v1")
            OwnershipJson.expect(root, "status", "proposed-offline-only")
            OwnershipJson.expect(root, "sourceRevision", SOURCE_REVISION)
            val pins = OwnershipJson.obj(root, "metadataPins")
            OwnershipJson.exact(pins, CHECKED_PINS.keys, "metadataPins")
            val decoded = pins.mapValues { (_, element) ->
                val pin = element as? JsonObject ?: ownershipFail("metadata pin must be an object")
                OwnershipJson.exact(pin, setOf("path", "bytes", "sha256"), "metadata pin")
                GccSourceBuildMetadataPin(OwnershipJson.text(pin, "path"), OwnershipJson.number(pin, "bytes", 1),
                    OwnershipJson.sha(OwnershipJson.text(pin, "sha256")))
            }
            ownershipRequire(decoded == CHECKED_PINS, "metadata pins differ from the checked historical generation")
            val runtime = OwnershipJson.obj(root, "runtimePolicy")
            OwnershipJson.exact(runtime, setOf("recordedOriginImageId", "proposedReproducedImageId", "originReference",
                "bridge", "exactPairRequired"), "runtimePolicy")
            OwnershipJson.expect(runtime, "recordedOriginImageId", ORIGIN_IMAGE)
            OwnershipJson.expect(runtime, "proposedReproducedImageId", REPRODUCED_IMAGE)
            OwnershipJson.expect(runtime, "originReference", "historical-image-id-not-pull-uri")
            OwnershipJson.expect(runtime, "bridge", "reviewed-runtime-reproduction-and-exact-pair-proof-required")
            ownershipRequire(runtime["exactPairRequired"]?.toString() == "true", "exact pair gate must be retained")
            val q = OwnershipJson.obj(root, "qualification")
            OwnershipJson.exact(q, setOf("actualCapturedBuilds", "independentEvidenceReplays", "extraBuilds"), "qualification")
            ownershipRequire(OwnershipJson.number(q, "actualCapturedBuilds") == 1L &&
                OwnershipJson.number(q, "independentEvidenceReplays") == 2L, "capture/replay requirement differs")
            OwnershipJson.expect(q, "extraBuilds", "concrete-remaining-risk-only")
            val units = OwnershipJson.obj(root, "units")
            OwnershipJson.exact(units, setOf("owner", "physicalCu", "sourceOnly", "nominalIdentity"), "units")
            OwnershipJson.expect(units, "owner", "source-tu-build-root-role-target-effective-command-variant-linked-object")
            OwnershipJson.expect(units, "physicalCu", "physical-witness-not-owner")
            OwnershipJson.expect(units, "sourceOnly", "retained-nonowner")
            OwnershipJson.expect(units, "nominalIdentity", "separate-reviewed-language-authority-required")
            val gates = OwnershipJson.strings(root, "mandatoryGates")
            ownershipRequire(gates == GATES, "mandatory gates differ")
            val authority = OwnershipJson.obj(root, "authority")
            OwnershipJson.exact(authority, AUTHORITY_FIELDS, "authority")
            AUTHORITY_FIELDS.forEach { OwnershipJson.falseValue(authority, it) }
            val ceilings = OwnershipJson.obj(root, "resourceCeilings")
            OwnershipJson.exact(ceilings, CEILINGS.keys, "resourceCeilings")
            val decodedCeilings = ceilings.keys.associateWith { OwnershipJson.number(ceilings, it, 1) }
            ownershipRequire(decodedCeilings == CEILINGS, "proposed ceilings differ from the reviewed plan")
            GccSourceBuildOwnershipProfile(decoded, gates, decodedCeilings,
                OracleJson.canonicalBytes(root, OwnershipJson.limits(maximumProfileBytes)))
        }
    }
}

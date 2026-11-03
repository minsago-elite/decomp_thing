package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeFunctionObservationIsolationConfiguration
import decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeArtifactRole
import decompengine.oracle.machinecalls.MachineCallFileV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV2
import java.nio.file.Path
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/** Shared exact role/root join for live external worker requests. */
internal fun requireExternalRuntimeSnapshotBindings(
    runtime: MachineCallRuntimeV2,
    controlRoot: Path,
    configuration: FullTreeFunctionObservationIsolationConfiguration,
) {
    val artifacts = configuration.runtimeArtifacts.associateBy { it.role }
    require(artifacts.keys == setOf(FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BRIDGE,
        FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BUNDLE_MANIFEST)) {
        "external runtime artifact roles differ from the authenticated materializer"
    }
    require(runtime.bridgeSnapshot.path == controlRoot.resolve("runtime").resolve(
        FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BRIDGE.snapshotName) &&
        runtime.bundleManifestSnapshot.path == controlRoot.resolve("runtime").resolve(
            FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BUNDLE_MANIFEST.snapshotName)) {
        "external runtime snapshot path differs from the exact owned control root"
    }
    for ((role, file) in listOf(
        FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BRIDGE to runtime.bridgeSnapshot,
        FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BUNDLE_MANIFEST to runtime.bundleManifestSnapshot,
    )) {
        val declared = artifacts.getValue(role)
        require(declared.path == runtime.bundleRoot.resolve(role.sourceName) && declared.bytes == file.bytes &&
            declared.expectedSha256 == file.sha256) {
            "external runtime snapshot differs from its configuration materializer source role: $role"
        }
    }
}

internal fun parseMachineCallRuntimeV2(value: JsonObject): MachineCallRuntimeV2 {
    require(value.keys == setOf("bundleRoot", "ghidraArchivePath", "archiveSha256", "archiveBytes", "bridgeSha256",
        "bundleManifestSha256", "languageId", "languageVersion", "bridgeSnapshot", "bundleManifestSnapshot"))
    fun file(key: String): MachineCallFileV1 {
        val record = value.getValue(key) as JsonObject
        require(record.keys == setOf("path", "bytes", "sha256"))
        return MachineCallFileV1(Path.of(record.string("path")), record.number("bytes"), record.string("sha256"))
    }
    return MachineCallRuntimeV2(Path.of(value.string("bundleRoot")), Path.of(value.string("ghidraArchivePath")),
        value.string("archiveSha256"), value.number("archiveBytes"), value.string("bridgeSha256"),
        value.string("bundleManifestSha256"), value.string("languageId"), value.string("languageVersion"),
        file("bridgeSnapshot"), file("bundleManifestSnapshot"))
}

internal fun v2ExternalRequestBytes(
    legacyBytes: ByteArray,
    runtime: MachineCallRuntimeV2,
    controlRoot: Path,
    kind: String,
): ByteArray {
    val legacy = OracleJson.parseCanonical(legacyBytes) as JsonObject
    return OracleJson.canonicalBytes(JsonObject(legacy + mapOf(
        "schemaVersion" to JsonPrimitive(2), "kind" to JsonPrimitive(kind),
        "runtime" to runtime.json(), "controlRoot" to JsonPrimitive(controlRoot.toString()),
    )))
}

internal fun legacyExternalRequestBytes(value: JsonObject, runtime: MachineCallRuntimeV2, kindV1: String): ByteArray =
    OracleJson.canonicalBytes(JsonObject(value - "controlRoot" + mapOf(
        "schemaVersion" to JsonPrimitive(1), "kind" to JsonPrimitive(kindV1),
        "runtime" to runtime.reportJson(),
    )))

private fun JsonObject.string(key: String): String =
    (getValue(key) as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("$key must be a string")
private fun JsonObject.number(key: String): Long =
    (getValue(key) as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull ?: error("$key must be an integer")

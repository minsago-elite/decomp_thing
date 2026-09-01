package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeScopeControlTest {
    @Test
    fun `frozen Python v1 scope bindings path normalization and sharding remain exact`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("fixture"))
            val scope = fixture.authenticatedScope()

            assertEquals(FROZEN_SCOPE_SHA256, scope.sha256)
            assertEquals(FROZEN_SOURCE_LOCK_SHA256, scope.sourceLockSha256)
            assertEquals(FROZEN_MANIFEST_SHA256, scope.artifactManifestSha256)
            assertEquals(
                "source/clang/lib/Driver/main.cpp",
                FullTreeScopeControl.normalizeSourcePath(
                    scope,
                    "/fixture/source-tree/clang/lib/Driver/main.cpp",
                ),
            )
            assertEquals(
                "generated-tools-clang",
                FullTreeScopeControl.shardForSourcePath(
                    scope,
                    "generated/tools/clang/lib/Basic/Generated.cpp",
                ),
            )
            assertEquals(
                "clang-lib-driver",
                FullTreeScopeControl.shardForSourcePath(scope, "source/clang/lib/Driver/main.cpp"),
            )
        }

    @Test
    fun `scope rejects stale bindings noncanonical JSON duplicate keys and configured limits`(): Unit =
        inControlTemporaryDirectory { directory ->
            val stale = createFullTreeControlFixture(directory.resolve("stale"))
            val scope = parseControlObject(stale.scope)
            val oracle = scope.controlObject("oracle")
            writeControlObject(
                stale.scope,
                JsonObject(scope.toMutableMap().apply {
                    this["oracle"] = JsonObject(oracle.toMutableMap().apply {
                        this["sourceLockSha256"] = JsonPrimitive("0".repeat(64))
                    })
                }),
            )
            assertFailsWith<FullTreeControlException> { stale.authenticatedScope() }

            val noncanonical = createFullTreeControlFixture(directory.resolve("noncanonical"))
            Files.write(noncanonical.scope, Files.readAllBytes(noncanonical.scope) + byteArrayOf(' '.code.toByte()))
            assertFailsWith<FullTreeControlException> { noncanonical.authenticatedScope() }

            val duplicate = createFullTreeControlFixture(directory.resolve("duplicate"))
            val text = Files.readString(duplicate.scope)
            Files.writeString(duplicate.scope, text.replaceFirst("{\n", "{\n  \"bounds\": {},\n"))
            assertFailsWith<FullTreeControlException> { duplicate.authenticatedScope() }

            val bounded = createFullTreeControlFixture(directory.resolve("bounded"))
            assertFailsWith<FullTreeControlException> {
                bounded.authenticatedScope(
                    FullTreeControlLimits(maximumScopeBytes = Files.size(bounded.scope).toInt() - 1),
                )
            }

            val forged = bounded.authenticatedScope()
            assertFailsWith<FullTreeControlException> {
                FullTreeScopeControl.validate(
                    AuthenticatedFullTreeScope(
                        document = forged.document,
                        sha256 = "0".repeat(64),
                        sourceLock = forged.sourceLock,
                        sourceLockSha256 = forged.sourceLockSha256,
                        artifactManifest = forged.artifactManifest,
                        artifactManifestSha256 = forged.artifactManifestSha256,
                    ),
                )
            }
        }

    @Test
    fun `scope input symlinks and untrusted write modes fail closed`(): Unit =
        inControlTemporaryDirectory { directory ->
            val linked = createFullTreeControlFixture(directory.resolve("linked"))
            val real = linked.root.resolve("scope-real.json")
            Files.move(linked.scope, real)
            Files.createSymbolicLink(linked.scope, real.fileName)
            assertFailsWith<FullTreeControlException> { linked.authenticatedScope() }

            val writable = createFullTreeControlFixture(directory.resolve("writable"))
            Files.setPosixFilePermissions(writable.sourceLock, PosixFilePermissions.fromString("rw-rw-r--"))
            assertFailsWith<FullTreeControlException> { writable.authenticatedScope() }

            val writableDirectory = createFullTreeControlFixture(directory.resolve("writable-directory"))
            Files.setPosixFilePermissions(
                writableDirectory.root,
                PosixFilePermissions.fromString("rwxrwx---"),
            )
            assertFailsWith<FullTreeControlException> { writableDirectory.authenticatedScope() }
        }

    @Test
    fun `oracle manifest binds the exact full-tree build record bytes`(): Unit =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("build-record-binding"))
            val scope = fixture.authenticatedScope()
            val exactBytes = Files.readAllBytes(fixture.buildRecord)

            assertEquals(
                fixtureSha256(fixture.buildRecord),
                FullTreeScopeControl.requireBuildRecordBinding(scope, exactBytes),
            )

            val buildRecord = parseControlObject(fixture.buildRecord)
            val toolDigest = buildRecord.controlArray("tools").controlObjects("build-record tools")
                .first().controlString("executableSha256")
            val replacementDigest = (if (toolDigest[0] == '0') "1" else "0") + toolDigest.drop(1)
            val crossPairedBytes = exactBytes.toString(Charsets.UTF_8)
                .replaceFirst(toolDigest, replacementDigest)
                .toByteArray(Charsets.UTF_8)
            assertEquals(exactBytes.size, crossPairedBytes.size)
            assertFailsWith<FullTreeControlException> {
                FullTreeScopeControl.requireBuildRecordBinding(scope, crossPairedBytes)
            }
            assertFailsWith<FullTreeControlException> {
                FullTreeScopeControl.requireBuildRecordBinding(scope, exactBytes.copyOf(exactBytes.size - 1))
            }
        }

    @Test
    fun `oracle manifest rejects a cross-paired source lock`(): Unit =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("source-lock-binding"))
            val sourceLock = parseControlObject(fixture.sourceLock)
            val archiveDigest = sourceLock.controlObject("source").controlObject("archive").controlString("sha256")
            val replacementDigest = (if (archiveDigest[0] == '0') "1" else "0") + archiveDigest.drop(1)
            val crossPairedBytes = Files.readAllBytes(fixture.sourceLock).toString(Charsets.UTF_8)
                .replaceFirst(archiveDigest, replacementDigest)
                .toByteArray(Charsets.UTF_8)
            Files.write(fixture.sourceLock, crossPairedBytes)

            val scope = parseControlObject(fixture.scope)
            writeControlObject(
                fixture.scope,
                JsonObject(scope.toMutableMap().apply {
                    this["oracle"] = JsonObject(scope.controlObject("oracle").toMutableMap().apply {
                        this["sourceLockSha256"] = JsonPrimitive(fixtureSha256(fixture.sourceLock))
                    })
                }),
            )
            assertFailsWith<FullTreeControlException> { fixture.authenticatedScope() }
        }

    @Test
    fun `ambiguous unmapped shallow and contradictory scope policies fail closed`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("policy"))
            val scope = fixture.authenticatedScope().document
            assertFailsWith<FullTreeControlException> {
                FullTreeScopeControl.normalizeSourcePath(scope, "/outside/tree/file.cpp")
            }
            assertFailsWith<FullTreeControlException> {
                FullTreeScopeControl.shardForSourcePath(scope, "source/cmake/Probe.cpp")
            }
            assertFailsWith<FullTreeControlException> {
                FullTreeScopeControl.shardForSourcePath(scope, "generated/tools/file.cpp")
            }

            val overlap = parseControlObject(fixture.scope)
            val maps = overlap.controlObject("pathPolicy").controlArray("prefixMaps").toMutableList()
            maps += JsonObject(mapOf("from" to JsonPrimitive("/fixture/build/tools/"), "to" to JsonPrimitive("shadow/")))
            val mutated = JsonObject(overlap.toMutableMap().apply {
                this["pathPolicy"] = JsonObject(mapOf("prefixMaps" to JsonArray(maps)))
            })
            val authenticated = authenticatedScopeWithDocument(fixture.authenticatedScope(), mutated)
            assertFailsWith<FullTreeControlException> { FullTreeScopeControl.validate(authenticated) }

            val excessive = parseControlObject(fixture.scope)
            val bounds = excessive.controlObject("bounds")
            val perShard = bounds.controlObject("perShard")
            val whole = bounds.controlObject("wholeRun")
            val excessiveDocument = JsonObject(excessive.toMutableMap().apply {
                this["bounds"] = JsonObject(
                    mapOf(
                        "perShard" to JsonObject(perShard.toMutableMap().apply {
                            this["entities"] = JsonPrimitive(whole.controlLong("entities") + 1L)
                        }),
                        "wholeRun" to whole,
                    ),
                )
            })
            val excessiveScope = authenticatedScopeWithDocument(fixture.authenticatedScope(), excessiveDocument)
            val failure = assertFailsWith<FullTreeControlException> {
                FullTreeScopeControl.validate(excessiveScope)
            }
            assertTrue("per-shard entities" in failure.message.orEmpty())
        }

    private companion object {
        const val FROZEN_SCOPE_SHA256 = "9f097308c076fbbc8822169db6088ecfa94e2a95449eb2434a39a60a3db6973e"
        const val FROZEN_SOURCE_LOCK_SHA256 = "0478d3a9279d67489e441d8b154857aa95f45425843d84ed1af3ca89d06e8381"
        const val FROZEN_MANIFEST_SHA256 = "6bd78d1a4fa0613f37581262bbea15c14e7d86ccf415d1ac383fcf542e39a1f1"
    }
}

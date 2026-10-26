package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.*
import kotlinx.serialization.json.*

class ContainedCommandRetainedInputVisibilityTest {
    @Test fun `strict selection is closed bounded canonical and distinct from legacy null`() = fixture { root ->
        val selected = input("reports/native/manifest.json")
        val original = mutableListOf(selected)
        val view = ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"), original)
        original.clear()
        assertEquals(listOf(selected), view.inputs)
        assertEquals(JsonPrimitive(3), view.canonicalIdentity()["parentCount"])
        assertFails { (view.inputs as MutableList<KotlinContainedCommandRetainedInput>).clear() }
        val empty = ContainedCommandRetainedInputVisibility(ACTIVE, emptySet(), emptyList())
        assertTrue(empty.inputs.isEmpty())
        val legacy = ContainedCommandRetainedDirectories(ACTIVE, emptyMap())
        assertNull(legacy.visibilityToJson())
        assertEquals(listOf("--bind", root.toString(), root.toString()), legacy.runRootMountArguments(root))
        assertTrue(empty.mountArguments(root).contains("--tmpfs"))
        assertEquals(listOf("--remount-ro", root.toString()), empty.mountArguments(root).takeLast(2))
        for (path in listOf("/reports/a", "reports/../a", "reports/./a", "reports//a", "reports/a/", "reports/a/b/c/d", "reports/a\nb", "reports"))
            assertFails(path) { input(path) }
        assertFails { ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"), listOf(input("state/a"))) }
        assertFails { ContainedCommandRetainedInputVisibility(ACTIVE, setOf(ACTIVE), listOf(input("$ACTIVE/a"))) }
        assertFails { ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"), listOf(selected, selected)) }
        assertFails { ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"), listOf(input("reports/a"), input("reports/a/b"))) }
        assertFails { ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"), (0..64).map { input("reports/f$it") }) }
        assertFails { ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"), (0..63).map { input("reports/p$it/q$it/file") }) }
        assertFails { ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"), (0..2).map { input("reports/f$it", 64L * 1024 * 1024) }) }
        for (bytes in listOf(0L, 64L * 1024 * 1024 + 1)) assertFails { input("reports/a", bytes) }
        assertFails { KotlinContainedCommandRetainedInput("reports/a", 1, "bad") }
    }

    @Test fun `strict v4 request binds selection through canonical bytes and authenticated protocol`() {
        val policy = ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"), listOf(input("reports/a"))).canonicalIdentity()
        val hash = OracleArtifacts.sha256(OracleJson.canonicalBytes(policy))
        fun request(visibility: String? = null, interrupted: Boolean = false) = KotlinContainedCommandRequest(
            Path.of("/srv/contained/$ACTIVE"), "a".repeat(64), listOf("/usr/bin/java", "-version"),
            mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"), 10, 10, 1024, 1024,
            allowInterruption = interrupted, retainedInputVisibilitySha256 = visibility)
        for (interrupted in listOf(false, true)) {
            val strict = request(hash, interrupted)
            val parsed = KotlinContainedCommandRequest.parse(strict.canonicalBytes)
            assertContentEquals(strict.canonicalBytes, parsed.canonicalBytes)
            assertEquals(hash, parsed.retainedInputVisibilitySha256)
            assertEquals(interrupted, parsed.allowInterruption)
            assertEquals(JsonPrimitive(4), OracleJson.parseCanonical(strict.canonicalBytes).jsonObject["schemaVersion"])
            assertNotEquals(request(null, interrupted).sha256, strict.sha256)
            val secret = ByteArray(32) { it.toByte() }
            val start = KotlinContainedCommandProtocol.start(secret, strict, 123)
            KotlinContainedCommandProtocol.requireStart(start, secret, parsed, 123)
            assertFails { KotlinContainedCommandProtocol.requireStart(start, secret, request("b".repeat(64), interrupted), 123) }
            val root = OracleJson.parseCanonical(strict.canonicalBytes).jsonObject
            for (field in listOf("retainedInputVisibilitySha256", "allowInterruption"))
                assertFails { KotlinContainedCommandRequest.parse(OracleJson.canonicalBytes(JsonObject(root - field))) }
            assertFails { KotlinContainedCommandRequest.parse(OracleJson.canonicalBytes(JsonObject(root + ("retainedInputVisibilitySha256" to JsonPrimitive("bad"))))) }
        }
        assertEquals(JsonPrimitive(1), OracleJson.parseCanonical(request().canonicalBytes).jsonObject["schemaVersion"])
        assertEquals(JsonPrimitive(2), OracleJson.parseCanonical(request(interrupted = true).canonicalBytes).jsonObject["schemaVersion"])
    }

    @Test fun `selected source identities reject aliases symlinks unsafe permissions and ancestor replacement`() = fixture { root ->
        val file = write(root, "reports/native/input", "pinned-input")
        val view = ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"), listOf(input("reports/native/input", Files.size(file))))
        LinuxFilesystemSyscalls.openRoot(root).use { parent ->
            view.verifySources(parent)
            Files.createLink(root.resolve("alias"), file)
            assertFails { view.verifySources(parent) }
            Files.delete(root.resolve("alias"))
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-rw----"))
            assertFails { view.verifySources(parent) }
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"))
            StableControlFile.open(file, 1024, "visibility test source").use { guard ->
                val old = root.resolve("original-native")
                Files.move(file.parent, old)
                write(root, "reports/native/input", "pinned-input")
                assertFails { guard.requirePathAndIdentity("source ancestor replaced after selection") }
                assertFails { guard.verifyUnchanged("source ancestor replaced after selection") }
            }
            Files.move(file, root.resolve("old-input"))
            Files.createSymbolicLink(file, root.resolve("old-input"))
            assertFails { view.verifySources(parent) }
        }
    }

    @Test fun `last cooperative source check cannot replace an earlier pinned file`() = fixture { root ->
        val first = write(root, "reports/native/first", "first")
        val second = write(root, "reports/native/second", "second")
        StableControlFile.open(first, 1024, "first source").use { a ->
            var mutate = false
            var changed = false
            StableControlFile.openWithCheckpoint(second, 1024, "second source") { stage ->
                if (mutate && !changed && stage.startsWith("after hashing")) {
                    val replacement = root.resolve("replacement")
                    Files.writeString(replacement, "first")
                    Files.setPosixFilePermissions(replacement, PosixFilePermissions.fromString("rw-------"))
                    Files.move(replacement, first, StandardCopyOption.REPLACE_EXISTING)
                    changed = true
                }
            }.use { b ->
                a.verifyUnchanged("first terminal source")
                mutate = true
                b.verifyUnchanged("second terminal source")
                assertTrue(changed)
                assertFails { listOf(a, b).forEach { it.requirePathAndIdentity("final whole-set identity pass") } }
            }
        }
    }

    @Test fun `actual generated strict namespaces hide every forbidden sibling and preserve only bounded active writes`() = fixture { root ->
        val bwrap = Path.of("/usr/bin/bwrap")
        assumeTrue(Files.isExecutable(bwrap), "bubblewrap is unavailable")
        val prefix = listOf(bwrap.toString(), "--unshare-all", "--die-with-parent", "--cap-drop", "ALL", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev")
        assumeTrue(run(prefix + listOf("/bin/true"), root.resolve("probe-log")) == 0, "local namespaces are unavailable")
        val files = linkedMapOf("reports/program_model.json" to "forbidden-model", "reports/native-calls-v1/manifest.json" to "manifest",
            "reports/native-calls-v1/native-calls.json" to "native", "state/oracle" to "forbidden-state",
            "$PRIOR/reports/machine.json" to "independent", "$OTHER/reports/external.json" to "forbidden-external",
            "untracked-sibling/unknown" to "forbidden-untracked")
        files.forEach { (relative, value) -> write(root, relative, value) }
        privateDirectory(root.resolve(ACTIVE))
        val choices = listOf(emptyList(), listOf("$PRIOR/reports/machine.json"),
            listOf("reports/native-calls-v1/manifest.json", "reports/native-calls-v1/native-calls.json"))
        val evidence = arrayListOf<JsonElement>()
        for ((index, visible) in choices.withIndex()) {
            val inputs = visible.map { relative -> KotlinContainedCommandRetainedInput(relative, files.getValue(relative).toByteArray().size.toLong(),
                OracleArtifacts.sha256(files.getValue(relative).toByteArray())) }
            val view = ContainedCommandRetainedInputVisibility(ACTIVE, setOf(PRIOR, OTHER, "state", "reports"), inputs)
            LinuxFilesystemSyscalls.openRoot(root).use { view.verifySources(it) }
            val command = prefix + view.mountArguments(root) + listOf("--chdir", root.resolve(ACTIVE).toString(), "--", "/usr/bin/python3", "-B", "-c", CANARY,
                root.toString(), OracleJson.canonicalBytes(JsonArray(visible.map(::JsonPrimitive))).decodeToString(),
                OracleJson.canonicalBytes(JsonObject(files.mapValues { JsonPrimitive(it.value) })).decodeToString(), ACTIVE)
            val log = root.resolve("canary-$index.log")
            assertEquals(0, run(command, log), Files.readString(log))
            files.forEach { (relative, expected) -> assertEquals(expected, Files.readString(root.resolve(relative))) }
            assertEquals("owned-write", Files.readString(root.resolve("$ACTIVE/owned-result")))
            evidence += JsonObject(mapOf("policy" to view.canonicalIdentity(), "exitCode" to JsonPrimitive(0),
                "childOutput" to JsonPrimitive(Files.readString(log)), "hostSourcesUnchanged" to JsonPrimitive(true)))
        }
        val output = Files.createDirectories(Path.of("build/verification")).resolve("visibility-kotlin-generated-canaries.json")
        Files.write(output, OracleJson.canonicalBytes(JsonObject(mapOf("scope" to JsonPrimitive("actual-generated-bubblewrap-view-controls"),
            "containedLifecycleQualified" to JsonPrimitive(false), "views" to JsonArray(evidence)))))
    }

    private fun input(path: String, bytes: Long = 1) = KotlinContainedCommandRetainedInput(path, bytes, "a".repeat(64))
    private fun write(root: Path, relative: String, value: String): Path {
        val path = root.resolve(relative)
        var current = root
        relative.split('/').dropLast(1).forEach { current = current.resolve(it); privateDirectory(current) }
        Files.writeString(path, value)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        return path
    }
    private fun privateDirectory(path: Path) {
        Files.createDirectories(path)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
    }
    private fun run(command: List<String>, log: Path): Int {
        val process = ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start()
        try {
            assertTrue(process.waitFor(15, TimeUnit.SECONDS), "canary child exceeded its bound")
            assertTrue(Files.size(log) <= 64 * 1024)
            return process.exitValue()
        } finally { if (process.isAlive) { process.destroyForcibly(); assertTrue(process.waitFor(5, TimeUnit.SECONDS)) } }
    }
    private fun fixture(action: (Path) -> Unit): Unit {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/task-tmp/visibility-controls").toAbsolutePath()), "view-")
        privateDirectory(root)
        try { action(root) } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }
    private companion object {
        val ACTIVE = "control-" + "a".repeat(64)
        val PRIOR = "control-" + "b".repeat(64)
        val OTHER = "control-" + "c".repeat(64)
        val CANARY = """import json,pathlib,sys
r=pathlib.Path(sys.argv[1]);allowed=json.loads(sys.argv[2]);allfiles=json.loads(sys.argv[3]);active=sys.argv[4]
for rel,data in allfiles.items():
 p=r/rel
 if rel in allowed:
  assert p.read_text()==data,rel
  try:p.write_text('wrong')
  except OSError:pass
  else:raise AssertionError('allowed input writable:'+rel)
 else:
  try:p.read_bytes()
  except OSError:pass
  else:raise AssertionError('forbidden input readable:'+rel)
try:(r/'overlay-residue').write_text('escape')
except OSError:pass
else:raise AssertionError('root overlay writable')
(r/active/'owned-result').write_text('owned-write')
print(json.dumps({'allowed':allowed,'hidden':sorted(set(allfiles)-set(allowed)),'rootReadonly':True,'activeWritable':True}))
"""
    }
}

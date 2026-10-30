package decompengine.oracle.gcc

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.PrintStream
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.net.URLClassLoader
import java.nio.file.AccessDeniedException
import java.nio.file.FileSystemException
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Authored refusal controls only. No installed driver operation or production ownership is manufactured. */
class GccBundledInterfaceContainmentProbeTest {
    @Test
    fun `fixed probe covers seven hidden paths and both readonly inputs with one bounded digest frame`() {
        withProbe { probe ->
            val calls = mutableListOf<Pair<String, Path>>()
            val first = probe.receipt { method, path -> calls.add(method to path); accepted(method, path) }
            assertEquals(expectedReceipt(), first)
            assertEquals(first, probe.receipt(callback = ::accepted))
            assertTrue(first.toByteArray(Charsets.UTF_8).size + 1 <= 2048)
            assertFalse(first.contains('\n') || first.contains('\r'))
            assertFalse(first.contains("/selected") || first.contains("/scripts") || first.contains("canary"))
            assertEquals(HIDDEN.map { "openReadable" to it } + listOf(
                "openReadable" to BINARY, "readOnly" to BINARY, "openWritable" to BINARY,
                "openReadable" to EXPORTER, "readOnly" to EXPORTER, "openWritable" to EXPORTER), calls)
        }
    }

    @Test
    fun `any readable hidden canary or actual full binary refuses instead of emitting a receipt`() {
        withProbe { probe ->
            for (visible in HIDDEN) {
                val failure = assertFailsWith<InvocationTargetException> {
                    probe.receipt { method, path ->
                        if (method == "openReadable" && path == visible) null else accepted(method, path)
                    }
                }
                assertIs<IllegalStateException>(failure.cause)
                assertTrue(checkNotNull(failure.cause).message.orEmpty().contains("READ open"))
            }
        }
    }

    @Test
    fun `hidden failures accept only absence or access denial and never arbitrary IO errors`() {
        withProbe { probe ->
            assertEquals(expectedReceipt(), probe.receipt { method, path ->
                if (method == "openReadable" && path in HIDDEN) throw AccessDeniedException(path.toString())
                accepted(method, path)
            })
            for (failure in listOf(IOException("unclassified failure"), FileSystemException("fixed", null, "Too many open files"))) {
                val wrapped = assertFailsWith<InvocationTargetException> {
                    probe.receipt { method, path ->
                        if (method == "openReadable" && path == HIDDEN.first()) throw failure
                        accepted(method, path)
                    }
                }
                assertTrue(wrapped.cause === failure)
            }
        }
    }

    @Test
    fun `binary and exporter must each remain readable`() {
        withProbe { probe ->
            for (unreadable in listOf(BINARY, EXPORTER)) {
                val wrapped = assertFailsWith<InvocationTargetException> {
                    probe.receipt { method, path ->
                        if (method == "openReadable" && path == unreadable) throw AccessDeniedException(path.toString())
                        accepted(method, path)
                    }
                }
                assertIs<AccessDeniedException>(wrapped.cause)
            }
        }
    }

    @Test
    fun `permission denial alone cannot replace a readonly filesystem observation`() {
        withProbe { probe ->
            for (writable in listOf(BINARY, EXPORTER)) {
                val wrapped = assertFailsWith<InvocationTargetException> {
                    probe.receipt { method, path ->
                        if (method == "readOnly" && path == writable) false else accepted(method, path)
                    }
                }
                assertIs<IllegalStateException>(wrapped.cause)
                assertTrue(checkNotNull(wrapped.cause).message.orEmpty().contains("writable filesystem"))
            }
        }
    }

    @Test
    fun `either successful write open refuses despite reported readonly filesystem`() {
        withProbe { probe ->
            for (writable in listOf(BINARY, EXPORTER)) {
                val wrapped = assertFailsWith<InvocationTargetException> {
                    probe.receipt { method, path ->
                        if (method == "openWritable" && path == writable) null else accepted(method, path)
                    }
                }
                assertIs<IllegalStateException>(wrapped.cause)
                assertTrue(checkNotNull(wrapped.cause).message.orEmpty().contains("WRITE open"))
            }
        }
    }

    @Test
    fun `write refusals require access denied or exact readonly filesystem error`() {
        withProbe { probe ->
            assertEquals(expectedReceipt(), probe.receipt { method, path ->
                if (method == "openWritable") throw AccessDeniedException(path.toString())
                accepted(method, path)
            })
            for (failure in listOf(NoSuchFileException("missing"), IOException("unclassified write failure"),
                FileSystemException("fixed", null, "Too many open files"))) {
                val wrapped = assertFailsWith<InvocationTargetException> {
                    probe.receipt { method, path ->
                        if (method == "openWritable") throw failure
                        accepted(method, path)
                    }
                }
                assertTrue(wrapped.cause === failure)
            }
        }
    }

    @Test
    fun `malformed paired invocation or noncanonical probe input refuses before IO`() {
        withProbe { probe ->
            for (arguments in listOf(paired().copyOf().also { it[14] = SHA_B },
                paired().copyOf().also { it[22] = SHA_B }, paired().copyOf().also { it[14] = "not-a-digest"; it[22] = "not-a-digest" },
                paired().copyOf().also { it[21] = "10" }, paired().copyOf().also { it[4] = "relative-binary" },
                paired().copyOf().also { it[5] = "/scripts/../other" }, paired() + "ignored", arrayOf("/bundle", "probe"))) {
                var calls = 0
                val wrapped = assertFailsWith<InvocationTargetException> {
                    probe.receipt(arguments) { method, path -> calls++; accepted(method, path) }
                }
                assertIs<IllegalArgumentException>(wrapped.cause)
                assertEquals(0, calls)
            }
        }
    }

    @Test
    fun `legacy worker invocations emit no probe frame and perform no probe filesystem work`() {
        withProbe { probe ->
            val previous = System.err
            val output = ByteArrayOutputStream()
            try {
                System.setErr(PrintStream(output, true, Charsets.UTF_8))
                for (arguments in listOf(arrayOf("/bundle", "probe"),
                    paired().take(12).toTypedArray(), arrayOf("/bundle", "analyze-diagnostics-v1"),
                    arrayOf("/bundle", "ExportNativeCallsV1.class"))) {
                    probe.productionProbe.invoke(null, arguments as Any)
                }
            } finally {
                System.setErr(previous)
            }
            assertEquals(0, output.size())
        }
    }

    private class Probe(val loader: ClassLoader, val access: Class<*>, val checker: Method, val productionProbe: Method) {
        fun receipt(arguments: Array<String> = paired(), callback: (String, Path) -> Any?): String {
            val proxy = Proxy.newProxyInstance(loader, arrayOf(access)) { _, method, values ->
                callback(method.name, checkNotNull(values).single() as Path)
            }
            return checker.invoke(null, arguments, proxy) as String
        }
    }

    private fun withProbe(block: (Probe) -> Unit) {
        GccBundledGhidraDeploymentReference.open().use { deployment ->
            val urls = deployment.reference.classPath.map { deployment.bundleRoot.resolve(it).toUri().toURL() }.toTypedArray()
            URLClassLoader(urls, ClassLoader.getPlatformClassLoader()).use { loader ->
                val worker = Class.forName("decompengine.ghidra.BundledGhidraWorker", false, loader)
                val access = Class.forName("decompengine.ghidra.BundledGhidraWorker\$InterfaceContainmentAccess", false, loader)
                val checker = worker.getDeclaredMethod("interfaceContainmentReceipt", Array<String>::class.java, access).also { it.isAccessible = true }
                val production = worker.getDeclaredMethod("probeInterfaceContainment", Array<String>::class.java).also { it.isAccessible = true }
                block(Probe(loader, access, checker, production))
            }
        }
    }

    private companion object {
        const val SHA_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val SHA_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        val BINARY: Path = Path.of("/selected/gcc-driver.stripped")
        val EXPORTER: Path = Path.of("/scripts/ExportProgramModel.java")
        val HIDDEN: List<Path> = listOf("rich", "debug", "source", "build", "oracle", "nominal").map {
            Path.of("/selected/.decomp-interface-hidden-canaries-v1/$it.canary")
        } + listOf(Path.of("/selected/gcc-driver.full"))
        fun accepted(method: String, path: Path): Any? = when (method) {
            "openReadable" -> if (path in HIDDEN) throw NoSuchFileException(path.toString()) else null
            "readOnly" -> true
            "openWritable" -> throw FileSystemException(path.toString(), null, "Read-only file system")
            else -> error("unexpected probe API: $method")
        }
        fun paired() = arrayOf("/bundle", "analyze", "/scratch/state", "archival_reconstruction", BINARY.toString(), "/scripts",
            "ExportProgramModel.java", "4", SHA_B, SHA_B, "full", "/scratch/reports/program_model.json",
            "ExportNativeInterfacesV1.class", "6", SHA_A, SHA_B, SHA_B, SHA_B, "/scratch/reports/program_model.json",
            "/scratch/reports/native-interfaces-v1", "ExportInferredInterfacesV1.class", "11", SHA_A, SHA_B, SHA_B,
            SHA_B, SHA_B, SHA_B, SHA_B, SHA_B, "/scratch/reports/program_model.json", "/scratch/reports/native-interfaces-v1",
            "/scratch/reports/native-inferred-interfaces-v1")
        fun expectedReceipt() = "DECOMP_INTERFACE_CONTAINMENT_V1 " +
            "{\"hidden\":{\"build\":true,\"debug\":true,\"fullBinary\":true,\"nominal\":true,\"oracle\":true,\"rich\":true,\"source\":true}," +
            "\"inputSha256\":\"$SHA_A\",\"provider\":\"gcc-interface-containment-probe-v1\",\"readOnly\":{\"binary\":true,\"exporter\":true},\"schemaVersion\":1}"
    }
}

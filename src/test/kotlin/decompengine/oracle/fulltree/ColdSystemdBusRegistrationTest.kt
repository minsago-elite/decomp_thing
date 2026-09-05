package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class ColdSystemdBusRegistrationTest {
    @Test
    fun `an already registered manager requires exactly one query and no pause`() {
        val budgets = mutableListOf<Duration>()
        awaitColdSystemdManagerBusRegistration(
            query = { remaining ->
                budgets += remaining
                "{\"type\":\"b\",\"data\":[true]}\n"
            },
            nanoTime = { 0L },
            pause = { error("an available manager must not wait") },
        )
        assertEquals(listOf(Duration.ofSeconds(2)), budgets)
    }

    @Test
    fun `only successful false registration observations are retried under one deadline`() {
        var now = 0L
        val budgets = mutableListOf<Duration>()
        val pauses = mutableListOf<Long>()
        awaitColdSystemdManagerBusRegistration(
            query = { remaining ->
                budgets += remaining
                "{\"type\":\"b\",\"data\":[${budgets.size == 3}]}\n"
            },
            nanoTime = { now },
            pause = { millis ->
                pauses += millis
                now += Duration.ofMillis(millis).toNanos()
            },
        )
        assertEquals(listOf(2000L, 1975L, 1950L), budgets.map(Duration::toMillis))
        assertEquals(listOf(25L, 25L), pauses)
    }

    @Test
    fun `an absent manager exhausts the original deadline without unbounded polling`() {
        var now = 0L
        var queries = 0
        assertFailsWith<FullTreeFunctionObservationIsolationException> {
            awaitColdSystemdManagerBusRegistration(
                query = {
                    queries += 1
                    "{\"type\":\"b\",\"data\":[false]}\n"
                },
                nanoTime = { now },
                pause = { now += Duration.ofMillis(it).toNanos() },
            )
        }
        assertEquals(80, queries)
        assertEquals(Duration.ofSeconds(2).toNanos(), now)
    }

    @Test
    fun `a late successful reply cannot admit a manager after the deadline`() {
        var now = 0L
        assertFailsWith<FullTreeFunctionObservationIsolationException> {
            awaitColdSystemdManagerBusRegistration(
                query = {
                    now = Duration.ofSeconds(2).toNanos()
                    "{\"type\":\"b\",\"data\":[true]}\n"
                },
                nanoTime = { now },
                pause = { error("late replies must not retry") },
            )
        }
    }

    @Test
    fun `failed or malformed queries are never retried as missing registration`() {
        val failure = FullTreeFunctionObservationIsolationException("injected denied transport")
        val observed = assertFailsWith<FullTreeFunctionObservationIsolationException> {
            awaitColdSystemdManagerBusRegistration(
                query = { throw failure },
                nanoTime = { 0L },
                pause = { error("failed queries must not retry") },
            )
        }
        assertSame(failure, observed)
        val malformed = listOf("false", "\"false\"", "[]", "[false,true]", "[\"false\"]", "[null]", "[[false]]")
            .map { data -> "{\"type\":\"b\",\"data\":$data}\n" } + listOf(
                "",
                "{\"type\":\"b\",\"data\":[false],\"data\":[true]}\n",
                "{\"type\":\"s\",\"data\":[true]}\n",
                "{\"type\":\"b\",\"data\":[true],\"extra\":true}\n",
            )
        for (output in malformed) {
            assertFailsWith<FullTreeFunctionObservationIsolationException> {
                awaitColdSystemdManagerBusRegistration(
                    query = { output },
                    nanoTime = { 0L },
                    pause = { error("malformed replies must not retry") },
                )
            }
        }
    }

    @Test
    fun `interruption terminates registration waiting without another query`() {
        val failure = InterruptedException("injected registration interruption")
        var queries = 0
        val observed = assertFailsWith<InterruptedException> {
            awaitColdSystemdManagerBusRegistration(
                query = {
                    queries += 1
                    "{\"type\":\"b\",\"data\":[false]}\n"
                },
                nanoTime = { 0L },
                pause = { throw failure },
            )
        }
        assertSame(failure, observed)
        assertEquals(1, queries)
    }

    @Test
    fun `a nonadvancing clock still cannot exceed the fixed query count`() {
        var queries = 0
        assertFailsWith<FullTreeFunctionObservationIsolationException> {
            awaitColdSystemdManagerBusRegistration(
                query = {
                    queries += 1
                    "{\"type\":\"b\",\"data\":[false]}\n"
                },
                nanoTime = { 0L },
                pause = {},
            )
        }
        assertEquals(81, queries)
    }

    @Test
    fun `the live user bus returns the single boolean method envelope`() {
        assumeTrue(System.getProperty("os.name").lowercase().contains("linux"))
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        val runtime = Path.of("/run/user/$uid")
        val busctl = Path.of("/usr/bin/busctl")
        val available = Files.exists(runtime.resolve("bus")) && Files.isExecutable(busctl)
        if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
            assertTrue(available, "required CI session bus is unavailable")
        }
        assumeTrue(available, "a live user session bus and busctl are required")
        awaitColdSystemdManagerBusRegistration(query = { remaining ->
            val process = ProcessBuilder(
                busctl.toString(), "--user", "--no-pager", "--json=short", "--auto-start=no",
                "--allow-interactive-authorization=no", "--timeout=2",
                "call", "org.freedesktop.DBus", "/org/freedesktop/DBus",
                "org.freedesktop.DBus", "NameHasOwner", "s", "org.freedesktop.systemd1",
            ).redirectErrorStream(true).also { builder ->
                builder.environment().clear()
                builder.environment()["XDG_RUNTIME_DIR"] = runtime.toString()
                builder.environment()["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=${runtime.resolve("bus")}"
            }.start()
            try {
                assertTrue(process.waitFor(remaining.toNanos(), TimeUnit.NANOSECONDS), "registration query timed out")
                val bytes = process.inputStream.readNBytes(4097)
                assertTrue(bytes.size <= 4096, "registration reply exceeded its test bound")
                assertEquals(0, process.exitValue(), bytes.toString(Charsets.UTF_8))
                bytes.toString(Charsets.UTF_8)
            } finally {
                if (process.isAlive) {
                    process.destroyForcibly()
                    assertTrue(process.waitFor(2, TimeUnit.SECONDS), "registration query did not terminate")
                }
            }
        })
    }
}

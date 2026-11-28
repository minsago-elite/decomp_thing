package decompengine.project

import java.io.ByteArrayOutputStream
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import javax.tools.ToolProvider
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import org.junit.jupiter.api.parallel.Isolated

@Isolated("compares legacy formatting under several process default locales")
class ExporterPureRenderingTest {
    @Test
    fun `production address and digest rendering equals legacy formatting across bits bytes and locales`() =
        withPureRenderingHarness("numeric")

    @Test
    fun `production type-name rendering equals legacy regex over BMP supplementary and malformed UTF16 names`() =
        withPureRenderingHarness("type-name")
}

private fun withPureRenderingHarness(scenario: String) {
    val exporter = Path.of("src/main/resources/ghidra_scripts/ExportProgramModel.java").readText()
    val beginMarker = "// PURE_RENDERING_TEST_BEGIN\n"
    val endMarker = "// PURE_RENDERING_TEST_END"
    val begin = exporter.indexOf(beginMarker)
    val end = exporter.indexOf(endMarker)
    require(begin >= 0 && end > begin && exporter.indexOf(beginMarker, begin + 1) == -1 &&
        exporter.indexOf(endMarker, end + 1) == -1) { "unique production pure rendering markers are missing" }
    val implementation = exporter.substring(begin + beginMarker.length, end)
    val root = Path.of("build", "exporter-rendering-v16").createDirectories()
    val temporary = Files.createTempDirectory(root, "differential-")
    try {
        val source = temporary.resolve("PureRenderingHarness.java").also {
            it.writeText(PURE_RENDERING_PREFIX + implementation + PURE_RENDERING_HARNESS)
        }
        val compiler = ToolProvider.getSystemJavaCompiler() ?: error("pure rendering tests require a JDK")
        val diagnostics = ByteArrayOutputStream()
        val result = compiler.run(null, diagnostics, diagnostics, "-Xlint:all", "-Werror", "-d", temporary.toString(), source.toString())
        check(result == 0) { diagnostics.toString(Charsets.UTF_8) }
        URLClassLoader(arrayOf(temporary.toUri().toURL())).use { loader ->
            loader.loadClass("PureRenderingHarness").getMethod("run", String::class.java).invoke(null, scenario)
        }
    } finally {
        temporary.toFile().deleteRecursively()
    }
}

private val PURE_RENDERING_PREFIX = """
    import java.util.Locale;
    import java.util.Random;
    import java.util.regex.Pattern;

""".trimIndent() + "\n"

private val PURE_RENDERING_HARNESS = """
    public final class PureRenderingHarness {
        private static final Locale[] LOCALES = {
            Locale.ROOT, Locale.US, Locale.forLanguageTag("tr-TR"),
            Locale.forLanguageTag("ar-EG"), Locale.forLanguageTag("fa-IR"), Locale.JAPAN
        };
        private static final String[] NAMES = {
            "", "a", "valid_Ascii_Name9", "123leadingDigit", "_", "$", "a-b.c/d\\e",
            "space and\ttab\nnewline", "é", "e\u0301", "İıiI", "Σσς", "مرحبا", "漢字",
            "a\u200db", "a\u0000b", "\ud800", "\udfff", "\ud800A\udfff",
            "\ud83d\ude00", "prefix\ud83d\ude00suffix", "\ud800\udc00\udbff\udfff",
            "\ud800\ud800\udc00\udc00", "_9α combining\u0301 pair\ud83d\ude00"
        };

        public static void run(String scenario) {
            Locale original = Locale.getDefault();
            Locale originalFormat = Locale.getDefault(Locale.Category.FORMAT);
            Locale originalDisplay = Locale.getDefault(Locale.Category.DISPLAY);
            try {
                switch (scenario) {
                    case "numeric": numeric(); break;
                    case "type-name": names(); break;
                    default: throw new AssertionError("unknown differential scenario " + scenario);
                }
            } finally {
                Locale.setDefault(original);
                Locale.setDefault(Locale.Category.FORMAT, originalFormat);
                Locale.setDefault(Locale.Category.DISPLAY, originalDisplay);
            }
            require(Locale.getDefault().equals(original), "default locale was not restored");
            require(Locale.getDefault(Locale.Category.FORMAT).equals(originalFormat), "format locale was not restored");
            require(Locale.getDefault(Locale.Category.DISPLAY).equals(originalDisplay), "display locale was not restored");
        }

        private static void numeric() {
            long[] offsets = new long[1040];
            long[] boundaries = {0, 1, 15, 16, 255, 256, 0xffffL, 0x10000L,
                0xffffffffL, 0x100000000L, Long.MIN_VALUE, Long.MIN_VALUE + 1,
                Long.MAX_VALUE - 1, Long.MAX_VALUE, -2, -1};
            System.arraycopy(boundaries, 0, offsets, 0, boundaries.length);
            Random random = new Random(0x63a415ec80b7L);
            for (int i = boundaries.length; i < offsets.length; i++) offsets[i] = random.nextLong();
            byte[] allBytes = new byte[256];
            for (int i = 0; i < allBytes.length; i++) allBytes[i] = (byte)i;
            byte[] digest32 = new byte[32];
            random.nextBytes(digest32);
            for (Locale locale : LOCALES) {
                Locale.setDefault(locale);
                for (long offset : offsets) {
                    equal(String.format("fn_%016x", offset), ExporterPureRenderingV1.addressId("fn_", offset), "function ID " + locale);
                    equal(String.format("global_%016x", offset), ExporterPureRenderingV1.addressId("global_", offset), "global ID " + locale);
                    equal("" + String.format("%016x", offset), ExporterPureRenderingV1.addressId("", offset), "empty ID prefix " + locale);
                    equal("préfix_" + String.format("%016x", offset), ExporterPureRenderingV1.addressId("préfix_", offset), "unchanged ID prefix " + locale);
                }
                equal(legacyDigest(new byte[0]), ExporterPureRenderingV1.hexDigest(new byte[0]), "empty digest " + locale);
                equal(legacyDigest(digest32), ExporterPureRenderingV1.hexDigest(digest32), "32-byte digest " + locale);
                equal(legacyDigest(allBytes), ExporterPureRenderingV1.hexDigest(allBytes), "256-byte digest " + locale);
                for (int value = 0; value < 256; value++) {
                    byte[] one = {(byte)value};
                    equal(legacyDigest(one), ExporterPureRenderingV1.hexDigest(one), "single digest byte " + value + " " + locale);
                }
                for (int iteration = 0; iteration < 32; iteration++) {
                    byte[] digest = new byte[32];
                    random.nextBytes(digest);
                    equal(legacyDigest(digest), ExporterPureRenderingV1.hexDigest(digest), "seeded digest " + iteration + " " + locale);
                }
            }
        }

        private static String legacyDigest(byte[] digest) {
            StringBuilder result = new StringBuilder();
            for (byte value : digest) result.append(String.format("%02x", value & 0xff));
            return result.toString();
        }

        private static void names() {
            for (Locale locale : LOCALES) {
                Locale.setDefault(locale);
                for (String name : NAMES) equal(name.replaceAll("[^A-Za-z0-9_]", "_"), ExporterPureRenderingV1.typeName(name), "name " + locale);
            }
            Locale.setDefault(Locale.ROOT);
            StringBuilder completeBmp = new StringBuilder(65536);
            for (int value = 0; value <= 0xffff; value++) {
                String isolated = String.valueOf((char)value);
                equal(isolated.replaceAll("[^A-Za-z0-9_]", "_"), ExporterPureRenderingV1.typeName(isolated), "isolated BMP unit " + value);
                String surrounded = "A" + isolated + "9_";
                equal(surrounded.replaceAll("[^A-Za-z0-9_]", "_"), ExporterPureRenderingV1.typeName(surrounded), "surrounded BMP unit " + value);
                completeBmp.append((char)value);
            }
            String combined = completeBmp.toString();
            equal(combined.replaceAll("[^A-Za-z0-9_]", "_"), ExporterPureRenderingV1.typeName(combined), "complete BMP sequence");
            Random random = new Random(0x762134aeL);
            for (int iteration = 0; iteration < 512; iteration++) {
                char[] units = new char[random.nextInt(129)];
                for (int i = 0; i < units.length; i++) units[i] = (char)random.nextInt(65536);
                String name = new String(units);
                equal(name.replaceAll("[^A-Za-z0-9_]", "_"), ExporterPureRenderingV1.typeName(name), "seeded UTF16 name " + iteration);
            }
        }

        private static void equal(String expected, String actual, String label) {
            if (expected.equals(actual)) return;
            int difference = 0;
            int common = Math.min(expected.length(), actual.length());
            while (difference < common && expected.charAt(difference) == actual.charAt(difference)) difference++;
            throw new AssertionError(label + ": legacy length=" + expected.length() + ", actual length=" + actual.length() + ", first differing UTF16 index=" + difference);
        }
        private static void require(boolean condition, String message) {
            if (!condition) throw new AssertionError(message);
        }
    }
""".trimIndent()

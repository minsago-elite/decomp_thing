package decompengine.acp;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/** Protocol controls packaged separately from the production DNS worker and resolver SPI fixture. */
public final class ProviderDnsWorker {
    private static final byte[] FRAME = {
        'A', 'D', 'P', '1', 4, (byte) 192, 0, 2, 1
    };
    private static final int MAX_MODE_BYTES = 16;

    private ProviderDnsWorker() { }

    public static void main(String[] args) {
        if (args.length != 0) {
            System.exit(2);
            return;
        }
        try {
            switch (readMode()) {
                case "EMPTY" -> { }
                case "SHORT" -> write(Arrays.copyOf(FRAME, FRAME.length - 1));
                case "EXTRA" -> write(Arrays.copyOf(FRAME, FRAME.length + 1));
                case "OVERSIZED" -> {
                    byte[] output = new byte[64 * 1024];
                    Arrays.fill(output, (byte) 'x');
                    System.arraycopy(FRAME, 0, output, 0, FRAME.length);
                    write(output);
                }
                case "STDERR" -> {
                    write(FRAME);
                    System.err.write('x');
                    System.err.flush();
                }
                case "NONZERO" -> {
                    write(FRAME);
                    System.exit(2);
                }
                case "HOLD" -> {
                    write(FRAME);
                    writeFile("lookup-ready", "ready\n");
                    for (;;) {
                        try {
                            Thread.sleep(10L);
                        } catch (InterruptedException exception) {
                            // A valid frame must not permit admission while its child remains alive.
                        }
                    }
                }
                case "ENV" -> inspectEnvironment(args);
                default -> System.exit(2);
            }
        } catch (IOException exception) {
            System.exit(2);
        }
    }

    private static String readMode() throws IOException {
        try (InputStream input = Files.newInputStream(Path.of("fixture-mode"))) {
            byte[] bytes = input.readNBytes(MAX_MODE_BYTES + 1);
            if (bytes.length > MAX_MODE_BYTES) {
                throw new IOException("fixture mode rejected");
            }
            return new String(bytes, StandardCharsets.US_ASCII).strip();
        }
    }

    private static void inspectEnvironment(String[] args) throws IOException {
        int environmentCount = System.getenv().size();
        boolean stdinEof = System.in.read() == -1;
        boolean classpathEnvironmentAbsent = System.getenv("CLASSPATH") == null;
        writeFile(
                "fixture-proof",
                "env=" + environmentCount + "\n"
                        + "args=" + args.length + "\n"
                        + "stdinEOF=" + stdinEof + "\n"
                        + "classpathEnvironmentAbsent=" + classpathEnvironmentAbsent + "\n");
        if (environmentCount != 0 || !stdinEof || !classpathEnvironmentAbsent) {
            System.exit(2);
            return;
        }
        write(FRAME);
    }

    private static void write(byte[] bytes) throws IOException {
        System.out.write(bytes);
        System.out.flush();
    }

    private static void writeFile(String name, String content) throws IOException {
        Files.writeString(
                Path.of(name),
                content,
                StandardCharsets.US_ASCII,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE);
    }
}

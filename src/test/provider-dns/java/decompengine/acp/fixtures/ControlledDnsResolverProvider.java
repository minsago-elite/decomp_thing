package decompengine.acp.fixtures;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.stream.Stream;

/** Resolver SPI controls used only by the isolated provider DNS component fixtures. */
public final class ControlledDnsResolverProvider extends InetAddressResolverProvider {
    private static final String HOST = "chatgpt.com";
    private static final Path MODE = Path.of("fixture-mode");
    private static final Path READY = Path.of("lookup-ready");
    private static final Path RELEASE = Path.of("lookup-release");
    private static final int MAX_MODE_BYTES = 16;

    @Override
    public InetAddressResolver get(Configuration configuration) {
        return new InetAddressResolver() {
            @Override
            public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy)
                    throws UnknownHostException {
                if (!HOST.equals(host)) {
                    throw failure();
                }
                String mode = readMode();
                signalReady();
                return switch (mode) {
                    case "STALL" -> stall();
                    case "IPV4" -> Stream.of(ipv4());
                    case "IPV6" -> Stream.of(ipv6());
                    case "LATE" -> waitForRelease();
                    case "FAIL" -> throw failure();
                    default -> throw failure();
                };
            }

            @Override
            public String lookupByAddress(byte[] address) throws UnknownHostException {
                throw failure();
            }
        };
    }

    @Override
    public String name() {
        return "provider-dns-component-fixture";
    }

    private static String readMode() throws UnknownHostException {
        try (InputStream input = Files.newInputStream(MODE)) {
            byte[] bytes = input.readNBytes(MAX_MODE_BYTES + 1);
            if (bytes.length > MAX_MODE_BYTES) {
                throw failure();
            }
            return new String(bytes, StandardCharsets.US_ASCII).strip();
        } catch (IOException exception) {
            throw failure();
        }
    }

    private static void signalReady() throws UnknownHostException {
        try {
            Files.writeString(
                    READY,
                    "ready\n",
                    StandardCharsets.US_ASCII,
                    StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE);
        } catch (FileAlreadyExistsException exception) {
            // A repeated lookup must retain the first lookup's readiness evidence.
        } catch (IOException exception) {
            throw failure();
        }
    }

    private static Stream<InetAddress> stall() {
        for (;;) {
            pauseIgnoringInterrupts();
        }
    }

    private static Stream<InetAddress> waitForRelease() throws UnknownHostException {
        while (!Files.exists(RELEASE)) {
            pauseIgnoringInterrupts();
        }
        return Stream.of(ipv4());
    }

    private static void pauseIgnoringInterrupts() {
        try {
            Thread.sleep(10L);
        } catch (InterruptedException exception) {
            // A stalled resolver deliberately cannot be stopped by thread interruption.
        }
    }

    private static InetAddress ipv4() throws UnknownHostException {
        return InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 1});
    }

    private static InetAddress ipv6() throws UnknownHostException {
        byte[] address = new byte[16];
        address[15] = 1;
        return InetAddress.getByAddress(address);
    }

    private static UnknownHostException failure() {
        return new UnknownHostException("provider DNS fixture rejected lookup");
    }
}

import decompengine.acp.AcpRuntimeClosureLimits;
import decompengine.acp.LinuxBubblewrapBoundaryKt;
import java.nio.file.Path;

public final class AcpRuntimeManifest {
    private AcpRuntimeManifest() {}

    public static void main(String[] arguments) {
        if (arguments.length != 1) {
            throw new IllegalArgumentException("expected one final installed path");
        }
        var limits = new AcpRuntimeClosureLimits(10_000, 536_870_912L, 32);
        var digest = LinuxBubblewrapBoundaryKt.calculateAcpRuntimeManifestSha256(
            Path.of(arguments[0]),
            limits
        );
        System.out.println(digest);
    }
}

import java.nio.file.*;
import decompengine.binary.ElfMetadataReader;
import decompengine.jobs.Job;
import decompengine.web.WebViewsKt;

/** Render an active display fixture without starting any workflow or executing an input. */
class ProgressPageFixture {
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[0]).toAbsolutePath();
        Files.createDirectories(root);
        byte[] header = new byte[64];
        header[0] = 0x7f; header[1] = 'E'; header[2] = 'L'; header[3] = 'F';
        header[4] = 2; header[5] = 1; header[6] = 1;
        Job job = new Job("fixture", "display fixture", "analyzing", "2026-09-05T00:00:00Z",
            "2026-09-05T00:00:00Z", null, header.length, root.resolve("input"),
            ElfMetadataReader.INSTANCE.read(header));
        Files.writeString(root.resolve("page.html"), WebViewsKt.renderJob(job, null, false));
    }
}

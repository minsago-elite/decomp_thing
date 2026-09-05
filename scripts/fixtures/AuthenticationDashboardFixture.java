import java.nio.file.*;
import java.util.List;
import decompengine.jobs.JobRecoveryInventory;
import decompengine.web.WebViewsKt;

/** Render only: no job, agent, or authentication operation starts. */
class AuthenticationDashboardFixture {
    public static void main(String[] args) throws Exception {
        Path output = Path.of(args[0]);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, WebViewsKt.renderDashboard(List.of(), new JobRecoveryInventory(0, 0, 0, 0L, 0, true)));
    }
}

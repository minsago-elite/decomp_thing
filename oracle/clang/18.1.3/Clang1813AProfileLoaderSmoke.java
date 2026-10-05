import decompengine.oracle.fulltree.FullTreeGenericTemplateFrontendProfileV1;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import kotlin.Pair;

/**
 * Infrastructure-only smoke of the repository's real A profile projections.
 * This intentionally does not instantiate a frontend adapter or claim a B profile.
 */
public final class Clang1813AProfileLoaderSmoke {
  private Clang1813AProfileLoaderSmoke() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 1) throw new IllegalArgumentException("usage: <loader-input.properties>");
    Properties input = new Properties();
    try (InputStream stream = Files.newInputStream(Path.of(args[0]))) {
      input.load(stream);
    }

    String imageDigest = required(input, "containerImageDigest");
    FullTreeGenericTemplateFrontendProfileV1 loader = FullTreeGenericTemplateFrontendProfileV1.INSTANCE;
    FullTreeGenericTemplateFrontendProfileV1.PathTransformV1 path = loader.transformPath(
        required(input, "rawPath"), imageDigest);
    FullTreeGenericTemplateFrontendProfileV1.ResourceManifestV1 resources = loader.loadResourceManifest(
        Path.of(required(input, "rootfs")),
        required(input, "resolvedResourceDirectory"),
        FullTreeGenericTemplateFrontendProfileV1.MAX_RESOURCE_FILES,
        FullTreeGenericTemplateFrontendProfileV1.MAX_RESOURCE_TREE_BYTES,
        FullTreeGenericTemplateFrontendProfileV1.MAX_RESOURCE_MANIFEST_BYTES);

    int count = Integer.parseInt(required(input, "symlinkCount"));
    List<Pair<String, String>> chain = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      chain.add(new Pair<>(required(input, "symlink." + i + ".path"),
          required(input, "symlink." + i + ".sha256")));
    }
    String cxxDriverIdentity = loader.cxxDriverIdentity(
        new FullTreeGenericTemplateFrontendProfileV1.CxxDriverIdentityInputV1(
            required(input, "buildRecordSha256"), imageDigest,
            required(input, "configuredPathSha256"), chain,
            required(input, "resolvedDriverPath"), required(input, "executableSha256"),
            Long.parseLong(required(input, "executableBytes")), required(input, "executableMode"),
            required(input, "compilerSha256"), required(input, "toolchainProfileSha256")));

    int runtimeCount = Integer.parseInt(required(input, "runtimeCount"));
    List<FullTreeGenericTemplateFrontendProfileV1.RuntimeLibraryDigestV1> runtime = new ArrayList<>();
    Path root = Path.of(required(input, "rootfs")).toAbsolutePath().normalize();
    for (int i = 0; i < runtimeCount; i++) {
      String runtimePath = required(input, "runtime." + i + ".path");
      String runtimeSha = required(input, "runtime." + i + ".sha256");
      Path file = root.resolve(runtimePath.substring("toolchain/".length())).normalize();
      if (!file.startsWith(root) || !Files.isRegularFile(file)) {
        throw new IllegalStateException("authenticated runtime library is missing: " + runtimePath);
      }
      if (!sha256(file).equals(runtimeSha)) {
        throw new IllegalStateException("authenticated runtime library bytes changed: " + runtimePath);
      }
      runtime.add(new FullTreeGenericTemplateFrontendProfileV1.RuntimeLibraryDigestV1(runtimePath, runtimeSha));
    }
    FullTreeGenericTemplateFrontendProfileV1.ProfileV1 profile = profile(loader, input, path, resources,
        cxxDriverIdentity, runtime, resources.getSha256());
    profile.requirePathTransform(path);
    boolean rejectedWrongImage = rejects(() -> profile.requirePathTransform(
        loader.transformPath(required(input, "rawPath"), "sha256:" + mutateSha(imageDigest.substring(7)))));
    if (!rejectedWrongImage) throw new IllegalStateException("A profile loader accepted a mismatched image digest");

    String wrongExecutableSha = mutateSha(required(input, "executableSha256"));
    boolean rejectedWrongDriver = rejects(() -> loader.cxxDriverIdentity(
        new FullTreeGenericTemplateFrontendProfileV1.CxxDriverIdentityInputV1(
            required(input, "buildRecordSha256"), imageDigest,
            required(input, "configuredPathSha256"), chain,
            required(input, "resolvedDriverPath"), wrongExecutableSha,
            Long.parseLong(required(input, "executableBytes")), required(input, "executableMode"),
            required(input, "compilerSha256"), required(input, "toolchainProfileSha256"))));
    if (!rejectedWrongDriver) throw new IllegalStateException("A profile loader accepted mismatched C++ driver bytes");

    String wrongResourceSha = mutateSha(resources.getSha256());
    FullTreeGenericTemplateFrontendProfileV1.ProfileV1 changedResource = profile(loader, input, path,
        resources, cxxDriverIdentity, runtime, wrongResourceSha);
    boolean rejectedChangedResource = rejects(() -> loader.requireHomogeneousProfiles(List.of(profile, changedResource)));
    if (!rejectedChangedResource) throw new IllegalStateException("A profile loader accepted mismatched resource identities");

    if (runtime.isEmpty()) throw new IllegalStateException("runtime library manifest is unexpectedly empty");
    List<FullTreeGenericTemplateFrontendProfileV1.RuntimeLibraryDigestV1> changedRuntime = new ArrayList<>(runtime);
    FullTreeGenericTemplateFrontendProfileV1.RuntimeLibraryDigestV1 firstRuntime = changedRuntime.get(0);
    changedRuntime.set(0, new FullTreeGenericTemplateFrontendProfileV1.RuntimeLibraryDigestV1(
        firstRuntime.getPath(), mutateSha(firstRuntime.getSha256())));
    FullTreeGenericTemplateFrontendProfileV1.ProfileV1 changedLibrary = profile(loader, input, path,
        resources, cxxDriverIdentity, changedRuntime, resources.getSha256());
    boolean rejectedChangedLibrary = rejects(() -> loader.requireHomogeneousProfiles(List.of(profile, changedLibrary)));
    if (!rejectedChangedLibrary) throw new IllegalStateException("A profile loader accepted mismatched runtime-library identities");

    boolean rejectedMissingResource = rejects(() -> loader.loadResourceManifest(
        root, "toolchain/usr/lib/llvm-18/missing-resource-directory",
        FullTreeGenericTemplateFrontendProfileV1.MAX_RESOURCE_FILES,
        FullTreeGenericTemplateFrontendProfileV1.MAX_RESOURCE_TREE_BYTES,
        FullTreeGenericTemplateFrontendProfileV1.MAX_RESOURCE_MANIFEST_BYTES));
    if (!rejectedMissingResource) throw new IllegalStateException("A profile loader accepted a missing resource directory");

    String report = "{\"scope\":\"infrastructure-loader-smoke-only\","
        + "\"buildRecordSha256\":\"" + required(input, "buildRecordSha256") + "\","
        + "\"imageDigest\":\"" + imageDigest + "\","
        + "\"infrastructureProfileProjectionSha256\":\"" + profile.sha256() + "\","
        + "\"pathTransformSha256\":\"" + path.getPathTransformSha256() + "\","
        + "\"resourceDirectory\":\"" + resources.getResolvedResourceDirectory() + "\","
        + "\"resourceFileCount\":" + resources.getFiles().size() + ","
        + "\"resourceTreeBytes\":" + resources.getTotalBytes() + ","
        + "\"resourceManifestSha256\":\"" + resources.getSha256() + "\","
        + "\"cxxDriverIdentitySha256\":\"" + cxxDriverIdentity + "\","
        + "\"rejectedWrongImage\":" + rejectedWrongImage + ","
        + "\"rejectedWrongCxxDriverBytes\":" + rejectedWrongDriver + ","
        + "\"rejectedChangedResourceIdentity\":" + rejectedChangedResource + ","
        + "\"rejectedChangedRuntimeLibraryIdentity\":" + rejectedChangedLibrary + ","
        + "\"rejectedMissingResourceDirectory\":" + rejectedMissingResource + "}\n";
    Files.writeString(Path.of(required(input, "smokeOutput")), report, StandardCharsets.UTF_8);
    System.out.print(report);
  }

  private static String required(Properties properties, String name) {
    String value = properties.getProperty(name);
    if (value == null || value.isEmpty()) throw new IllegalArgumentException("missing input: " + name);
    return value;
  }

  private static FullTreeGenericTemplateFrontendProfileV1.ProfileV1 profile(
      FullTreeGenericTemplateFrontendProfileV1 loader, Properties input,
      FullTreeGenericTemplateFrontendProfileV1.PathTransformV1 path,
      FullTreeGenericTemplateFrontendProfileV1.ResourceManifestV1 resources,
      String cxxDriverIdentity,
      List<FullTreeGenericTemplateFrontendProfileV1.RuntimeLibraryDigestV1> runtime,
      String resourceSha) {
    return new FullTreeGenericTemplateFrontendProfileV1.ProfileV1(
        required(input, "compilerSha256"), cxxDriverIdentity, path.getPathTransformSha256(), runtime,
        resources.getResolvedResourceDirectory(), resourceSha,
        required(input, "adapterSourceRevision"), required(input, "adapterSha256"),
        required(input, "adapterApiVersion"), required(input, "targetTriple"),
        required(input, "toolchainProfileSha256"), required(input, "containerImageDigest"));
  }

  private static boolean rejects(Runnable action) {
    try {
      action.run();
      return false;
    } catch (RuntimeException expected) {
      return true;
    }
  }

  private static String mutateSha(String value) {
    if (value.length() != 64) throw new IllegalArgumentException("expected SHA-256");
    char first = value.charAt(0) == '0' ? '1' : '0';
    return first + value.substring(1);
  }

  private static String sha256(Path path) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (var stream = Files.newInputStream(path)) {
      byte[] buffer = new byte[1024 * 1024];
      int count;
      while ((count = stream.read(buffer)) >= 0) digest.update(buffer, 0, count);
    }
    byte[] bytes = digest.digest();
    StringBuilder result = new StringBuilder(64);
    for (byte value : bytes) result.append(String.format("%02x", value & 0xff));
    return result.toString();
  }
}

package decompengine.oracle.behavior;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.StringArray;
import decompengine.oracle.fulltree.StableControlFile;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.IntSupplier;
import java.util.regex.Pattern;

/**
 * Package-owned native boundary for the hosted Clang and LLD build steps.
 *
 * <p>The class deliberately has no public class, field, constructor, or method. Raw descriptors,
 * pidfds, procfs capability construction, native mutation calls, and the generic process engine
 * stay in private members of this one Java nest. Kotlin receives only package-owned retained-file,
 * pinned-directory, and immutable-result values and invokes the two role-fixed entry points.</p>
 */
final class HostedNativeExecution {
    private static final long PARENT_PID = ProcessHandle.current().pid();
    private static final Object PROCESS_LOCK = new Object();

    private static final long MAXIMUM_TOOL_BYTES = 512L * 1024L * 1024L;
    private static final long MAXIMUM_EXECUTABLE_BYTES = 64L * 1024L * 1024L;
    private static final long MAXIMUM_RETAINED_AUXILIARY_BYTES = 4L * 1024L * 1024L;
    private static final int MAXIMUM_COMMAND_OUTPUT_BYTES = 64 * 1024 * 1024;
    private static final int PROCESS_BUFFER_BYTES = 64 * 1024;
    private static final Duration MAXIMUM_COMMAND_TIMEOUT = Duration.ofMinutes(10);
    private static final Duration MAXIMUM_CLEANUP_TIMEOUT = Duration.ofSeconds(5);

    private static final int MAXIMUM_ARGUMENTS = 768;
    private static final long MAXIMUM_ARGUMENT_BYTES = 256L * 1024L;
    private static final int MAXIMUM_NATIVE_STRING_BYTES = 16 * 1024;
    private static final int MAXIMUM_ENVIRONMENT_BINDINGS = 16;
    private static final long MAXIMUM_ENVIRONMENT_BYTES = 64L * 1024L;
    private static final Pattern ENVIRONMENT_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");
    private static final Set<String> FORBIDDEN_ENVIRONMENT_NAMES = Set.of(
        "CPATH",
        "LIBRARY_PATH",
        "COMPILER_PATH",
        "GCC_EXEC_PREFIX",
        "HOME",
        "PWD",
        "GLIBC_TUNABLES"
    );

    private static final long OPAQUE_NATIVE_STORAGE_BYTES = 4096L;
    private static final long SIGSET_BYTES = 128L;
    private static final long SIGACTION_BYTES_X86_64_GLIBC = 152L;
    private static final long SIGACTION_HANDLER_OFFSET = 0L;
    private static final long SIGACTION_FLAGS_OFFSET = 136L;
    private static final long SIGINFO_BYTES = 128L;
    private static final long SIGINFO_PID_OFFSET_X86_64 = 16L;
    private static final int POLLFD_BYTES = 8;
    private static final int ACTIVE_POLL_MILLIS = 25;
    private static final int POST_EXIT_POLL_MILLIS = 5;
    private static final long CLEANUP_POLL_MILLIS = 5L;

    private static final String NULL_DEVICE = "/dev/null";
    private static final int POSIX_SPAWN_SETSIGDEF = 0x04;
    private static final int POSIX_SPAWN_SETSIGMASK = 0x08;
    private static final int POSIX_SPAWN_SETSID = 0x80;
    private static final int MFD_CLOEXEC = 0x0001;
    private static final int MFD_ALLOW_SEALING = 0x0002;
    private static final int MFD_EXEC = 0x0010;
    private static final int F_ADD_SEALS = 1033;
    private static final int F_GET_SEALS = 1034;
    private static final int F_SEAL_SEAL = 0x0001;
    private static final int F_SEAL_SHRINK = 0x0002;
    private static final int F_SEAL_GROW = 0x0004;
    private static final int F_SEAL_WRITE = 0x0008;
    private static final int MODE_READ_ONLY = 0400;
    private static final int MODE_READ_EXECUTE = 0500;
    private static final int O_RDONLY = 0;
    private static final int O_RDWR = 2;
    private static final int O_NONBLOCK = 0x800;
    private static final int O_DIRECTORY = 0x10000;
    private static final int O_NOFOLLOW = 0x20000;
    private static final int O_CLOEXEC = 0x80000;
    private static final int O_ACCMODE = 0x3;
    private static final int SEEK_SET = 0;
    private static final int F_GETFD = 1;
    private static final int F_DUPFD_CLOEXEC = 1030;
    private static final int F_GETFL = 3;
    private static final int F_SETFL = 4;
    private static final int POLLIN = 0x001;
    private static final int POLLERR = 0x008;
    private static final int POLLHUP = 0x010;
    private static final int POLLNVAL = 0x020;
    private static final int WNOHANG = 1;
    private static final int WEXITED = 0x00000004;
    private static final int WNOWAIT = 0x01000000;
    private static final int P_PID = 1;
    private static final int P_PIDFD = 3;
    private static final int SIGCHLD = 17;
    private static final int SIGKILL = 9;
    private static final int SIGSTOP = 19;
    private static final int SA_NOCLDWAIT = 0x00000002;
    private static final long SIG_DFL = 0L;
    private static final int EINTR = 4;
    private static final int ECHILD = 10;
    private static final int EBADF = 9;
    private static final int EAGAIN = 11;
    private static final int ESRCH = 3;

    static {
        Native.register(HostedNativeExecution.class, Platform.C_LIBRARY_NAME);
    }

    private HostedNativeExecution() {
        throw new AssertionError("no instances");
    }

    static final class RetainedFile {
        private int descriptor;
        private long bytes;
        private String sha256;
        private boolean executable;
        private boolean sealed;

        private RetainedFile(
            int descriptor,
            long bytes,
            String sha256,
            boolean executable,
            boolean sealed
        ) {
            this.descriptor = descriptor;
            this.bytes = bytes;
            this.sha256 = Objects.requireNonNull(sha256, "sha256");
            this.executable = executable;
            this.sealed = sealed;
        }

        synchronized long getBytes() {
            requireOpen("retained identity");
            return bytes;
        }

        synchronized String getSha256() {
            requireOpen("retained identity");
            return sha256;
        }

        synchronized String capabilityPath(String label) {
            requireOpen(label);
            return descriptorPath(descriptor);
        }

        synchronized void sealProduced(long maximumBytes, boolean makeExecutable, String label) {
            requireOpen(label);
            if (sealed) {
                throw fail(label + " retained identity is already sealed");
            }
            if (maximumBytes <= 0L || maximumBytes > Integer.MAX_VALUE) {
                throw fail(label + " has an unsupported retained-output bound");
            }
            syscallZero(label, "synchronize", () -> fsync(descriptor));
            syscallZero(
                label,
                "set mode",
                () -> fchmod(descriptor, makeExecutable ? MODE_READ_EXECUTE : MODE_READ_ONLY)
            );
            addRequiredSeals(descriptor, label);
            sealed = true;
            executable = makeExecutable;
            Identity identity = readIdentity(descriptor, maximumBytes, label);
            if (identity.bytes <= 0L) {
                throw fail(label + " is empty");
            }
            bytes = identity.bytes;
            sha256 = identity.sha256;
        }

        synchronized byte[] readBytes(long maximumBytes, String label) {
            requireOpen(label);
            return readRetainedBytes(descriptor, maximumBytes, label);
        }

        synchronized void close() {
            int owned = descriptor;
            descriptor = -1;
            if (owned >= 0) {
                HostedNativeExecution.close(owned);
            }
        }

        private synchronized String executionPath(String label) {
            requireOpen(label);
            if (!executable) {
                throw fail(label + " retained identity is not executable");
            }
            if (!sealed) {
                throw fail(label + " executable identity is not sealed");
            }
            return descriptorPath(descriptor);
        }

        private synchronized String sealedInputPath(String label) {
            requireOpen(label);
            if (!sealed || bytes <= 0L) {
                throw fail(label + " standard-input identity is not sealed and nonempty");
            }
            return descriptorPath(descriptor);
        }

        private void requireOpen(String label) {
            requireLabel(label);
            if (descriptor < 0) {
                throw fail(label + " retained identity is closed");
            }
        }
    }

    static final class PinnedDirectory {
        private int descriptor;

        private PinnedDirectory(int descriptor) {
            this.descriptor = descriptor;
        }

        synchronized String capabilityPath(String label) {
            requireOpen(label);
            return descriptorPath(descriptor);
        }

        synchronized void close() {
            int owned = descriptor;
            descriptor = -1;
            if (owned >= 0) {
                HostedNativeExecution.close(owned);
            }
        }

        private synchronized void addWorkingDirectoryAction(Memory actions, String label) {
            requireOpen(label);
            nativeResult(
                label + " configure descriptor-pinned working directory",
                posix_spawn_file_actions_addfchdir_np(actions, descriptor)
            );
        }

        private void requireOpen(String label) {
            requireLabel(label);
            if (descriptor < 3) {
                throw fail(label + " pinned working-directory descriptor is unavailable");
            }
        }
    }

    static final class Result {
        private final int exitCode;
        private final byte[] stdout;
        private final byte[] stderr;

        private Result(int exitCode, byte[] stdout, byte[] stderr) {
            this.exitCode = exitCode;
            this.stdout = stdout.clone();
            this.stderr = stderr.clone();
        }

        int getExitCode() {
            return exitCode;
        }

        byte[] getStdout() {
            return stdout.clone();
        }

        byte[] getStderr() {
            return stderr.clone();
        }
    }

    static RetainedFile snapshot(
        StableControlFile guard,
        long expectedBytes,
        String expectedSha256,
        boolean executable,
        String label
    ) {
        Objects.requireNonNull(guard, "guard");
        requireLabel(label);
        requireSha256(expectedSha256, label);
        if (expectedBytes <= 0L || expectedBytes > MAXIMUM_TOOL_BYTES || guard.getSize() != expectedBytes) {
            throw fail(label + " size is outside its adoption bound");
        }
        int descriptor = createMemfd(executable, label);
        try {
            MessageDigest digest = sha256Digest();
            long copied = 0L;
            try (InputStream input = guard.slice(0L, expectedBytes)) {
                byte[] buffer = new byte[8192];
                while (true) {
                    int count = input.read(buffer);
                    if (count < 0) {
                        break;
                    }
                    if (count == 0) {
                        continue;
                    }
                    copied = Math.addExact(copied, count);
                    if (copied > expectedBytes) {
                        throw fail(label + " grew during adoption");
                    }
                    digest.update(buffer, 0, count);
                    writeAll(descriptor, buffer, count, label);
                }
            }
            String observedSha256 = hex(digest.digest());
            if (copied != expectedBytes || !observedSha256.equals(expectedSha256)) {
                throw fail(label + " differs from its authenticated descriptor bytes");
            }
            finishSnapshot(descriptor, executable, label);
            Identity identity = readIdentity(descriptor, expectedBytes, label);
            if (identity.bytes != expectedBytes || !identity.sha256.equals(expectedSha256)) {
                throw fail(label + " changed while its anonymous identity was sealed");
            }
            guard.verifyUnchanged(label);
            return new RetainedFile(descriptor, expectedBytes, expectedSha256, executable, true);
        } catch (Throwable failure) {
            close(descriptor);
            throw propagate(failure, label + " adoption failed");
        }
    }

    static RetainedFile snapshot(byte[] source, boolean executable, String label) {
        return snapshot(
            source,
            executable,
            executable ? MAXIMUM_EXECUTABLE_BYTES : MAXIMUM_RETAINED_AUXILIARY_BYTES,
            label
        );
    }

    static RetainedFile snapshot(byte[] source, boolean executable, long maximumBytes, String label) {
        Objects.requireNonNull(source, "source");
        requireLabel(label);
        if (maximumBytes <= 0L || maximumBytes > MAXIMUM_TOOL_BYTES) {
            throw fail(label + " has an unsupported adoption bound");
        }
        byte[] bytes = source.clone();
        if (bytes.length == 0 || bytes.length > maximumBytes) {
            throw fail(label + " exceeds its adoption bound");
        }
        int descriptor = createMemfd(executable, label);
        try {
            writeAll(descriptor, bytes, bytes.length, label);
            finishSnapshot(descriptor, executable, label);
            String sha256 = hex(sha256Digest().digest(bytes));
            Identity identity = readIdentity(descriptor, bytes.length, label);
            if (identity.bytes != bytes.length || !identity.sha256.equals(sha256)) {
                throw fail(label + " changed while its anonymous identity was sealed");
            }
            return new RetainedFile(descriptor, identity.bytes, identity.sha256, executable, true);
        } catch (Throwable failure) {
            close(descriptor);
            throw propagate(failure, label + " adoption failed");
        }
    }

    static RetainedFile writable(boolean makeExecutable, String label) {
        requireLabel(label);
        return new RetainedFile(
            createMemfd(makeExecutable, label),
            0L,
            zeroSha256(),
            makeExecutable,
            false
        );
    }

    static PinnedDirectory open(Path path, String label) {
        Objects.requireNonNull(path, "path");
        requireLabel(label);
        Path real;
        try {
            real = path.toRealPath();
        } catch (Exception failure) {
            throw fail(label + " canonical directory is unavailable", failure);
        }
        if (!path.isAbsolute() || !path.normalize().equals(path) || !real.equals(path)
            || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw fail(label + " is not a canonical directory");
        }
        BasicFileAttributes before = readAttributes(path, label);
        int descriptor = openRetry(
            path.toString(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            label
        );
        try {
            if (descriptor < 3) {
                int original = descriptor;
                descriptor = duplicateAboveStdio(original, label);
                close(original);
            }
            if (descriptor < 3) {
                throw fail(label + " did not retain a descriptor above standard I/O");
            }
            BasicFileAttributes after = readAttributes(Path.of(descriptorPath(descriptor)), label);
            if (!before.isDirectory() || before.fileKey() == null || !before.fileKey().equals(after.fileKey())) {
                throw fail(label + " changed while its descriptor was pinned");
            }
            return new PinnedDirectory(descriptor);
        } catch (Throwable failure) {
            close(descriptor);
            throw propagate(failure, label + " pinning failed");
        }
    }

    static Result runClang(
        RetainedFile executable,
        RetainedFile standardInput,
        List<String> arguments,
        Map<String, String> environment,
        PinnedDirectory workingDirectory,
        Duration timeout,
        int maximumOutputBytes,
        Duration cleanupTimeout,
        String label
    ) {
        return runRole(
            Role.CLANG,
            executable,
            standardInput,
            arguments,
            environment,
            workingDirectory,
            timeout,
            maximumOutputBytes,
            cleanupTimeout,
            label
        );
    }

    static Result runLld(
        RetainedFile executable,
        List<String> arguments,
        Map<String, String> environment,
        PinnedDirectory workingDirectory,
        Duration timeout,
        int maximumOutputBytes,
        Duration cleanupTimeout,
        String label
    ) {
        return runRole(
            Role.LLD,
            executable,
            null,
            arguments,
            environment,
            workingDirectory,
            timeout,
            maximumOutputBytes,
            cleanupTimeout,
            label
        );
    }

    private static Result runRole(
        Role role,
        RetainedFile executable,
        RetainedFile standardInput,
        List<String> arguments,
        Map<String, String> environment,
        PinnedDirectory workingDirectory,
        Duration timeout,
        int maximumOutputBytes,
        Duration cleanupTimeout,
        String label
    ) {
        Objects.requireNonNull(executable, "executable");
        Objects.requireNonNull(arguments, "arguments");
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(workingDirectory, "workingDirectory");
        requireLabel(label);

        ArrayList<String> argumentCopy = new ArrayList<>(arguments.size() + 1);
        argumentCopy.add(role.argumentZero);
        argumentCopy.addAll(List.copyOf(arguments));
        List<String> frozenArguments = List.copyOf(argumentCopy);
        TreeMap<String, String> orderedEnvironment = new TreeMap<>();
        orderedEnvironment.putAll(environment);
        Map<String, String> frozenEnvironment = Collections.unmodifiableMap(orderedEnvironment);
        requireNativeVector(
            frozenArguments,
            frozenEnvironment,
            timeout,
            maximumOutputBytes,
            cleanupTimeout,
            label
        );
        requireRoleArguments(role, frozenArguments, label);

        synchronized (PROCESS_LOCK) {
            synchronized (executable) {
                synchronized (workingDirectory) {
                    if (standardInput == null) {
                        return executeLockedRole(
                            executable,
                            null,
                            role,
                            frozenArguments,
                            frozenEnvironment,
                            workingDirectory,
                            maximumOutputBytes,
                            cleanupTimeout,
                            timeout,
                            label
                        );
                    }
                    synchronized (standardInput) {
                        return executeLockedRole(
                            executable,
                            standardInput,
                            role,
                            frozenArguments,
                            frozenEnvironment,
                            workingDirectory,
                            maximumOutputBytes,
                            cleanupTimeout,
                            timeout,
                            label
                        );
                    }
                }
            }
        }
    }

    private static Result executeLockedRole(
        RetainedFile executable,
        RetainedFile standardInput,
        Role role,
        List<String> arguments,
        Map<String, String> environment,
        PinnedDirectory workingDirectory,
        int maximumOutputBytes,
        Duration cleanupTimeout,
        Duration timeout,
        String label
    ) {
        String executionPath = executable.executionPath(label);
        String standardInputPath = standardInput == null ? null : standardInput.sealedInputPath(label);
        workingDirectory.requireOpen(label);
        return new NativeProcess(
            executionPath,
            standardInputPath,
            role,
            arguments,
            environment,
            workingDirectory,
            maximumOutputBytes,
            cleanupTimeout,
            label
        ).execute(deadlineAfter(timeout, label));
    }

    private static final class NativeProcess {
        private final String executionPath;
        private final String standardInputPath;
        private final Role role;
        private final List<String> arguments;
        private final Map<String, String> environment;
        private final PinnedDirectory workingDirectory;
        private final int maximumOutputBytes;
        private final Duration cleanupTimeout;
        private final String label;

        private final Memory attributes = new Memory(OPAQUE_NATIVE_STORAGE_BYTES);
        private final Memory fileActions = new Memory(OPAQUE_NATIVE_STORAGE_BYTES);
        private final ArrayList<Integer> reservedStandardDescriptors = new ArrayList<>(3);
        private boolean attributesInitialized;
        private boolean fileActionsInitialized;
        private int stdinFd = -1;
        private int stdoutReadFd = -1;
        private int stdoutWriteFd = -1;
        private int stderrReadFd = -1;
        private int stderrWriteFd = -1;
        private int pid = -1;
        private int pidfd = -1;
        private boolean sessionVerified;
        private boolean waitableIdentityProven;
        private boolean identityLost;
        private boolean reaped;
        private boolean cleanupInterrupted;

        private NativeProcess(
            String executionPath,
            String standardInputPath,
            Role role,
            List<String> arguments,
            Map<String, String> environment,
            PinnedDirectory workingDirectory,
            int maximumOutputBytes,
            Duration cleanupTimeout,
            String label
        ) {
            this.executionPath = executionPath;
            this.standardInputPath = standardInputPath;
            this.role = role;
            this.arguments = arguments;
            this.environment = environment;
            this.workingDirectory = workingDirectory;
            this.maximumOutputBytes = maximumOutputBytes;
            this.cleanupTimeout = cleanupTimeout;
            this.label = label;
            attributes.clear();
            fileActions.clear();
        }

        private Result execute(long commandDeadline) {
            Throwable primary = null;
            try {
                requireDeadline(commandDeadline, label, false);
                requirePlatformAndPidfd(label);
                requireSigchldWaitable(label);
                prepare(commandDeadline);
                spawn(commandDeadline);
                closeParentWriteEnds();
                makeOutputNonblocking(commandDeadline);
                CapturedOutput output = capture(commandDeadline);
                int status = reapProvenLeader(commandDeadline, false);
                int exitCode;
                if (waitExited(status)) {
                    exitCode = waitExitStatus(status);
                } else if (waitSignaled(status)) {
                    exitCode = 128 + waitTermSignal(status);
                } else {
                    throw fail(label + " returned an unsupported wait status");
                }
                return new Result(exitCode, output.stdout, output.stderr);
            } catch (Throwable failure) {
                primary = failure;
                if (pid > 0 && !reaped && !identityLost) {
                    try {
                        cleanup(deadlineAfter(cleanupTimeout, label));
                    } catch (Throwable cleanupFailure) {
                        LlvmBehaviorHostedCleanBuildV2Exception wrapped = fail(
                            label + " failed and its exact session leader could not be killed and reaped",
                            cleanupFailure
                        );
                        wrapped.addSuppressed(failure);
                        primary = wrapped;
                    }
                }
                throw propagate(primary, label + " native execution failed");
            } finally {
                closeFd(stdoutReadFd);
                stdoutReadFd = -1;
                closeFd(stdoutWriteFd);
                stdoutWriteFd = -1;
                closeFd(stderrReadFd);
                stderrReadFd = -1;
                closeFd(stderrWriteFd);
                stderrWriteFd = -1;
                closeFd(stdinFd);
                stdinFd = -1;
                for (int descriptor : reservedStandardDescriptors) {
                    closeFd(descriptor);
                }
                reservedStandardDescriptors.clear();
                closeFd(pidfd);
                pidfd = -1;
                if (fileActionsInitialized) {
                    posix_spawn_file_actions_destroy(fileActions);
                }
                if (attributesInitialized) {
                    posix_spawnattr_destroy(attributes);
                }
                if (primary == null && pid > 0 && !reaped) {
                    throw fail(label + " returned without reaping its exact session leader");
                }
            }
        }

        private void prepare(long deadline) {
            requireDeadline(deadline, label, false);
            int attributesResult = posix_spawnattr_init(attributes);
            if (attributesResult == 0) {
                attributesInitialized = true;
            }
            nativeResult(label + " initialize spawn attributes", attributesResult);

            Memory defaults = new Memory(SIGSET_BYTES);
            Memory mask = new Memory(SIGSET_BYTES);
            defaults.clear();
            mask.clear();
            syscallZero(label, "initialize default signals", () -> sigfillset(defaults));
            syscallZero(label, "exclude SIGKILL from defaults", () -> sigdelset(defaults, SIGKILL));
            syscallZero(label, "exclude SIGSTOP from defaults", () -> sigdelset(defaults, SIGSTOP));
            syscallZero(label, "initialize empty signal mask", () -> sigemptyset(mask));
            nativeResult(
                label + " configure default signals",
                posix_spawnattr_setsigdefault(attributes, defaults)
            );
            nativeResult(
                label + " configure signal mask",
                posix_spawnattr_setsigmask(attributes, mask)
            );
            nativeResult(
                label + " configure fresh session",
                posix_spawnattr_setflags(
                    attributes,
                    (short) (POSIX_SPAWN_SETSID | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)
                )
            );

            int actionsResult = posix_spawn_file_actions_init(fileActions);
            if (actionsResult == 0) {
                fileActionsInitialized = true;
            }
            nativeResult(label + " initialize spawn file actions", actionsResult);
            reserveClosedStandardDescriptors(deadline);
            stdinFd = openRetry(
                standardInputPath == null ? NULL_DEVICE : standardInputPath,
                O_RDONLY | O_CLOEXEC,
                label
            );
            if (standardInputPath != null) {
                int stdinFlags = fcntl(stdinFd, F_GETFL, 0);
                if (stdinFlags < 0 || (stdinFlags & O_ACCMODE) != O_RDONLY) {
                    throw fail(label + " retained standard input is not open read-only");
                }
                long inputOffset = lseek(stdinFd, new NativeLong(0L), SEEK_SET).longValue();
                if (inputOffset != 0L) {
                    int error = inputOffset < 0L ? Native.getLastError() : 0;
                    throw fail(label + " retained standard input could not be rewound: errno " + error);
                }
            }
            int[] stdoutPipe = createPipe("stdout", deadline);
            stdoutReadFd = stdoutPipe[0];
            stdoutWriteFd = stdoutPipe[1];
            int[] stderrPipe = createPipe("stderr", deadline);
            stderrReadFd = stderrPipe[0];
            stderrWriteFd = stderrPipe[1];

            nativeResult(
                label + " bind stdin",
                posix_spawn_file_actions_adddup2(fileActions, stdinFd, 0)
            );
            nativeResult(
                label + " bind stdout",
                posix_spawn_file_actions_adddup2(fileActions, stdoutWriteFd, 1)
            );
            nativeResult(
                label + " bind stderr",
                posix_spawn_file_actions_adddup2(fileActions, stderrWriteFd, 2)
            );
            LinkedHashSet<Integer> surplus = new LinkedHashSet<>(List.of(
                stdinFd,
                stdoutReadFd,
                stdoutWriteFd,
                stderrReadFd,
                stderrWriteFd
            ));
            for (int descriptor : surplus) {
                if (descriptor > 2) {
                    nativeResult(
                        label + " close surplus pipe descriptor",
                        posix_spawn_file_actions_addclose(fileActions, descriptor)
                    );
                }
            }
            workingDirectory.addWorkingDirectoryAction(fileActions, label);
            nativeResult(
                label + " close inherited descriptors",
                posix_spawn_file_actions_addclosefrom_np(fileActions, 3)
            );
            requireDeadline(deadline, label, false);
        }

        private void spawn(long deadline) {
            requireDeadline(deadline, label, false);
            requireSigchldWaitable(label);
            Memory pidStorage = new Memory(Integer.BYTES);
            pidStorage.clear();
            StringArray argumentArray = new StringArray(
                arguments.toArray(String[]::new),
                StandardCharsets.UTF_8.name()
            );
            StringArray environmentArray = new StringArray(
                environment.entrySet().stream()
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .toArray(String[]::new),
                StandardCharsets.UTF_8.name()
            );
            int result = posix_spawn(
                pidStorage,
                executionPath,
                fileActions,
                attributes,
                argumentArray,
                environmentArray
            );
            if (result == 0) {
                pid = pidStorage.getInt(0L);
            }
            nativeResult(label + " start exact retained " + role.argumentZero, result);
            if (pid <= 0) {
                throw fail(label + " returned an invalid process id");
            }
            requireDeadline(deadline, label, false);
            try {
                pidfd = pidfdOpen(pid, deadline, label);
            } catch (Throwable failure) {
                emergencyReapUnpinnedLeader(deadline);
                throw failure;
            }
            verifyFreshSession(deadline);
        }

        private CapturedOutput capture(long deadline) {
            CaptureBudget budget = new CaptureBudget(maximumOutputBytes, label);
            BoundedCapture stdout = new BoundedCapture(budget, label + " stdout");
            BoundedCapture stderr = new BoundedCapture(budget, label + " stderr");
            boolean groupSignaled = false;
            while (true) {
                requireDeadline(deadline, label, false);
                if (stdout.drain(stdoutReadFd, deadline)) {
                    stdoutReadFd = -1;
                }
                if (stderr.drain(stderrReadFd, deadline)) {
                    stderrReadFd = -1;
                }
                if (!waitableIdentityProven && pidfdExited(deadline, false)) {
                    proveWaitableLeader(deadline, false);
                }
                if (waitableIdentityProven && !groupSignaled) {
                    signalVerifiedGroup(SIGKILL, deadline, false);
                    groupSignaled = true;
                }
                if (waitableIdentityProven && stdoutReadFd < 0 && stderrReadFd < 0) {
                    return new CapturedOutput(stdout.bytes(), stderr.bytes());
                }
                pollOutput(
                    waitableIdentityProven ? POST_EXIT_POLL_MILLIS : ACTIVE_POLL_MILLIS,
                    deadline
                );
            }
        }

        private void cleanup(long deadline) {
            deferCleanupInterrupt();
            try {
                closeParentWriteEnds();
                closeFd(stdoutReadFd);
                stdoutReadFd = -1;
                closeFd(stderrReadFd);
                stderrReadFd = -1;
                if (pidfd < 0) {
                    emergencyReapUnpinnedLeader(deadline);
                    return;
                }
                signalPidfd(SIGKILL, deadline, true);
                waitForPidfdExit(deadline, true);
                proveWaitableLeader(deadline, true);
                if (sessionVerified) {
                    signalVerifiedGroup(SIGKILL, deadline, true);
                }
                reapProvenLeader(deadline, true);
            } finally {
                restoreCleanupInterrupt();
            }
        }

        private void verifyFreshSession(long deadline) {
            requireDeadline(deadline, label, false);
            int processGroup = getpgid(pid);
            int groupError = processGroup < 0 ? Native.getLastError() : 0;
            int session = getsid(pid);
            int sessionError = session < 0 ? Native.getLastError() : 0;
            if (processGroup != pid || session != pid) {
                throw fail(
                    label + " did not enter its required fresh session and process group"
                        + " (pgrp=" + processGroup + ", pgrp errno=" + groupError
                        + ", session=" + session + ", session errno=" + sessionError + ")"
                );
            }
            sessionVerified = true;
        }

        private void proveWaitableLeader(long deadline, boolean cleanup) {
            if (waitableIdentityProven) {
                return;
            }
            if (identityLost || pidfd < 0) {
                throw fail(label + " cannot prove a waitable pidfd-owned session leader");
            }
            Memory information = new Memory(SIGINFO_BYTES);
            while (true) {
                requireDeadline(deadline, label, cleanup);
                requireSigchldWaitable(label);
                information.clear();
                int result = waitid(P_PIDFD, pidfd, information, WEXITED | WNOHANG | WNOWAIT);
                int error = result != 0 ? Native.getLastError() : 0;
                if (result == 0) {
                    int observedPid = information.getInt(SIGINFO_PID_OFFSET_X86_64);
                    if (observedPid == pid) {
                        waitableIdentityProven = true;
                        return;
                    }
                    if (observedPid != 0) {
                        identityLost = true;
                        throw fail(
                            label + " pidfd wait proof returned a different child " + observedPid
                        );
                    }
                    sleep(deadline, CLEANUP_POLL_MILLIS, label, cleanup);
                    continue;
                }
                if (error == EINTR) {
                    continue;
                }
                if (error == ECHILD) {
                    identityLost = true;
                    throw fail(label + " lost child wait ownership before numeric group cleanup");
                }
                throw fail(label + " pidfd wait proof failed with errno " + error);
            }
        }

        private int reapProvenLeader(long deadline, boolean cleanup) {
            if (!waitableIdentityProven || identityLost) {
                throw fail(label + " refused to reap an unproven session leader");
            }
            Memory status = new Memory(Integer.BYTES);
            while (true) {
                requireDeadline(deadline, label, cleanup);
                int result = waitpid(pid, status, 0);
                int error = result < 0 ? Native.getLastError() : 0;
                if (result == pid) {
                    reaped = true;
                    return status.getInt(0L);
                }
                if (result < 0 && error == EINTR) {
                    continue;
                }
                if (result < 0 && error == ECHILD) {
                    identityLost = true;
                    throw fail(label + " lost child wait ownership while reaping the proven leader");
                }
                throw fail(label + " waitpid returned an unexpected result " + result + " errno " + error);
            }
        }

        private void signalVerifiedGroup(int signal, long deadline, boolean cleanup) {
            if (!sessionVerified || !waitableIdentityProven || identityLost || reaped) {
                throw fail(label + " refused an unpinned numeric process-group signal");
            }
            requireSigchldWaitable(label);
            while (true) {
                requireDeadline(deadline, label, cleanup);
                int result = kill(-pid, signal);
                int error = result != 0 ? Native.getLastError() : 0;
                if (result == 0 || error == ESRCH) {
                    return;
                }
                if (error != EINTR) {
                    throw fail(label + " process-group signal failed with errno " + error);
                }
            }
        }

        private void signalPidfd(int signal, long deadline, boolean cleanup) {
            if (pidfd < 0 || identityLost || reaped) {
                throw fail(label + " refused to signal an unavailable pidfd");
            }
            while (true) {
                requireDeadline(deadline, label, cleanup);
                int result = pidfd_send_signal(pidfd, signal, null, 0);
                int error = result != 0 ? Native.getLastError() : 0;
                if (result == 0 || error == ESRCH) {
                    return;
                }
                if (error != EINTR) {
                    throw fail(label + " pidfd signal failed with errno " + error);
                }
            }
        }

        private void waitForPidfdExit(long deadline, boolean cleanup) {
            while (!pidfdExited(deadline, cleanup)) {
                sleep(deadline, CLEANUP_POLL_MILLIS, label, cleanup);
            }
        }

        private boolean pidfdExited(long deadline, boolean cleanup) {
            if (pidfd < 0) {
                throw fail(label + " cannot poll an unavailable pidfd");
            }
            Memory descriptor = new Memory(POLLFD_BYTES);
            descriptor.clear();
            descriptor.setInt(0L, pidfd);
            descriptor.setShort(Integer.BYTES, (short) POLLIN);
            while (true) {
                requireDeadline(deadline, label, cleanup);
                int result = poll(descriptor, new NativeLong(1L), 0);
                int error = result < 0 ? Native.getLastError() : 0;
                if (result >= 0) {
                    int events = descriptor.getShort(Integer.BYTES + Short.BYTES) & 0xffff;
                    if ((events & POLLNVAL) != 0) {
                        identityLost = true;
                        throw fail(label + " pidfd poll observed an invalid descriptor");
                    }
                    if ((events & (POLLHUP | POLLERR)) != 0) {
                        identityLost = true;
                        throw fail(label + " pidfd poll lost wait ownership");
                    }
                    return result > 0 && (events & POLLIN) != 0;
                }
                if (error != EINTR) {
                    throw fail(label + " pidfd poll failed with errno " + error);
                }
            }
        }

        private void pollOutput(int maximumMillis, long deadline) {
            ArrayList<Integer> descriptors = new ArrayList<>(2);
            if (stdoutReadFd >= 0) {
                descriptors.add(stdoutReadFd);
            }
            if (stderrReadFd >= 0) {
                descriptors.add(stderrReadFd);
            }
            if (descriptors.isEmpty()) {
                sleep(deadline, maximumMillis, label, false);
                return;
            }
            Memory polling = new Memory((long) descriptors.size() * POLLFD_BYTES);
            polling.clear();
            for (int index = 0; index < descriptors.size(); index++) {
                long offset = (long) index * POLLFD_BYTES;
                polling.setInt(offset, descriptors.get(index));
                polling.setShort(offset + Integer.BYTES, (short) POLLIN);
            }
            while (true) {
                requireDeadline(deadline, label, false);
                long remainingNanos = Math.max(1L, deadline - System.nanoTime());
                int remainingMillis = (int) Math.max(1L, remainingNanos / 1_000_000L);
                int timeoutMillis = Math.min(maximumMillis, remainingMillis);
                int result = poll(polling, new NativeLong(descriptors.size()), timeoutMillis);
                int error = result < 0 ? Native.getLastError() : 0;
                if (result >= 0) {
                    for (int index = 0; index < descriptors.size(); index++) {
                        long offset = (long) index * POLLFD_BYTES;
                        int events = polling.getShort(offset + Integer.BYTES + Short.BYTES) & 0xffff;
                        if ((events & POLLNVAL) != 0) {
                            throw fail(label + " output poll observed an invalid descriptor");
                        }
                    }
                    return;
                }
                if (error != EINTR) {
                    throw fail(label + " output poll failed with errno " + error);
                }
            }
        }

        private int[] createPipe(String stream, long deadline) {
            requireDeadline(deadline, label, false);
            Memory descriptors = new Memory(2L * Integer.BYTES);
            descriptors.clear();
            int result = pipe2(descriptors, O_CLOEXEC);
            if (result != 0) {
                throw fail(label + " " + stream + " pipe creation failed with errno " + Native.getLastError());
            }
            int[] pipe = {descriptors.getInt(0L), descriptors.getInt(Integer.BYTES)};
            try {
                requireDeadline(deadline, label, false);
                return pipe;
            } catch (Throwable failure) {
                closeFd(pipe[0]);
                closeFd(pipe[1]);
                throw failure;
            }
        }

        private void reserveClosedStandardDescriptors(long deadline) {
            for (int target = 0; target <= 2; target++) {
                requireDeadline(deadline, label, false);
                int result = fcntl(target, F_GETFD, 0);
                if (result >= 0) {
                    continue;
                }
                int error = Native.getLastError();
                if (error != EBADF) {
                    throw fail(label + " stdio inspection failed with errno " + error);
                }
                int opened = openRetry(NULL_DEVICE, O_RDWR | O_CLOEXEC, label);
                if (opened != target) {
                    closeFd(opened);
                    throw fail(label + " could not reserve closed standard descriptor " + target);
                }
                reservedStandardDescriptors.add(opened);
            }
        }

        private void makeOutputNonblocking(long deadline) {
            requireDeadline(deadline, label, false);
            for (int descriptor : List.of(stdoutReadFd, stderrReadFd)) {
                int flags = fcntl(descriptor, F_GETFL, 0);
                if (flags < 0) {
                    throw fail(label + " output flags are unavailable: errno " + Native.getLastError());
                }
                if (fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) {
                    throw fail(label + " could not make output nonblocking: errno " + Native.getLastError());
                }
            }
        }

        private void closeParentWriteEnds() {
            closeFd(stdinFd);
            stdinFd = -1;
            closeFd(stdoutWriteFd);
            stdoutWriteFd = -1;
            closeFd(stderrWriteFd);
            stderrWriteFd = -1;
        }

        private void emergencyReapUnpinnedLeader(long deadline) {
            if (pid <= 0 || reaped || identityLost) {
                return;
            }
            deferCleanupInterrupt();
            try {
                Memory information = new Memory(SIGINFO_BYTES);
                while (true) {
                    requireDeadline(deadline, label, true);
                    requireSigchldWaitable(label);
                    information.clear();
                    int waitResult = waitid(P_PID, pid, information, WEXITED | WNOHANG | WNOWAIT);
                    int waitError = waitResult != 0 ? Native.getLastError() : 0;
                    if (waitResult != 0 && waitError == EINTR) {
                        continue;
                    }
                    if (waitResult != 0 && waitError == ECHILD) {
                        identityLost = true;
                        throw fail(label + " lost emergency child wait ownership before numeric cleanup");
                    }
                    if (waitResult != 0) {
                        throw fail(label + " emergency child wait proof failed with errno " + waitError);
                    }
                    int observedPid = information.getInt(SIGINFO_PID_OFFSET_X86_64);
                    if (observedPid == pid) {
                        waitableIdentityProven = true;
                        break;
                    }
                    if (observedPid != 0) {
                        identityLost = true;
                        throw fail(label + " emergency wait proof returned a different child " + observedPid);
                    }

                    // A zero si_pid with P_PID confirms a matching live child but no waitable event.
                    // Check this before every numeric signal so an observed ECHILD can never be followed
                    // by a potentially reused-pid kill when per-child pidfd acquisition failed.
                    int signalResult = kill(pid, SIGKILL);
                    int signalError = signalResult != 0 ? Native.getLastError() : 0;
                    if (signalResult != 0 && signalError != ESRCH && signalError != EINTR) {
                        throw fail(label + " emergency exact-child signal failed with errno " + signalError);
                    }
                    sleep(deadline, CLEANUP_POLL_MILLIS, label, true);
                }
                reapProvenLeader(deadline, true);
            } finally {
                restoreCleanupInterrupt();
            }
        }

        private void deferCleanupInterrupt() {
            if (Thread.interrupted()) {
                cleanupInterrupted = true;
            }
        }

        private void restoreCleanupInterrupt() {
            if (Thread.interrupted()) {
                cleanupInterrupted = true;
            }
            if (cleanupInterrupted) {
                Thread.currentThread().interrupt();
            }
        }

        private void sleep(long deadline, long maximumMillis, String sleepLabel, boolean cleanup) {
            requireDeadline(deadline, sleepLabel, cleanup);
            long remainingNanos = deadline - System.nanoTime();
            long millis = Math.min(maximumMillis, Math.max(0L, remainingNanos / 1_000_000L));
            if (millis <= 0L) {
                Thread.onSpinWait();
            } else {
                try {
                    Thread.sleep(millis);
                } catch (InterruptedException failure) {
                    if (!cleanup) {
                        Thread.currentThread().interrupt();
                        throw fail(sleepLabel + " was interrupted", failure);
                    }
                    cleanupInterrupted = true;
                }
            }
            requireDeadline(deadline, sleepLabel, cleanup);
        }
    }

    private static final class CaptureBudget {
        private int remaining;
        private final String label;

        private CaptureBudget(int maximumBytes, String label) {
            this.remaining = maximumBytes;
            this.label = label;
        }

        private void consume(int count) {
            if (count < 0 || count > remaining) {
                throw fail(label + " exceeded its live aggregate output bound");
            }
            remaining -= count;
        }
    }

    private static final class BoundedCapture {
        private final CaptureBudget budget;
        private final String label;
        private final ByteArrayOutputStream output;
        private final Memory buffer = new Memory(PROCESS_BUFFER_BYTES);

        private BoundedCapture(CaptureBudget budget, String label) {
            this.budget = budget;
            this.label = label;
            this.output = new ByteArrayOutputStream(Math.min(PROCESS_BUFFER_BYTES, budget.remaining));
        }

        private boolean drain(int descriptor, long deadline) {
            if (descriptor < 0) {
                return true;
            }
            while (true) {
                requireDeadline(deadline, label, false);
                long count = read(descriptor, buffer, new NativeLong(PROCESS_BUFFER_BYTES)).longValue();
                int error = count < 0L ? Native.getLastError() : 0;
                if (count > 0L) {
                    if (count > Integer.MAX_VALUE) {
                        throw fail(label + " returned an unsupported read size");
                    }
                    budget.consume((int) count);
                    output.writeBytes(buffer.getByteArray(0L, (int) count));
                    continue;
                }
                if (count == 0L) {
                    close(descriptor);
                    return true;
                }
                if (error == EINTR) {
                    continue;
                }
                if (error == EAGAIN) {
                    return false;
                }
                throw fail(label + " output read failed with errno " + error);
            }
        }

        private byte[] bytes() {
            return output.toByteArray();
        }
    }

    private static final class CapturedOutput {
        private final byte[] stdout;
        private final byte[] stderr;

        private CapturedOutput(byte[] stdout, byte[] stderr) {
            this.stdout = stdout;
            this.stderr = stderr;
        }
    }

    private static final class Identity {
        private final long bytes;
        private final String sha256;

        private Identity(long bytes, String sha256) {
            this.bytes = bytes;
            this.sha256 = sha256;
        }
    }

    private static final class Role {
        private static final Role CLANG = new Role("clang");
        private static final Role LLD = new Role("ld.lld");

        private final String argumentZero;

        private Role(String argumentZero) {
            this.argumentZero = argumentZero;
        }
    }

    private static void finishSnapshot(int descriptor, boolean executable, String label) {
        syscallZero(label, "synchronize", () -> fsync(descriptor));
        syscallZero(
            label,
            "set mode",
            () -> fchmod(descriptor, executable ? MODE_READ_EXECUTE : MODE_READ_ONLY)
        );
        addRequiredSeals(descriptor, label);
    }

    private static int createMemfd(boolean executable, String label) {
        requirePlatform(label);
        int flags = MFD_CLOEXEC | MFD_ALLOW_SEALING | (executable ? MFD_EXEC : 0);
        while (true) {
            int descriptor = memfd_create("decomp-hosted-retained", flags);
            if (descriptor >= 0) {
                return descriptor;
            }
            int error = Native.getLastError();
            if (error != EINTR) {
                throw fail(label + " could not create an anonymous retained identity: errno " + error);
            }
        }
    }

    private static void writeAll(int descriptor, byte[] bytes, int count, String label) {
        int offset = 0;
        Memory buffer = new Memory(Math.max(1, Math.min(count, 8192)));
        while (offset < count) {
            int amount = Math.min(count - offset, 8192);
            buffer.write(0L, bytes, offset, amount);
            int written = 0;
            while (written < amount) {
                long result = write(
                    descriptor,
                    buffer.share(written),
                    new NativeLong(amount - written)
                ).longValue();
                if (result > 0L && result <= amount - written) {
                    written += (int) result;
                    continue;
                }
                int error = result < 0L ? Native.getLastError() : 0;
                if (result < 0L && error == EINTR) {
                    continue;
                }
                throw fail(label + " anonymous write failed with errno " + error);
            }
            offset += amount;
        }
    }

    private static void addRequiredSeals(int descriptor, String label) {
        int seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
        while (true) {
            if (fcntl(descriptor, F_ADD_SEALS, seals) >= 0) {
                break;
            }
            int error = Native.getLastError();
            if (error != EINTR) {
                throw fail(label + " could not be sealed: errno " + error);
            }
        }
        int observed = fcntl(descriptor, F_GET_SEALS, 0);
        if (observed < 0 || (observed & seals) != seals) {
            throw fail(label + " did not retain all required write seals");
        }
    }

    private static Identity readIdentity(int descriptor, long maximumBytes, String label) {
        byte[] bytes = readRetainedBytes(descriptor, maximumBytes, label);
        return new Identity(bytes.length, hex(sha256Digest().digest(bytes)));
    }

    private static byte[] readRetainedBytes(int descriptor, long maximumBytes, String label) {
        if (maximumBytes <= 0L || maximumBytes > Integer.MAX_VALUE) {
            throw fail(label + " has an unsupported read bound");
        }
        Path capability = Path.of(descriptorPath(descriptor));
        try {
            Object links = Files.getAttribute(capability, "unix:nlink");
            if (!(links instanceof Number) || ((Number) links).longValue() != 0L) {
                throw fail(label + " is not an unlinked retained identity");
            }
            ByteArrayOutputStream output = new ByteArrayOutputStream(
                (int) Math.min(maximumBytes, PROCESS_BUFFER_BYTES)
            );
            try (InputStream input = Files.newInputStream(capability, StandardOpenOption.READ)) {
                byte[] buffer = new byte[8192];
                while (true) {
                    int count = input.read(buffer);
                    if (count < 0) {
                        break;
                    }
                    if (count == 0) {
                        continue;
                    }
                    if ((long) output.size() + count > maximumBytes) {
                        throw fail(label + " exceeds its byte bound");
                    }
                    output.write(buffer, 0, count);
                }
            }
            return output.toByteArray();
        } catch (LlvmBehaviorHostedCleanBuildV2Exception failure) {
            throw failure;
        } catch (Exception failure) {
            throw fail(label + " retained bytes are unavailable", failure);
        }
    }

    private static int openRetry(String path, int flags, String label) {
        while (true) {
            int descriptor = open(path, flags);
            if (descriptor >= 0) {
                return descriptor;
            }
            int error = Native.getLastError();
            if (error != EINTR) {
                throw fail(label + " open failed with errno " + error);
            }
        }
    }

    private static int duplicateAboveStdio(int descriptor, String label) {
        while (true) {
            int duplicated = fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
            if (duplicated >= 3) {
                return duplicated;
            }
            int error = Native.getLastError();
            if (error != EINTR) {
                throw fail(label + " could not move its pinned descriptor above stdio: errno " + error);
            }
        }
    }

    private static int pidfdOpen(int pid, long deadline, String label) {
        while (true) {
            requireDeadline(deadline, label, false);
            int descriptor = pidfd_open(pid, 0);
            if (descriptor >= 0) {
                return descriptor;
            }
            int error = Native.getLastError();
            if (error != EINTR) {
                throw fail(label + " could not pin its process with pidfd: errno " + error);
            }
        }
    }

    private static void requirePlatformAndPidfd(String label) {
        requirePlatform(label);
        int probe = pidfd_open(getpid(), 0);
        if (probe < 0) {
            throw fail(label + " requires pidfd process ownership: errno " + Native.getLastError());
        }
        try {
            int result = pidfd_send_signal(probe, 0, null, 0);
            if (result != 0) {
                throw fail(label + " pidfd ownership probe failed with errno " + Native.getLastError());
            }
            Memory information = new Memory(SIGINFO_BYTES);
            information.clear();
            int waitResult = waitid(P_PIDFD, probe, information, WEXITED | WNOHANG | WNOWAIT);
            int waitError = waitResult != 0 ? Native.getLastError() : 0;
            if (waitResult != -1 || waitError != ECHILD) {
                throw fail(
                    label + " requires waitid P_PIDFD WNOWAIT ownership proof"
                        + " (result=" + waitResult + ", errno=" + waitError + ")"
                );
            }
        } finally {
            close(probe);
        }
    }

    private static void requirePlatform(String label) {
        String os = System.getProperty("os.name", "");
        String architecture = System.getProperty("os.arch", "");
        if (!"Linux".equals(os)
            || !("amd64".equals(architecture) || "x86_64".equals(architecture))
            || Native.POINTER_SIZE != Long.BYTES
            || NativeLong.SIZE != Long.BYTES
            || !Files.isDirectory(Path.of("/proc/self/fd"))) {
            throw fail(label + " retained execution requires Linux x86-64 glibc procfs");
        }
    }

    private static void requireSigchldWaitable(String label) {
        Memory action = new Memory(SIGACTION_BYTES_X86_64_GLIBC);
        action.clear();
        int result = sigaction(SIGCHLD, null, action);
        if (result != 0) {
            throw fail(label + " could not inspect SIGCHLD disposition: errno " + Native.getLastError());
        }
        long handler = Pointer.nativeValue(action.getPointer(SIGACTION_HANDLER_OFFSET));
        int flags = action.getInt(SIGACTION_FLAGS_OFFSET);
        if (handler != SIG_DFL || (flags & SA_NOCLDWAIT) != 0) {
            throw fail(label + " requires default waitable SIGCHLD disposition");
        }
    }

    private static void requireNativeVector(
        List<String> arguments,
        Map<String, String> environment,
        Duration timeout,
        int maximumOutputBytes,
        Duration cleanupTimeout,
        String label
    ) {
        Objects.requireNonNull(timeout, "timeout");
        Objects.requireNonNull(cleanupTimeout, "cleanupTimeout");
        if (arguments.isEmpty() || arguments.size() > MAXIMUM_ARGUMENTS) {
            throw fail(label + " argv is outside its count bound");
        }
        long argumentBytes = 0L;
        for (String argument : arguments) {
            Objects.requireNonNull(argument, "argument");
            int bytes = utf8Length(argument);
            if (argument.isEmpty() || argument.indexOf('\0') >= 0 || bytes > MAXIMUM_NATIVE_STRING_BYTES) {
                throw fail(label + " argv contains an invalid native string");
            }
            argumentBytes = Math.addExact(argumentBytes, bytes + 1L);
        }
        if (argumentBytes > MAXIMUM_ARGUMENT_BYTES) {
            throw fail(label + " argv exceeds its aggregate byte bound");
        }
        if (environment.size() > MAXIMUM_ENVIRONMENT_BINDINGS) {
            throw fail(label + " environment exceeds its binding bound");
        }
        long environmentBytes = 0L;
        for (Map.Entry<String, String> entry : environment.entrySet()) {
            String name = Objects.requireNonNull(entry.getKey(), "environment name");
            String value = Objects.requireNonNull(entry.getValue(), "environment value");
            if (!ENVIRONMENT_NAME.matcher(name).matches()
                || name.startsWith("LD_")
                || FORBIDDEN_ENVIRONMENT_NAMES.contains(name)
                || value.indexOf('\0') >= 0) {
                throw fail(label + " environment is not closed and deterministic");
            }
            int nameBytes = utf8Length(name);
            int valueBytes = utf8Length(value);
            if (nameBytes > MAXIMUM_NATIVE_STRING_BYTES || valueBytes > MAXIMUM_NATIVE_STRING_BYTES) {
                throw fail(label + " environment contains an oversized native string");
            }
            environmentBytes = Math.addExact(environmentBytes, nameBytes + valueBytes + 2L);
        }
        if (environmentBytes > MAXIMUM_ENVIRONMENT_BYTES) {
            throw fail(label + " environment exceeds its aggregate byte bound");
        }
        if (timeout.isZero() || timeout.isNegative() || timeout.compareTo(MAXIMUM_COMMAND_TIMEOUT) > 0
            || cleanupTimeout.isZero() || cleanupTimeout.isNegative()
            || cleanupTimeout.compareTo(MAXIMUM_CLEANUP_TIMEOUT) > 0
            || maximumOutputBytes < 0 || maximumOutputBytes > MAXIMUM_COMMAND_OUTPUT_BYTES) {
            throw fail(label + " runtime or capture bound is invalid");
        }
    }

    private static void requireRoleArguments(Role role, List<String> arguments, String label) {
        if (!arguments.getFirst().equals(role.argumentZero)) {
            throw fail(label + " lost its fixed logical argv[0]");
        }
        for (int index = 1; index < arguments.size(); index++) {
            String argument = arguments.get(index);
            if ("-###".equals(argument) || argument.startsWith("@")) {
                throw fail(label + " contains shell-text or implicit tool-selection syntax");
            }
            if (role == Role.LLD
                && ("-L".equals(argument)
                    || argument.startsWith("-L")
                    || (argument.startsWith("-l") && argument.length() > 2))) {
                throw fail(label + " contains implicit LLD library resolution syntax");
            }
        }
    }

    private static long deadlineAfter(Duration duration, String label) {
        try {
            return Math.addExact(System.nanoTime(), duration.toNanos());
        } catch (ArithmeticException failure) {
            throw fail(label + " duration exceeds the monotonic deadline range", failure);
        }
    }

    private static void requireDeadline(long deadline, String label, boolean cleanup) {
        if (System.nanoTime() >= deadline) {
            throw fail(cleanup ? label + " cleanup exceeded its deadline" : label + " exceeded its deadline");
        }
    }

    private static BasicFileAttributes readAttributes(Path path, String label) {
        try {
            return Files.readAttributes(path, BasicFileAttributes.class);
        } catch (Exception failure) {
            throw fail(label + " attributes are unavailable", failure);
        }
    }

    private static void syscallZero(String label, String operation, IntSupplier invocation) {
        while (true) {
            int result = invocation.getAsInt();
            if (result == 0) {
                return;
            }
            int error = Native.getLastError();
            if (error != EINTR) {
                throw fail(label + " " + operation + " failed with errno " + error);
            }
        }
    }

    private static void nativeResult(String operation, int result) {
        if (result != 0) {
            throw fail(operation + " failed with errno " + result);
        }
    }

    private static void closeFd(int descriptor) {
        if (descriptor >= 0) {
            close(descriptor);
        }
    }

    private static String descriptorPath(int descriptor) {
        return "/proc/" + PARENT_PID + "/fd/" + descriptor;
    }

    private static int utf8Length(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (Exception failure) {
            throw new AssertionError("SHA-256 is unavailable", failure);
        }
    }

    private static String hex(byte[] bytes) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] encoded = new char[bytes.length * 2];
        for (int index = 0; index < bytes.length; index++) {
            int value = bytes[index] & 0xff;
            encoded[index * 2] = digits[value >>> 4];
            encoded[index * 2 + 1] = digits[value & 0x0f];
        }
        return new String(encoded);
    }

    private static String zeroSha256() {
        return "0".repeat(64);
    }

    private static void requireSha256(String value, String label) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw fail(label + " has an invalid SHA-256 identity");
        }
    }

    private static void requireLabel(String label) {
        if (label == null || label.isEmpty() || label.indexOf('\0') >= 0 || utf8Length(label) > 1024) {
            throw new IllegalArgumentException("hosted native label is invalid");
        }
    }

    private static boolean waitExited(int status) {
        return (status & 0x7f) == 0;
    }

    private static int waitExitStatus(int status) {
        return (status >>> 8) & 0xff;
    }

    private static boolean waitSignaled(int status) {
        int signal = status & 0x7f;
        return signal >= 1 && signal <= 0x7e;
    }

    private static int waitTermSignal(int status) {
        return status & 0x7f;
    }

    private static LlvmBehaviorHostedCleanBuildV2Exception fail(String message) {
        return new LlvmBehaviorHostedCleanBuildV2Exception(message, null);
    }

    private static LlvmBehaviorHostedCleanBuildV2Exception fail(String message, Throwable cause) {
        return new LlvmBehaviorHostedCleanBuildV2Exception(message, cause);
    }

    private static RuntimeException propagate(Throwable failure, String message) {
        if (failure instanceof RuntimeException runtime) {
            return runtime;
        }
        if (failure instanceof Error error) {
            throw error;
        }
        return fail(message, failure);
    }

    private static native int memfd_create(String name, int flags);
    private static native int open(String path, int flags);
    private static native int close(int descriptor);
    private static native NativeLong read(int descriptor, Pointer buffer, NativeLong count);
    private static native NativeLong write(int descriptor, Pointer buffer, NativeLong count);
    private static native int fsync(int descriptor);
    private static native int fchmod(int descriptor, int mode);
    private static native int fcntl(int descriptor, int command, int argument);
    private static native NativeLong lseek(int descriptor, NativeLong offset, int whence);
    private static native int pipe2(Pointer descriptors, int flags);
    private static native int poll(Pointer descriptors, NativeLong count, int timeoutMilliseconds);
    private static native int kill(int pid, int signal);
    private static native int waitpid(int pid, Pointer status, int options);
    private static native int waitid(int idType, int id, Pointer information, int options);
    private static native int getpid();
    private static native int getpgid(int pid);
    private static native int getsid(int pid);
    private static native int pidfd_open(int pid, int flags);
    private static native int pidfd_send_signal(int pidfd, int signal, Pointer information, int flags);
    private static native int sigaction(int signal, Pointer action, Pointer previousAction);
    private static native int sigfillset(Pointer set);
    private static native int sigemptyset(Pointer set);
    private static native int sigdelset(Pointer set, int signal);
    private static native int posix_spawnattr_init(Pointer attributes);
    private static native int posix_spawnattr_destroy(Pointer attributes);
    private static native int posix_spawnattr_setflags(Pointer attributes, short flags);
    private static native int posix_spawnattr_setsigdefault(Pointer attributes, Pointer signals);
    private static native int posix_spawnattr_setsigmask(Pointer attributes, Pointer signals);
    private static native int posix_spawn_file_actions_init(Pointer actions);
    private static native int posix_spawn_file_actions_destroy(Pointer actions);
    private static native int posix_spawn_file_actions_adddup2(Pointer actions, int descriptor, int target);
    private static native int posix_spawn_file_actions_addclose(Pointer actions, int descriptor);
    private static native int posix_spawn_file_actions_addclosefrom_np(Pointer actions, int firstDescriptor);
    private static native int posix_spawn_file_actions_addfchdir_np(Pointer actions, int descriptor);
    private static native int posix_spawn(
        Pointer pid,
        String path,
        Pointer actions,
        Pointer attributes,
        Pointer arguments,
        Pointer environment
    );
}

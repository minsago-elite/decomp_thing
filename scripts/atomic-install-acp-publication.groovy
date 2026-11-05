// Build-only publication engine. Callbacks keep Gradle's compiler environment and
// existing ELF/protocol validator; inert controls never execute native binaries.
import java.nio.file.*
import java.nio.file.attribute.*
import java.nio.channels.*
import java.security.MessageDigest

class AcpPublication {
    static final List FLAGS = ['-std=c11', '-O2', '-static', '-Wall', '-Wextra', '-Werror', '-Wl,--build-id=none']
    static final long MAX = 4L * 1024 * 1024
    static final def MODE = PosixFilePermissions.fromString('rwxr-xr-x')
    static void need(boolean ok, String message) { if (!ok) throw new IOException(message) }
    static Map attrs(Path p) {
        def a = Files.readAttributes(p, 'unix:dev,ino,mode,size,lastModifiedTime,ctime', LinkOption.NOFOLLOW_LINKS)
        need(((a.mode as int) & 0170000) == 0100000, "ACP nonregular file: $p")
        a
    }
    static Map parents(Path p) {
        def result = [:]
        for (Path q = p.parent; q != null; q = q.parent) {
            def a = Files.readAttributes(q, BasicFileAttributes, LinkOption.NOFOLLOW_LINKS)
            need(a.isDirectory() && !a.isSymbolicLink(), "ACP unsafe parent: $q")
            result[q.toString()] = [a.fileKey().toString(), Files.getPosixFilePermissions(q, LinkOption.NOFOLLOW_LINKS)]
        }
        result
    }
    // The first Throwable owns all later failures directly, including failures from
    // nested cleanup scopes. These are namespace observations, not channel fstat.
    static Throwable addFailure(Throwable first, Throwable next) {
        if (first == null) return next
        if (!first.is(next)) {
            first.addSuppressed(next)
            next.suppressed.each { later -> addFailure(first, later) }
        }
        first
    }
    static Throwable cleanup(Throwable first, List actions) {
        actions.each { action ->
            try { action.call() } catch (Throwable failure) { first = addFailure(first, failure) }
        }
        first
    }
    static def withParent(Path p, Closure action) {
        need(p.isAbsolute() && p.normalize() == p && p.nameCount <= 128, 'ACP noncanonical/deep path')
        def streams = []
        Throwable failure = null
        def result
        try {
            def stream = Files.newDirectoryStream(p.root)
            streams.add(stream)
            need(stream instanceof SecureDirectoryStream, 'ACP secure directory traversal unavailable')
            for (Path part : p.parent) {
                stream = stream.newDirectoryStream(part, LinkOption.NOFOLLOW_LINKS)
                streams.add(stream)
            }
            result = action.call(stream)
        } catch (Throwable problem) { failure = problem }
        failure = cleanup(failure, streams.reverse().collect { stream -> { -> stream.close() } })
        if (failure != null) throw failure
        result
    }
    static Path lockPath(Path output) {
        // Never configurable by scratch; never removed by any supported producer.
        output.resolveSibling('.' + output.fileName.toString() + '.publication.lock')
    }
    static def withOutputLock(Path output, Closure action) {
        Path path = lockPath(output)
        def prior = Files.exists(path, LinkOption.NOFOLLOW_LINKS) ? attrs(path) : null
        def channel = null
        def lock = null
        Throwable failure = null
        def result
        boolean interrupted = false
        try {
            withParent(path) { directory ->
                // Register ownership BEFORE traversal close/type/identity can fail.
                channel = directory.newByteChannel(path.fileName,
                    [StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE,
                     LinkOption.NOFOLLOW_LINKS] as Set,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString('rw-------')))
            }
            need(channel instanceof FileChannel, 'ACP lock channel unavailable')
            def identity = attrs(path)
            need(prior == null || prior == identity, 'ACP producer lock exchanged while opening')
            need(identity.size == 0 && ((identity.mode as int) & 07777) == 0600, 'ACP unsafe producer lock')
            try { lock = channel.tryLock() } catch (OverlappingFileLockException ignored) { }
            need(lock != null, 'ACP producer lock is already held')
            result = action.call({ need(identity == attrs(path), 'ACP producer lock identity exchanged') })
        } catch (Throwable problem) {
            failure = problem
            interrupted = problem instanceof InterruptedException
        }
        interrupted = Thread.interrupted() || interrupted
        failure = cleanup(failure, [{ if (lock != null) lock.release() }, { if (channel != null) channel.close() }])
        if (interrupted || failure instanceof InterruptedException || failure?.suppressed?.any { it instanceof InterruptedException })
            Thread.currentThread().interrupt()
        if (failure != null) throw failure
        result
    }
    def consume(Path path, Map expected, Closure action) {
        Path output = path.toAbsolutePath().normalize()
        withOutputLock(output) { assertLock ->
            def observed = read(output, 64, MAX)
            need(observed.receipt == expected, 'ACP consumer generation differs from producer')
            def result = action.call(observed)
            same(output, observed)
            assertLock()
            result
        }
    }
    // The caller's ELF checks precede this pathname launch. Stable build ownership
    // is required; this does not authenticate the executable inode used by exec.
    int validateProcess(Path helper, Closure checkIdentity, Closure launch = { Path p ->
        def builder = new ProcessBuilder(p.toString())
        builder.environment().clear()
        builder.start()
    }) {
        Process process = null
        def streams = []
        Throwable failure = null
        boolean interrupted = false
        try {
            process = launch.call(helper)
            failure = cleanup(null, [{ streams.add(process.outputStream) },
                { streams.add(process.inputStream) }, { streams.add(process.errorStream) }])
            if (failure != null) throw failure
            streams[0].close()
            need(process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) && process.exitValue() == 120,
                'ACP gate helper did not fail closed on a missing protocol invocation')
            checkIdentity.call()
        } catch (Throwable problem) {
            failure = problem
            interrupted = problem instanceof InterruptedException
        }
        interrupted = Thread.interrupted() || interrupted
        if (process != null) {
            // Attempt reaping even if destroy fails; close every acquired stream.
            failure = cleanup(failure, [
                { if (process.isAlive()) process.destroyForcibly() },
                {
                    long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(2)
                    boolean reaped = false
                    Throwable reapFailure = null
                    while (!reaped && System.nanoTime() < deadline) {
                        try { reaped = process.waitFor(Math.max(1L, deadline - System.nanoTime()), java.util.concurrent.TimeUnit.NANOSECONDS) }
                        catch (InterruptedException problem) {
                            interrupted = true
                            reapFailure = addFailure(reapFailure, problem)
                            Thread.interrupted()
                        }
                    }
                    if (!reaped) reapFailure = addFailure(reapFailure, new IOException('ACP validation probe did not reap'))
                    if (reapFailure != null) throw reapFailure
                }
            ])
        }
        failure = cleanup(failure, streams.reverse().collect { stream -> { -> stream.close() } })
        if (interrupted || failure instanceof InterruptedException || failure?.suppressed?.any { it instanceof InterruptedException })
            Thread.currentThread().interrupt()
        if (failure != null) throw failure
        120
    }
    static Map read(Path p, long minimum = 0, long maximum = 512L * 1024 * 1024) {
        def chain = parents(p)
        def before = attrs(p)
        need(before.size >= minimum && before.size <= maximum, "ACP file size bound: $p")
        byte[] bytes
        withParent(p) { directory ->
          def view = directory.getFileAttributeView(p.fileName, PosixFileAttributeView, LinkOption.NOFOLLOW_LINKS)
          def opened = view.readAttributes()
          need(opened.isRegularFile() && opened.fileKey() == Files.readAttributes(p, BasicFileAttributes, LinkOption.NOFOLLOW_LINKS).fileKey(),
               'ACP observed leaf identity differs')
          directory.newByteChannel(p.fileName, [StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS] as Set).withCloseable { channel ->
            need(channel.size() == before.size, 'ACP opened size changed')
            def buffer = java.nio.ByteBuffer.allocate((before.size as int) + 1)
            while (buffer.hasRemaining() && channel.read(buffer) != -1) { }
            need(buffer.position() == before.size && channel.size() == before.size, 'ACP bounded read changed')
            bytes = Arrays.copyOf(buffer.array(), before.size as int)
          }
          def after = view.readAttributes()
          need(opened.fileKey() == after.fileKey() && opened.size() == after.size() &&
               opened.lastModifiedTime() == after.lastModifiedTime() && opened.permissions() == after.permissions(),
               'ACP observed pathname identity changed')
        }
        need(before == attrs(p) && chain == parents(p), 'ACP identity changed during read')
        [bytes: bytes, identity: before, receipt: [type: 'file', bytes: bytes.length,
            sha256: HexFormat.of().formatHex(MessageDigest.getInstance('SHA-256').digest(bytes)),
            mode: (before.mode as int) & 07777, key: [before.dev, before.ino]]]
    }
    static void same(Path p, Map snapshot) {
        need(read(p).identity == snapshot.identity, "ACP identity exchanged: $p")
    }
    static void force(Path p, boolean directory = false) {
        withParent(p) { parent ->
            parent.newByteChannel(p.fileName, directory ? [StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS] as Set :
                [StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS] as Set).withCloseable { channel ->
                    need(channel instanceof FileChannel, 'ACP force channel unavailable')
                    channel.force(true)
                }
        }
    }
    static long now() { def t = java.time.Instant.now(); t.epochSecond * 1000000000L + t.nano }
    Map publish(Map config) {
        need(config.flags == FLAGS, 'ACP compiler flags differ')
        Path output = config.output.toAbsolutePath().normalize()
        Path scratchRoot = config.scratch.toAbsolutePath().normalize()
        // Parent creation belongs to the trusted build configuration. Inspect both
        // before and after creation so a preexisting symlink is never accepted.
        [output.parent, scratchRoot].each { p ->
            Path existing = p
            while (!Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) existing = existing.parent
            parents(existing.resolve('check'))
            Files.createDirectories(p, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString('rwx------')))
            parents(p.resolve('check'))
        }
        need(!scratchRoot.startsWith(output.parent), 'ACP scratch overlaps published root')
        need(Files.getFileStore(output.parent) == Files.getFileStore(scratchRoot), 'ACP staging crosses filesystem')
        def chain = parents(output)
        def scratchChain = parents(scratchRoot.resolve('check'))
        Path staging = null
        def stageIdentity = null
        def owned = [:]
        Throwable primary = null
        String phase = 'lock'
        def receipt = [schemaVersion: 2, publicationScope: 'cooperative-build-producer-v1',
                       bindingEvidence: 'stable-namespace-path-observations-v1',
                       startedAtUnixNs: now(), output: output.toString(),
                       flags: config.flags, exitCode: null, cleanup: false]
        withOutputLock(output) { assertLock ->
          try {
            def assertParents = {
                need(chain == parents(output) && scratchChain == parents(scratchRoot.resolve('check')),
                     'ACP parent identity exchanged')
                assertLock()
            }
            assertParents()
            def pins = [:]
            ['compiler', 'source', 'recipe', 'publication'].each { name ->
                Path path = config[name].toAbsolutePath().normalize()
                pins[name] = read(path)
                receipt[name] = [path: path.toString(), file: pins[name].receipt]
            }
            need((pins.compiler.receipt.mode & 0111) != 0 && Files.isExecutable(config.compiler), 'ACP compiler not executable')
            def old = Files.exists(output, LinkOption.NOFOLLOW_LINKS) ? read(output, 64, MAX) : null
            staging = Files.createTempDirectory(scratchRoot, 'invocation-',
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString('rwx------')))
            stageIdentity = parents(staging.resolve('check'))
            Path candidate = staging.resolve(output.fileName)
            receipt.candidatePath = candidate.toString()
            receipt.arguments = [config.compiler.toString(), *config.flags, config.source.toString(), '-o', candidate.toString()]
            receipt.compileStartedAtUnixNs = now()
            phase = 'compile'
            // The candidate is the only compiler output owned by this invocation.
            // Record its observed identity even on partial compiler failure.
            Throwable compileFailure = null
            try { receipt.exitCode = config.compile.call(receipt.arguments) }
            catch (Throwable problem) { compileFailure = problem }
            compileFailure = cleanup(compileFailure, [{
                need(stageIdentity == parents(candidate), 'ACP staging directory exchanged')
                if (Files.exists(candidate, LinkOption.NOFOLLOW_LINKS))
                    owned[candidate] = Files.readAttributes(candidate, 'unix:dev,ino,mode,size,lastModifiedTime,ctime', LinkOption.NOFOLLOW_LINKS)
            }])
            if (compileFailure != null) throw compileFailure
            receipt.compileFinishedAtUnixNs = now()
            need(receipt.exitCode == 0, 'ACP fresh compilation failed')
            def fresh = read(candidate, 64, MAX)
            same(candidate, fresh)
            Files.getFileAttributeView(candidate, PosixFileAttributeView, LinkOption.NOFOLLOW_LINKS).setPermissions(MODE)
            fresh = read(candidate, 64, MAX)
            owned[candidate] = fresh.identity
            phase = 'candidate-validation'
            receipt.candidateValidationExitCode = config.validate.call(candidate)
            need(receipt.candidateValidationExitCode == 120, 'ACP candidate fail-closed probe differs')
            same(candidate, fresh)
            phase = 'candidate-force'
            (config.force ?: { Path p, boolean directory -> force(p, directory) }).call(candidate, false)
            same(candidate, fresh)
            pins.each { name, value -> same(config[name], value) }
            need(stageIdentity == parents(candidate), 'ACP staging directory exchanged')
            assertParents()
            if (old != null) same(output, old)
            else need(!Files.exists(output, LinkOption.NOFOLLOW_LINKS), 'ACP final appeared concurrently')
            receipt.candidate = fresh.receipt
            receipt.previous = old?.receipt
            if (old != null && old.receipt.mode == 0755 && Arrays.equals(old.bytes, fresh.bytes)) {
                phase = 'final-validation'
                receipt.finalValidationExitCode = config.validate.call(output)
                need(receipt.finalValidationExitCode == 120, 'ACP final fail-closed probe differs')
                same(output, old)
                same(candidate, fresh)
                receipt.outcome = 'retained'
            } else {
                // No copy fallback. An old executable never excuses failed compilation.
                phase = 'atomic-move'
                (config.move ?: { Path a, Path b -> Files.move(a, b, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING) }).call(candidate, output)
                owned.remove(candidate)
                phase = 'parent-force-after-rename'
                (config.force ?: { Path p, boolean directory -> force(p, directory) }).call(output.parent, true)
                receipt.outcome = 'replaced'
                phase = 'final-validation'
                receipt.finalValidationExitCode = config.validate.call(output)
                need(receipt.finalValidationExitCode == 120, 'ACP final fail-closed probe differs')
            }
            assertParents()
            def published = read(output, 64, MAX)
            need(published.receipt == (receipt.outcome == 'retained' ? old.receipt : fresh.receipt), 'ACP published identity differs')
            receipt.final = published.receipt
            receipt.finishedAtUnixNs = now()
          } catch (Throwable failure) {
            primary = failure
            // Preserve the original Throwable; post-rename uncertainty is failure.
            if (phase in ['atomic-move', 'parent-force-after-rename', 'final-validation'])
                failure.addSuppressed(new IOException('ACP publication phase: ' + phase))
          } finally {
            boolean interrupted = Thread.interrupted() || primary instanceof InterruptedException
            primary = cleanup(primary, [{
                if (staging != null) {
                    need(stageIdentity == parents(staging.resolve('check')), 'ACP cleanup ancestor exchanged')
                    def items = []
                    withParent(staging.resolve('check')) { stream ->
                        for (Path item : stream) {
                            need(items.size() < 16, 'ACP cleanup entry bound')
                            items.add(staging.resolve(item.fileName))
                        }
                    }
                    // Inspect the whole bounded set before deleting anything. Unknown
                    // children and changed identities stay available for diagnosis.
                    items.each { item ->
                        need(owned.containsKey(item), 'ACP unexpected cleanup entry')
                        need(!Files.isDirectory(item, LinkOption.NOFOLLOW_LINKS), 'ACP unexpected cleanup directory')
                        need(owned[item] == Files.readAttributes(item, 'unix:dev,ino,mode,size,lastModifiedTime,ctime', LinkOption.NOFOLLOW_LINKS),
                            'ACP cleanup child identity changed')
                    }
                    def actions = items.reverse().collect { item -> { -> Files.delete(item) } }
                    if (config.cleanup != null) actions.add(config.cleanup)
                    actions.add({ Files.delete(staging) })
                    def failure = cleanup(null, actions)
                    if (failure != null) throw failure
                }
            }])
            if (interrupted) Thread.currentThread().interrupt()
          }
          if (primary != null) {
              if (receipt.outcome == 'replaced') primary.addSuppressed(new IOException('ACP publication phase: cleanup-after-rename'))
              throw primary
          }
          // All filesystem cleanup and receipt observations finish under ownership.
        }
        // No receipt escapes if release/channel/traversal cleanup failed. Record
        // completion only after these last releases have actually succeeded.
        receipt.cleanup = true
        receipt.cleanupFinishedAtUnixNs = now()
        receipt
    }
}
return new AcpPublication()

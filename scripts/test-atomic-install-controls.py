#!/usr/bin/env python3
"""Inert driver controls; --gradle-writers adds only the publisher task, never product compilation."""
import importlib.util, json, os, pathlib, shlex, signal, subprocess, sys, tempfile, time, unittest.mock, zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("atomic_driver", ROOT / "scripts/test-atomic-install.py")
driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
PYTHON = os.environ.get("ATOMIC_CONTROL_PYTHON", "/usr/bin/python3.14" if pathlib.Path("/usr/bin/python3.14").exists() else sys.executable)
BASE = ROOT / "build/orchestration/atomic-install-remediation"
if "ATOMIC_CONTROL_EVIDENCE_ROOT" in os.environ:
    BASE = pathlib.Path(os.environ["ATOMIC_CONTROL_EVIDENCE_ROOT"]).resolve(strict=True)
    if not BASE.is_relative_to(ROOT): raise RuntimeError('control evidence must stay inside repository')
BASE.mkdir(parents=True, exist_ok=True)
WORK = pathlib.Path(tempfile.mkdtemp(prefix="driver-controls-", dir=BASE))
driver.WORK = WORK
driver.INIT = WORK / "atomic-install.init.gradle"
for path in (WORK / "tmp", WORK / "home", WORK / "barriers", driver.install_root() / "bin", driver.install_root() / "lib"):
    path.mkdir(parents=True, exist_ok=True)
passed = []


def check_failure(name, action, expected):
    try: action()
    except expected: pass
    else: raise AssertionError(name + " did not fail")
    assert not driver.ACTIVE, name + " leaked an owned child"
    passed.append(name)


def check_dead(pid):
    # A child process started with this launcher must have been reaped, not merely signaled.
    try: os.waitpid(pid, os.WNOHANG)
    except ChildProcessError: return
    raise AssertionError("child is still waitable")


def wait_file(path, child, timeout=90):
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        if child.process.poll() is not None: raise AssertionError(child.text())
        time.sleep(.05)
    assert path.exists(), str(path)



def acp_publication_controls():
    """Run the actual build-only publisher with inert compiler/validator callbacks."""
    java = pathlib.Path(os.environ['ACP_CONTROL_JAVA']) if 'ACP_CONTROL_JAVA' in os.environ else driver.qualified_java_home() / 'bin/java'
    jars = os.environ.get('ACP_CONTROL_GROOVY_CLASSPATH')
    if not jars:
        import re
        wrapper = (ROOT / 'gradle/wrapper/gradle-wrapper.properties').read_text()
        version = re.search(r'gradle-([0-9.]+)-bin\.zip', wrapper).group(1)
        caches = [pathlib.Path(os.environ.get('GRADLE_USER_HOME', ROOT / 'build/.gradle-user-home')), pathlib.Path.home() / '.gradle']
        found = sorted({p for cache in caches for p in cache.glob(f'wrapper/dists/gradle-{version}-bin/*/gradle-{version}/lib/groovy-[0-9]*.jar')})
        if not found: raise RuntimeError('set ACP_CONTROL_GROOVY_CLASSPATH to the pinned Gradle Groovy JAR')
        jars = str(found[-1])
    script = WORK / 'acp-publication-controls.groovy'
    script.write_text(ACP_PUBLICATION_CONTROLS)
    code, result = driver.run([java, '-XX:-UsePerfData', '-Djava.io.tmpdir=' + str(WORK / 'tmp'),
        '-cp', jars, 'groovy.ui.GroovyMain', script, ROOT / 'scripts/atomic-install-acp-publication.groovy',
        WORK / 'root-build/acp-inert', PYTHON], log=WORK / 'acp-publication-controls.log', timeout=120)
    assert code == 0, result
    resources = WORK / 'acp-resource-controls.groovy'
    resources.write_text(ACP_RESOURCE_CONTROLS)
    code, result = driver.run([java, '-XX:-UsePerfData', '-Djava.io.tmpdir=' + str(WORK / 'tmp'),
        '-cp', jars, 'groovy.ui.GroovyMain', resources, ROOT / 'scripts/atomic-install-acp-publication.groovy',
        WORK / 'root-build/acp-resources'], log=WORK / 'acp-resource-controls.log', timeout=120)
    assert code == 0, result
    passed.append('ACP-actual-publication-engine-inert-adversarial-controls')


ACP_PUBLICATION_CONTROLS = r'''import java.nio.file.*
import java.nio.file.attribute.*
import java.nio.channels.*
import java.util.concurrent.*

def engine = new GroovyShell().evaluate(new File(args[0]))
def root = Path.of(args[1]); Files.createDirectories(root)
def results = []
def bytes = ('inert candidate data; never executable\n' * 8).bytes
def config = { String name ->
    def base = Files.createDirectory(root.resolve(name))
    def pin = { String leaf -> def p = base.resolve(leaf); Files.write(p, ('inert ' + leaf).bytes); p }
    def cc = pin('compiler'); Files.setPosixFilePermissions(cc, PosixFilePermissions.fromString('rwxr-xr-x'))
    [output: base.resolve('native/acp/helper'), scratch: base.resolve('private'), compiler: cc,
     source: pin('source'), recipe: pin('recipe'), publication: Path.of(args[0]), flags: ['-std=c11', '-O2', '-static', '-Wall', '-Wextra', '-Werror', '-Wl,--build-id=none'],
     compile: { arguments -> Files.write(Path.of(arguments[-1]), bytes, StandardOpenOption.CREATE_NEW); 0 },
     validate: { Path p -> assert Files.size(p) >= 64; 120 }]
}
def failed = { String label, Closure action ->
    try { action(); throw new AssertionError('unexpected success: ' + label) }
    catch (IOException | IllegalStateException | InterruptedException expected) { results << label; Thread.interrupted() }
}
def empty = { cfg ->
    Files.newDirectoryStream(cfg.scratch).withCloseable { stream ->
        assert stream.every { it.fileName.toString().endsWith('.lock') }
    }
}
// Red: direct-final compile simulation unlinks/replaces identical bytes, as the
// original compiler path did. Hold the old descriptor so inode reuse cannot hide it.
def red = config('red'); Files.createDirectories(red.output.parent)
Files.write(red.output, bytes); Files.setPosixFilePermissions(red.output, engine.MODE)
def initial = engine.read(red.output)
FileChannel.open(red.output, StandardOpenOption.READ).withCloseable { held ->
    Files.delete(red.output); Files.write(red.output, bytes); Files.setPosixFilePermissions(red.output, engine.MODE)
    def after = engine.read(red.output)
    assert after.receipt.sha256 == initial.receipt.sha256 && after.receipt.mode == initial.receipt.mode
    assert after.receipt.key != initial.receipt.key
    println('RED direct-final identical bytes/mode change key; strict equality rejects')
}
def green = config('green'); int calls = 0
green.compile = { arguments ->
    calls++
    assert Files.getPosixFilePermissions(Path.of(arguments[-1]).parent) == PosixFilePermissions.fromString('rwx------')
    Files.write(Path.of(arguments[-1]), bytes, StandardOpenOption.CREATE_NEW); 0
}
def first = engine.publish(green); def before = engine.read(green.output)
def second = engine.publish(green)
assert first.schemaVersion == 2 && first.publicationScope == 'cooperative-build-producer-v1' && first.bindingEvidence == 'stable-namespace-path-observations-v1'
assert calls == 2 && first.outcome == 'replaced' && second.outcome == 'retained'
assert engine.read(green.output).identity == before.identity && second.final == first.final && second.cleanup
empty(green); results << 'two-fresh-compiles-retain-identical-byte-mode-inode-and-metadata'
// Full bytes matter, not only length. Compiler/source changes are reflected in
// receipts; changed output is published and the strict replay inventory differs.
['compiler', 'source', 'output'].each { name ->
    def cfg = config('changed-' + name); engine.publish(cfg); def old = engine.read(cfg.output)
    if (name != 'output') Files.write(cfg[name], ('changed ' + name).bytes)
    cfg.compile = { arguments -> Files.write(Path.of(arguments[-1]), ('X' * bytes.length).bytes); 0 }
    def changed = engine.publish(cfg)
    assert changed.outcome == 'replaced' && changed.final != old.receipt
    empty(cfg); results << 'changed-' + name
}
def mode = config('mode'); engine.publish(mode); Files.setPosixFilePermissions(mode.output, PosixFilePermissions.fromString('rw-------'))
def oldMode = engine.read(mode.output); def fixed = engine.publish(mode)
assert fixed.outcome == 'replaced' && fixed.final.mode == 0755 && fixed.final.key != oldMode.receipt.key
results << 'wrong-mode-never-retained'
['failed', 'partial', 'missing', 'oversize', 'symlink', 'validate', 'force', 'move', 'cancel', 'cleanup',
 'identity', 'source-exchange', 'compiler-exchange', 'staging-exchange', 'extra-directory'].each { fault ->
    def cfg = config('failure-' + fault); engine.publish(cfg); def old = engine.read(cfg.output)
    def normal = cfg.compile
    if (fault in ['failed', 'partial', 'missing', 'oversize', 'symlink', 'cancel', 'extra-directory']) {
        cfg.compile = { arguments ->
            Path candidate = Path.of(arguments[-1])
            switch (fault) {
                case 'failed': return 1
                case 'partial': Files.write(candidate, 'partial'.bytes); return 1
                case 'missing': return 0
                case 'oversize':
                    FileChannel.open(candidate, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).withCloseable {
                        it.position(engine.MAX); it.write(java.nio.ByteBuffer.wrap([1] as byte[]))
                    }; return 0
                case 'symlink': Files.createSymbolicLink(candidate, cfg.output); return 0
                case 'cancel': Files.write(candidate, bytes); throw new InterruptedException('cancelled compiler')
                case 'extra-directory': Files.createDirectory(candidate.parent.resolve('unexpected')); return 1
            }
        }
    } else if (fault == 'validate') cfg.validate = { Path p -> throw new IOException('validation failure') }
    else if (fault == 'force') cfg.force = { Path p, boolean dir -> throw new IOException('force failure') }
    else if (fault == 'move') {
        cfg.compile = { arguments -> Files.write(Path.of(arguments[-1]), ('M' * bytes.length).bytes); 0 }
        cfg.move = { Path a, Path b -> throw new AtomicMoveNotSupportedException(a.toString(), b.toString(), 'injected') }
    } else if (fault == 'cleanup') cfg.cleanup = { throw new IOException('cleanup failure') }
    else if (fault in ['source-exchange', 'compiler-exchange']) cfg.validate = { Path p ->
        if (p != cfg.output) { Path pin = cfg[fault.split('-')[0]]; Files.write(pin, 'exchanged'.bytes) }; 120
    }
    else if (fault == 'identity') cfg.validate = { Path p ->
        if (p != cfg.output) { def temp = p.resolveSibling('replacement'); Files.write(temp, bytes); Files.move(temp, p, StandardCopyOption.REPLACE_EXISTING) }; 120
    }
    else if (fault == 'staging-exchange') cfg.validate = { Path p ->
        if (p != cfg.output) { Files.move(p.parent, p.parent.resolveSibling('foreign')); Files.createDirectory(p.parent) }; 120
    }
    failed(fault) { engine.publish(cfg) }
    assert engine.read(cfg.output).identity == old.identity
    if (!(fault in ['cleanup', 'staging-exchange', 'extra-directory', 'identity'])) empty(cfg)
    if (fault == 'identity') assert Files.list(cfg.scratch).withCloseable { it.count() } == 1 // uncertain replacement retained
    if (fault == 'cleanup') { cfg.remove('cleanup'); assert engine.publish(cfg).outcome == 'retained' }
}
['final', 'ancestor', 'lock'].each { kind ->
    def cfg = config('symlink-' + kind); engine.publish(cfg)
    Path target
    if (kind == 'final') { target = cfg.output; Files.delete(target) }
    else if (kind == 'ancestor') { target = cfg.output.parent; Files.move(target, target.resolveSibling('saved')) }
    else { target = engine.lockPath(cfg.output); Files.delete(target) }
    Files.createSymbolicLink(target, Path.of('missing'))
    failed('symlink-' + kind) { engine.publish(cfg) }
}
// Failures after rename are reported; never restore the old executable.
['parent-force', 'final-validation'].each { fault ->
    def cfg = config(fault); engine.publish(cfg); def old = engine.read(cfg.output)
    cfg.compile = { a -> Files.write(Path.of(a[-1]), ('N' * bytes.length).bytes); 0 }
    if (fault == 'parent-force') cfg.force = { Path p, boolean dir ->
        if (dir) throw new IOException('directory force failure')
        engine.force(p, false)
    }
    else cfg.validate = { Path p -> if (p == cfg.output) throw new IOException('final validation failure'); 120 }
    failed(fault) { engine.publish(cfg) }
    assert engine.read(cfg.output).receipt.sha256 != old.receipt.sha256
    empty(cfg)
}
def overflow = config('cleanup-overflow')
overflow.compile = { a ->
    (0..16).each { Files.write(Path.of(a[-1]).parent.resolve('owned-' + it), bytes) }; 1
}
try { engine.publish(overflow); throw new AssertionError('unexpected success') }
catch (IOException ex) { assert ex.message == 'ACP fresh compilation failed'; assert ex.suppressed[0].message == 'ACP cleanup entry bound'; results << 'cleanup-overflow-primary' }
['lock', 'candidate', 'final'].each { kind ->
    def cfg = config('fifo-' + kind); engine.publish(cfg)
    def makeFifo = { Path p ->
        def child = new ProcessBuilder(args[2], '-B', '-c', 'import os,sys; os.mkfifo(sys.argv[1])', p.toString()).start()
        try { assert child.waitFor(5, TimeUnit.SECONDS) && child.exitValue() == 0 }
        finally { if (child.isAlive()) child.destroyForcibly(); assert child.waitFor(2, TimeUnit.SECONDS) }
    }
    if (kind == 'candidate') cfg.compile = { a -> makeFifo(Path.of(a[-1])); 0 }
    else {
        Path path = cfg.output
        if (kind == 'lock') path = engine.lockPath(cfg.output)
        Files.delete(path); makeFifo(path)
    }
    failed('fifo-' + kind) { engine.publish(cfg) }
}
// Stable lock refuses another cooperative producer, then releases on completion.
def concurrent = config('concurrent'); engine.publish(concurrent)
def entered = new CountDownLatch(1); def release = new CountDownLatch(1)
def normal = concurrent.compile
concurrent.compile = { arguments -> entered.countDown(); assert release.await(10, TimeUnit.SECONDS); normal(arguments) }
def pool = Executors.newSingleThreadExecutor()
try {
    def future = pool.submit({ engine.publish(concurrent) } as Callable)
    assert entered.await(10, TimeUnit.SECONDS)
    failed('concurrent-writer-refused') { engine.publish(concurrent) }
    failed('different-scratch-same-output-refused') { engine.publish(concurrent + [scratch: concurrent.scratch.resolveSibling('other-private')]) }
    failed('consumer-during-producer-refused') { engine.consume(concurrent.output, first.final) { throw new AssertionError('consumer entered') } }
    release.countDown(); assert future.get(10, TimeUnit.SECONDS).outcome == 'retained'
    assert engine.publish(concurrent).outcome == 'retained'; empty(concurrent)
    results << 'concurrent-lock-release'
} finally { release.countDown(); pool.shutdownNow(); assert pool.awaitTermination(10, TimeUnit.SECONDS) }
// An independent OS process holds the same POSIX byte-range lock used by
// FileChannel, proving contention is not only the JVM overlapping-lock registry.
def cross = config('cross-process'); engine.publish(cross)
Path crossLock = engine.lockPath(cross.output)
def ready = root.resolve('cross-ready'); def releaseFile = root.resolve('cross-release')
def python = """import fcntl, pathlib, sys, time
with open(sys.argv[1], 'r+b') as lock:
 fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
 pathlib.Path(sys.argv[2]).write_text('ready')
 deadline = time.monotonic() + 10
 while not pathlib.Path(sys.argv[3]).exists():
  if time.monotonic() >= deadline: raise RuntimeError('release timeout')
  time.sleep(.01)
"""
def holder = new ProcessBuilder(args[2], '-B', '-c', python, crossLock.toString(), ready.toString(), releaseFile.toString()).start()
try {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
    while (!Files.exists(ready) && holder.isAlive() && System.nanoTime() < deadline) Thread.sleep(10)
    assert Files.exists(ready)
    failed('cross-process-lock-refusal') { engine.publish(cross) }
    Files.writeString(releaseFile, 'release'); assert holder.waitFor(10, TimeUnit.SECONDS) && holder.exitValue() == 0
    assert engine.publish(cross).outcome == 'retained'; empty(cross)
    results << 'cross-process-lock-release'
} finally { if (holder.isAlive()) holder.destroyForcibly(); assert holder.waitFor(2, TimeUnit.SECONDS) }
def both = config('primary-cleanup'); both.compile = { a -> Files.write(Path.of(a[-1]), bytes); throw new IllegalStateException('primary compile') }
both.cleanup = { throw new IOException('secondary cleanup') }
try { engine.publish(both); throw new AssertionError('missing primary') }
catch (IllegalStateException ex) { assert ex.message == 'primary compile'; assert ex.suppressed*.message == ['secondary cleanup']; results << 'primary-preserved' }
// A consumer uses the same lock and exact producer generation; a later producer
// cannot enter verification/checksum callbacks, and stale observations fail.
engine.consume(green.output, second.final) { observed ->
    assert observed.receipt == second.final
    failed('producer-during-consumer-refused') { engine.publish(green + [scratch: green.scratch.resolveSibling('consumer-other')]) }
}
failed('consumer-stale-generation-refused') { engine.consume(green.output, second.final + [sha256: '0' * 64]) { throw new AssertionError('stale consumer entered') } }
results << 'consumer-generation-and-lock'
// First creation also shares the canonical lock before any candidate exists.
def initialRace = config('first-creation'); def enteredFirst = new CountDownLatch(1); def finishFirst = new CountDownLatch(1)
def initialCompile = initialRace.compile
initialRace.compile = { a -> enteredFirst.countDown(); assert finishFirst.await(10, TimeUnit.SECONDS); initialCompile(a) }
def firstPool = Executors.newSingleThreadExecutor()
try {
    def future = firstPool.submit({ engine.publish(initialRace) } as Callable)
    assert enteredFirst.await(10, TimeUnit.SECONDS)
    assert !Files.exists(initialRace.output)
    failed('first-create-distinct-scratch-refused') { engine.publish(initialRace + [scratch: initialRace.scratch.resolveSibling('second-private')]) }
    finishFirst.countDown(); assert future.get(10, TimeUnit.SECONDS).outcome == 'replaced'
} finally { finishFirst.countDown(); firstPool.shutdownNow(); assert firstPool.awaitTermination(10, TimeUnit.SECONDS) }
// Receipt cleanup remains inside the lock, even after successful publication.
def duringCleanup = config('cleanup-lock')
duringCleanup.cleanup = {
    failed('producer-during-cleanup-refused') { engine.publish(duringCleanup + [scratch: duringCleanup.scratch.resolveSibling('other')]) }
}
assert engine.publish(duringCleanup).cleanup
results << 'cleanup-completion-ownership'
// Two real independent JVM producers contend on first creation and an existing
// final, with different scratch configurations and no native subject execution.
def childScript = root.resolve('cooperative-child.groovy')
Files.writeString(childScript, """import java.nio.file.*
import java.util.concurrent.TimeUnit
 def engine = new GroovyShell().evaluate(new File(args[0]))
 def base = Path.of(args[1]); def ready = base.resolve('child-ready'); def release = base.resolve('child-release')
 def cfg = [output: base.resolve('native/acp/helper'), scratch: base.resolve('child-scratch'),
    compiler: base.resolve('compiler'), source: base.resolve('source'), recipe: base.resolve('recipe'),
    publication: Path.of(args[0]), flags: ['-std=c11','-O2','-static','-Wall','-Wextra','-Werror','-Wl,--build-id=none'],
    compile: { a ->
        Files.writeString(ready, 'ready')
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (!Files.exists(release)) { assert System.nanoTime() < deadline; Thread.sleep(10) }
        Files.write(Path.of(a[-1]), ('inert candidate data; never executable\\n' * 8).bytes); 0
    }, validate: { p -> 120 }]
 assert engine.publish(cfg).cleanup
""")
['first','existing'].each { scenario ->
    def cfg = config('process-' + scenario)
    if (scenario == 'existing') engine.publish(cfg)
    def base = cfg.source.parent
    def readyFile = base.resolve('child-ready'); def releaseChild = base.resolve('child-release')
    def child = new ProcessBuilder(Path.of(System.getProperty('java.home'),'bin/java').toString(),
        '-XX:-UsePerfData', '-Djava.io.tmpdir=' + root.toString(), '-cp', System.getProperty('java.class.path'),
        'groovy.ui.GroovyMain', childScript.toString(), args[0], base.toString())
        .redirectErrorStream(true).redirectOutput(base.resolve('child.log').toFile()).start()
    try {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (!Files.exists(readyFile) && child.isAlive() && System.nanoTime() < deadline) Thread.sleep(10)
        assert Files.exists(readyFile): Files.readString(base.resolve('child.log'))
        failed('two-jvm-' + scenario + '-refused') { engine.publish(cfg) }
        Files.writeString(releaseChild, 'release')
        assert child.waitFor(20, TimeUnit.SECONDS) && child.exitValue() == 0: Files.readString(base.resolve('child.log'))
        assert engine.publish(cfg).outcome == 'retained'
        results << 'two-jvm-' + scenario + '-release'
    } finally {
        if (child.isAlive()) child.destroyForcibly()
        assert child.waitFor(2, TimeUnit.SECONDS)
        child.errorStream.close(); child.inputStream.close(); child.outputStream.close()
    }
}
// Tiny Python children prove the real process/reap path, not native helper ABI.
['success','timeout','interrupt','identity'].each { scenario ->
    Process child = null
    Throwable problem = null
    try {
        engine.validateProcess(root.resolve('inert-probe'), {
            if (scenario == 'identity') throw new IOException('identity-check')
        }, { p ->
            child = new ProcessBuilder(args[2], '-B', '-c', scenario in ['success','identity'] ?
                'import sys; sys.exit(120)' : 'import time; time.sleep(30)').start()
            if (scenario == 'interrupt') Thread.currentThread().interrupt()
            child
        })
    } catch (Throwable failure) { problem = failure }
    assert (problem == null) == (scenario == 'success')
    assert child != null && !child.isAlive()
    assert child.waitFor(1, TimeUnit.SECONDS)
    if (scenario == 'interrupt') assert Thread.interrupted()
    else assert !Thread.interrupted()
    results << 'real-inert-probe-' + scenario + '-reaped'
}
def flagFault = config('flags')
failed('exact-seven-flags-required') { engine.publish(flagFault + [flags: ['-O0']]) }
// Compiler-created unknown regular files, like directories, are not owned
// cleanup targets and must remain intact when the whole bounded set is rejected.
def unknown = config('unknown-regular')
unknown.compile = { a -> Files.write(Path.of(a[-1]), bytes); Files.writeString(Path.of(a[-1]).parent.resolve('foreign'), 'retain-me'); 0 }
failed('unknown-cleanup-entry-refused') { engine.publish(unknown) }
Files.newDirectoryStream(unknown.scratch).withCloseable { ds ->
    assert ds.any { Files.readString(it.resolve('foreign')) == 'retain-me' }
}
// All cleanup attempts run despite earlier deletion/callback failures. The
// compiler cause survives, and each later failure is directly suppressed.
def multiCleanup = config('cleanup-multiple')
Path ownedCandidate
multiCleanup.compile = { a -> ownedCandidate = Path.of(a[-1]); Files.write(ownedCandidate, bytes); throw new IOException('compile-primary') }
multiCleanup.cleanup = { throw new IOException('callback-cleanup') }
def deleteMethod = Files.getMethod('delete',Path)
def deleteAttempts = []
Files.metaClass.static.delete = { Path p ->
    deleteAttempts << p
    if (p == ownedCandidate) throw new IOException('candidate-delete')
    if (p == ownedCandidate?.parent) throw new IOException('directory-delete')
    deleteMethod.invoke(null,p)
}
try {
    try { engine.publish(multiCleanup); throw new AssertionError('cleanup success') }
    catch (IOException problem) {
        assert problem.message == 'compile-primary'
        assert problem.suppressed*.message == ['candidate-delete','callback-cleanup','directory-delete']
        assert deleteAttempts == [ownedCandidate, ownedCandidate.parent]
        assert Files.exists(ownedCandidate)
    }
} finally { GroovySystem.metaClassRegistry.removeMetaClass(Files) }
assert engine.withOutputLock(multiCleanup.output) { true }
results << 'all-owned-cleanup-attempts-directly-suppressed'
println('GREEN ACP inert controls: ' + results.size() + ' ' + results)
'''

ACP_RESOURCE_CONTROLS = r'''import java.nio.file.*
import java.nio.channels.*
import java.nio.ByteBuffer
import java.lang.reflect.*
import java.util.concurrent.TimeUnit

@groovy.transform.CompileStatic
class FaultLock extends FileLock {
    FileLock real; List events; Set faults
    FaultLock(FileChannel channel, FileLock real, List events, Set faults) {
        super(channel, real.position(), real.size(), real.isShared())
        this.real = real; this.events = events; this.faults = faults
    }
    boolean isValid() { real.isValid() }
    void release() { real.release(); events << 'release'; if ('release' in faults) throw new IOException('release') }
}
class FaultChannel extends FileChannel {
    FileChannel real
    List events
    Set faults
    FileLock acquired
    protected void implCloseChannel() { real.close(); events << 'channel'; if ('channel' in faults) throw new IOException('channel') }
    FileLock tryLock(long p, long n, boolean shared) {
        if ('acquire' in faults) throw new IOException('acquire')
        def held = real.tryLock(p, n, shared)
        if (held == null) return null
        acquired = held
        new FaultLock(this, held, events, faults)
    }
    FileLock lock(long p,long n,boolean shared) { throw new AssertionError('blocking lock') }
    int read(ByteBuffer b) { if ('read' in faults) throw new IOException('read'); real.read(b) }
    int read(ByteBuffer b,long p) { real.read(b,p) }
    long read(ByteBuffer[] b,int o,int n) { real.read(b,o,n) }
    int write(ByteBuffer b) { real.write(b) }
    int write(ByteBuffer b,long p) { real.write(b,p) }
    long write(ByteBuffer[] b,int o,int n) { real.write(b,o,n) }
    long position() { real.position() }
    FileChannel position(long p) { real.position(p); this }
    long size() { real.size() }
    FileChannel truncate(long n) { real.truncate(n); this }
    void force(boolean metadata) { if ('force' in faults) throw new IOException('force'); real.force(metadata) }
    long transferTo(long p,long n,WritableByteChannel c) { real.transferTo(p,n,c) }
    long transferFrom(ReadableByteChannel c,long p,long n) { real.transferFrom(c,p,n) }
    java.nio.MappedByteBuffer map(FileChannel.MapMode m,long p,long n) { real.map(m,p,n) }
}
class FaultInput extends InputStream {
    String name; List events; Set faults
    int read() { -1 }
    void close() { events << name; if (name in faults) throw new IOException(name) }
}
class FaultOutput extends OutputStream {
    List events; Set faults
    void write(int b) { }
    void close() { events << 'stdin'; if ('stdin' in faults) throw new IOException('stdin') }
}
class FakeProbe extends Process {
    List events = []; Set faults = [] as Set; boolean alive = true; int waits = 0
    OutputStream getOutputStream() { new FaultOutput(events:events, faults:faults) }
    InputStream getInputStream() { if ('get-stdout' in faults) throw new IOException('get-stdout'); new FaultInput(name:'stdout',events:events,faults:faults) }
    InputStream getErrorStream() { if ('get-stderr' in faults) throw new IOException('get-stderr'); new FaultInput(name:'stderr',events:events,faults:faults) }
    int waitFor() { throw new AssertionError('unbounded reap') }
    boolean waitFor(long amount,TimeUnit unit) {
        waits++; events << 'wait-' + waits
        if (waits == 1 && 'interrupt' in faults) throw new InterruptedException('interrupt')
        if (waits == 2 && 'reap-interrupt' in faults) throw new InterruptedException('reap-interrupt')
        if (waits == 1 && 'wait' in faults) throw new IOException('wait')
        if (waits > 1 && 'reap' in faults) throw new IOException('reap')
        if (waits == 1 && 'timeout' in faults) return false
        alive = false; true
    }
    boolean isAlive() { alive }
    int exitValue() { 'exit' in faults ? 7 : 120 }
    void destroy() { destroyForcibly() }
    Process destroyForcibly() { events << 'destroy'; if ('destroy' in faults) throw new IOException('destroy'); this }
}
def engine = new GroovyShell().evaluate(new File(args[0]))
def root = Path.of(args[1]); Files.createDirectories(root)
def output = root.resolve('helper')
def directoryOpen = Files.getMethod('newDirectoryStream',Path)
def successes = []
// Every traversal close is faulted individually, and all simultaneously, with and
// without an action failure. All actual underlying streams must still close.
int depth = output.nameCount
(0..depth).each { selected ->
  [false,true].each { operationFailure ->
    def opened = []; def closed = []; def faults = selected == depth ? (0..<depth).toSet() : [selected] as Set
    Closure wrap
    wrap = { SecureDirectoryStream real ->
        int id = opened.size(); opened << id
        Proxy.newProxyInstance(SecureDirectoryStream.class.classLoader,[SecureDirectoryStream] as Class[],
          { Object proxy, Method method, Object[] a ->
            if (method.name == 'newDirectoryStream') return wrap(method.invoke(real,a))
            try {
                def result = method.invoke(real,a)
                if (method.name == 'close') { closed << id; if (id in faults) throw new IOException('stream-' + id) }
                result
            } catch (InvocationTargetException failure) { throw failure.cause }
          } as InvocationHandler)
    }
    Files.metaClass.static.newDirectoryStream = { Path p -> wrap(directoryOpen.invoke(null,p)) }
    try {
        try { engine.withParent(output) { if (operationFailure) throw new IOException('primary'); 7 }; throw new AssertionError('accepted stream fault') }
        catch (IOException failure) {
            def messages = faults.toList().sort().reverse().collect { 'stream-' + it }
            assert failure.message == (operationFailure ? 'primary' : messages.remove(0))
            assert failure.suppressed*.message == messages
            assert closed == opened.reverse()
        }
    } finally { GroovySystem.metaClassRegistry.removeMetaClass(Files) }
    successes << "stream-${selected}-${operationFailure}"
  }
}
// Acquisition-before-registration, type failure, release, channel close and
// simultaneous primary+cleanup faults all use actual directory/channel objects.
['handoff','type','identity','acquire','release','channel','both','primary-both'].each { scenario ->
    def events = []; def channels = []; def opened = []; def closed = []
    def faults = scenario in ['both','primary-both'] ? ['release','channel'] as Set : [scenario] as Set
    if (scenario == 'identity') Files.write(engine.lockPath(output), [1] as byte[])
    boolean openedChannel = false; boolean handoffFaulted = false
    Closure wrap
    wrap = { SecureDirectoryStream real ->
        int id = opened.size(); opened << id
        Proxy.newProxyInstance(SecureDirectoryStream.class.classLoader,[SecureDirectoryStream] as Class[],
          { Object proxy,Method method,Object[] a ->
            try {
                if (method.name == 'newDirectoryStream') return wrap(method.invoke(real,a))
                def result = method.invoke(real,a)
                if (method.name == 'newByteChannel') {
                    openedChannel = true
                    def channel = new FaultChannel(real:result,events:events,faults:faults); channels << channel
                    if (scenario == 'type') return Proxy.newProxyInstance(SeekableByteChannel.class.classLoader,[SeekableByteChannel] as Class[],
                        { Object x,Method m,Object[] v -> m.invoke(channel,v) } as InvocationHandler)
                    return channel
                }
                if (method.name == 'close') {
                    closed << id
                    if (scenario == 'handoff' && openedChannel && !handoffFaulted) { handoffFaulted = true; throw new IOException('handoff') }
                }
                result
            } catch (InvocationTargetException failure) { throw failure.cause }
          } as InvocationHandler)
    }
    Files.metaClass.static.newDirectoryStream = { Path p -> wrap(directoryOpen.invoke(null,p)) }
    try {
        try { engine.withOutputLock(output) { if (scenario == 'primary-both') throw new IOException('primary'); 7 }; throw new AssertionError('accepted ' + scenario) }
        catch (IOException failure) {
            assert failure.message == [handoff:'handoff',type:'ACP lock channel unavailable',identity:'ACP unsafe producer lock',acquire:'acquire',release:'release',channel:'channel',both:'release','primary-both':'primary'][scenario]
            assert failure.suppressed*.message == (scenario == 'both' ? ['channel'] : scenario == 'primary-both' ? ['release','channel'] : [])
            assert events == (scenario in ['handoff','type','identity','acquire'] ? ['channel'] : ['release','channel'])
            assert channels.every { !it.isOpen() && !it.real.isOpen() && (it.acquired == null || !it.acquired.isValid()) }
            assert closed == opened.reverse()
        }
    } finally { GroovySystem.metaClassRegistry.removeMetaClass(Files) }
    if (scenario == 'identity') Files.write(engine.lockPath(output), new byte[0])
    assert engine.withOutputLock(output) { 9 } == 9
    successes << 'lock-' + scenario
}
// Bounded process cleanup exercised with an inert Process, never an ELF/compiler.
[[],['stdin'],['stdout'],['stderr'],['get-stdout'],['get-stderr'],['wait'],['timeout'],['exit'],
 ['interrupt'],['timeout','reap-interrupt'],['wait','destroy'],['wait','reap'],
 ['wait','destroy','reap','stderr','stdout','stdin']].each { selected ->
    def probe = new FakeProbe(faults:selected as Set)
    Throwable caught = null
    try { assert engine.validateProcess(output, { }, { p -> probe }) == 120 }
    catch (Throwable failure) { caught = failure }
    assert (caught == null) == selected.isEmpty()
    def closes = probe.events.findAll { it in ['stdin','stdout','stderr'] }
    if ('get-stdout' in selected) assert closes == ['stderr','stdin']
    else if ('get-stderr' in selected) assert closes == ['stdout','stdin']
    else assert closes[-3..-1] == ['stderr','stdout','stdin']
    assert probe.waits >= 1
    if ('interrupt' in selected || 'reap-interrupt' in selected) assert Thread.interrupted()
    else assert !Thread.interrupted()
    if ('wait' in selected && selected.size() > 3) {
        assert caught.message == 'stdin' // stdin fails before wait, all later cleanups still run
        assert caught.suppressed*.message == ['destroy','wait','stderr','stdout','stdin']
    }
    if (!('reap' in selected) && !('wait' in selected && 'stdin' in selected)) assert !probe.alive
    successes << 'probe-' + selected
}
// Read/force channel cleanup nests inside traversal; preserve the operation,
// directly suppress channel AND every stream failure, and close real handles.
['read','force'].each { operation ->
  [false,true].each { allCloses ->
    def file = root.resolve(operation + '-' + allCloses)
    Files.write(file, ('inert' * 32).bytes)
    def events = []; def channels = []; def opened = []; def closed = []
    Closure wrap
    wrap = { SecureDirectoryStream real ->
      int id = opened.size(); opened << id
      Proxy.newProxyInstance(SecureDirectoryStream.class.classLoader,[SecureDirectoryStream] as Class[],
        { Object proxy,Method method,Object[] a ->
          try {
            if (method.name == 'newDirectoryStream') return wrap(method.invoke(real,a))
            def result = method.invoke(real,a)
            if (method.name == 'newByteChannel') {
                def channel = new FaultChannel(real:result,events:events,faults:([operation] + (allCloses ? ['channel'] : [])) as Set)
                channels << channel; return channel
            }
            if (method.name == 'close') { closed << id; if (allCloses) throw new IOException('stream-' + id) }
            result
          } catch (InvocationTargetException problem) { throw problem.cause }
        } as InvocationHandler)
    }
    Files.metaClass.static.newDirectoryStream = { Path p -> wrap(directoryOpen.invoke(null,p)) }
    try {
      try { if (operation == 'read') engine.read(file) else engine.force(file); throw new AssertionError('accepted ' + operation) }
      catch (IOException failure) {
        assert failure.message == operation
        assert failure.suppressed*.message == (allCloses ? ['channel'] + opened.reverse().collect { 'stream-' + it } : [])
        assert closed == opened.reverse()
        assert channels.every { !it.real.isOpen() && !it.isOpen() }
      }
    } finally { GroovySystem.metaClassRegistry.removeMetaClass(Files) }
    successes << operation + '-nested-cleanup-' + allCloses
  }
}
println('GREEN ACP resource controls: ' + successes.size() + ' ' + successes)
'''

try:
    # Explicit and PATH-derived real executable homes; launcher option JSON/path roundtrip.
    jdk = WORK / "jdk with spaces"; (jdk / "bin").mkdir(parents=True)
    java = jdk / "bin/java"; java.write_text("#!/bin/sh\nexit 0\n"); java.chmod(0o755)
    (jdk / "release").write_text('JAVA_VERSION="21.0.12"\n')
    with unittest.mock.patch.dict(os.environ, {"JAVA_HOME": str(jdk)}): assert driver.qualified_java_home() == jdk
    with unittest.mock.patch.dict(os.environ, {}, clear=True), unittest.mock.patch.object(driver.shutil, "which", return_value=str(java)):
        assert driver.qualified_java_home() == jdk
    args = ['-Djson=' + driver.MODEL, '-javaagent:/path with spaces/agent.jar', '-Dpath=apostrophe\' and "quotes"']
    # GNU xargs is the unmodified Gradle launcher's tokenizer.
    result = subprocess.run(["xargs", "-n1", "printf", "%s\\n"], input=shlex.join(args), text=True, capture_output=True, check=True)
    assert result.stdout.splitlines() == args
    passed.append("explicit/derived-JDK-home-and-launcher-quote-roundtrip")

    driver.write_init("A")
    init_text = driver.INIT.read_text()
    assert driver.install_root() == WORK / "root-build/install" / driver.APP
    assert "destinationDir = new File(" + driver.groovy_path(driver.install_root()) + ")" in init_text
    assert driver.groovy_path(ROOT / "build/frontend") in init_text
    assert driver.groovy_path(WORK / "root-build/frontend") in init_text
    assert 'outputs.upToDateWhen { false }' in init_text
    assert '"dist", "bundle-report.json", "bundle-composition.json"' in init_text
    passed.append("one-install-root-and-fresh-frontend-output-wiring")
    with unittest.mock.patch.object(driver, "qualified_java_home", return_value=jdk):
        original_home = os.environ.get("HOME")
        assert driver.safe_env().get("HOME") == original_home
        with unittest.mock.patch.object(driver, "run", return_value=(0, "")) as run:
            driver.gradle("help")
            assert run.call_args.kwargs["timeout"] == driver.BUILD_TIMEOUT
    assert 120 < driver.BUILD_TIMEOUT < driver.RELEASE_TIMEOUT <= 3600
    assert driver.RELEASE_TIMEOUT >= driver.BUILD_TIMEOUT + driver.READY_TIMEOUT + driver.PROBE_FINISH_TIMEOUT + 60
    passed.append("original-home-and-whole-overlap-budget")
    prepared_spec = importlib.util.spec_from_file_location("prepared_ordering_controls", ROOT / "scripts/test-atomic-install-prepared.py")
    prepared_controls = importlib.util.module_from_spec(prepared_spec)
    prepared_spec.loader.exec_module(prepared_controls)
    prepared_controls.PreparedControls().exercise()
    passed.append("live-no-update-orchestration-before-reinstall-and-late-load-after")

    child = driver.Child([PYTHON, "-c", "print('complete')"], log=WORK / "success.log")
    assert child.wait(10) == 0 and child.text() == "complete\n"
    check_dead(child.process.pid)
    passed.append("bounded-process-success-reaped")
    child = driver.Child([PYTHON, "-c", "import time; time.sleep(60)"], log=WORK / "timeout.log")
    check_failure("timeout-group-kill-reap", lambda: child.wait(.05), subprocess.TimeoutExpired)
    check_dead(child.process.pid)
    child = driver.Child([PYTHON, "-c", "import time; time.sleep(60)"], log=WORK / "interrupt.log")
    original_wait = child.process.wait
    calls = [0]
    def interrupt_once(*args, **kwargs):
        calls[0] += 1
        if calls[0] == 1: raise KeyboardInterrupt()
        return original_wait(*args, **kwargs)
    with unittest.mock.patch.object(child.process, "wait", side_effect=interrupt_once):
        check_failure("interrupt-group-kill-reap", lambda: child.wait(10), KeyboardInterrupt)
    check_dead(child.process.pid)
    old_limit = driver.MAX_LOG; driver.MAX_LOG = 4096
    child = driver.Child([PYTHON, "-c", "import os; os.write(1,b'x'*1000000)"], log=WORK / "overflow.log")
    check_failure("output-bound-group-kill-reap", lambda: child.wait(10), RuntimeError)
    assert child.log.stat().st_size <= driver.MAX_LOG and len(child.tail) <= 12000
    driver.MAX_LOG = old_limit
    # A descendant retains the output pipe after its parent exits. Cleanup kills the whole group.
    child = driver.Child([PYTHON, "-c", "import os,time; p=os.fork(); time.sleep(60) if p==0 else None"], log=WORK / "descendant.log")
    assert child.wait(10) == 0
    check_dead(child.process.pid)
    passed.append("descendant-pipe-group-cleanup")

    with zipfile.ZipFile(driver.install_root() / "lib/app.jar", "w") as archive: archive.writestr("decompengine/MainKt.class", b"fixture")
    launcher = driver.install_root() / "bin" / driver.APP
    launcher.write_text("#!" + PYTHON + "\nimport os,shlex,pathlib,time\n"
        "p=dict(x[2:].split('=',1) for x in shlex.split(os.environ['JAVA_OPTS']) if x.startswith('-D'))\n"
        "pathlib.Path(p['atomic.probe.ready']).write_text('malformed READY')\n"
        "time.sleep(60)\n")
    launcher.chmod(0o755)
    with unittest.mock.patch.object(driver, "qualified_java_home", return_value=jdk):
        check_failure("malformed-READY-local-ownership-cleanup", lambda: driver.launch_blocked("A"), json.JSONDecodeError)
        with unittest.mock.patch.object(driver, "read_evidence", side_effect=OSError("injected READY read failure")):
            check_failure("READY-read-failure-local-cleanup", lambda: driver.launch_blocked("A"), OSError)
        original_sleep = time.sleep
        interrupted = [False]
        def interrupt_sleep_once(seconds):
            if not interrupted[0]:
                interrupted[0] = True
                raise KeyboardInterrupt()
            return original_sleep(seconds)
        with unittest.mock.patch.object(driver.time, "sleep", side_effect=interrupt_sleep_once):
            check_failure("READY-interrupt-local-cleanup", lambda: driver.launch_blocked("A"), KeyboardInterrupt)
    assert len(list((WORK / "barriers").iterdir())) == 3
    passed.append("unique-barriers-per-attempt")

    if "--gradle-init" in sys.argv:
        project = WORK / "init-project"; project.mkdir()
        (project / "settings.gradle").write_text("rootProject.name = 'atomic-init-control'\n")
        (project / "build.gradle").write_text('''plugins { id 'application' }
application { applicationName = 'llm_bin_patch'; mainClass = 'unused.Main' }
tasks.register('frontendBuild') {
 outputs.dir(layout.buildDirectory.dir('frontend/dist'))
 outputs.files(layout.buildDirectory.file('frontend/bundle-report.json'), layout.buildDirectory.file('frontend/bundle-composition.json'))
 doLast {
  def produced = file('build/frontend')
  def countFile = file('producer-count')
  def count = countFile.exists() ? countFile.text.toInteger() + 1 : 1
  countFile.text = count.toString()
  new File(produced, 'dist').mkdirs()
  new File(produced, 'dist/current.js').text = 'fresh-' + count
  new File(produced, 'bundle-report.json').text = '{"fresh":' + count + '}'
  new File(produced, 'bundle-composition.json').text = '{"fresh":' + count + '}'
 }
}
tasks.register('verifyDriverInit') {
 dependsOn('frontendBuild')
 doLast {
  def actual = tasks.named('installDist').get().destinationDir
  def expected = layout.buildDirectory.dir('install/llm_bin_patch').get().asFile
  assert actual == expected
  def count = file('producer-count').text.toInteger()
  def consumed = layout.buildDirectory.dir('frontend').get().asFile
  assert new File(consumed, 'dist/current.js').text == 'fresh-' + count
  assert !new File(consumed, 'dist/stale.js').exists()
  ['bundle-report.json', 'bundle-composition.json'].each { name ->
   assert new File(consumed, name).text == '{"fresh":' + count + '}'
  }
  println('driver init producer/consumer/destination agreement: ' + count)
 }
}
''')
        with unittest.mock.patch.object(driver, "ROOT", project): driver.write_init("A", command_id=100)
        env = driver.safe_env(); env["JAVA_OPTS"] = shlex.join(driver.jvm_options())
        for iteration in (1, 2):
            consumed_dist = WORK / "root-build/frontend/dist"
            consumed_dist.mkdir(parents=True, exist_ok=True)
            (consumed_dist / "stale.js").write_text("stale")
            command = [ROOT / "gradlew", "--offline", "--no-daemon", "-g", env["GRADLE_USER_HOME"],
                       "-Dorg.gradle.jvmargs=" + shlex.join(driver.jvm_options()), "-p", project, "-I", driver.INIT, "verifyDriverInit"]
            _, output = driver.run(command, env=env, log=WORK / f"init-{iteration}.log", timeout=120)
            assert f"driver init producer/consumer/destination agreement: {iteration}" in output
        passed.append("real-Gradle-init-fresh-producer/copy/stale-removal/repeated-build/exact-install-destination")

    if "--gradle-writers" in sys.argv:
        destination = WORK / "shared-install"
        commands = []
        def writer(name, failure=False, released=False):
            folder = WORK / name; folder.mkdir()
            ready = folder / "READY"; release = folder / "RELEASE"
            if released: release.write_text("release")
            config = {"destination": str(destination), "ready": str(ready), "release": str(release), "failure": str(failure).lower()}
            init = folder / "writer.init.gradle"
            init.write_text("allprojects { p -> if (p == p.rootProject) { p.buildDir = new File(" + driver.groovy_path(folder / "build") + ")\n"
                "p.tasks.matching { it.name == 'verifyAtomicApplicationPublication' }.configureEach {\n"
                "ext.atomicWriterControl = [" + ",".join(driver.groovy_path(k)+":"+driver.groovy_path(v) for k,v in config.items()) + "]\n} } }\n")
            env = driver.safe_env(); env["JAVA_OPTS"] = shlex.join(driver.jvm_options())
            args = [ROOT / "gradlew", "--no-daemon", "--project-cache-dir", folder / "project-cache", "-g", env["GRADLE_USER_HOME"],
                    "-Dorg.gradle.jvmargs=" + shlex.join(driver.jvm_options()), "-I", init, "verifyAtomicApplicationPublication"]
            commands.append(list(map(str, args)))
            return driver.Child(args, env=env, log=folder / "gradle.log"), ready, release
        first, ready, release = writer("writer-one"); wait_file(ready, first)
        second, _, _ = writer("writer-two")
        assert second.wait(120) != 0 and "Another installDist writer holds" in second.text()
        release.write_text("release"); assert first.wait(120) == 0
        third, _, _ = writer("writer-after-success", released=True); assert third.wait(120) == 0
        failed, _, _ = writer("writer-task-failure", failure=True)
        assert failed.wait(120) != 0 and "injected writer task failure" in failed.text()
        after_failure, _, _ = writer("writer-after-failure", released=True); assert after_failure.wait(120) == 0
        cancelled, ready, _ = writer("writer-cancelled"); wait_file(ready, cancelled)
        cancelled.close(); check_dead(cancelled.process.pid)
        after_cancel, _, _ = writer("writer-after-cancel", released=True); assert after_cancel.wait(120) == 0
        assert len(list(destination.parent.glob(".install-*.lock"))) == 1
        passed.append("distinct-buildDir-production-service-contention/release/task-failure/process-cancel/reacquire")
        (WORK / "writer-commands.json").write_text(json.dumps(commands, indent=2))
    if "--java-agent" in sys.argv:
        # Synthetic Java fixtures exercise the exact agent mechanics only, NOT installed acceptance.
        java_home = driver.qualified_java_home()
        fixture = WORK / "java-fixture"; fixture.mkdir()
        budget_source = fixture / "AtomicInstallBudgetControl.java"
        budget_source.write_text('''package decompengine.install;
public class AtomicInstallBudgetControl {
 public static void main(String[] args) {
  long budget = Long.parseLong(args[0]) * 1_000_000_000L;
  long validUpdate = 121_000_000_000L;
  if (AtomicInstallProbeAgent.releaseWaitExpired(0, validUpdate, budget)) throw new AssertionError("valid long update expired");
  if (!AtomicInstallProbeAgent.releaseWaitExpired(0, budget, budget)) throw new AssertionError("deadline not enforced");
  long nearWrap = Long.MAX_VALUE - 1_000_000_000L;
  if (AtomicInstallProbeAgent.releaseWaitExpired(nearWrap, nearWrap + validUpdate, budget)) throw new AssertionError("signed wrap");
  if (!AtomicInstallProbeAgent.releaseWaitExpired(10, 9, budget)) throw new AssertionError("backward clock");
 }
}''')
        budget_classes = fixture / "budget-classes"; budget_classes.mkdir()
        driver.run([java_home / "bin/javac", "-J-XX:-UsePerfData", "-J-Djava.io.tmpdir=" + str(WORK / "tmp"),
                    "--release", "21", "-cp", driver.AGENT, "-d", budget_classes, budget_source],
                   env=driver.safe_env(), log=fixture / "budget-compile.log", timeout=30)
        driver.run([java_home / "bin/java", *driver.jvm_options(), "-cp", str(budget_classes) + os.pathsep + str(driver.AGENT),
                    "decompengine.install.AtomicInstallBudgetControl", str(driver.RELEASE_TIMEOUT)],
                   env=driver.safe_env(), log=fixture / "budget.log", timeout=10)
        passed.append("agent-clock-121-second-update/full-expiry/signed-wrap/backward-rejection")
        sources = fixture / "src"; sources.mkdir()
        classes = fixture / "classes"; classes.mkdir()
        (sources / "MainKt.java").write_text('package decompengine; public class MainKt { public static void main(String[] a) { throw new AssertionError("production main entered"); } }')
        model_literal = json.dumps(driver.MODEL)
        (sources / "ProgramModelJson.java").write_text('''package decompengine.project;
public class ProgramModelJson {
 public static final ProgramModelJson INSTANCE = new ProgramModelJson();
 public Model read(String json) { if (!json.equals(MODEL_LITERAL)) throw new IllegalArgumentException("JSON token changed"); return new Model(); }
 public static class Model { public int getSchemaVersion() { return 4; } public String getInputSha256() { return "a".repeat(64); } }
}'''.replace("MODEL_LITERAL", model_literal))
        driver.run([java_home / "bin/javac", "-J-Djava.io.tmpdir=" + str(WORK / "tmp"), "-J-XX:-UsePerfData", "--release", "21", "-d", classes,
                    sources / "MainKt.java", sources / "ProgramModelJson.java"], env=driver.safe_env(), log=fixture / "javac.log", timeout=30)
        jar = fixture / "app.jar"
        def write_jar(marker):
            stage = fixture / "app-stage.jar"
            with zipfile.ZipFile(stage, "w") as archive:
                for path in sorted(classes.rglob("*.class")): archive.write(path, path.relative_to(classes).as_posix())
                archive.writestr("atomic-install-generation.txt", marker)
            stage.replace(jar)
        def probe(marker):
            barrier = pathlib.Path(tempfile.mkdtemp(prefix="probe-", dir=fixture))
            ready = barrier / "READY"; release = barrier / "RELEASE"
            args = [java_home / "bin/java", *driver.jvm_options(), "-javaagent:" + str(driver.AGENT),
                    "-Datomic.probe.app=" + str(jar), "-Datomic.probe.ready=" + str(ready),
                    "-Datomic.probe.release=" + str(release), "-Datomic.probe.marker=" + marker,
                    "-Datomic.probe.releaseTimeoutSeconds=" + str(driver.RELEASE_TIMEOUT),
                    "-Datomic.probe.model=" + driver.MODEL, "-cp", jar, "decompengine.MainKt"]
            child = driver.Child(args, env=driver.safe_env(), log=barrier / "agent.log")
            child.probe = {"scope": "synthetic Java agent fixture", "root": str(barrier)}
            wait_file(ready, child, 15)
            evidence = driver.read_evidence(ready)
            assert evidence["modelAbsentBeforeReady"] == "true" and evidence["archiveMarker"] == marker
            assert evidence["releaseTimeoutSeconds"] == str(driver.RELEASE_TIMEOUT)
            return child, release, evidence
        observations = []
        for old, new in (("A", "B"), ("B", "A")):
            write_jar(old)
            child, release, ready = probe(old)
            write_jar(new); current_digest = driver.digest(jar)
            fresh, fresh_release, fresh_ready = probe(new)
            fresh_result = driver.release_and_reap(fresh, fresh_release, new)
            old_result = driver.release_and_reap(child, release, old)
            assert old_result["descriptorDigest"] == ready["descriptorDigest"] != current_digest
            assert old_result["installedPathDigestAfterRelease"] == fresh_result["descriptorDigest"] == current_digest
            observations.append({"from": old, "to": new, "old": old_result, "fresh": fresh_result})
        with zipfile.ZipFile(driver.AGENT) as archive:
            assert all(name.startswith(("META-INF/", "decompengine/install/")) for name in archive.namelist() if not name.endswith('/'))
        (fixture / "synthetic-agent-results.json").write_text(json.dumps(observations, indent=2))
        passed.append("synthetic-agent-A-B-A-late-loader-origin-resource-descriptor-JSON/no-product-main")
    if "--acp-publication" in sys.argv: acp_publication_controls()
    record = {"status": "passed", "passed": passed, "sourceHashes": {p: driver.digest(ROOT/p) for p in driver.OWNED_SOURCES}}
except BaseException as failure:
    record = {"status": "failed", "passed": passed, "failure": repr(failure)}
    raise
finally:
    for child in list(driver.ACTIVE): child.close()
    (WORK / "controls.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"record": str(WORK / "controls.json"), **record}, indent=2))

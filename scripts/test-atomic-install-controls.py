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
    original = driver.Child.close
    observed = []
    def checked_close(child):
        try: return original(child)
        finally:
            if child._complete:
                check_dead(child)
                observed.append(child)
    with unittest.mock.patch.object(driver.Child, 'close', checked_close):
        try: action()
        except expected: pass
        else: raise AssertionError(name + " did not fail")
    assert observed, name + " lacked an exact settlement observation"
    assert not driver.ACTIVE, name + " leaked an owned child"
    passed.append(name)


def check_dead(child):
    assert child.actual_exited(), "actual retained pidfd never reported exit"
    ack = child.settlement
    assert ack and ack['pid'] == child.process.pid and ack['code'] == child.process.returncode
    assert ack['actualReaped'] and ack['allRegisteredReaped'] and ack['echild'] and ack['error'] is None
    assert child._helper.pid != child.process.pid and child._helper.returncode == 0
    assert not child.reader.is_alive() and not child.pump.is_alive()
    assert child._complete and child not in driver.ACTIVE


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

def ownership_controls():
    """Inert exact-source controls; never a compensating descendant kill."""
    import array, concurrent.futures, errno, threading, socket, types
    from unittest import mock
    rt = driver.child_runtime
    receipts = []
    def run_case(label, action):
        action()
        assert not driver.ACTIVE, (label, driver.ACTIVE)
        passed.append(label)
    def spawn(code, name, extra=()):
        return driver.Child([PYTHON, '-B', '-c', code, *map(str, extra)], log=WORK / (name+'.log'))
    def save(child):
        check_dead(child)
        receipts.append({'actualPid': child.process.pid, 'helperPid': child._helper.pid,
                         'nonce': child._nonce, 'ack': child.settlement,
                         'startupDeadline': child.startup_deadline, 'cleanupDeadline': child.cleanup_deadline,
                         'outputJoined': not child.reader.is_alive(), 'pumpJoined': not child.pump.is_alive()})
    def foreign():
        # Actual production enrollment/signal hooks with safe modeled generation
        # reuse. Numeric targets never go to a kernel signal operation.
        owner = rt.Supervisor(None, 'model', time.monotonic()+10, float('inf'), ['inert'])
        owner.cap = 8
        sent, opened, closed = [], [], []
        def acquire(pid):
            opened.append(pid)
            return {43000: 900}[pid]
        terminal = types.SimpleNamespace(si_pid=43000, si_code=os.CLD_EXITED, si_status=23)
        with mock.patch.object(rt.os, 'pidfd_open', side_effect=acquire), \
             mock.patch.object(rt.os, 'waitid', return_value=None), \
             mock.patch.object(rt.os, 'kill', side_effect=AssertionError('numeric kill')), \
             mock.patch.object(rt.os, 'killpg', side_effect=AssertionError('numeric group signal')), \
             mock.patch.object(rt.signal, 'pidfd_send_signal', side_effect=lambda fd, sig: sent.append(fd)), \
             mock.patch.object(rt.os, 'close', side_effect=lambda fd: closed.append(fd)):
            # The sole waiter's direct-child list excludes foreign43002/group43000.
            with mock.patch('builtins.open', mock.mock_open(read_data=b'43000')):
                owner.census()
            owner.signal_owned(owner.handles[43000])
            # Diagnostic numeric generation could now change; it is never read.
            owner.signal_owned(owner.handles[43000])
            with mock.patch.object(rt.os, 'waitid', return_value=terminal):
                owner.harvest()
        assert opened == [43000] and sent == [900, 900] and closed == [900]
        assert 43002 not in owner.handles and not owner.handles
        (WORK/'foreign-green.json').write_text(json.dumps({'foreignEnrolled':False,'exactHandlesSignaled':sent,'numericSignals':0}))
    run_case('ownership-foreign-generation-production-hooks', foreign)

    def detached():
        marker = WORK/'detached-worker.json'
        code = '''import os,sys,time,pathlib,json
r,w=os.pipe()
p=os.fork()
if p:
 os.close(w);os.read(r,1);os._exit(23)
os.close(r);os.setsid()
pathlib.Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid()}))
for fd in (0,1,2):os.close(fd)
os.write(w,b'X');os.close(w);time.sleep(60)
'''
        child = spawn(code, 'detached', (marker,))
        assert child.wait(10) == 23
        worker = json.loads(marker.read_text())['pid']
        assert worker in {row['pid'] for row in child.settlement['sample']}
        assert child.settlement['reaped'] == 2
        assert not pathlib.Path('/proc', str(worker)).exists()
        save(child)
    run_case('ownership-detached-worker-before-first-census', detached)

    def topology():
        for mode in ('doublefork', 'intermediate-subreaper'):
            code = '''import ctypes,os,time,sys
r,w=os.pipe()
p=os.fork()
if p:
 os.close(w);os.read(r,1);os._exit(19)
os.close(r);os.setsid()
if sys.argv[1]=='intermediate-subreaper':
 assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
p=os.fork()
if not p:
 p=os.fork()
 if p:os._exit(0)
 os.write(w,b'X');os.close(w);time.sleep(60)
else:
 os.close(w);time.sleep(60)
'''
            child = spawn(code, mode, (mode,))
            assert child.wait(10) == 19
            assert child.settlement['reaped'] >= 3
            save(child)
    run_case('ownership-doublefork-intermediate-subreaper', topology)

    import concurrent.futures as futures
    def concurrent_fixed():
        def launch(i):
            child = spawn('import os,time; print(os.getpid(),flush=True); time.sleep(.1)', 'concurrent-'+str(i))
            assert child.wait(10) == 0 and int(child.text()) == child.process.pid
            save(child)
            return {r['pid'] for r in child.settlement['sample']}
        with futures.ThreadPoolExecutor(max_workers=4) as executor:
            sets = list(executor.map(launch, range(4)))
        assert sum(map(len,sets)) == len(set().union(*sets))
    run_case('ownership-concurrent-owner-isolation-self-pid', concurrent_fixed)

    def status_paths():
        for code in (0, 127, 23):
            child = spawn('import os,sys; os._exit(int(sys.argv[1]))', 'fast-'+str(code), (code,))
            assert child.wait(10) == code
            save(child)
        try:
            driver.Child([str(WORK/'missing-executable')], log=WORK/'missing.log')
        except FileNotFoundError as failure:
            assert failure.errno == errno.ENOENT and failure.filename == str(WORK/'missing-executable')
        else:
            raise AssertionError('exec error confused with exit127')
        child = spawn('import time; time.sleep(60)', 'nonblocking')
        before=time.monotonic()
        for _ in range(100): assert child.process.poll() is None
        assert time.monotonic()-before < .5 and child.process.is_running()
        child.close();save(child)
        assert child.process.returncode == -signal.SIGKILL
    run_case('ownership-fast127-execerror-nonblocking-status', status_paths)

    def frame_faults():
        def fdset(): return set(os.listdir('/proc/self/fd'))
        left,right = socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        source=rt.FD(os.pidfd_open(os.getpid()))
        try:
            for payload, count in ((b'{',1),(b'{}',2),(b'[]',1),(b'x'*20000,1),
                                   (b'{"kind":"BOUND","kind":"BOUND"}',1)):
                before=fdset()
                left.sendmsg([payload],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[source.number]*count))])
                rights=[]
                try:
                    frame,rights=rt.receive(right)
                    assert len(rights)==count
                    # Application state validation owns rights even after decoding.
                    rt.validate(frame,'nonce','helper',0,'BOUND',{'pid'})
                    raise AssertionError('bad frame accepted')
                except (rt.OwnershipError, json.JSONDecodeError): pass
                finally: rt.retire_all(rights)
                assert fdset()==before
            # Valid BOUND FD type/PID checks cannot use waitid(nonchild).
            rt.validate_pidfd(source,os.getpid())
            with mock.patch.object(rt.os,'waitid',side_effect=AssertionError('nonchild wait')):
                rt.validate_pidfd(source,os.getpid())
            r,w=os.pipe()
            try:
                with unittest.TestCase().assertRaises(rt.OwnershipError): rt.validate_pidfd(rt.FD(r),os.getpid())
                with unittest.TestCase().assertRaises(rt.OwnershipError): rt.validate_pidfd(source,os.getpid()+1)
            finally: os.close(r);os.close(w)
        finally:source.close();left.close();right.close()
    run_case('ownership-malformed-extra-truncated-wrong-fd', frame_faults)

    def close_faults():
        for error in (OSError(errno.EIO,'late close'),InterruptedError(errno.EINTR,'ambiguous close')):
            read,write=os.pipe(); handle=rt.FD(read); replacement=[]; real_close=os.close
            def late(fd):
                real_close(fd)
                replacement.extend(os.pipe())
                raise error
            with mock.patch.object(rt.os,'close',side_effect=late):
                with unittest.TestCase().assertRaises(OSError):handle.close()
            assert handle.number is None and handle.close_error is error
            handle.close()
            assert replacement[0]==read
            os.fstat(replacement[0])
            for fd in (*replacement,write):os.close(fd)
        transport=mock.Mock()
        transport.recvmsg.return_value=(b'{',[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[900]).tobytes())],0,None)
        with mock.patch.object(rt.os,'close',side_effect=InterruptedError(errno.EINTR,'close uncertainty')):
            with unittest.TestCase().assertRaises(json.JSONDecodeError) as caught:rt.receive(transport)
        assert any('close uncertainty' in note for note in caught.exception.__notes__)
    run_case('ownership-detached-close-eio-eintr-reused-integer', close_faults)

    def acquisition_close_priority():
        for secondary in (OSError(errno.EIO, 'acquisition close uncertain'),
                          InterruptedError(errno.EINTR, 'acquisition close interrupted')):
            owner = rt.Supervisor(None, 'model', time.monotonic()+10, float('inf'), ['inert'])
            owner.cap = 8
            primary = ChildProcessError(errno.ECHILD, 'original child relation rejected')
            handles = []
            original_fd = rt.FD
            def retain(number):
                handle = original_fd(number); handles.append(handle); return handle
            with mock.patch.object(rt, 'FD', side_effect=retain), \
                 mock.patch.object(rt.os, 'pidfd_open', return_value=900), \
                 mock.patch.object(rt.os, 'waitid', side_effect=primary), \
                 mock.patch.object(rt.os, 'close', side_effect=secondary) as close:
                try: owner.acquire(43002)
                except ChildProcessError as caught:
                    assert caught is primary
                    owner.fail(caught)
                else: raise AssertionError('child relation rejection was lost')
                assert len(handles) == 1 and handles[0].number is None
                handles[0].close()
                assert close.call_count == 1 and close.call_args.args == (900,)
            assert not owner.handles and owner.deadline is not None
            assert repr(primary) in owner.failure and repr(secondary) in owner.failure
            assert len(owner.failure) <= 4096
            first = owner.failure; owner.fail(RuntimeError('later failure'))
            assert owner.failure == first
    run_case('ownership-acquisition-close-primary-and-receipt', acquisition_close_priority)

    def writer_call_contract():
        # Execute the optional writer branch's actual assertion call against a
        # settled owned child without running Gradle or replacing the assertion.
        import ast
        tree = ast.parse(pathlib.Path(__file__).read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Expr)
                 and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                 and node.value.func.id == 'check_dead'
                 and any(isinstance(part, ast.Name) and part.id == 'cancelled'
                         for part in ast.walk(node.value))]
        assert len(calls) == 1
        child = spawn('pass', 'writer-call-contract'); assert child.wait(3) == 0
        exec(compile(ast.Module(body=calls, type_ignores=[]), __file__, 'exec'),
             {'check_dead': check_dead, 'cancelled': child})
        save(child)
    run_case('ownership-optional-writer-check-dead-contract', writer_call_contract)

    def prego():
        marker=WORK/'must-not-exec'
        original=rt.Child._send
        primary=KeyboardInterrupt('pre-GO injected interrupt')
        owners=[]
        def intercept(owner, kind, **kwargs):
            if kind=='GO':
                owners.append(owner)
                raise primary
            return original(owner,kind,**kwargs)
        with mock.patch.object(rt.Child,'_send',intercept):
            try:spawn('import pathlib,sys; pathlib.Path(sys.argv[1]).write_text("BAD")','prego',(marker,))
            except KeyboardInterrupt as failure: assert failure is primary
            else:raise AssertionError('preGO accepted')
        assert not marker.exists()
        assert owners[0].settlement['code'] in (125, -signal.SIGKILL)
        save(owners[0])
        # A failed output reader start still pumps/reaps a never-released command.
        original_start=threading.Thread.start; once=[False]; owners=[]
        def failed_start(thread):
            if thread.name=='atomic-output' and not once[0]:
                once[0]=True;owners.extend(driver.ACTIVE);raise RuntimeError('reader start injected')
            return original_start(thread)
        with mock.patch.object(threading.Thread,'start',failed_start):
            with unittest.TestCase().assertRaisesRegex(RuntimeError,'reader start injected'):
                spawn('raise RuntimeError("must not execute")','reader-start')
        assert len(owners)==1 and owners[0]._complete and owners[0].settlement['code'] in (125, -signal.SIGKILL)
    run_case('ownership-preGO-interrupt-reader-start-no-exec', prego)

    def deadlines():
        owner=object.__new__(rt.Child)
        owner._condition=threading.Condition();owner.cleanup_deadline=None;owner.startup_deadline=90
        with mock.patch.object(rt.time,'monotonic',return_value=100): first=owner._trigger_cleanup()
        with mock.patch.object(rt.time,'monotonic',return_value=999):
            assert owner._trigger_cleanup()==first==110
            assert owner.startup_deadline==90
        child=spawn('import time; time.sleep(60)','deadlines')
        child.close();deadline=child.cleanup_deadline;child.close()
        assert child.cleanup_deadline==deadline
        save(child)
        # No live process: expired close must use zero waits and retain custody.
        owner=object.__new__(rt.Child)
        owner.__dict__.update(_complete=False,_peer=None,_close_lock=threading.RLock(),_condition=threading.Condition(),
            cleanup_deadline=50,_helper=mock.Mock(),_helper_fd=rt.FD(999),_actual_fd=None,_socket=mock.Mock(),
            pump=mock.Mock(),reader=None,process=mock.Mock(),settlement=None,_protocol_error=None,
            error=None,_reader_stop=threading.Event(),_pump_stop=threading.Event(),_protocol_complete=False)
        owner.process.returncode=7;owner.pump.ident=1;owner.pump.is_alive.return_value=True
        owner._helper.wait.side_effect=subprocess.TimeoutExpired(['helper'],0)
        with mock.patch.object(rt.time,'monotonic',return_value=100):
            for _ in range(3):
                with unittest.TestCase().assertRaises(rt.OwnershipError):owner.close()
        assert owner.cleanup_deadline==50 and all(c.kwargs['timeout']==0 for c in owner._helper.wait.call_args_list)
        assert all(c.args==(0,) for c in owner.pump.join.call_args_list)
    run_case('ownership-immutable-start-first-cleanup-deadlines', deadlines)

    def exhaustion():
        with mock.patch.object(rt.resource,'getrlimit',return_value=(20,20)):
            with unittest.TestCase().assertRaises(rt.OwnershipError):spawn('raise AssertionError','admission-refused')
        owner=rt.Supervisor(None,'fault',10,20,['inert']);owner.cap=4
        with mock.patch.object(rt.os,'pidfd_open',side_effect=OSError(errno.EMFILE,'injected exhaustion')):
            with unittest.TestCase().assertRaises(OSError):owner.acquire(43000)
        assert not owner.handles
        owner.handles={43000:rt.FD(800)};owner.pid=43000;owner.deadline=10
        with mock.patch.object(rt.os,'waitid',side_effect=InterruptedError(errno.EINTR,'wait interrupted')):
            with unittest.TestCase().assertRaises(InterruptedError):owner.harvest()
        assert owner.handles[43000].number==800 and owner.reaped==0
        result=types.SimpleNamespace(si_pid=43000,si_code=os.CLD_EXITED,si_status=23)
        with mock.patch.object(rt.os,'waitid',return_value=result),mock.patch.object(rt.os,'close') as close:
            owner.harvest();owner.harvest()
        assert owner.reaped==1 and owner.actual_reaped and close.call_count==1
    run_case('ownership-exhaustion-interrupted-exact-wait', exhaustion)

    def output_fault():
        child=spawn('import time,os; time.sleep(.15); os.write(1,b"x"*4194304); time.sleep(60)','output-fault')
        original=child.sink
        class Sink:
            def write(self,data):raise OSError('injected output sink failure')
            def close(self):original.close()
        child.sink=Sink()
        with unittest.TestCase().assertRaisesRegex(OSError,'injected output sink failure'):child.wait(10)
        assert child.settlement and child._complete and not child.reader.is_alive() and not child.pump.is_alive()
    run_case('ownership-output-sink-failure-settles', output_fault)

    def lowfd():
        code='''import importlib.util,pathlib,resource,sys,concurrent.futures
root=pathlib.Path(sys.argv[1]);out=pathlib.Path(sys.argv[2])
spec=importlib.util.spec_from_file_location('child',root/'scripts/atomic_install_child.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE);resource.setrlimit(resource.RLIMIT_NOFILE,(64,hard))
active=set()
def launch(i):
 c=m.Child([sys.executable,'-B','-c','print("lowfd")'],log=out/('low-'+str(i)+'.log'),active=active)
 assert c.wait(5)==0 and c.text()=='lowfd\\n' and c._complete
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as e:list(e.map(launch,range(3)))
assert not active
'''
        child=spawn(code,'lowfd-runner',(ROOT,WORK))
        assert child.wait(15)==0,child.text();save(child)
    run_case('ownership-low-fd-concurrent-admission',lowfd)
    def late_and_protocol():
        child=spawn('import time; time.sleep(60)','late-fds')
        before=set(os.listdir('/proc/self/fd'))
        duplicate=rt.FD(os.dup(child._actual_fd.number))
        with unittest.TestCase().assertRaisesRegex(rt.OwnershipError,'late descriptors'):
            child._accept({},[duplicate])
        assert duplicate.number is None and set(os.listdir('/proc/self/fd'))==before
        for frame in (rt.packet('wrong','helper',child._in_seq,'EXIT',pid=child.process.pid,code=0,deadline=time.monotonic()+10),
                      rt.packet(child._nonce,'helper',child._in_seq+1,'EXIT',pid=child.process.pid,code=0,deadline=time.monotonic()+10)):
            with unittest.TestCase().assertRaises(rt.OwnershipError):child._accept(frame,[])
        assert child.process.is_running()
        with mock.patch.object(child,'actual_exited',return_value=True):
            assert child.process.poll() is None and not child.process.is_running()
        child.close();save(child)
        # Late pump delivery cannot fabricate a positive ACK from booleans.
        owner=object.__new__(rt.Child);owner.process=types.SimpleNamespace(pid=43000,returncode=0)
        owner._nonce='model';owner._in_seq=3;owner.settlement=None;owner.actual_exited=lambda:False
        frame=rt.packet('model','helper',3,'SETTLED',pid=43000,code=0,deadline=100,
                        actualReaped=True,allRegisteredReaped=True,echild=True,error=None,reaped=1,sample=[],reapDigest='0'*64)
        with unittest.TestCase().assertRaisesRegex(rt.OwnershipError,'incomplete actual settlement'):owner._accept(frame,[])
    run_case('ownership-late-fd-wrong-nonce-sequence-pending-status',late_and_protocol)

    def create_binding_failure():
        primary=OSError(errno.EMFILE,'helper pidfd injection');original=rt.os.pidfd_open;once=[False];owners=[]
        def fail_once(pid,*args):
            if not once[0]:
                once[0]=True;owners.extend(driver.ACTIVE);raise primary
            return original(pid,*args)
        with mock.patch.object(rt.os,'pidfd_open',side_effect=fail_once):
            try:spawn('raise AssertionError("not released")','helper-bind-failure')
            except OSError as failure:assert failure is primary
            else:raise AssertionError('binding failure lost')
        assert len(owners)==1 and owners[0]._complete and owners[0]._helper.returncode==0
        marker=WORK/'preexec-must-not-run'
        original_send=rt.Child._send
        def kill_preexec(owner,kind,**kwargs):
            if kind=='GO':rt.signal.pidfd_send_signal(owner._actual_fd.number,signal.SIGKILL)
            return original_send(owner,kind,**kwargs)
        with mock.patch.object(rt.Child,'_send',kill_preexec):
            child=spawn('import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("BAD")','preexec-death',(marker,))
        assert child.wait(10)==-signal.SIGKILL and not marker.exists()
        save(child)
    run_case('ownership-provisional-helper-binding-preexec-death',create_binding_failure)

    def catastrophic_model():
        owner=object.__new__(rt.Child);active={owner}
        error=rt.OwnershipError('modeled catastrophic supervisor death')
        owner.__dict__.update(_complete=False,_peer=None,_close_lock=threading.RLock(),_condition=threading.Condition(),
            cleanup_deadline=50,_helper=mock.Mock(),_helper_fd=rt.FD(999),_actual_fd=rt.FD(998),_socket=mock.Mock(),
            pump=mock.Mock(),reader=None,process=mock.Mock(),settlement=None,_protocol_error=error,
            error=error,_reader_stop=threading.Event(),_pump_stop=threading.Event(),_protocol_complete=False,_active=active)
        owner.process.returncode=None;owner.pump.ident=1;owner.pump.is_alive.return_value=False
        owner._helper.wait.return_value=0
        with mock.patch.object(rt.time,'monotonic',return_value=100), \
             mock.patch.object(rt.signal,'pidfd_send_signal') as signal_fd, \
             mock.patch.object(rt.os,'kill',side_effect=AssertionError('numeric signal')), \
             mock.patch.object(rt.os,'killpg',side_effect=AssertionError('group signal')):
            with unittest.TestCase().assertRaises(rt.OwnershipError) as caught:owner.close()
        assert caught.exception is error and owner in active and owner.settlement is None and not owner._complete
        signal_fd.assert_called_once_with(998,signal.SIGKILL)
        assert owner.cleanup_deadline==50
    run_case('ownership-catastrophic-death-explicitly-unresolved-model',catastrophic_model)

    def stale_handle():
        # Isolated sole waiter: delayed zombie binding is valid; the retained
        # handle after exact reap reports ESRCH rather than another generation.
        code='''import os,signal,time
p=os.fork()
if p==0:os._exit(23)
time.sleep(.03)
f=os.pidfd_open(p)
r=os.waitid(os.P_PIDFD,f,os.WEXITED|os.WNOWAIT);assert r.si_pid==p and r.si_status==23
r=os.waitid(os.P_PIDFD,f,os.WEXITED);assert r.si_pid==p
try:signal.pidfd_send_signal(f,signal.SIGKILL)
except ProcessLookupError:pass
else:raise AssertionError('stale handle signaled a process')
os.close(f)
'''
        child=spawn(code,'stale-handle');assert child.wait(10)==0;save(child)
    run_case('ownership-delayed-zombie-stale-retained-pidfd',stale_handle)

    def mutants():
        source=pathlib.Path(rt.__file__).read_text()
        results=[]
        def reject(label,old,new,check):
            assert old in source,label
            namespace={'__name__':'inert_mutant','__file__':rt.__file__}
            changed=source.replace(old,new,1)
            exec(compile(changed,'<'+label+'>','exec'),namespace)
            check(rt.__dict__)  # The exact production implementation must pass.
            try:check(namespace)
            except AssertionError:results.append({'mutant':label,'status':'REJECTED','sha256':driver.hashlib.sha256(changed.encode()).hexdigest()})
            else:raise AssertionError('mutant survived: '+label)
        def bad_rights(ns):
            transport=mock.Mock();transport.recvmsg.return_value=(b'{',[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[900,901]).tobytes())],0,None)
            with mock.patch.object(os,'close') as close:
                try:ns['receive'](transport)
                except json.JSONDecodeError:pass
            assert [call.args[0] for call in close.call_args_list]==[900,901]
        reject('malformed-rights-leak','                retire_all(rights)\n','                pass  # mutant drops all received rights\n',bad_rights)
        def close_detach(ns):
            handle=ns['FD'](900)
            with mock.patch.object(os,'close',side_effect=OSError('post-close fault')) as close:
                try:handle.close()
                except OSError:pass
                try:handle.close()
                except OSError:pass
            assert handle.number is None and close.call_count==1
        reject('retry-recycled-descriptor','number, self.number = self.number, None','number = self.number',close_detach)
        def deadline(ns):
            owner=object.__new__(ns['Child']);owner._condition=threading.Condition();owner.cleanup_deadline=None
            with mock.patch.object(time,'monotonic',return_value=100):owner._trigger_cleanup()
            with mock.patch.object(time,'monotonic',return_value=200):owner._trigger_cleanup()
            assert owner.cleanup_deadline==110
        reject('renewed-cleanup-budget','value if self.cleanup_deadline is None else min(self.cleanup_deadline, value)','value',deadline)
        def acquisition(ns):
            owner=ns['Supervisor'](None,'model',10,20,['inert']);owner.cap=3
            with mock.patch.object(os,'pidfd_open',return_value=900),mock.patch.object(os,'waitid',side_effect=ChildProcessError()),mock.patch.object(os,'close'):
                try:owner.acquire(43002)
                except ChildProcessError:pass
            assert not owner.handles
        reject('unchecked-child-enrollment','            os.waitid(os.P_PIDFD, handle.number, os.WEXITED | os.WNOHANG | os.WNOWAIT)\n','            pass  # mutant omits child relation\n',acquisition)
        def empty(ns):
            owner=ns['Supervisor'](None,'model',10,20,['inert'])
            with mock.patch.object(os,'waitid',return_value=None):assert not owner.empty()
        reject('quiet-census-settlement','return False  # no event is NOT ECHILD','return True  # mutant claims quiet means empty',empty)
        def pending(ns):
            facade=ns['ActualProcess'](types.SimpleNamespace(actual_exited=lambda:True),43000,['inert'],None)
            assert facade.poll() is None and not facade.is_running()
        reject('pending-exit-counted-alive','return self.returncode is None and not self.owner.actual_exited()','return self.returncode is None',pending)
        def numeric(ns):
            owner=ns['Supervisor'](None,'model',10,20,['inert'])
            with mock.patch.object(os,'kill',side_effect=AssertionError('numeric signaling')),mock.patch.object(signal,'pidfd_send_signal') as send:
                owner.signal_owned(ns['FD'](900))
                assert send.call_args.args==(900,signal.SIGKILL)
        reject('numeric-signal-authority','signal.pidfd_send_signal(handle.number, signal.SIGKILL)','os.kill(handle.number, signal.SIGKILL)',numeric)
        (WORK/'ownership-mutants.json').write_text(json.dumps(results,indent=2)+'\n')
    run_case('ownership-seven-meaningful-mutants-rejected',mutants)

    def actual_helper_faults():
        # Fresh executed Python wrappers inject faults into the exact helper;
        # they create only inert, gated fixtures and retain every abort receipt.
        original_path=pathlib.Path(rt.__file__).resolve()
        for mode in ('preflight', 'root-acquire', 'census'):
            wrapper=WORK/('helper-fault-'+mode+'.py')
            common='''import importlib.util,sys,os,errno
spec=importlib.util.spec_from_file_location('exact_child',%r)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
''' % str(original_path)
            injection={
                'preflight':'''def refused(self):raise OSError(errno.EMFILE,'injected preflight capacity')
m.Supervisor.preflight=refused
''',
                'root-acquire':'''original=m.os.pidfd_open
calls=0
def failed(pid,*args):
 global calls
 calls+=1
 if calls==2:raise OSError(errno.EMFILE,'injected gated root acquisition')
 return original(pid,*args)
m.os.pidfd_open=failed
''',
                'census':'''original=m.Supervisor.census
calls=0
def failed(self):
 global calls
 calls+=1
 if calls==2:raise OSError(errno.EMFILE,'injected cleanup census')
 return original(self)
m.Supervisor.census=failed
'''}[mode]
            wrapper.write_text(common+injection+'sys.exit(m.main())\n')
            seen=[];original_close=rt.Child.close
            def observe(owner):
                if owner not in seen:seen.append(owner)
                return original_close(owner)
            with mock.patch.object(rt,'__file__',str(wrapper)),mock.patch.object(rt.Child,'close',observe):
                if mode=='census':
                    child=spawn('import os,time; p=os.fork(); time.sleep(60) if p==0 else None','census-fault')
                    with unittest.TestCase().assertRaisesRegex(rt.OwnershipError,'injected cleanup census'):child.wait(10)
                    assert child._complete and child.settlement['reaped']==2 and child.settlement['error']
                    assert child.actual_exited() and not child.reader.is_alive() and not child.pump.is_alive()
                else:
                    marker=WORK/('refused-'+mode)
                    with unittest.TestCase().assertRaises(OSError):
                        spawn('import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("BAD")',mode,(marker,))
                    assert not marker.exists() and len(seen)==1 and seen[0]._complete
                    receipt=seen[0]._pre_go_receipt
                    assert receipt['kind']==('REFUSED' if mode=='preflight' else 'ABORTED')
                    if mode=='root-acquire':assert receipt['actualReaped'] and receipt['echild']
                    (WORK/(mode+'-abort.json')).write_text(json.dumps(receipt,indent=2))
    run_case('ownership-actual-preflight-gated-acquire-census-faults',actual_helper_faults)

    def startup_and_highfd():
        import fcntl
        phase=time.monotonic()+3
        child=driver.Child([PYTHON,'-B','-c','import time;time.sleep(60)'],log=WORK/'absolute-start.log',phase_deadline=phase)
        assert child.startup_deadline==phase
        child.close();save(child)
        fd=rt.FD(os.pidfd_open(os.getpid()))
        high=rt.FD(fcntl.fcntl(fd.number,fcntl.F_DUPFD_CLOEXEC,1100))
        try:assert not rt.readable(high.number)
        finally:high.close();fd.close()
        transport=mock.Mock()
        transport.recvmsg.return_value=(b'{}',[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[900,901]).tobytes())],socket.MSG_CTRUNC,None)
        with mock.patch.object(rt.os,'close') as close:
            with unittest.TestCase().assertRaisesRegex(rt.OwnershipError,'truncated'):rt.receive(transport)
        assert [c.args[0] for c in close.call_args_list]==[900,901]
    run_case('ownership-absolute-startup-high-fd-ctrunc-retention',startup_and_highfd)

    (WORK/'ownership-receipts.json').write_text(json.dumps(receipts,indent=2)+'\n')

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
    check_dead(child)
    passed.append("bounded-process-success-reaped")
    child = driver.Child([PYTHON, "-c", "import time; time.sleep(60)"], log=WORK / "timeout.log")
    check_failure("timeout-group-kill-reap", lambda: child.wait(.05), subprocess.TimeoutExpired)
    check_dead(child)
    child = driver.Child([PYTHON, "-c", "import time; time.sleep(60)"], log=WORK / "interrupt.log")
    original_wait = child.process.wait
    calls = [0]
    def interrupt_once(*args, **kwargs):
        calls[0] += 1
        if calls[0] == 1: raise KeyboardInterrupt()
        return original_wait(*args, **kwargs)
    with unittest.mock.patch.object(child.process, "wait", side_effect=interrupt_once):
        check_failure("interrupt-group-kill-reap", lambda: child.wait(10), KeyboardInterrupt)
    check_dead(child)
    old_limit = driver.MAX_LOG; driver.MAX_LOG = 4096
    child = driver.Child([PYTHON, "-c", "import os; os.write(1,b'x'*1000000)"], log=WORK / "overflow.log")
    check_failure("output-bound-group-kill-reap", lambda: child.wait(10), RuntimeError)
    assert child.log.stat().st_size <= driver.MAX_LOG and len(child.tail) <= 12000
    driver.MAX_LOG = old_limit
    # A descendant retains the output pipe after its parent exits. Cleanup kills the whole group.
    child = driver.Child([PYTHON, "-c", "import os,time; p=os.fork(); time.sleep(60) if p==0 else None"], log=WORK / "descendant.log")
    assert child.wait(10) == 0
    check_dead(child)
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

    ownership_controls()

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
        cancelled.close(); check_dead(cancelled)
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

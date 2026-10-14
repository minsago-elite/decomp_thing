"""Finite static resolver for recorded configured GCC shared-library links.

No tool executes here. Recorded command authenticity/completeness must be
qualified against a real authorized GCC dry-run and link inventory later.
Unknown syntax is a refusal, not an implicit empty dependency set.
"""
from pathlib import Path, PurePosixPath
import hashlib
import io
import json
import os
import posixpath
import re
import shlex
import stat

MAX_FILES = 20000
MAX_BYTES = 512 * 1024 * 1024
MAX_TEXT = 1024 * 1024
MAX_DEPTH = 32
MAX_WORDS = 20000
MAX_WORK = 200000
MAX_MANIFEST = 2 * 1024 * 1024
BLOCK = 64 * 1024


class Refusal(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def logical(path, base='/'):
    if type(path) is not str or not path or len(path) > 4096 or '\0' in path:
        raise Refusal('invalid logical link path')
    # Never normpath here: symlink/.. walks are filesystem operations. Preserve
    # exact selection spelling and apply dot components only after symlinks.
    value = posixpath.join(base, path)
    if not value.startswith('/') or value.startswith('//') or len(value) > 4096:
        raise Refusal('link paths must resolve within the absolute logical root')
    return value


def exact(value, keys):
    if type(value) is not dict or len(value) != len(keys) or any(key not in value for key in keys):
        raise Refusal('unexpected recorded link contract fields')


class Resolver:
    def __init__(self, filesystem_root):
        self.root = Path(filesystem_root)
        self.files = {}
        self.directories = {}
        self.selections = []
        self.active = set()
        self.generated = set()
        self.search = []
        self.bytes = 0
        self.cwd = '/work'
        self.work = self.io_bytes = self.entry_work = self.expanded_words = 0

    def tick(self):
        if self.work >= MAX_WORK:
            raise Refusal('shared resolution work budget')
        self.work += 1

    def resolve(self, name):
        name = logical(name, self.cwd)
        pending = name.split('/')[1:]
        parts, links = [], []
        while pending:
            self.tick()
            part = pending.pop(0)
            if part in ('', '.'):
                continue
            if part == '..':
                if not parts:
                    raise Refusal('symlink escapes logical root')
                parts.pop()
                continue
            location = '/' + '/'.join(parts + [part])
            physical = self.root / location.lstrip('/')
            metadata = physical.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(physical)
                if len(target) > 4096:
                    raise Refusal('symlink target byte budget')
                links.append({'path': location, 'target': target})
                if len(links) > 40:
                    raise Refusal('symlink cycle/depth')
                if target.startswith('/'):
                    parts = []
                pending = target.split('/') + pending
            else:
                if pending and not stat.S_ISDIR(metadata.st_mode):
                    raise Refusal('non-directory link path component')
                parts.append(part)
        return '/' + '/'.join(parts), links

    def file(self, name, *, text=False, link_input=False):
        name = logical(name, self.cwd)
        real, links = self.resolve(name)
        physical = self.root / real.lstrip('/')
        metadata = physical.stat()
        size = metadata.st_size
        if not stat.S_ISREG(metadata.st_mode) or size < 0 or size > MAX_BYTES:
            raise Refusal('not a bounded regular link input')
        fresh = name not in self.files
        if ((fresh and (len(self.files) >= MAX_FILES or size > MAX_BYTES - self.bytes)) or
                size > MAX_BYTES - self.io_bytes or (text and size > MAX_TEXT)):
            raise Refusal('link input count/remaining byte/text budget before read')
        # Reserve known work before opening. Binary inputs are hashed in blocks;
        # only admitted small text is retained for response/script parsing.
        self.io_bytes += size
        if fresh:
            self.bytes += size
        hasher = hashlib.sha256()
        chunks = []
        with physical.open('rb') as stream:
            first = stream.read(min(8, size + 1))
            binary = first.startswith((b'\x7fELF', b'!<arch>\n', b'!<thin>\n'))
            keep = text or (link_input and not binary)
            if keep and size > MAX_TEXT:
                raise Refusal('linker script text budget before full read')
            total = len(first)
            hasher.update(first)
            if keep:
                chunks.append(first)
            while total <= size:
                block = stream.read(min(BLOCK, size - total + 1))
                if not block:
                    break
                total += len(block)
                if total > size:
                    raise Refusal('link input grew beyond reserved bytes')
                hasher.update(block)
                if keep:
                    chunks.append(block)
            if total != size:
                raise Refusal('link input changed size')
        value = {'logicalPath':name, 'realpath':real, 'sha256':hasher.hexdigest(),
                 'bytes':size, 'symlinks':links}
        if name in self.files and self.files[name] != value:
            raise Refusal('link input changed during closure resolution')
        self.files[name] = value
        return b''.join(chunks) if keep else first

    def directory(self, name, recursive=False):
        name = logical(name, self.cwd)
        key = ('recursive:' if recursive else 'search:') + name
        if key in self.directories:
            return
        if len(self.directories) >= MAX_FILES:
            raise Refusal('configuration directory budget before enumeration')
        real, links = self.resolve(name)
        physical = self.root / real.lstrip('/')
        if not physical.is_dir():
            raise Refusal('link search/config root is not a directory')
        entries = []
        with os.scandir(physical) as children:
            for entry in children:
                child = Path(entry.path)
                if len(entries) >= MAX_FILES or self.entry_work >= MAX_FILES:
                    raise Refusal('directory entry budget before materialization')
                self.entry_work += 1
                self.tick()
                metadata = child.lstat()
                kind = ('symlink' if stat.S_ISLNK(metadata.st_mode) else 'directory' if stat.S_ISDIR(metadata.st_mode)
                        else 'file' if stat.S_ISREG(metadata.st_mode) else 'unsupported')
                if kind == 'unsupported':
                    raise Refusal('unsupported link configuration entry')
                row = {'name': child.name, 'kind': kind}
                if kind == 'symlink':
                    row['target'] = os.readlink(child)
                entries.append(row)
                if len(entries) > MAX_FILES:
                    raise Refusal('directory entry budget')
        entries.sort(key=lambda row: row['name'])
        self.directories[key] = {'logicalPath': name, 'realpath': real, 'symlinks': links, 'entries': entries}
        if len(self.directories) > MAX_FILES:
            raise Refusal('configuration directory budget')
        if recursive:
            for row in entries:
                child = logical(row['name'], name)
                # Directory symlinks are resolved and traversed, with active-path
                # recursion protection; target substitutions remain in closure.
                real_child, _ = self.resolve(child)
                target = self.root / real_child.lstrip('/')
                if target.is_dir():
                    if real_child in self.active:
                        raise Refusal('configuration directory cycle')
                    self.active.add(real_child)
                    try:
                        self.directory(child, True)
                    finally:
                        self.active.remove(real_child)
                else:
                    self.file(child)

    def choose(self, token, directories, *, library=False, static=False):
        self.tick()
        if len(self.selections) >= MAX_FILES:
            raise Refusal('selection budget before resolution')
        if library:
            if token.startswith(':'):
                names = [token[1:]]
            else:
                names = ['lib' + token + '.a'] if static else ['lib' + token + '.so', 'lib' + token + '.a']
        else:
            names = [token]
        if any('/' in name or not name or name in ('.', '..') for name in names):
            raise Refusal('unsupported search selection name')
        attempts = []
        for directory in directories:
            self.directory(directory)
            for name in names:
                candidate = logical(name, directory)
                try:
                    self.resolve(candidate)
                except FileNotFoundError:
                    attempts.append({'path': candidate, 'exists': False})
                    continue
                attempts.append({'path': candidate, 'exists': True})
                self.selections.append({'request': ('-l' if library else '') + token,
                                        'static': static, 'attempts': attempts, 'selected': candidate})
                return candidate
        raise Refusal('unresolved implicit link input: ' + token)

    def response(self, argv, depth=0):
        if depth > MAX_DEPTH:
            raise Refusal('response nesting budget')
        result = []
        for arg in argv:
            if arg.startswith('@'):
                if self.expanded_words >= MAX_WORDS:
                    raise Refusal('expanded word budget before response read')
                self.tick()
                name = logical(arg[1:], self.cwd)
                if name in self.active:
                    raise Refusal('response file cycle')
                self.active.add(name)
                try:
                    data = self.file(name, text=True)
                    lexer = shlex.shlex(data.decode('utf-8'), posix=True)
                    lexer.whitespace_split = True
                    lexer.commenters = ''
                    result.extend(self.response(lexer, depth + 1))
                except (UnicodeError, ValueError) as error:
                    raise Refusal('invalid response syntax') from error
                finally:
                    self.active.remove(name)
            else:
                if self.expanded_words >= MAX_WORDS:
                    raise Refusal('expanded word budget before append')
                if type(arg) is not str or len(arg) > 4096:
                    raise Refusal('expanded argument byte/type budget')
                self.tick()
                self.expanded_words += 1
                result.append(arg)
        return result

    def input(self, name, depth=0, static=False):
        name = logical(name, self.cwd)
        if name in self.generated:
            return
        if depth > MAX_DEPTH or name in self.active:
            raise Refusal('linker script cycle/depth')
        self.tick()
        data = self.file(name, link_input=True)
        if data.startswith((b'\x7fELF', b'!<arch>\n')):
            return
        if data.startswith(b'!<thin>\n'):
            raise Refusal('thin archive member closure unsupported')
        if len(data) > MAX_TEXT:
            raise Refusal('linker script budget')
        try:
            text = data.decode('ascii')
        except UnicodeError as error:
            raise Refusal('unknown binary link input') from error
        self.active.add(name)
        try:
            self.script(text, name, depth, static)
        finally:
            self.active.remove(name)

    def script(self, text, name, depth, static=False):
        # Only a finite GNU ld library-script grammar. Expressions, SECTIONS,
        # OUTPUT/STARTUP, assignments and unreviewed directives refuse.
        text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
        if '/*' in text or '*/' in text:
            raise Refusal('unterminated linker script comment')
        lexer = shlex.shlex(text, posix=True, punctuation_chars='(),;')
        lexer.whitespace_split = True
        lexer.commenters = '#'
        tokens = []
        try:
            for item in lexer:
                self.tick()
                if len(item) > 4096 and not all(c in '(),;' for c in item):
                    raise Refusal('linker script word budget')
                pieces = item if item and all(c in '(),;' for c in item) else (item,)
                for piece in pieces:
                    if len(tokens) >= MAX_FILES:
                        raise Refusal('linker script token budget before append')
                    tokens.append(piece)
        except ValueError as error:
            raise Refusal('invalid linker script quotes') from error
        position = 0
        consumed = False
        def group(inputs, nesting=0):
            nonlocal position, consumed
            if nesting > MAX_DEPTH:
                raise Refusal('linker script group depth budget')
            if position >= len(tokens) or tokens[position] != '(':
                raise Refusal('expected linker script group')
            position += 1
            count = 0
            while position < len(tokens) and tokens[position] != ')':
                token = tokens[position]; position += 1
                if token in (',', ';'):
                    continue
                if token == 'AS_NEEDED' and inputs:
                    group(True, nesting + 1); count += 1
                elif token in ('(', ')'):
                    raise Refusal('unexpected linker script punctuation')
                elif inputs:
                    if token.startswith('-l') and len(token) > 2:
                        target = self.choose(token[2:], self.search, library=True, static=static)
                    elif token.startswith('/'):
                        target = token
                    elif re.fullmatch(r'[A-Za-z0-9_.+\-]+', token):
                        target = self.choose(token, [posixpath.dirname(name), self.cwd, *self.search])
                    else:
                        raise Refusal('unknown linker script input syntax')
                    self.input(target, depth + 1, static=static)
                    consumed = True; count += 1
                else:
                    # OUTPUT_FORMAT/OUTPUT_ARCH metadata only: these fixed values
                    # describe the configured target, not arbitrary expressions.
                    if token not in ('elf64-x86-64', 'i386:x86-64'):
                        raise Refusal('unsupported linker script target')
                    count += 1
            if position >= len(tokens) or not count:
                raise Refusal('empty or unclosed linker script group')
            position += 1
        while position < len(tokens):
            token = tokens[position]; position += 1
            if token == ';':
                continue
            if token in ('INPUT', 'GROUP', 'AS_NEEDED'):
                group(True)
            elif token in ('OUTPUT_FORMAT', 'OUTPUT_ARCH'):
                group(False)
            elif token == 'SEARCH_DIR':
                if position + 2 >= len(tokens) or tokens[position] != '(' or tokens[position+2] != ')':
                    raise Refusal('invalid SEARCH_DIR syntax')
                directory = tokens[position+1]
                if directory.startswith('='):
                    directory = directory[1:]
                if not directory.startswith('/'):
                    raise Refusal('relative SEARCH_DIR unsupported')
                directory = logical(directory)
                self.directory(directory)
                self.search.append(directory)
                position += 3
            elif token == 'INCLUDE':
                if position >= len(tokens):
                    raise Refusal('missing INCLUDE path')
                target = tokens[position]; position += 1
                if not target.startswith('/'):
                    target = self.choose(target, [posixpath.dirname(name), self.cwd, *self.search])
                self.input(target, depth + 1, static=static); consumed = True
            else:
                raise Refusal('unsupported linker script directive: ' + token)
        if not consumed:
            raise Refusal('linker script has no supported inputs')

    def command(self, argv, *, expanded=False):
        argv = argv if expanded else self.response(argv)
        if not argv:
            raise Refusal('missing recorded linker command')
        self.file(argv[0])
        args = argv[1:]
        # GCC places all -L options before implicit libraries. Resolve the entire
        # ordered list before consuming inputs, as GNU ld does for this profile.
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == '-L':
                i += 1
                if i >= len(args): raise Refusal('missing -L operand')
                self.search.append(logical(args[i], self.cwd))
            elif arg.startswith('-L'):
                self.search.append(logical(arg[2:], self.cwd))
            i += 1
        if not self.search:
            raise Refusal('explicit recorded link search paths required')
        for directory in self.search:
            self.directory(directory)
        static = False
        stack = []
        i = 0
        noarg = {'-shared', '--eh-frame-hdr', '--hash-style=gnu', '--hash-style=both', '--build-id',
                 '--no-undefined', '--as-needed', '--no-as-needed', '-Bsymbolic', '--enable-new-dtags'}
        while i < len(args):
            arg = args[i]; i += 1
            if arg in noarg:
                continue
            if arg == '--push-state':
                stack.append(static); continue
            if arg == '--pop-state':
                if not stack: raise Refusal('unbalanced linker state')
                static = stack.pop(); continue
            if arg in ('-Bstatic', '-static'):
                static = True; continue
            if arg in ('-Bdynamic', '-dynamic'):
                static = False; continue
            if arg == '-L':
                i += 1; continue
            if arg.startswith('-L'):
                continue
            if arg in ('-o', '-m', '-z', '-plugin'):
                if i >= len(args): raise Refusal('missing linker operand')
                operand = args[i]; i += 1
                if arg == '-o':
                    if logical(operand, self.cwd) not in self.generated:
                        raise Refusal('unbound linker output')
                elif arg == '-m' and operand != 'elf_x86_64':
                    raise Refusal('unsupported linker emulation')
                elif arg == '-z' and operand not in ('relro', 'now', 'noexecstack'):
                    raise Refusal('unsupported linker -z policy')
                elif arg == '-plugin':
                    self.file(operand)
                continue
            if arg.startswith('-plugin-opt='):
                operand = arg[len('-plugin-opt='):]
                if operand.startswith('-pass-through=-l'):
                    # Passed-through library is still selected by its real -l
                    # operand; plugin option bytes remain in recorded argv.
                    if operand[len('-pass-through='):] not in args:
                        raise Refusal('unmatched plugin pass-through library')
                elif operand.startswith('-fresolution='):
                    if logical(operand[len('-fresolution='):], self.cwd) not in self.generated:
                        raise Refusal('unbound generated plugin resolution file')
                elif operand.startswith('/'):
                    self.file(operand)
                else:
                    raise Refusal('unknown plugin option')
                continue
            if arg in ('-T', '--script'):
                if i >= len(args): raise Refusal('missing script operand')
                self.input(args[i], static=static); i += 1; continue
            if arg.startswith('-l') and len(arg) > 2:
                self.input(self.choose(arg[2:], self.search, library=True, static=static), static=static); continue
            if arg.startswith('-'):
                raise Refusal('unsupported linker option: ' + arg)
            self.input(arg, static=static)
        if stack:
            raise Refusal('unbalanced linker state')


def dry_lines(text):
    if type(text) is not str or len(text) > MAX_TEXT or len(text.encode()) > MAX_TEXT:
        raise Refusal('dry-run recording budget')
    for index, line in enumerate(io.StringIO(text)):
        if index >= MAX_FILES:
            raise Refusal('dry-run metadata line budget')
        yield line


def recorded_command(text):
    if type(text) is not str or len(text) > MAX_TEXT or len(text.encode()) > MAX_TEXT:
        raise Refusal('dry-run recording budget')
    commands = []
    for line in dry_lines(text):
        stripped = line.strip()
        if not stripped:
            continue
        if line[:1].isspace() and stripped.startswith(('/', '"/')):
            try:
                if commands:
                    raise Refusal('multiple link commands')
                lexer = shlex.shlex(stripped, posix=True)
                lexer.whitespace_split = True
                lexer.commenters = ''
                words = []
                for word in lexer:
                    if len(words) >= MAX_WORDS or len(word) > 4096:
                        raise Refusal('recorded command word budget before append')
                    words.append(word)
                commands.append(words)
            except ValueError as error:
                raise Refusal('invalid dry-run shell quoting') from error
        elif (stripped.startswith(('Using built-in specs.', 'Reading specs from ', 'COLLECT_GCC=',
                                   'COLLECT_LTO_WRAPPER=', 'Target:', 'Configured with:', 'Thread model:',
                                   'Supported LTO compression algorithms:', 'gcc version ', 'COMPILER_PATH=',
                                   'LIBRARY_PATH=', 'COLLECT_GCC_OPTIONS='))):
            continue
        else:
            raise Refusal('unknown GCC dry-run output')
    if len(commands) != 1:
        raise Refusal('exactly one configured link command required')
    return commands[0]


def validate_manifest(manifest):
    exact(manifest, ('schemaVersion', 'driverArgv', 'dryRun', 'workingDirectory', 'environment',
                     'tools', 'specs', 'configurationRoots', 'generatedFiles'))
    if type(manifest['schemaVersion']) is not int or manifest['schemaVersion'] != 3:
        raise Refusal('recorded link manifest version')
    expected = ['/usr/bin/gcc', '-shared', '-Wl,-z,relro,-z,now,-z,noexecstack,--no-undefined',
                '/work/candidate.o', '-o', '/work/libcandidate.so']
    if manifest['driverArgv'] != expected or manifest['workingDirectory'] != '/work':
        raise Refusal('configured candidate link command changed')
    if manifest['environment'] != {'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C', 'TMPDIR':'/tmp'}:
        raise Refusal('configured link environment changed')
    exact(manifest['tools'], ('gcc', 'cc1', 'collect2', 'as', 'ld'))
    if manifest['tools']['gcc'] != '/usr/bin/gcc':
        raise Refusal('driver identity changed')
    for key in ('specs', 'configurationRoots', 'generatedFiles'):
        if type(manifest[key]) is not list or len(manifest[key]) > 128 or any(type(p) is not str or len(p) > 4096 or not p.startswith('/') for p in manifest[key]):
            raise Refusal('invalid recorded link path inventory')
    if not manifest['configurationRoots'] or not {'/work/candidate.o', '/work/libcandidate.so'} <= set(manifest['generatedFiles']):
        raise Refusal('missing configuration/generated inventory')
    root_count = sum(len(manifest[key]) for key in ('specs', 'configurationRoots', 'generatedFiles'))
    if root_count > 128:
        raise Refusal('combined recorded root budget')
    for path in [*manifest['tools'].values(), *manifest['specs'], *manifest['configurationRoots'], *manifest['generatedFiles']]:
        if type(path) is not str or not path.startswith('/'):
            raise Refusal('recorded inventory path type')
        logical(path)
    if any(len(set(manifest[key])) != len(manifest[key]) for key in ('specs', 'configurationRoots')):
        raise Refusal('duplicate recorded inventory root')
    command = recorded_command(manifest['dryRun'])
    if command[0] != manifest['tools']['collect2']:
        raise Refusal('unexpected GCC link executor')
    return command


def collect(manifest, filesystem_root):
    command = validate_manifest(manifest)
    resolver = Resolver(filesystem_root)
    base_generated = {'/work/candidate.o', '/work/libcandidate.so'}
    if len(set(manifest['generatedFiles'])) != len(manifest['generatedFiles']):
        raise Refusal('duplicate generated input identity')
    for name in set(manifest['generatedFiles']) - base_generated:
        if re.fullmatch(r'/tmp/cc[A-Za-z0-9_]+\.res', name) is None:
            raise Refusal('unknown generated link file')
    resolver.generated = set(manifest['generatedFiles'])
    for name in manifest['tools'].values(): resolver.file(name)
    for name in manifest['specs']: resolver.file(name)
    for name in manifest['configurationRoots']: resolver.directory(name, True)
    for line in dry_lines(manifest['dryRun']):
        line = line.strip()
        if line.startswith('Reading specs from '):
            name = line[len('Reading specs from '):]
            if name not in manifest['specs']:
                raise Refusal('unlisted GCC specs dependency')
        elif line.startswith('COLLECT_LTO_WRAPPER='):
            resolver.file(line.split('=', 1)[1])
    expanded = resolver.response(command)
    resolutions = {arg.split('-fresolution=', 1)[1] for arg in expanded
                   if arg.startswith('-plugin-opt=-fresolution=')}
    if resolutions != resolver.generated - base_generated:
        raise Refusal('generated plugin inventory differs from command')
    resolver.command(expanded, expanded=True)
    paths = [row['logicalPath'] for row in resolver.files.values()]
    for suffix in ('crti.o', 'crtn.o', 'crtbeginS.o', 'crtendS.o'):
        if not any(PurePosixPath(path).name == suffix for path in paths):
            raise Refusal('missing shared-link startup input: ' + suffix)
    for request in ('-lc', '-lgcc', '-lgcc_s'):
        if not any(row['request'] == request for row in resolver.selections):
            raise Refusal('missing configured default library: ' + request)
    return {'schemaVersion':3, 'manifest':manifest, 'expandedLinkArgv':expanded,
            'files':dict(sorted(resolver.files.items())), 'directories':dict(sorted(resolver.directories.items())),
            'selections':resolver.selections, 'status':'static-recording-unqualified'}


def revalidate(pin, filesystem_root):
    exact(pin, ('schemaVersion', 'manifest', 'expandedLinkArgv', 'files', 'directories', 'selections', 'status'))
    rebuilt = collect(pin['manifest'], filesystem_root)
    if canonical(rebuilt) != canonical(pin):
        raise Refusal('implicit link closure drift or new selection/configuration input')
    return rebuilt

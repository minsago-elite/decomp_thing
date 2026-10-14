"""Pure operational byte closure. Neither recorded build inputs nor ELF edges qualify a host.

The finite declared SONAME selection is checked against every reachable ELF byte
edge. Actual GCC/header/link and dynamic-loader selection remain native gates.
"""
from pathlib import PurePosixPath
import json
import re
import struct

MAX_IMAGES = 128
MAX_INPUTS = 128
MAX_IMAGE = 16 * 1024 * 1024
MAX_CACHE = 1024 * 1024
ROLES = ('header', 'tool', 'startup', 'library', 'configuration')


def path(value, l):
    if (type(value) is not str or len(value.encode()) > 4096 or not value.startswith('/') or
            value.startswith('//') or '\0' in value or str(PurePosixPath(value)) != value or
            '..' in PurePosixPath(value).parts):
        raise l.Refusal('canonical absolute operational input path required')
    return value


def libraries(value, l):
    if type(value) is not list or not 0 < len(value) <= MAX_IMAGES:
        raise l.Refusal('nonempty bounded runtime library inventory required')
    result = {}
    for row in value:
        l.exact(row, ('soname', 'path'))
        name = row['soname']
        if (type(name) is not str or re.fullmatch(r'[A-Za-z0-9_.+\-]{1,255}', name) is None or
                name in result or PurePosixPath(path(row['path'], l)).name != name):
            raise l.Refusal('duplicate/malformed runtime SONAME selection')
        result[name] = row['path']
    return result


def validate_monitor(record, l):
    l.exact(record, ('schemaVersion', 'binaryPath', 'sourcePath', 'parserPath', 'protocolPath',
                     'buildScriptPath', 'provisioningManifestPath', 'buildInputs', 'runtimeLibraries', 'cachePath'))
    if type(record['schemaVersion']) is not int or record['schemaVersion'] != 1 or record['cachePath'] != '/etc/ld.so.cache':
        raise l.Refusal('closed monitor operational record required')
    for key in ('binaryPath', 'sourcePath', 'parserPath', 'protocolPath', 'buildScriptPath', 'provisioningManifestPath'):
        path(record[key], l)
    values = record['buildInputs']
    if type(values) is not list or not 0 < len(values) <= MAX_INPUTS:
        raise l.Refusal('nonempty bounded monitor build inventory required')
    seen = set(); roles = set()
    for row in values:
        l.exact(row, ('role', 'path'))
        if row['role'] not in ROLES or path(row['path'], l) in seen:
            raise l.Refusal('invalid or duplicate recorded monitor build input')
        seen.add(row['path']); roles.add(row['role'])
    if roles != set(ROLES):
        raise l.Refusal('monitor header/tool/startup/library/configuration inventory missing')
    libraries(record['runtimeLibraries'], l)


def validate_inspection(record, l):
    l.exact(record, ('schemaVersion', 'bashPath', 'scriptPath', 'cachePath', 'runtimeLibraries'))
    if (type(record['schemaVersion']) is not int or record['schemaVersion'] != 1 or
            record['bashPath'] != '/bin/bash' or record['scriptPath'] != '/usr/bin/ldd' or
            record['cachePath'] != '/etc/ld.so.cache'):
        raise l.Refusal('fixed Bash/ldd/cache inspection record required')
    libraries(record['runtimeLibraries'], l)


def strict_json(raw, l):
    if type(raw) is not bytes or not 0 < len(raw) <= l.MAX_MANIFEST:
        raise l.Refusal('bounded operational JSON required')
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result: raise l.Refusal('duplicate operational JSON field')
            result[key] = value
        return result
    def invalid(_): raise l.Refusal('noninteger operational JSON number')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise l.Refusal('malformed operational JSON') from error


def elf(raw, l):
    """Finite ELF64/x86-64 program/dynamic graph metadata; no tool or loader runs."""
    def refuse(message): raise l.Refusal('unsupported/malformed operational ELF: ' + message)
    def span(offset, size):
        if offset < 0 or size < 0 or offset > len(raw) or size > len(raw) - offset: refuse('file range')
        return raw[offset:offset + size]
    if (not 64 <= len(raw) <= MAX_IMAGE or raw[:7] != b'\x7fELF\x02\x01\x01' or
            raw[7] not in (0, 3) or raw[8:16] != b'\0' * 8): refuse('identity')
    header = struct.unpack('<HHIQQQIHHHHHH', span(16, 48))
    kind, machine, version, _, phoff, _, elf_flags, ehsize, phsize, phnum, _, _, _ = header
    if kind not in (2, 3) or machine != 62 or version != 1 or elf_flags != 0 or ehsize != 64 or phsize != 56 or not 1 <= phnum <= 128:
        refuse('header/profile')
    span(phoff, phnum * 56)
    loads = []; dynamic = []; interpreters = []
    for index in range(phnum):
        typ, flags, offset, address, _, filesz, memsz, _ = struct.unpack('<IIQQQQQQ', span(phoff + index * 56, 56))
        span(offset, filesz)
        if typ == 1:
            if filesz > memsz: refuse('load memory extent')
            loads.append((address, filesz, offset, flags))
        elif typ == 2: dynamic.append((offset, address, filesz))
        elif typ == 3:
            text = span(offset, filesz)
            if not 2 <= len(text) <= 4096 or text[-1:] != b'\0' or b'\0' in text[:-1]: refuse('interpreter')
            try: interpreters.append(path(text[:-1].decode('ascii'), l))
            except (ValueError, UnicodeError): refuse('interpreter path')
    if not loads or len(dynamic) != 1 or len(interpreters) > 1: refuse('program metadata multiplicity')
    def mapped(address, size):
        values = [offset + address - base for base, length, offset, _ in loads
                  if base <= address and address - base <= length and size <= length - (address - base)]
        if len(values) != 1: refuse('ambiguous/unmapped dynamic virtual address')
        return values[0]
    offset, address, size = dynamic[0]
    if not 16 <= size <= 4096 or size % 16 or mapped(address, size) != offset: refuse('dynamic load mapping')
    tags = {}; terminated = False
    # Only these metadata tags are accepted; search/auxiliary/audit/filter inputs refuse.
    allowed = set(range(0, 15)) | set(range(16, 29)) | {30, 32, 33, 35, 36, 37,
        0x70000000, 0x70000001, 0x70000003,
        0x6ffffef5, 0x6ffffff0, 0x6ffffff9, 0x6ffffffb, 0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff}
    for at in range(offset, offset + size, 16):
        tag, value = struct.unpack('<qQ', span(at, 16))
        if terminated:
            if tag or value: refuse('data after dynamic terminator')
            continue
        if tag == 0:
            if value: refuse('nonzero dynamic terminator')
            terminated = True; continue
        if tag not in allowed: refuse('dynamic tag/search/audit/filter')
        tags.setdefault(tag, []).append(value)
    if not terminated or len(tags.get(5, [])) != 1 or len(tags.get(10, [])) != 1: refuse('dynamic string table')
    if any(len(values) != 1 for tag, values in tags.items() if tag != 1): refuse('duplicate dynamic metadata')
    if tags.get(30, [0])[0] & ~(2 | 8 | 16) or tags.get(0x6ffffffb, [0])[0] & ~(1 | 8 | 0x08000000):
        refuse('unsupported dynamic selection flags')
    # Optional x86-64 psABI PLT metadata. Complete trio is our supported-profile
    # restriction, not a claim of instruction/relocation or native qualification.
    plt_tags = (0x70000000, 0x70000001, 0x70000003)
    if any(tag in tags for tag in plt_tags):
        if not all(tag in tags for tag in plt_tags): refuse('incomplete x86-64 PLT metadata')
        address, size, entry = (tags[tag][0] for tag in plt_tags)
        if (not address or not size or not entry or entry & (entry - 1) or
                size < entry or size % entry or address % entry or
                size > (1 << 64) - 1 - address):
            refuse('x86-64 PLT metadata extent/alignment')
        mapped(address, size)  # Preserve refusal of ambiguous file-backed mappings.
        matches = [flags for base, length, _, flags in loads
                   if base <= address and address - base <= length and size <= length - (address - base)]
        if not matches[0] & 1: refuse('x86-64 PLT requires executable file-backed load')
    length = tags[10][0]
    if not 0 < length <= 1024 * 1024: refuse('dynamic string byte budget')
    strings = span(mapped(tags[5][0], length), length)
    if strings[:1] != b'\0': refuse('string table initial terminator')
    def string(index):
        if index >= len(strings): refuse('string offset')
        end = strings.find(b'\0', index)
        if end < 0 or end - index > 255: refuse('bounded SONAME terminator')
        try: value = strings[index:end].decode('ascii')
        except UnicodeError: refuse('SONAME encoding')
        if re.fullmatch(r'[A-Za-z0-9_.+\-]{1,255}', value) is None: refuse('SONAME path/search syntax')
        return value
    needed = [string(index) for index in tags.get(1, [])]
    if len(needed) > 128 or len(set(needed)) != len(needed) or len(tags.get(14, [])) > 1: refuse('dependency count/duplicate')
    soname = string(tags[14][0]) if 14 in tags else None
    return {'type':kind, 'interpreter': interpreters[0] if interpreters else None, 'needed': needed, 'soname': soname}


def graph(binary, inventory, resolver, l, files):
    selections = libraries(inventory, l)
    pending = [binary]; seen = {}; used = set()
    while pending:
        name = pending.pop(0)
        if name in seen: continue
        if len(seen) >= MAX_IMAGES: raise l.Refusal('runtime ELF image count before read')
        raw = resolver.file(name, binary_data=True, maximum=MAX_IMAGE)
        files[name] = resolver.files[name]
        info = elf(raw, l); seen[name] = info
        if name == binary:
            if info['interpreter'] is None or info['interpreter'] == binary or not info['needed']:
                raise l.Refusal('dynamic operational executable/loader/nonempty dependencies required')
            pending.append(info['interpreter'])
        elif info['interpreter'] is not None or info['type'] != 3:
            raise l.Refusal('runtime dependency must not be another executable interpreter')
        for soname in info['needed']:
            if soname not in selections: raise l.Refusal('missing transitive runtime SONAME: ' + soname)
            used.add(soname); target = selections[soname]
            if target not in seen and target not in pending:
                if len(seen) + len(pending) >= MAX_IMAGES: raise l.Refusal('runtime graph work bound')
                pending.append(target)
    if used != set(selections): raise l.Refusal('extra/unreachable runtime dependency selection')
    for soname in used:
        if seen[selections[soname]]['soname'] != soname:
            raise l.Refusal('runtime SONAME and selected ELF disagree')
    return dict(sorted(seen.items()))


def collect_monitor(record, resolver, l):
    validate_monitor(record, l); files = {}
    for key in ('sourcePath', 'parserPath', 'protocolPath', 'buildScriptPath', 'provisioningManifestPath'):
        resolver.file(record[key], text=True); files[record[key]] = resolver.files[record[key]]
    raw = resolver.file(record['provisioningManifestPath'], text=True)
    provision = strict_json(raw, l)
    l.exact(provision, ('schemaVersion', 'status', 'binaryPath', 'binarySha256', 'sourceSha256', 'protocolSha256',
                        'parserSha256', 'dependencies', 'buildCommand', 'execution'))
    if type(provision['schemaVersion']) is not int or provision['schemaVersion'] != 1 or provision['status'] != 'provisioning-only-unqualified':
        raise l.Refusal('provisioning record cannot qualify monitor inputs')
    expected = ['/usr/bin/gcc', '-D_GNU_SOURCE', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-Wl,-z,relro,-z,now,-z,noexecstack', record['sourcePath'], '-o', record['binaryPath']]
    if provision['binaryPath'] != record['binaryPath'] or provision['buildCommand'] != expected:
        raise l.Refusal('fixed recorded monitor build command changed')
    if type(provision['dependencies']) is not list or len(provision['dependencies']) > MAX_IMAGES or type(provision['execution']) is not dict:
        raise l.Refusal('malformed provisioning-only record')
    for row in provision['dependencies']:
        l.exact(row, ('path', 'sha256')); path(row['path'], l)
        if type(row['sha256']) is not str or re.fullmatch('[0-9a-f]{64}', row['sha256']) is None:
            raise l.Refusal('malformed provisioning-only dependency hash')
    for row in record['buildInputs']:
        resolver.file(row['path']); files[row['path']] = resolver.files[row['path']]
    if '/usr/bin/gcc' not in files: raise l.Refusal('monitor compiler build input missing')
    images = graph(record['binaryPath'], record['runtimeLibraries'], resolver, l, files)
    cache = record['cachePath']; resolver.file(cache, maximum=MAX_CACHE); files[cache] = resolver.files[cache]
    if not 0 < files[cache]['bytes'] <= MAX_CACHE or files[cache]['symlinks'] or files[cache]['realpath'] != cache:
        raise l.Refusal('exact bounded loader cache file required')
    for field, key in [('binarySha256','binaryPath'), ('sourceSha256','sourcePath'), ('parserSha256','parserPath'), ('protocolSha256','protocolPath')]:
        if provision[field] != files[record[key]]['sha256']:
            raise l.Refusal('provisioning source/binary byte binding drift')
    # The provisioning list is never used as runtime inventory or completeness authority.
    return {'schemaVersion':1, 'status':'static-recording-unqualified', 'selectionStatus':'declared-selection-native-unqualified',
            'buildInputStatus':'recorded-build-inputs-unqualified', 'record':record, 'buildCommand':expected,
            'files':dict(sorted(files.items())), 'elfGraph':images}


def collect_inspection(record, resolver, l):
    validate_inspection(record, l); files = {}
    script = resolver.file(record['scriptPath'], text=True); files[record['scriptPath']] = resolver.files[record['scriptPath']]
    if script.split(b'\n', 1)[0] != b'#!/bin/bash' or b'\n' not in script:
        raise l.Refusal('supported single fixed Bash shebang required')
    images = graph(record['bashPath'], record['runtimeLibraries'], resolver, l, files)
    cache = record['cachePath']; resolver.file(cache, maximum=MAX_CACHE); files[cache] = resolver.files[cache]
    if not 0 < files[cache]['bytes'] <= MAX_CACHE or files[cache]['symlinks'] or files[cache]['realpath'] != cache:
        raise l.Refusal('exact bounded loader cache file required')
    return {'schemaVersion':1, 'status':'static-recording-unqualified', 'selectionStatus':'declared-selection-native-unqualified',
            'record':record, 'files':dict(sorted(files.items())), 'elfGraph':images}

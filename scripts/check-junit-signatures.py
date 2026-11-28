#!/usr/bin/env python3
"""Reject non-void ordinary JUnit methods from bounded class-file metadata, without loading classes.

This checks return signatures, not all JUnit discovery conditions or JVM bytecode validity.
JVMS 4 class framing, method descriptors and declaration annotations are read directly.
Code and other irrelevant attribute bodies remain opaque, bounded byte sequences.
"""

import argparse
from collections import defaultdict, deque
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys


ORDINARY = frozenset({
    "Lorg/junit/Test;",
    "Lorg/junit/jupiter/api/Test;",
    "Lorg/junit/jupiter/api/RepeatedTest;",
    "Lorg/junit/jupiter/api/TestTemplate;",
    "Lorg/junit/jupiter/params/ParameterizedTest;",
})
FACTORY = "Lorg/junit/jupiter/api/TestFactory;"
MAX_CLASS_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_CLASSES = 20_000
MAX_ENTRIES = 100_000
MAX_DIRECTORY_DEPTH = 64
MAX_METHODS = 250_000
MAX_ANNOTATION_NODES = 100_000
MAX_DEPTH = 32
MAX_IDENTIFIER = 4096
MAX_REPORT_BYTES = 16 * 1024 * 1024


class InvalidClass(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidClass(message)


class Reader:
    def __init__(self, data):
        self.data = memoryview(data)
        self.position = 0

    def take(self, count):
        require(0 <= count <= len(self.data) - self.position, "truncated class-file structure")
        value = self.data[self.position:self.position + count]
        self.position += count
        return value

    def u1(self):
        return self.take(1)[0]

    def u2(self):
        return struct.unpack(">H", self.take(2))[0]

    def u4(self):
        return struct.unpack(">I", self.take(4))[0]

    def finish(self):
        require(self.position == len(self.data), "trailing bytes in class-file structure")


def modified_utf8(raw):
    """Decode JVM UTF-16 code units, including encoded NUL and supplementary pairs."""
    raw = bytes(raw)
    if raw.isascii() and b"\0" not in raw:
        return raw.decode("ascii")
    units = bytearray()
    index = 0
    while index < len(raw):
        first = raw[index]
        index += 1
        if 0 < first < 0x80:
            value = first
        elif 0xC0 <= first <= 0xDF:
            require(index < len(raw) and raw[index] & 0xC0 == 0x80, "malformed modified UTF-8")
            value = ((first & 0x1F) << 6) | (raw[index] & 0x3F)
            index += 1
            require(value >= 0x80 or (first == 0xC0 and value == 0), "overlong modified UTF-8")
        elif 0xE0 <= first <= 0xEF:
            require(index + 1 < len(raw) and raw[index] & 0xC0 == 0x80 and raw[index + 1] & 0xC0 == 0x80,
                    "malformed modified UTF-8")
            value = ((first & 15) << 12) | ((raw[index] & 63) << 6) | (raw[index + 1] & 63)
            index += 2
            require(value >= 0x800, "overlong modified UTF-8")
        else:
            raise InvalidClass("unsupported or malformed modified UTF-8 byte")
        units.extend(struct.pack(">H", value))
    return units.decode("utf-16-be", errors="surrogatepass")


def field_end(descriptor, start, allow_void=False):
    require(start < len(descriptor), "truncated descriptor")
    position = start
    while position < len(descriptor) and descriptor[position] == "[":
        position += 1
    require(position - start <= 255 and position < len(descriptor), "invalid array descriptor")
    kind = descriptor[position]
    if kind in "BCDFIJSZ" or (allow_void and position == start and kind == "V"):
        return position + 1
    require(kind == "L", "invalid descriptor type")
    end = descriptor.find(";", position + 1)
    require(end > position + 1, "invalid object descriptor")
    name = descriptor[position + 1:end]
    require(not any(c in name for c in ".;[") and all(name.split("/")), "invalid descriptor class name")
    return end + 1


def method_return(descriptor):
    require(descriptor.startswith("("), "invalid method descriptor")
    position = 1
    while position < len(descriptor) and descriptor[position] != ")":
        position = field_end(descriptor, position)
    require(position < len(descriptor), "unterminated method descriptor")
    result = descriptor[position + 1:]
    require(field_end(result, 0, allow_void=True) == len(result), "trailing method descriptor bytes")
    return result


def parse_class(data):
    require(len(data) <= MAX_CLASS_BYTES, "class exceeds byte limit")
    reader = Reader(data)
    require(reader.u4() == 0xCAFEBABE, "invalid class-file magic")
    minor, major = reader.u2(), reader.u2()
    require(45 <= major <= 65 and (minor == 0 or (major == 45 and minor <= 3)),
            f"unsupported class version {major}.{minor}; require non-preview JVM 1.1 through 21")
    count = reader.u2()
    require(count > 0, "empty constant pool")
    pool = [None] * count
    index = 1
    while index < count:
        tag = reader.u1()
        if tag == 1:
            value = modified_utf8(reader.take(reader.u2()))
        elif tag in (3, 4):
            value = reader.take(4)
        elif tag in (5, 6):
            value = reader.take(8)
        elif tag in (7, 8, 16, 19, 20):
            value = reader.u2()
        elif tag in (9, 10, 11, 12, 17, 18):
            value = (reader.u2(), reader.u2())
        elif tag == 15:
            value = (reader.u1(), reader.u2())
        else:
            raise InvalidClass(f"unsupported constant-pool tag {tag}")
        pool[index] = (tag, value)
        index += 1
        if tag in (5, 6):
            require(index < count, "wide constant has no reserved slot")
            index += 1

    def constant(index, tags):
        require(0 < index < count and pool[index] is not None and pool[index][0] in tags,
                f"invalid constant-pool reference {index}, expected tags {sorted(tags)}")
        return pool[index][1]

    def text(index, identifier=False):
        value = constant(index, {1})
        if identifier:
            require(0 < len(value) <= MAX_IDENTIFIER, "empty or oversized metadata identifier")
        return value

    # Validate the references in all constant-pool entries, including forward references.
    for entry in pool[1:]:
        if entry is None:
            continue
        tag, value = entry
        if tag in (7, 8, 16, 19, 20):
            constant(value, {1})
        elif tag in (9, 10, 11):
            constant(value[0], {7}); constant(value[1], {12})
        elif tag == 12:
            constant(value[0], {1}); constant(value[1], {1})
        elif tag in (17, 18):
            constant(value[1], {12})  # The first value is a bootstrap-table index, not a CP index.
        elif tag == 15:
            kind, reference = value
            require(1 <= kind <= 9, "invalid method-handle reference kind")
            constant(reference, {9} if kind <= 4 else ({11} if kind == 9 else {10, 11}))

    nodes = 0

    def annotation(part, depth):
        nonlocal nodes
        nodes += 1
        require(depth <= MAX_DEPTH and nodes <= MAX_ANNOTATION_NODES, "annotation metadata exceeds bounds")
        descriptor = text(part.u2(), True)
        require(descriptor.startswith("L") and field_end(descriptor, 0) == len(descriptor), "invalid annotation descriptor")
        names = set()
        for _ in range(part.u2()):
            name = text(part.u2(), True)
            require(name not in names, "duplicate annotation element")
            names.add(name)
            element(part, depth + 1)
        return descriptor

    def element(part, depth):
        nonlocal nodes
        nodes += 1
        require(depth <= MAX_DEPTH and nodes <= MAX_ANNOTATION_NODES, "annotation metadata exceeds bounds")
        tag = chr(part.u1())
        scalar = {"B": 3, "C": 3, "I": 3, "S": 3, "Z": 3, "D": 6, "F": 4, "J": 5, "s": 1}
        if tag in scalar:
            constant(part.u2(), {scalar[tag]})
        elif tag == "e":
            text(part.u2(), True); text(part.u2(), True)
        elif tag == "c":
            descriptor = text(part.u2(), True)
            require(field_end(descriptor, 0, allow_void=True) == len(descriptor), "invalid annotation class descriptor")
        elif tag == "@":
            annotation(part, depth + 1)
        elif tag == "[":
            for _ in range(part.u2()):
                element(part, depth + 1)
        else:
            raise InvalidClass(f"unsupported annotation element tag {tag!r}")

    def attributes():
        annotations = set()
        seen = set()
        for _ in range(reader.u2()):
            name = text(reader.u2(), True)
            part = Reader(reader.take(reader.u4()))
            if name in ("RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations"):
                require(name not in seen, "duplicate declaration-annotation attribute")
                seen.add(name)
                declared = [annotation(part, 0) for _ in range(part.u2())]
                require(len(set(declared)) == len(declared), "duplicate declaration annotation")
                annotations.update(declared)
                part.finish()
            # JVMS permits other/custom attributes; their framed bodies are intentionally opaque.
        return sorted(annotations)

    flags = reader.u2()
    name = text(constant(reader.u2(), {7}), True)
    superclass = reader.u2()
    if superclass:
        constant(superclass, {7})
    for _ in range(reader.u2()):
        constant(reader.u2(), {7})
    for _ in range(reader.u2()):
        reader.u2(); text(reader.u2(), True)
        descriptor = text(reader.u2(), True)
        require(field_end(descriptor, 0) == len(descriptor), "invalid field descriptor")
        attributes()
    methods = []
    method_count = reader.u2()
    identities = set()
    for _ in range(method_count):
        access, method_name, descriptor = reader.u2(), text(reader.u2(), True), text(reader.u2(), True)
        returned = method_return(descriptor)
        require((method_name, descriptor) not in identities, "duplicate method name and descriptor")
        identities.add((method_name, descriptor))
        declared = attributes()
        if declared:
            methods.append({"name": method_name, "descriptor": descriptor, "returns": returned,
                            "annotations": declared, "access": access})
    declared = attributes()
    reader.finish()
    return {"name": name, "annotation": bool(flags & 0x2000), "annotations": declared,
            "methods": methods, "methodCount": method_count, "major": major}


def compact(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def audit(roots):
    report = {"schemaVersion": 1, "scope": "compiled-junit-return-signatures", "status": "failed",
              "classRoots": [str(root.absolute()) for root in roots], "classes": [], "methods": [],
              "violations": [], "errors": [], "totalBytes": 0, "totalMethods": 0,
              "supportedOrdinaryAnnotations": sorted(ORDINARY), "factoryAnnotation": FACTORY}
    budget = len(compact(report))
    parsed = {}

    def record(collection, value):
        nonlocal budget
        budget += len(compact(value)) + 1
        require(budget <= MAX_REPORT_BYTES - 16384, "discovery evidence exceeds report byte limit")
        report[collection].append(value)

    try:
        require(1 <= len(roots) <= 16, "require one through sixteen class roots")
        entries = 0
        paths = set()
        for root_index, root in enumerate(roots):
            require(not root.is_symlink() and root.is_dir(), f"missing or linked class root: {root}")
            canonical = root.resolve()
            require(canonical not in paths, "duplicate class root")
            paths.add(canonical)
            def walk_error(error):
                raise error

            for directory, folders, files in os.walk(root, followlinks=False, onerror=walk_error):
                require(len(Path(directory).relative_to(root).parts) <= MAX_DIRECTORY_DEPTH,
                        "class-root directory depth exceeds limit")
                folders.sort(); files.sort()
                entries += len(folders) + len(files)
                require(entries <= MAX_ENTRIES, "class-root entry limit exceeded")
                for child in folders + files:
                    require(not Path(directory, child).is_symlink(), "linked entry in class root")
                for filename in files:
                    if not filename.endswith(".class"):
                        continue
                    path = Path(directory, filename)
                    require(len(parsed) < MAX_CLASSES, "class count limit exceeded")
                    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
                        before = os.fstat(stream.fileno())
                        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_CLASS_BYTES,
                                "nonregular or oversized class input")
                        data = stream.read(MAX_CLASS_BYTES + 1)
                        after = os.fstat(stream.fileno())
                        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                                len(data) == before.st_size, "class changed during metadata capture")
                    report["totalBytes"] += len(data)
                    require(report["totalBytes"] <= MAX_TOTAL_BYTES, "total class-byte limit exceeded")
                    try:
                        item = parse_class(data)
                    except InvalidClass as failure:
                        raise InvalidClass(f"{path}: {failure}") from failure
                    relative = path.relative_to(root).as_posix()
                    require(relative == item["name"] + ".class", "class binary name differs from its relative path")
                    require(item["name"] not in parsed, "duplicate binary class identity")
                    parsed[item["name"]] = item
                    report["totalMethods"] += item["methodCount"]
                    require(report["totalMethods"] <= MAX_METHODS, "method count limit exceeded")
                    record("classes", {"root": root_index, "path": relative, "bytes": len(data),
                                       "sha256": hashlib.sha256(data).hexdigest(), "major": item["major"]})
        require(parsed, "no compiled classes found")
        # Bounded graph propagation handles composed annotations and cycles without recursive expansion.
        reverse = defaultdict(set)
        for name, value in parsed.items():
            if value["annotation"]:
                for parent in value["annotations"]:
                    reverse[parent].add("L" + name + ";")
        effective_markers = defaultdict(set)
        pending = deque((marker, marker) for marker in sorted(ORDINARY | {FACTORY}))
        while pending:
            descriptor, marker = pending.popleft()
            if marker not in effective_markers[descriptor]:
                effective_markers[descriptor].add(marker)
                pending.extend((child, marker) for child in sorted(reverse[descriptor]))

        for name, item in sorted(parsed.items()):
            for method in item["methods"]:
                effective = set().union(*(effective_markers[value] for value in method["annotations"]))
                if not effective:
                    continue
                invalid = bool(effective & ORDINARY) and method["returns"] != "V"
                row = {"class": name.replace("/", "."), "method": method["name"],
                       "descriptor": method["descriptor"], "annotations": method["annotations"],
                       "effectiveAnnotations": sorted(effective), "status": "non-void-ordinary-test" if invalid else "accepted"}
                record("methods", row)
                if invalid:
                    record("violations", row)
        require(report["methods"], "no supported JUnit method annotations found")
        if not report["violations"]:
            report["status"] = "passed"
    except (InvalidClass, OSError, UnicodeError) as failure:
        report["errors"].append(str(failure)[:1024])
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--class-root", action="append", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    arguments = parser.parse_args(argv)
    report = audit(arguments.class_root)
    data = compact(report) + b"\n"
    require(len(data) <= MAX_REPORT_BYTES, "report exceeds publication limit")
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    temporary = arguments.report.with_name(arguments.report.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(arguments.report)
    for error in report["errors"]:
        print("JUnit signature guard: " + error, file=sys.stderr)
    for row in report["violations"]:
        print(f"JUnit signature guard: {row['class']}.{row['method']} {row['descriptor']} must return void", file=sys.stderr)
    print(f"JUnit signature guard: {report['status']}; {len(report['classes'])} classes, "
          f"{len(report['methods'])} annotated methods; evidence {arguments.report}")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())

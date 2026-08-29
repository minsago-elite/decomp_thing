"""Strict source-aligned build-record and ELF twin verification.

The source lock identifies what must be built.  This module defines and
verifies the next boundary: a closed build record plus a DWARF-rich ELF and
its stripped twin.  All ELF facts are derived directly from the file bytes;
the verifier does not scrape locale-sensitive ``readelf`` output.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import struct
import subprocess
import tempfile
from typing import Any, Iterable, Mapping, Sequence

from oracle.source_lock import VerificationError, load_and_validate_lock


_SHA256 = re.compile(r"[0-9a-f]{64}")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REVISION = re.compile(r"[0-9a-f]{40}")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_ENVIRONMENT_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")
_TOOL_ROLE = re.compile(r"[a-z][A-Za-z0-9]*")
_BUILD_ID = re.compile(r"(?:[0-9a-f]{2}){4,64}")
_SECRET_ENVIRONMENT_NAME = re.compile(
    r"(?:^|_)(?:AUTH(?:ORIZATION)?|CREDENTIALS?|KEY|PASSWORD|PASSWD|SECRET|TOKEN)(?:_|$)"
)
_VERSION_COMMAND_TIMEOUT_SECONDS = 30

_PT_LOAD = 1
_PT_NOTE = 4
_PF_X = 1
_SHT_SYMTAB = 2
_SHT_STRTAB = 3
_SHT_NOTE = 7
_SHT_NOBITS = 8
_SHT_DYNSYM = 11
_SHF_ALLOC = 0x2
_SHF_EXECINSTR = 0x4
_PN_XNUM = 0xFFFF
_SHN_XINDEX = 0xFFFF
_NT_GNU_BUILD_ID = 3

_ELF_CLASS_NAMES = {1: "ELF32", 2: "ELF64"}
_DATA_ENCODING_NAMES = {1: "little-endian", 2: "big-endian"}
_OS_ABI_NAMES = {
    0: "ELFOSABI_SYSV",
    1: "ELFOSABI_HPUX",
    2: "ELFOSABI_NETBSD",
    3: "ELFOSABI_GNU",
    6: "ELFOSABI_SOLARIS",
    7: "ELFOSABI_AIX",
    8: "ELFOSABI_IRIX",
    9: "ELFOSABI_FREEBSD",
    12: "ELFOSABI_OPENBSD",
}
_ELF_TYPE_NAMES = {
    0: "ET_NONE",
    1: "ET_REL",
    2: "ET_EXEC",
    3: "ET_DYN",
    4: "ET_CORE",
}
_MACHINE_NAMES = {
    0: "EM_NONE",
    3: "EM_386",
    8: "EM_MIPS",
    20: "EM_PPC",
    21: "EM_PPC64",
    40: "EM_ARM",
    62: "EM_X86_64",
    183: "EM_AARCH64",
    243: "EM_RISCV",
}
_PROGRAM_TYPE_NAMES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO",
    0x6474E553: "PT_GNU_PROPERTY",
}
_SECTION_TYPE_NAMES = {
    0: "SHT_NULL",
    1: "SHT_PROGBITS",
    2: "SHT_SYMTAB",
    3: "SHT_STRTAB",
    4: "SHT_RELA",
    5: "SHT_HASH",
    6: "SHT_DYNAMIC",
    7: "SHT_NOTE",
    8: "SHT_NOBITS",
    9: "SHT_REL",
    10: "SHT_SHLIB",
    11: "SHT_DYNSYM",
    14: "SHT_INIT_ARRAY",
    15: "SHT_FINI_ARRAY",
    16: "SHT_PREINIT_ARRAY",
    17: "SHT_GROUP",
    18: "SHT_SYMTAB_SHNDX",
    0x6FFFFFF6: "SHT_GNU_HASH",
    0x6FFFFFFD: "SHT_GNU_VERDEF",
    0x6FFFFFFE: "SHT_GNU_VERNEED",
    0x6FFFFFFF: "SHT_GNU_VERSYM",
}


def _object(value: Any, path: str, keys: Iterable[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{path} must be an object")
    expected = set(keys)
    actual = set(value)
    if actual != expected:
        details: list[str] = []
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        if missing:
            details.append(f"missing {missing}")
        if unexpected:
            details.append(f"unexpected {unexpected}")
        raise VerificationError(f"{path} has invalid fields: {', '.join(details)}")
    return value


def _array(value: Any, path: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "a non-empty array" if nonempty else "an array"
        raise VerificationError(f"{path} must be {qualifier}")
    return value


def _string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value) or "\x00" in value:
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise VerificationError(f"{path} must be {qualifier} without NUL bytes")
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise VerificationError(f"{path} must be an integer greater than or equal to {minimum}")
    return value


def _matches(value: Any, path: str, pattern: re.Pattern[str]) -> str:
    text = _string(value, path)
    if pattern.fullmatch(text) is None:
        raise VerificationError(f"{path} has an invalid format")
    return text


def _normalized_relative_path(value: Any, path: str) -> str:
    text = _string(value, path)
    candidate = PurePosixPath(text)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or "\\" in text
        or str(candidate) != text
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise VerificationError(f"{path} must be a normalized relative POSIX path")
    return text


def _normalized_absolute_path(value: Any, path: str) -> str:
    text = _string(value, path)
    candidate = PurePosixPath(text)
    if (
        not candidate.is_absolute()
        or candidate == PurePosixPath("/")
        or "\\" in text
        or str(candidate) != text
        or any(part in {"", ".", ".."} for part in candidate.parts[1:])
    ):
        raise VerificationError(f"{path} must be a normalized non-root absolute POSIX path")
    return text


def _load_json(path: Path, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate JSON object key in {label}: {key}")
            result[key] = value
        return result

    try:
        payload = _read_regular_file(path, label)
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except OSError as error:
        raise VerificationError(f"cannot read {label} {path}: {error}") from error
    except UnicodeDecodeError as error:
        raise VerificationError(f"invalid UTF-8 in {label} {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise VerificationError(f"invalid JSON in {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{label} root must be an object")
    return value


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256_bytes(payload)


def _read_regular_file(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"{label} is not a non-symlink regular file: {path}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise VerificationError(f"cannot read {label} {path}: {error}") from error


def _resolve_within(base: Path, relative: str, label: str) -> Path:
    root = base.resolve()
    candidate = root
    for part in PurePosixPath(relative).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise VerificationError(f"{label} path contains a symbolic link: {candidate}")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise VerificationError(f"{label} escapes the manifest directory") from error
    return resolved


def _file_record(path: Path, relative: str, label: str) -> dict[str, Any]:
    payload = _read_regular_file(path, label)
    return {
        "path": relative,
        "bytes": len(payload),
        "sha256": _sha256_bytes(payload),
    }


def _relative_input_path(path: Path, manifest_directory: Path, label: str) -> str:
    absolute = path.absolute()
    try:
        relative = absolute.relative_to(manifest_directory.absolute())
    except ValueError as error:
        raise VerificationError(f"{label} must be inside the manifest directory") from error
    normalized = _normalized_relative_path(relative.as_posix(), label)
    _resolve_within(manifest_directory, normalized, label)
    return normalized


def _command(value: Any, path: str) -> list[str]:
    arguments = _array(value, path, nonempty=True)
    return [_string(argument, f"{path}[{index}]") for index, argument in enumerate(arguments)]


def validate_build_record(
    data: dict[str, Any],
    source_lock: Mapping[str, Any],
    source_lock_sha256: str,
) -> dict[str, Any]:
    """Validate a closed, source-bound ELF oracle build record."""

    schema_version = data.get("schemaVersion")
    root_fields = {
        "schemaVersion",
        "oracle",
        "environment",
        "directories",
        "commands",
        "tools",
        "outputs",
    }
    if schema_version == 2:
        root_fields.add("buildSystem")
    root = _object(
        data,
        "build record",
        root_fields,
    )
    if isinstance(schema_version, bool) or schema_version not in {1, 2}:
        raise VerificationError("build record schemaVersion must be the integer 1 or 2")
    build_system = "autoconf" if schema_version == 1 else _string(
        root["buildSystem"], "build record.buildSystem"
    )
    if build_system not in {"autoconf", "cmake-ninja"}:
        raise VerificationError("build record.buildSystem must be autoconf or cmake-ninja")

    oracle = _object(
        root["oracle"],
        "build record.oracle",
        {"id", "version", "sourceRevision", "sourceLockSha256"},
    )
    expected_oracle = source_lock["oracle"]
    if _string(oracle["id"], "build record.oracle.id") != expected_oracle["id"]:
        raise VerificationError("build record oracle.id does not match the source lock")
    if _matches(oracle["version"], "build record.oracle.version", _VERSION) != (
        expected_oracle["version"]
    ):
        raise VerificationError("build record oracle.version does not match the source lock")
    if _matches(
        oracle["sourceRevision"], "build record.oracle.sourceRevision", _REVISION
    ) != source_lock["revision"]["commit"]:
        raise VerificationError("build record sourceRevision does not match the source lock")
    if _matches(
        oracle["sourceLockSha256"], "build record.oracle.sourceLockSha256", _SHA256
    ) != source_lock_sha256:
        raise VerificationError("build record sourceLockSha256 does not match source-lock bytes")

    environment = _object(
        root["environment"],
        "build record.environment",
        {"container", "variables"},
    )
    container = _object(
        environment["container"],
        "build record.environment.container",
        {"image", "digest", "platform"},
    )
    image = _string(container["image"], "build record.environment.container.image")
    if "@" in image or any(character.isspace() for character in image):
        raise VerificationError("container.image must omit the separately locked digest")
    _matches(container["digest"], "build record.environment.container.digest", _IMAGE_DIGEST)
    if _string(container["platform"], "build record.environment.container.platform") != (
        "linux/amd64"
    ):
        raise VerificationError("the ELF oracle build platform must be linux/amd64")

    variables = environment["variables"]
    if not isinstance(variables, dict) or not variables:
        raise VerificationError("build record.environment.variables must be a non-empty object")
    for name, value in variables.items():
        if not isinstance(name, str) or _ENVIRONMENT_NAME.fullmatch(name) is None:
            raise VerificationError(f"invalid build environment variable name: {name!r}")
        _string(value, f"build record.environment.variables.{name}", allow_empty=True)
        if _SECRET_ENVIRONMENT_NAME.search(name) is not None:
            raise VerificationError(f"build record must not retain secret variable {name}")
    if variables.get("LC_ALL") != "C":
        raise VerificationError("build record must set LC_ALL=C")
    if variables.get("TZ") != "UTC":
        raise VerificationError("build record must set TZ=UTC")
    epoch = variables.get("SOURCE_DATE_EPOCH")
    if not isinstance(epoch, str) or re.fullmatch(r"[1-9][0-9]*", epoch) is None:
        raise VerificationError("build record must set a positive decimal SOURCE_DATE_EPOCH")

    directories = _object(
        root["directories"],
        "build record.directories",
        {"source", "build", "install"},
    )
    normalized_directories = {
        name: _normalized_absolute_path(value, f"build record.directories.{name}")
        for name, value in directories.items()
    }
    if len(set(normalized_directories.values())) != len(normalized_directories):
        raise VerificationError("source, build, and install directories must be distinct")
    source_directory = PurePosixPath(normalized_directories["source"])
    build_directory = PurePosixPath(normalized_directories["build"])
    if source_directory.name != source_lock["source"]["archiveRoot"]:
        raise VerificationError(
            "build source directory must end with the locked source archive root"
        )
    if source_directory in build_directory.parents or build_directory in source_directory.parents:
        raise VerificationError("the oracle build must be out of tree, not nested in its source")

    commands = _object(
        root["commands"],
        "build record.commands",
        {"configure", "compile", "install", "stageFull", "strip"},
    )
    parsed_commands = {
        name: _command(command, f"build record.commands.{name}")
        for name, command in commands.items()
    }
    if build_system == "autoconf":
        expected_configure = f"{normalized_directories['source']}/configure"
        if parsed_commands["configure"][0] != expected_configure:
            raise VerificationError(f"configure command must start with {expected_configure}")
    else:
        configure = parsed_commands["configure"]
        if PurePosixPath(configure[0]).name != "cmake":
            raise VerificationError("cmake-ninja configure command must invoke cmake")
        expected_source = f"{normalized_directories['source']}/llvm"
        required_pairs = (("-G", "Ninja"), ("-S", expected_source), ("-B", normalized_directories["build"]))
        for option, expected in required_pairs:
            positions = [index for index, value in enumerate(configure) if value == option]
            if len(positions) != 1 or positions[0] + 1 >= len(configure) or configure[positions[0] + 1] != expected:
                raise VerificationError(
                    f"cmake-ninja configure command must contain {option} {expected} exactly once"
                )
    if parsed_commands["stageFull"].count("{full}") != 1:
        raise VerificationError("stageFull command must contain {full} exactly once")
    if parsed_commands["strip"].count("{full}") != 1 or parsed_commands["strip"].count(
        "{stripped}"
    ) != 1:
        raise VerificationError("strip command must contain {full} and {stripped} exactly once")
    if not any(argument in {"--strip-all", "-s"} for argument in parsed_commands["strip"]):
        raise VerificationError("strip command must request complete symbol stripping")

    tools = _array(root["tools"], "build record.tools", nonempty=True)
    roles: list[str] = []
    tool_paths: dict[str, str] = {}
    for index, value in enumerate(tools):
        path = f"build record.tools[{index}]"
        tool = _object(
            value,
            path,
            {
                "role",
                "path",
                "versionCommand",
                "versionOutput",
                "executableBytes",
                "executableSha256",
            },
        )
        role = _matches(tool["role"], f"{path}.role", _TOOL_ROLE)
        roles.append(role)
        executable = _normalized_absolute_path(tool["path"], f"{path}.path")
        tool_paths[role] = executable
        version_command = _command(tool["versionCommand"], f"{path}.versionCommand")
        if version_command[0] != executable:
            raise VerificationError(f"{path}.versionCommand must invoke the locked tool path")
        _string(tool["versionOutput"], f"{path}.versionOutput")
        _integer(tool["executableBytes"], f"{path}.executableBytes", minimum=1)
        _matches(tool["executableSha256"], f"{path}.executableSha256", _SHA256)
    if roles != sorted(roles) or len(roles) != len(set(roles)):
        raise VerificationError("build-record tool roles must be unique and sorted")
    missing_roles = sorted({"compiler", "linker", "stripper"} - set(roles))
    if missing_roles:
        raise VerificationError(f"build record is missing required tool roles: {missing_roles}")
    if parsed_commands["strip"][0] != tool_paths["stripper"]:
        raise VerificationError("strip command must invoke the locked stripper tool path")

    outputs = _object(root["outputs"], "build record.outputs", {"full", "stripped"})
    full_output = _normalized_relative_path(outputs["full"], "build record.outputs.full")
    stripped_output = _normalized_relative_path(
        outputs["stripped"], "build record.outputs.stripped"
    )
    if full_output == stripped_output:
        raise VerificationError("full and stripped artifact paths must differ")
    return root


def verify_build_environment(
    build_record_path: Path,
    source_lock_path: Path,
    container_digest: str,
) -> dict[str, Any]:
    """Verify source binding and all live tool facts in a pinned build container.

    The caller supplies the digest of the container it launched.  This avoids
    trusting mutable image tags or attempting to infer an outer container ID
    from inside the build.  Tool commands are absolute and run with only the
    explicitly recorded build environment plus a deterministic PATH.
    """

    container_digest = _matches(container_digest, "container digest", _IMAGE_DIGEST)
    source_lock_path = source_lock_path.absolute()
    source_payload = _read_regular_file(source_lock_path, "source lock")
    source_lock = load_and_validate_lock(source_lock_path)
    build_record_path = build_record_path.absolute()
    build_record = _load_json(build_record_path, "build record")
    validate_build_record(build_record, source_lock, _sha256_bytes(source_payload))
    recorded_digest = build_record["environment"]["container"]["digest"]
    if container_digest != recorded_digest:
        raise VerificationError(
            f"build container digest mismatch: recorded {recorded_digest}, "
            f"running {container_digest}"
        )
    if platform.system() != "Linux" or platform.machine().lower() not in {
        "amd64",
        "x86_64",
    }:
        raise VerificationError("build environment is not Linux x86-64")

    environment = {
        **build_record["environment"]["variables"],
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    }
    for tool in build_record["tools"]:
        role = tool["role"]
        executable = Path(tool["path"])
        if executable.is_symlink() or not executable.is_file():
            raise VerificationError(
                f"{role} executable is not a non-symlink regular file: {executable}"
            )
        try:
            payload = executable.read_bytes()
        except OSError as error:
            raise VerificationError(
                f"cannot read {role} executable {executable}: {error}"
            ) from error
        if len(payload) != tool["executableBytes"]:
            raise VerificationError(
                f"{role} executable byte length mismatch: recorded "
                f"{tool['executableBytes']}, observed {len(payload)}"
            )
        observed_hash = _sha256_bytes(payload)
        if observed_hash != tool["executableSha256"]:
            raise VerificationError(
                f"{role} executable SHA-256 mismatch: recorded "
                f"{tool['executableSha256']}, observed {observed_hash}"
            )
        try:
            version = subprocess.run(
                tool["versionCommand"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="strict",
                env=environment,
                cwd="/",
                timeout=_VERSION_COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise VerificationError(
                f"{role} version command exceeded {_VERSION_COMMAND_TIMEOUT_SECONDS} seconds"
            ) from error
        except (OSError, UnicodeError) as error:
            raise VerificationError(f"could not query {role} version: {error}") from error
        if version.returncode != 0:
            raise VerificationError(
                f"{role} version command failed with exit code {version.returncode}"
            )
        if version.stdout != tool["versionOutput"]:
            raise VerificationError(
                f"{role} version output mismatch: recorded {tool['versionOutput']!r}, "
                f"observed {version.stdout!r}"
            )
    return build_record


def _range(payload: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset > len(payload) or size > len(payload) - offset:
        raise VerificationError(
            f"{label} file range is outside the ELF: offset={offset}, size={size}, "
            f"file={len(payload)}"
        )
    return payload[offset : offset + size]


def _unpack_from(format_string: str, payload: bytes, offset: int, label: str) -> tuple[Any, ...]:
    size = struct.calcsize(format_string)
    chunk = _range(payload, offset, size, label)
    try:
        return struct.unpack(format_string, chunk)
    except struct.error as error:
        raise VerificationError(f"could not decode {label}: {error}") from error


def _name(mapping: Mapping[int, str], value: int, prefix: str) -> str:
    return mapping.get(value, f"{prefix}_0x{value:x}")


def _program_flags(flags: int) -> str:
    return "".join(
        ("R" if flags & 4 else "-", "W" if flags & 2 else "-", "E" if flags & 1 else "-")
    )


def _read_string(table: bytes, offset: int, label: str) -> str:
    if offset < 0 or offset >= len(table):
        if offset == 0 and not table:
            return ""
        raise VerificationError(f"{label} offset {offset} is outside its string table")
    end = table.find(b"\x00", offset)
    if end < 0:
        raise VerificationError(f"{label} is not NUL terminated")
    try:
        return table[offset:end].decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"{label} is not UTF-8") from error


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _gnu_build_ids(note_payload: bytes, byte_order: str, label: str) -> list[str]:
    offset = 0
    results: list[str] = []
    header_format = f"{byte_order}III"
    header_size = struct.calcsize(header_format)
    while offset < len(note_payload):
        remaining = note_payload[offset:]
        if not remaining or all(value == 0 for value in remaining):
            break
        if len(remaining) < header_size:
            raise VerificationError(f"{label} has a truncated ELF note header")
        name_size, descriptor_size, note_type = _unpack_from(
            header_format, note_payload, offset, f"{label} note header"
        )
        offset += header_size
        name = _range(note_payload, offset, name_size, f"{label} note name")
        offset = _align(offset + name_size, 4)
        descriptor = _range(
            note_payload, offset, descriptor_size, f"{label} note descriptor"
        )
        offset = _align(offset + descriptor_size, 4)
        if note_type == _NT_GNU_BUILD_ID and name.rstrip(b"\x00") == b"GNU":
            if not descriptor:
                raise VerificationError(f"{label} contains an empty GNU Build ID")
            results.append(descriptor.hex())
    return results


def _dwarf_section(name: str) -> bool:
    return (
        name.startswith(".debug_")
        or name.startswith(".zdebug_")
        or name.startswith(".gnu.debuglto_")
        or name.startswith(".gnu.linkonce.wi.")
    )


def inspect_elf(path: Path) -> dict[str, Any]:
    """Derive deterministic ELF, DWARF, symbol, segment, and section facts."""

    path = path.absolute()
    payload = _read_regular_file(path, "ELF artifact")
    if len(payload) < 16 or payload[:4] != b"\x7fELF":
        raise VerificationError(f"artifact is not an ELF file: {path}")
    elf_class = payload[4]
    data_encoding = payload[5]
    if elf_class not in _ELF_CLASS_NAMES:
        raise VerificationError(f"unsupported ELF class {elf_class}: {path}")
    if data_encoding not in _DATA_ENCODING_NAMES:
        raise VerificationError(f"unsupported ELF data encoding {data_encoding}: {path}")
    byte_order = "<" if data_encoding == 1 else ">"

    if elf_class == 1:
        header_format = f"{byte_order}HHIIIIIHHHHHH"
        program_format = f"{byte_order}IIIIIIII"
        section_format = f"{byte_order}IIIIIIIIII"
    else:
        header_format = f"{byte_order}HHIQQQIHHHHHH"
        program_format = f"{byte_order}IIQQQQQQ"
        section_format = f"{byte_order}IIQQQQIIQQ"
    header_values = _unpack_from(header_format, payload, 16, "ELF header")
    (
        elf_type,
        machine,
        version,
        entry_point,
        program_offset,
        section_offset,
        flags,
        header_size,
        program_entry_size,
        program_count_raw,
        section_entry_size,
        section_count_raw,
        section_names_raw,
    ) = header_values
    expected_header_size = 16 + struct.calcsize(header_format)
    if payload[6] != 1 or version != 1:
        raise VerificationError("ELF identification and header versions must both be 1")
    if header_size < expected_header_size or header_size > len(payload):
        raise VerificationError("ELF header size is invalid")

    section_struct_size = struct.calcsize(section_format)
    program_struct_size = struct.calcsize(program_format)

    def raw_section(index: int) -> tuple[int, ...]:
        if section_offset == 0 or section_entry_size < section_struct_size:
            raise VerificationError("ELF section-header table metadata is invalid")
        return _unpack_from(
            section_format,
            payload,
            section_offset + index * section_entry_size,
            f"section header {index}",
        )  # type: ignore[return-value]

    section_zero: tuple[int, ...] | None = None
    if section_offset != 0 and (
        section_count_raw == 0
        or program_count_raw == _PN_XNUM
        or section_names_raw == _SHN_XINDEX
    ):
        section_zero = raw_section(0)
    section_count = (
        int(section_zero[5])
        if section_count_raw == 0 and section_zero is not None
        else section_count_raw
    )
    program_count = (
        int(section_zero[7])
        if program_count_raw == _PN_XNUM and section_zero is not None
        else program_count_raw
    )
    section_names_index = (
        int(section_zero[6])
        if section_names_raw == _SHN_XINDEX and section_zero is not None
        else section_names_raw
    )
    if section_count <= 0:
        raise VerificationError("oracle ELF must have a section-header table")
    if section_entry_size < section_struct_size:
        raise VerificationError("ELF section-header entry size is too small")
    _range(payload, section_offset, section_count * section_entry_size, "section-header table")
    if program_count > 0:
        if program_offset == 0 or program_entry_size < program_struct_size:
            raise VerificationError("ELF program-header table metadata is invalid")
        _range(payload, program_offset, program_count * program_entry_size, "program-header table")
    if section_names_index <= 0 or section_names_index >= section_count:
        raise VerificationError("ELF section-name string-table index is invalid")

    raw_sections = [raw_section(index) for index in range(section_count)]
    names_header = raw_sections[section_names_index]
    if names_header[1] != _SHT_STRTAB:
        raise VerificationError("ELF section-name table is not SHT_STRTAB")
    section_names = _range(
        payload,
        int(names_header[4]),
        int(names_header[5]),
        "section-name string table",
    )

    sections: list[dict[str, Any]] = []
    section_build_ids: list[str] = []
    for index, raw in enumerate(raw_sections):
        (
            name_offset,
            section_type,
            section_flags,
            address,
            offset,
            size,
            link,
            info,
            alignment,
            entry_size,
        ) = raw
        name = _read_string(section_names, int(name_offset), f"section {index} name")
        file_backed = section_type != _SHT_NOBITS
        content = b""
        content_sha256: str | None = None
        if file_backed:
            content = _range(payload, int(offset), int(size), f"section {index} ({name})")
            content_sha256 = _sha256_bytes(content)
        record = {
            "index": index,
            "name": name,
            "type": int(section_type),
            "typeName": _name(_SECTION_TYPE_NAMES, int(section_type), "SHT"),
            "flags": int(section_flags),
            "address": int(address),
            "offset": int(offset),
            "size": int(size),
            "link": int(link),
            "info": int(info),
            "alignment": int(alignment),
            "entrySize": int(entry_size),
            "allocated": bool(section_flags & _SHF_ALLOC),
            "executable": bool(section_flags & _SHF_EXECINSTR),
            "fileBacked": file_backed,
            "contentSha256": content_sha256,
        }
        sections.append(record)
        if section_type == _SHT_NOTE and name == ".note.gnu.build-id":
            section_build_ids.extend(
                _gnu_build_ids(content, byte_order, f"section {index} ({name})")
            )

    program_headers: list[dict[str, Any]] = []
    note_segment_payloads: list[tuple[bytes, str]] = []
    executable_payloads: list[bytes] = []
    executable_indexes: list[int] = []
    for index in range(program_count):
        raw = _unpack_from(
            program_format,
            payload,
            program_offset + index * program_entry_size,
            f"program header {index}",
        )
        if elf_class == 1:
            (
                program_type,
                offset,
                virtual_address,
                physical_address,
                file_size,
                memory_size,
                program_flags,
                alignment,
            ) = raw
        else:
            (
                program_type,
                program_flags,
                offset,
                virtual_address,
                physical_address,
                file_size,
                memory_size,
                alignment,
            ) = raw
        segment = _range(payload, int(offset), int(file_size), f"program segment {index}")
        if program_type == _PT_LOAD:
            if memory_size < file_size:
                raise VerificationError(
                    f"PT_LOAD segment {index} has p_memsz smaller than p_filesz"
                )
            if alignment not in {0, 1} and (
                alignment & (alignment - 1) != 0
                or offset % alignment != virtual_address % alignment
            ):
                raise VerificationError(f"PT_LOAD segment {index} has invalid alignment")
        program_headers.append(
            {
                "index": index,
                "type": int(program_type),
                "typeName": _name(_PROGRAM_TYPE_NAMES, int(program_type), "PT"),
                "flags": int(program_flags),
                "flagNames": _program_flags(int(program_flags)),
                "offset": int(offset),
                "virtualAddress": int(virtual_address),
                "physicalAddress": int(physical_address),
                "fileSize": int(file_size),
                "memorySize": int(memory_size),
                "alignment": int(alignment),
                "contentSha256": _sha256_bytes(segment),
            }
        )
        if program_type == _PT_NOTE:
            note_segment_payloads.append((segment, f"PT_NOTE segment {index}"))
        if program_type == _PT_LOAD and program_flags & _PF_X and file_size > 0:
            executable_indexes.append(index)
            executable_payloads.append(segment)

    build_ids = section_build_ids
    if not build_ids:
        for note_payload, label in note_segment_payloads:
            build_ids.extend(_gnu_build_ids(note_payload, byte_order, label))
    for index, build_id in enumerate(build_ids):
        _matches(build_id, f"GNU Build ID {index}", _BUILD_ID)

    dwarf_sections = sorted(
        section["name"] for section in sections if _dwarf_section(section["name"])
    )
    static_symbols = [
        {"section": section["name"], "entries": section["size"] // section["entrySize"]}
        for section in sections
        if section["type"] == _SHT_SYMTAB and section["entrySize"] > 0
    ]
    dynamic_symbols = [
        {"section": section["name"], "entries": section["size"] // section["entrySize"]}
        for section in sections
        if section["type"] == _SHT_DYNSYM and section["entrySize"] > 0
    ]
    executable_bytes = b"".join(executable_payloads)
    header = {
        "class": _ELF_CLASS_NAMES[elf_class],
        "dataEncoding": _DATA_ENCODING_NAMES[data_encoding],
        "identVersion": int(payload[6]),
        "osAbi": int(payload[7]),
        "osAbiName": _name(_OS_ABI_NAMES, int(payload[7]), "ELFOSABI"),
        "abiVersion": int(payload[8]),
        "type": int(elf_type),
        "typeName": _name(_ELF_TYPE_NAMES, int(elf_type), "ET"),
        "machine": int(machine),
        "machineName": _name(_MACHINE_NAMES, int(machine), "EM"),
        "version": int(version),
        "entryPoint": int(entry_point),
        "programHeaderOffset": int(program_offset),
        "sectionHeaderOffset": int(section_offset),
        "flags": int(flags),
        "headerSize": int(header_size),
        "programHeaderEntrySize": int(program_entry_size),
        "programHeaderCount": int(program_count),
        "sectionHeaderEntrySize": int(section_entry_size),
        "sectionHeaderCount": int(section_count),
        "sectionNameTableIndex": int(section_names_index),
    }
    identity_keys = (
        "class",
        "dataEncoding",
        "identVersion",
        "osAbi",
        "abiVersion",
        "type",
        "machine",
        "version",
        "entryPoint",
        "flags",
    )
    return {
        "header": header,
        "identity": {key: header[key] for key in identity_keys},
        "buildIds": build_ids,
        "programHeaders": program_headers,
        "sections": sections,
        "metadata": {
            "hasDwarf": bool(dwarf_sections),
            "dwarfSections": dwarf_sections,
            "hasStaticSymbols": bool(static_symbols),
            "staticSymbolTables": static_symbols,
            "hasDynamicSymbols": bool(dynamic_symbols),
            "dynamicSymbolTables": dynamic_symbols,
        },
        "executableLoad": {
            "selector": "PT_LOAD with PF_X and nonzero p_filesz",
            "segmentIndexes": executable_indexes,
            "bytes": len(executable_bytes),
            "sha256": _sha256_bytes(executable_bytes),
        },
    }


def _artifact_record(path: Path, relative: str, label: str) -> dict[str, Any]:
    payload = _read_regular_file(path, label)
    elf = inspect_elf(path)
    if _read_regular_file(path, label) != payload:
        raise VerificationError(f"{label} changed while it was being inspected")
    return {
        "path": relative,
        "bytes": len(payload),
        "sha256": _sha256_bytes(payload),
        "elf": elf,
    }


def _allocated_sections(elf: Mapping[str, Any]) -> list[dict[str, Any]]:
    keys = (
        "name",
        "type",
        "flags",
        "address",
        "size",
        "link",
        "info",
        "alignment",
        "entrySize",
        "fileBacked",
        "contentSha256",
    )
    return [
        {key: section[key] for key in keys}
        for section in elf["sections"]
        if section["allocated"]
    ]


def _program_header_layout(elf: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return program-header fields without hashes of overlapping payloads.

    A non-executable PT_LOAD commonly contains the ELF header itself.  Strip
    legitimately updates section-table coordinates in that header, so its
    encompassing segment hash is metadata, not a code-identity signal.
    Executable PT_LOAD hashes remain mandatory and are compared separately.
    """

    return [
        {key: value for key, value in header.items() if key != "contentSha256"}
        for header in elf["programHeaders"]
    ]


def _nonallocated_by_name(elf: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for section in elf["sections"]:
        if section["allocated"] or not section["name"]:
            continue
        result.setdefault(section["name"], []).append(section)
    return result


def _has_dwarf_component(names: Sequence[str], component: str) -> bool:
    suffixes = (f".debug_{component}", f".zdebug_{component}")
    return any(
        name in suffixes or name.startswith(f".gnu.debuglto_.debug_{component}")
        for name in names
    )


def _derive_equivalence(full: Mapping[str, Any], stripped: Mapping[str, Any]) -> dict[str, Any]:
    full_elf = full["elf"]
    stripped_elf = stripped["elf"]
    if full["sha256"] == stripped["sha256"]:
        raise VerificationError("stripping did not change the complete artifact bytes")
    if full["bytes"] <= stripped["bytes"]:
        raise VerificationError("stripped artifact must be smaller than the DWARF-rich artifact")
    if full_elf["identity"] != stripped_elf["identity"]:
        raise VerificationError("full and stripped artifacts have different ELF identities")
    if full_elf["header"]["class"] != "ELF64" or full_elf["header"]["machine"] != 62:
        raise VerificationError("the oracle pair must be x86-64 ELF64")
    if full_elf["header"]["dataEncoding"] != "little-endian":
        raise VerificationError("the oracle pair must use little-endian ELF encoding")
    if full_elf["header"]["type"] not in {2, 3}:
        raise VerificationError("the oracle artifact must be ET_EXEC or ET_DYN")

    full_build_ids = full_elf["buildIds"]
    stripped_build_ids = stripped_elf["buildIds"]
    if len(full_build_ids) != 1 or len(stripped_build_ids) != 1:
        raise VerificationError("each oracle artifact must contain exactly one GNU Build ID")
    if full_build_ids[0] != stripped_build_ids[0]:
        raise VerificationError("stripping changed the GNU Build ID")

    full_program_layout = _program_header_layout(full_elf)
    stripped_program_layout = _program_header_layout(stripped_elf)
    if full_program_layout != stripped_program_layout:
        raise VerificationError("stripping changed the ELF program-header layout")
    if not full_elf["executableLoad"]["segmentIndexes"]:
        raise VerificationError("oracle artifact has no file-backed executable PT_LOAD segment")
    if full_elf["executableLoad"] != stripped_elf["executableLoad"]:
        raise VerificationError("stripping changed file-backed PT_LOAD/PF_X bytes")

    full_allocated = _allocated_sections(full_elf)
    stripped_allocated = _allocated_sections(stripped_elf)
    if full_allocated != stripped_allocated:
        raise VerificationError("stripping changed allocated sections or their contents")

    full_metadata = full_elf["metadata"]
    stripped_metadata = stripped_elf["metadata"]
    dwarf_names = full_metadata["dwarfSections"]
    missing_dwarf = [
        component
        for component in ("info", "abbrev", "line")
        if not _has_dwarf_component(dwarf_names, component)
    ]
    if missing_dwarf:
        raise VerificationError(
            f"full artifact is not DWARF-rich; missing sections for {missing_dwarf}"
        )
    if not full_metadata["hasStaticSymbols"]:
        raise VerificationError("full artifact has no static symbol table")
    if stripped_metadata["hasDwarf"]:
        raise VerificationError("stripped artifact still contains DWARF sections")
    if stripped_metadata["hasStaticSymbols"]:
        raise VerificationError("stripped artifact still contains a static symbol table")

    full_nonallocated = _nonallocated_by_name(full_elf)
    stripped_nonallocated = _nonallocated_by_name(stripped_elf)
    full_names = set(full_nonallocated)
    stripped_names = set(stripped_nonallocated)
    common_names = full_names & stripped_names
    changed_common = sorted(
        name
        for name in common_names
        if full_nonallocated[name] != stripped_nonallocated[name]
    )
    return {
        "buildId": full_build_ids[0],
        "elfIdentity": full_elf["identity"],
        "programHeadersSha256": _canonical_sha256(full_program_layout),
        "allocatedSectionsSha256": _canonical_sha256(full_allocated),
        "executableLoad": full_elf["executableLoad"],
        "metadataDelta": {
            "fullOnlySections": sorted(full_names - stripped_names),
            "strippedOnlySections": sorted(stripped_names - full_names),
            "changedCommonSections": changed_common,
            "removedDwarfSections": dwarf_names,
            "removedStaticSymbolTables": full_metadata["staticSymbolTables"],
        },
    }


def _assemble_manifest(
    manifest_directory: Path,
    source_path: Path,
    source_relative: str,
    build_path: Path,
    build_relative: str,
    artifact_root: Path | None = None,
) -> dict[str, Any]:
    source_payload = _read_regular_file(source_path, "source lock")
    source_sha256 = _sha256_bytes(source_payload)
    source_lock = load_and_validate_lock(source_path)
    build_record = _load_json(build_path, "build record")
    validate_build_record(build_record, source_lock, source_sha256)

    full_relative = build_record["outputs"]["full"]
    stripped_relative = build_record["outputs"]["stripped"]
    resolved_artifact_root = manifest_directory if artifact_root is None else artifact_root
    full_path = _resolve_within(resolved_artifact_root, full_relative, "full artifact")
    stripped_path = _resolve_within(
        resolved_artifact_root, stripped_relative, "stripped artifact"
    )
    full = _artifact_record(full_path, full_relative, "full artifact")
    stripped = _artifact_record(stripped_path, stripped_relative, "stripped artifact")
    equivalence = _derive_equivalence(full, stripped)
    return {
        "schemaVersion": 1,
        "oracle": {
            "id": source_lock["oracle"]["id"],
            "version": source_lock["oracle"]["version"],
            "sourceRevision": source_lock["revision"]["commit"],
        },
        "inputs": {
            "sourceLock": _file_record(source_path, source_relative, "source lock"),
            "buildRecord": _file_record(build_path, build_relative, "build record"),
        },
        "artifacts": {"full": full, "stripped": stripped},
        "equivalence": equivalence,
    }


def create_oracle_manifest(
    manifest_path: Path,
    source_lock_path: Path,
    build_record_path: Path,
    *,
    artifact_root: Path | None = None,
) -> dict[str, Any]:
    """Create a manifest after proving the supplied ELF twin contract."""

    manifest_path = manifest_path.absolute()
    manifest_directory = manifest_path.parent
    if manifest_path.exists() and (manifest_path.is_symlink() or not manifest_path.is_file()):
        raise VerificationError(f"manifest output is not a regular file: {manifest_path}")
    source_relative = _relative_input_path(
        source_lock_path, manifest_directory, "source-lock path"
    )
    build_relative = _relative_input_path(
        build_record_path, manifest_directory, "build-record path"
    )
    manifest = _assemble_manifest(
        manifest_directory,
        source_lock_path.absolute(),
        source_relative,
        build_record_path.absolute(),
        build_relative,
        None if artifact_root is None else artifact_root.absolute(),
    )
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{manifest_path.name}.", suffix=".tmp", dir=manifest_directory
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, manifest_path)
        temporary_path = None
    except OSError as error:
        raise VerificationError(f"cannot write oracle manifest {manifest_path}: {error}") from error
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return manifest


def _validate_input_record(value: Any, path: str) -> dict[str, Any]:
    record = _object(value, path, {"path", "bytes", "sha256"})
    _normalized_relative_path(record["path"], f"{path}.path")
    _integer(record["bytes"], f"{path}.bytes", minimum=1)
    _matches(record["sha256"], f"{path}.sha256", _SHA256)
    return record


def _compare_exact(recorded: Any, observed: Any, path: str) -> None:
    if type(recorded) is not type(observed):
        raise VerificationError(
            f"{path} type mismatch: recorded {type(recorded).__name__}, "
            f"observed {type(observed).__name__}"
        )
    if isinstance(recorded, dict):
        recorded_keys = set(recorded)
        observed_keys = set(observed)
        if recorded_keys != observed_keys:
            missing = sorted(observed_keys - recorded_keys)
            unexpected = sorted(recorded_keys - observed_keys)
            details: list[str] = []
            if missing:
                details.append(f"missing {missing}")
            if unexpected:
                details.append(f"unexpected {unexpected}")
            raise VerificationError(f"{path} has invalid fields: {', '.join(details)}")
        for key in observed:
            _compare_exact(recorded[key], observed[key], f"{path}.{key}")
        return
    if isinstance(recorded, list):
        if len(recorded) != len(observed):
            raise VerificationError(
                f"{path} length mismatch: recorded {len(recorded)}, observed {len(observed)}"
            )
        for index, (recorded_item, observed_item) in enumerate(zip(recorded, observed)):
            _compare_exact(recorded_item, observed_item, f"{path}[{index}]")
        return
    if recorded != observed:
        raise VerificationError(
            f"{path} mismatch: recorded {recorded!r}, observed {observed!r}"
        )


def verify_oracle_manifest(
    manifest_path: Path,
    *,
    artifact_root: Path | None = None,
) -> dict[str, Any]:
    """Recompute every recorded input, artifact, and equivalence field."""

    manifest_path = manifest_path.absolute()
    data = _load_json(manifest_path, "oracle artifact manifest")
    root = _object(
        data,
        "oracle artifact manifest",
        {"schemaVersion", "oracle", "inputs", "artifacts", "equivalence"},
    )
    if isinstance(root["schemaVersion"], bool) or root["schemaVersion"] != 1:
        raise VerificationError("oracle artifact manifest schemaVersion must be the integer 1")
    inputs = _object(
        root["inputs"],
        "oracle artifact manifest.inputs",
        {"sourceLock", "buildRecord"},
    )
    source_record = _validate_input_record(
        inputs["sourceLock"], "oracle artifact manifest.inputs.sourceLock"
    )
    build_record = _validate_input_record(
        inputs["buildRecord"], "oracle artifact manifest.inputs.buildRecord"
    )
    directory = manifest_path.parent
    source_path = _resolve_within(directory, source_record["path"], "source lock")
    build_path = _resolve_within(directory, build_record["path"], "build record")
    expected = _assemble_manifest(
        directory,
        source_path,
        source_record["path"],
        build_path,
        build_record["path"],
        None if artifact_root is None else artifact_root.absolute(),
    )
    _compare_exact(data, expected, "oracle artifact manifest")
    return data

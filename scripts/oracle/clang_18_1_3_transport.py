"""Bounded v2 transport primitives; not a deployed privileged supervisor.

Approval, durable admission, capture helpers and installed socket authority remain
separate prerequisites. No received descriptor is inspected or read here.
"""
from __future__ import annotations

import array
import copy
import hashlib
import json
import os
import re
import select
import socket
import struct
import time
from types import MappingProxyType

MAX_FRAME = 65536
MAX_FDS = 32
DOMAIN = b"decomp-thing:clang1813:fd-transcript:v2\0"
# Fixed protocol classes. Action approval can narrow these limits, never widen
# them. A source payload is authenticated package/acquisition material, not a
# small recipe-source snapshot. Additional roles have no generic catch-all.
ROLE_LIMITS = MappingProxyType({
    "recipe": ("recipeSource", 16 * 1024**2),
    "source": ("recipeSource", 16 * 1024**2),
    "payload": ("packagePayload", 1024**3),
    "source-payload": ("packagePayload", 1024**3),
    "record": ("additional", 1024**2),
    "report": ("additional", 1024**2),
    "rootfs": ("additional", 2 * 1024**3),
    "oci": ("additional", 2 * 1024**3),
})
CATEGORY_LIMITS = MappingProxyType({
    "recipeSource": (512, 64 * 1024**2),
    "packagePayload": (1200, 3 * 1024**3),
    # Eight rootfs/OCI inputs can consume at most sixteen GiB; the separate
    # twenty-GiB reservation remains an outer job limit, not a per-file cap.
    "additional": (8, 16 * 1024**3),
})
HEX = re.compile(r"[0-9a-f]{64}\Z")


class Refusal(RuntimeError):
    pass


def close_fds(fds):
    for fd in fds:
        os.close(fd)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise Refusal("unexpected transport fields")


def integer(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise Refusal("invalid transport integer")


def sha(value):
    if type(value) is not str or not HEX.fullmatch(value):
        raise Refusal("invalid transport digest")


def parse(payload):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refusal("duplicate transport key")
            result[key] = value
        return result
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs,
                           parse_float=lambda _: (_ for _ in ()).throw(Refusal("floating transport number")),
                           parse_constant=lambda _: (_ for _ in ()).throw(Refusal("nonfinite transport number")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refusal("invalid transport JSON") from error
    nodes = 0
    def walk(item, depth):
        nonlocal nodes
        nodes += 1
        if depth > 16 or nodes > 4096:
            raise Refusal("transport JSON budget exceeded")
        if type(item) is dict:
            for key, child in item.items():
                walk(key, depth + 1)
                walk(child, depth + 1)
        elif type(item) is list:
            for child in item:
                walk(child, depth + 1)
    walk(value, 0)
    if type(value) is not dict:
        raise Refusal("transport frame must be object")
    return value, nodes


def peer_credentials(connection, expected_uid):
    """Kernel identity only; installed path/action policy must be checked separately."""
    if connection.family != socket.AF_UNIX or connection.type & 0xf != socket.SOCK_SEQPACKET:
        raise Refusal("expected Unix sequenced-packet socket")
    pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != expected_uid or pid <= 0:
        raise Refusal("unauthorized transport peer")
    return pid, uid, gid


def receive(connection, deadline):
    """Own returned FDs; caller must close them or transfer them to InputTranscript."""
    fds = []
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([connection], [], [], remaining)[0]:
            raise Refusal("transport deadline expired")
        payload, ancillary, flags, _ = connection.recvmsg(
            MAX_FRAME, socket.CMSG_SPACE(MAX_FDS * array.array("i").itemsize),
            socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT)
        unexpected = False
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array("i")
                width = values.itemsize
                values.frombytes(data[:len(data) - len(data) % width])
                fds.extend(values)
                unexpected |= bool(len(data) % width)
            else:
                unexpected = True
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or unexpected or len(fds) > MAX_FDS:
            raise Refusal("truncated or unexpected transport ancillary data")
        if not payload:
            raise Refusal("transport peer disconnected")
        value, nodes = parse(payload)
        return value, fds, nodes
    except BaseException:
        close_fds(fds)
        raise


class InputTranscript:
    """FD-owning receiver bound to a previously independently approved closure.

    expected_begin excludes transcriptSha256. expected_rows are canonical rows
    from that closure, never rows promoted from a caller's request. Successful
    COMMIT validates declarations only: it does not authenticate file contents,
    admit a durable job, freeze artifacts, or authorize execution.
    """
    def __init__(self, expected_begin, expected_rows):
        exact(expected_begin, ("type", "protocolVersion", "action", "approvalIndexSha256",
                               "lockSha256", "actionManifestSha256", "clientNonce", "parentJobId",
                               "counts", "totalBytes"))
        if (expected_begin["type"] != "BEGIN" or type(expected_begin["protocolVersion"]) is not int or
                expected_begin["protocolVersion"] != 2 or expected_begin["action"] not in
                ("bootstrap-offline-v2", "probe-compile-v2", "driver-replay-v2", "runtime-replay-v2",
                 "probe-run-v2", "loader-compile-v2", "loader-run-v2", "package-provenance-v2")):
            raise Refusal("invalid approved v2 transport request")
        for key in ("approvalIndexSha256", "lockSha256", "actionManifestSha256", "clientNonce"):
            sha(expected_begin[key])
        parent = expected_begin["parentJobId"]
        if parent is not None and (type(parent) is not str or not 1 <= len(parent) <= 64 or
                                   not parent.isascii()):
            raise Refusal("invalid approved parent identity")
        exact(expected_begin["counts"], ("recipeSource", "packagePayload", "additional"))
        for key, maximum in (("recipeSource", 512), ("packagePayload", 1200), ("additional", 8)):
            integer(expected_begin["counts"][key], maximum)
        integer(expected_begin["totalBytes"], 20 * 1024**3)
        if (type(expected_rows) is not list or len(expected_rows) > 1720 or
                sum(expected_begin["counts"].values()) != len(expected_rows)):
            raise Refusal("invalid approved closure count")
        identities = set()
        category_counts = {key: 0 for key in CATEGORY_LIMITS}
        category_bytes = {key: 0 for key in CATEGORY_LIMITS}
        total = 0
        for ordinal, row in enumerate(expected_rows):
            exact(row, ("ordinal", "role", "inputId", "bytes", "sha256"))
            integer(row["ordinal"], 1719)
            integer(row["bytes"], 20 * 1024**3)
            sha(row["inputId"])
            sha(row["sha256"])
            if (row["ordinal"] != ordinal or row["inputId"] in identities or
                    type(row["role"]) is not str or not 1 <= len(row["role"]) <= 16 or
                    not row["role"].isascii() or len(canonical(row)) > 512):
                raise Refusal("invalid approved ordered closure")
            if row["role"] not in ROLE_LIMITS:
                raise Refusal("unknown fixed input role")
            category, per_file = ROLE_LIMITS[row["role"]]
            if row["bytes"] > per_file:
                raise Refusal("input role byte limit exceeded")
            category_counts[category] += 1
            category_bytes[category] += row["bytes"]
            count_limit, byte_limit = CATEGORY_LIMITS[category]
            if category_counts[category] > count_limit or category_bytes[category] > byte_limit:
                raise Refusal("input category resource limit exceeded")
            identities.add(row["inputId"])
            total += row["bytes"]
        if category_counts != expected_begin["counts"]:
            raise Refusal("declared input categories differ from role counts")
        if total != expected_begin["totalBytes"]:
            raise Refusal("invalid approved byte total")
        self.expected_begin = copy.deepcopy(expected_begin)
        self.expected_rows = copy.deepcopy(expected_rows)
        self.fds = []
        self.rows = 0
        self.batches = 0
        self.total = 0
        self.messages = 0
        self.nodes = 0
        self.bytes = 0
        self.state = "BEGIN"
        self.hash = hashlib.sha256(DOMAIN)
        self.declared = None

    def close(self):
        close_fds(self.fds)
        self.fds = []
        self.state = "CLOSED"

    def receive(self, connection, deadline):
        """Receive one frame, closing all retained inputs on transport failure."""
        try:
            value, fds, nodes = receive(connection, deadline)
            self.accept(value, fds, nodes)
        except BaseException:
            self.close()
            raise

    def add(self, value):
        payload = canonical(value)
        self.bytes += len(payload)
        if self.bytes > 1024 * 1024:
            raise Refusal("aggregate transcript bytes exceeded")
        self.hash.update(len(payload).to_bytes(4, "big"))
        self.hash.update(payload)

    def accept(self, value, fds, nodes):
        """Always takes ownership of fds, including on refusal."""
        incoming = list(fds)
        try:
            self.messages += 1
            self.nodes += nodes
            if self.messages > 64 or self.nodes > 65536:
                raise Refusal("aggregate transport budget exceeded")
            kind = value.get("type")
            if self.state == "BEGIN" and kind == "BEGIN":
                exact(value, (*self.expected_begin.keys(), "transcriptSha256"))
                sha(value["transcriptSha256"])
                projection = {k: v for k, v in value.items() if k != "transcriptSha256"}
                # Canonical comparison preserves bool versus integer distinctions.
                if incoming or canonical(projection) != canonical(self.expected_begin):
                    raise Refusal("BEGIN differs from independently approved request")
                self.declared = value["transcriptSha256"]
                self.add(projection)
                self.state = "BATCH"
            elif self.state == "BATCH" and kind == "FD_BATCH":
                exact(value, ("type", "sequence", "firstOrdinal", "rows"))
                integer(value["sequence"], 53)
                integer(value["firstOrdinal"], 1719)
                rows = value["rows"]
                if (type(rows) is not list or not 1 <= len(rows) <= MAX_FDS or
                        len(incoming) != len(rows) or value["sequence"] != self.batches or
                        value["firstOrdinal"] != self.rows or self.rows + len(rows) > 1720):
                    raise Refusal("invalid ordered descriptor batch")
                for offset, row in enumerate(rows):
                    exact(row, ("ordinal", "role", "inputId", "bytes", "sha256"))
                    integer(row["ordinal"], 1719)
                    integer(row["bytes"], 20 * 1024**3)
                    sha(row["inputId"])
                    sha(row["sha256"])
                    if (type(row["role"]) is not str or not row["role"].isascii() or
                            len(row["role"]) > 16 or len(canonical(row)) > 512 or
                            self.rows + offset >= len(self.expected_rows) or
                            canonical(row) != canonical(self.expected_rows[self.rows + offset])):
                        raise Refusal("descriptor row differs from approved closure")
                self.add({"type": "FD_BATCH", "sequence": self.batches,
                          "firstOrdinal": self.rows, "rowCount": len(rows)})
                for row in rows:
                    self.add(row)
                    self.total += row["bytes"]
                self.rows += len(rows)
                self.batches += 1
                self.fds.extend(incoming)
                incoming = []
            elif self.state == "BATCH" and kind == "COMMIT_INPUTS":
                exact(value, ("type", "batchCount", "rowCount", "totalBytes", "transcriptSha256"))
                for key, maximum in (("batchCount", 54), ("rowCount", 1720), ("totalBytes", 20 * 1024**3)):
                    integer(value[key], maximum)
                sha(value["transcriptSha256"])
                if (incoming or value["batchCount"] != self.batches or value["rowCount"] != self.rows or
                        self.rows != len(self.expected_rows) or value["totalBytes"] != self.total or
                        self.total != self.expected_begin["totalBytes"]):
                    raise Refusal("incomplete input transcript")
                self.add({k: v for k, v in value.items() if k != "transcriptSha256"})
                if self.hash.hexdigest() != self.declared or self.declared != value["transcriptSha256"]:
                    raise Refusal("input transcript digest mismatch")
                self.state = "COMMITTED"
            else:
                raise Refusal("unexpected input protocol state")
        except BaseException:
            close_fds(incoming)
            self.close()
            raise

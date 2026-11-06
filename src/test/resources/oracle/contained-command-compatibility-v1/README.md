# Authored contained-command compatibility fixtures

These 28 JSON files are authored, source-derived controls: six valid request
expectations, nineteen rejection expectations and three policy preimages. They
are exact byte copies from the repository-local source packet:

`.omo/a-series-20261025/module-compile-nofile-a46/integration-sequence/compatibility-fixtures/authored-source-derived/`

They are not historical request captures, authenticated receipts, execution
evidence or production authority. The original packet derived expectations from
source without running the product parser or JVM. Tests that consume these
resources establish only the behavior they actually exercise; they do not turn
these authored inputs into historical captures or live authority.

The original packet pins two source contexts:

- A (`a46`): `a46d25423c72ead7dc68db8ad473fddb90c8e576`, which supplies the existing terminal-policy request v3.
- V (`b85`): `b85cbbc8a875546a3dc833ffa7379dd8f2a76059`, which supplies the existing retained-input-visibility request v4.

Both contexts support the ordinary v1 and interruption v2 requests. A supports
v3; V supports v4. The packet rejects combined terminal and visibility fields
under every existing request version it covers. It defines no new request
version and manufactures no HMAC. Request versions are distinct from HMAC wire,
runtime, attachment and execution versions.

The copied bytes retain the original packet's ASCII/integer subset of the
pinned `OracleJson` encoding: code-point-sorted keys, two-space indentation,
multiline arrays and one final LF. Paths in these documents are authored string
values; no corresponding external directories or runtime files are implied.
The policy documents are authored preimages, not filesystem observations.

`manifest.json` records the source packet and commits plus each resource-relative
fixture path, exact byte count, SHA-256 and kind (`valid`, `reject` or `policy`).
The manifest inventories only the 28 copied JSON fixtures, excluding itself and
this README. Its kinds preserve the original source-derived expectations; they
do not claim acceptance by an executed parser. All fixture bytes, including
whitespace and final newlines, must remain unchanged.

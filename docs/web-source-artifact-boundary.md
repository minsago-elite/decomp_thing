# GUI source and artifact read boundary

The A4 source and download routes consume bounded descriptor-backed snapshots,
not a checked pathname followed by an independent open. JobStore anchors reads at
its configured root, walks the job/report components without following symbolic
links, and revalidates the selected file and directory identities after reading.
Nonregular targets, path substitution, traversal and growth beyond the limit fail
closed. Job metadata is itself read through this boundary and must name the exact
store job and input location. No uploaded program is executed by these reads.

Per-read host ceilings are 256 KiB for job metadata, 32 MiB for the uploaded input,
4 MiB for a source-tree file, 1 MiB for its manifest, and 64 MiB for a report or
archive download. Canonical report paths have at most 32 components and 4,096
characters. JSON also has explicit depth/node/string bounds, and rendered source
uses strict UTF-8 decoding rather than replacement characters.

## Source admission

The host supplies a bounded allowlist of reconstruction profiles; the default is
the generated-C/Make profile. A request cannot supply a new profile or override
its policy. The closed version-3 source manifest must match an admitted profile's
ID and canonical digest, its declared roles/content kinds, and the current
uploaded input hash. All declared files are read and hash-checked under a
4,096-file and 64 MiB aggregate bound. Their identities, the manifest and the
input are rechecked before a source snapshot is returned.

Only manifest files declared VIEWABLE and UTF8_TEXT appear in the source browser
or pass the source route. Filename suffixes do not authorize access: an explicitly
admitted alternate profile can expose Rust or other text while a `.c` file with
binary or non-viewable policy remains unavailable. Undeclared files are not
discovered by walking the source tree. The general report listing skips this
subtree and has its own 10,000-entry/32-component traversal ceiling.

The source renderer receives captured metadata; it does not reopen provenance or
confidence paths. Confidence is shown only from a hash-matched declared file, and
is not interpreted as measured behavioral equivalence. An unavailable or changed
source snapshot is explicitly shown as unavailable on the job page.

## Archive status still requiring completion

A bounded download snapshot proves which bytes are served, not that its ZIP
payload passes ArchivalBundleVerifier or matches the current source/build tree.
Accordingly the source panel does not label an existing ZIP as a verified archive.
The existing report-download link remains a raw, bounded artifact download.
Issue #33 remains open for independently verifying the exact downloaded archive
and binding the displayed verified state to the current archive/source identity.
These local read checks are not production oracle, execution or release authority.

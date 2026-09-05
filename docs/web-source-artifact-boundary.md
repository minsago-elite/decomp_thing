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

## Verified archive downloads

The canonical `reports/source-tree.zip` route verifies the exact captured bytes
through ArchivalBundleVerifier, including its stored ZIP/hash-manifest, successful
source-bound build contract, source profile and candidate lineage checks. Its
private extraction has a 2,048-file, 4 MiB per-file, 64 MiB expanded-payload and
30-component path bound. Control JSON is also strictly parsed before legacy
semantic readers run. Depth is rejected before creating deep directories, and
partial extraction and successful verification both clean up before any response.
The separate cleanup byte budget includes the 64 MiB payload plus bounded UTF-8
path-name accounting (2,048 paths of at most 4,096 characters, at most four bytes
per character, plus 4 KiB for staging names); it does not enlarge extraction limits.

A descriptor-relative inventory of the complete current source tree, excluding
the packager's excluded `build` subtree, must have exactly the archived file set.
Every archived payload, including manifest, build contract and other evidence,
must match the current file bytes and selected identity. The current rebuilt
executable is separately checked against the contract under a 64 MiB read bound.
Inventory traversal is limited to 100,000 entries and 30 directory levels. Source,
input, payload, executable and archive bindings are rechecked before serving the
same captured ZIP bytes. Only compact file identities are retained for payload
rechecks, rather than another full in-memory copy of the source tree.

The job page displays a verified archive link only from this verification result,
with its exact SHA-256 in both the displayed digest and download URL. A later
request with that digest rejects even a different otherwise valid archive. A
direct request without a digest still performs full current-tree verification.
An ETag identifies the served bytes; merely finding a ZIP never grants verified
status. Other report downloads remain bounded raw artifacts, not certificates.
The source page separately reports current build verification only when this
archive verification succeeds for the exact manifest used to render that source;
otherwise its build status remains explicitly unavailable. Implementation
acceptance is displayed separately from successful compilation.

Verification is a local point-in-time observation, not an immutable cross-file
transaction or exclusion of same-UID replace-and-restore interference. It does not
establish behavioral equivalence, retained execution or runtime-library closure,
production oracle authority, or release eligibility.

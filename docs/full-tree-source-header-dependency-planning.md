# Full-tree source/header dependency planning evidence

`FullTreeSourceHeaderDependencies.assess` is the next bounded Kotlin/JVM checkpoint
for issue #113. It consumes only raw paths to the authenticated full-tree controls,
the source-bound planning inventory, and the source archive locked by those controls.
It does not invoke Python and it has no publication, scoring, reconstruction, or
release surface. ACP remains the first-class candidate producer/operator: it may
consume admitted planning evidence read-only, but it cannot supply header truth,
validate this control, or turn candidate output into oracle authority.

This output is intentionally **planning-only and non-authoritative**. It records
`releaseEligible: false`, `cleanCompilationProven: false`, and withholds the module
graph until compiler-resolution semantics and header ownership are authenticated.
The absence of a `moduleGraph.edges` array is deliberate: this checkpoint neither
emits an empty graph nor claims that the real build has no dependencies.

## Authenticated header-plan readiness envelope

`FullTreeHeaderPlanReadinessControl` is the Kotlin/JVM-owned aggregation boundary
between the source assessment and later compiler capture. It accepts only the source
archive and seven existing control paths. It reconstructs the A13 planning registry,
runs the source/header assessment internally, requires their planning-artifact
bindings to agree, and publishes a canonical `full-tree-header-plan-readiness-v1`
envelope. Callers cannot supply module IDs, shards, source-only records, header paths,
digests, blockers, readiness flags, parsed facts, or callbacks.

The envelope serializes the exact authenticated module and source-only populations
plus the eligible regular source-header candidate subset. For the locked 22.1.6
archive that subset contains 6,579 `.def`, `.h`, `.hh`, `.hpp`, `.hxx`, and `.inc`
files under the enabled A13-derived source roots. It is deliberately not called a
complete project-header universe. Source files outside those roots, generated files,
external files, symlinks, and nonstandard suffixes are not represented.

Readiness v1 fixes these unresolved blockers in the machine contract:

- `complete-project-header-inventory-missing`;
- `compiler-capture-provenance-missing`;
- `generated-file-provenance-missing`;
- `ninja-generator-provenance-missing`; and
- `physical-project-roots-unverified`.

Consequently `headerPlanReady`, `headerPopulationComplete`,
`compilerCaptureAuthenticated`, `cleanCompilationProven`, and `releaseEligible` are
all false by construction. The ACP section is also machine-fixed: ACP is the
first-class candidate producer/operator and later candidate lineage may enter host
validation read-only, but no ACP lineage is admitted by readiness v1 and every
oracle, reference-authoring, policy, validation, observation, execution, scoring,
certification, and release authority remains false.

Readiness accounting charges one output record per module, source-only exclusion,
source-header candidate, and fixed blocker. Aggregation work charges three units per
population record, two per fixed blocker, and nine for the committed provenance
bindings; the locked population therefore uses 11,059 records and 33,181 work units.

Generate the envelope without Python using:

```bash
./gradlew generateFullTreeHeaderPlanReadiness --args="\
  --archive /path/to/llvm-project-22.1.6.src.tar.xz \
  --output /path/to/full-tree-header-plan-readiness.json"
```

## Generated-file snapshot registry

`FullTreeGeneratedFileInventoryControl` is the Kotlin/JVM-only generated-tree input
boundary that follows readiness. It accepts raw paths to a generated TAR/XZ snapshot,
its provenance sidecar, and the authenticated planning controls. The snapshot is
selective by contract: every regular member must be either a case-sensitive
`.def`, `.h`, `.hh`, `.hpp`, `.hxx`, or `.inc` generated header, or the exact A13
module whose planning record has `sourceKind: generated`. Other regular files are
forbidden, every A13 generated module must be present, the sidecar file table must
equal the streamed archive population, and producer actions must cover those files
exactly once.

The archive profile is a single CRC64 XZ stream containing canonical USTAR with one
`generated/` root, normalized ownership and modes, timestamps equal to the build
record's `SOURCE_DATE_EPOCH`, canonical parent-before-child paths, no PAX metadata,
and no links. The control streams file byte counts and SHA-256 values under explicit
compressed, expanded, member, path, per-file, aggregate, action, output, work, and
serialization bounds. It binds the authenticated CMake and Ninja runner identities,
commands, build directory, and epoch from the build record; opaque generator and
Ninja-edge commitments remain sidecar claims.

Accordingly the result is **integrity-verified but unreceipted**. It does not claim
authenticated origin, complete generated-header population, live Ninja-edge replay,
a verified physical build root, clean compilation, or release eligibility. Those
four unresolved classes are emitted as fixed blockers. A separate isolated
CMake/Ninja capture must bind real generation evidence before later controls can
clear them.

ACP remains the first-class candidate producer/operator. Its authenticated session,
change, build-artifact, and provenance lineage can be admitted read-only by later
Kotlin/JVM host validation, but ACP does not author this snapshot, its provenance,
the reference population, policy, validation result, score, certification, or
release decision. ACP lineage is explicitly not an input to generated-snapshot v1.

Validate and publish the canonical registry without Python using:

```bash
./gradlew generateFullTreeGeneratedFileInventory --args="\
  --generated-archive /path/to/generated.tar.xz \
  --generated-provenance /path/to/full-tree-generated-file-provenance.json \
  --output /path/to/full-tree-generated-file-inventory.json"
```

No locally discovered build tree is promoted automatically. For production use,
the archive and sidecar must come from the separately reviewed capture path and must
reconcile with the checked build record and planning inventory supplied here.

## Unexecuted Clang capture-input registry

`FullTreeClangCaptureInputControl` is the load-only Kotlin/JVM boundary for the next
all-TU compiler-capture step. It accepts only the raw capture-input artifact and the
twelve raw predecessor paths needed to reconstruct readiness, generated-file, source,
planning, and build-record state. It has no generator, publisher, process runner,
callback, parsed-object, or Python surface.

Each raw action contains exactly a working directory, a physical main-input path,
and the complete ordered compiler argument vector. The loader derives every action
identity itself and requires one action, in authenticated A13 order, for each source
module and no action for a source-only unit or header. Handwritten inputs join the
authenticated source archive. Generated inputs must also join the generated registry
by both compilation-unit ID and source path, including their byte, file-digest, and
producer-action commitments.

The command profile is positional rather than token-count based. It requires the
configured C or C++ driver, then exactly one `--no-default-config`, the fixed
`-MD -MT <object> -MF <depfile> -o <object> -c <main-input>` frame, and only
self-contained option tokens afterward. This prevents another option from consuming
a required token, prevents a second primary input, and prevents Clang from loading an
uncommitted implicit configuration file.

The required dependency file must be the required object operand plus `.d`; both
must resolve strictly below the recorded build root and be collision-free. The
registry does not infer or authorize an exclusive compiler write set. A later
isolated runner must contain every process write independently before it may execute
the argv. Response and compiler configuration files, shell/wrapper entry points,
joined or duplicate critical options, opaque compiler/preprocessor/assembler
forwarding, language overrides, preprocessing-only and dependency-only modes, path
escapes, extra translation-unit operands, and caller-authored header-capture overlays
fail closed. The loader derives a
domain-separated action SHA-256 and `traces/<action-sha256>.json` slot from the exact
argv and predecessor evidence without rewriting the command.

The inherited environment is cleared. Sorted build-record variables are retained as
the base environment, while Kotlin fixes `CC_PRINT_HEADERS_FORMAT=json` and
`CC_PRINT_HEADERS_FILTERING=direct-per-file`; a later isolated host runner must derive
`CC_PRINT_HEADERS_FILE` from its trusted scratch root and the action's trace slot.
Source-readiness and generated-registry header paths are combined into one sorted
**candidate** population. That population is not a complete project-header universe.

This registry is deliberately `unexecuted-unreceipted-capture-input`. Its only
positive authority facts are exact A13 module/action joining, reconciled predecessor
bindings, and combination of the two header-candidate sources. Compiler-action and
capture authentication, execution, exit statuses, complete header coverage, a ready
header plan, compiler write-set containment, clean compilation, and release
eligibility all remain false. Seven active blockers record missing complete project
headers, compiler-capture provenance,
generated-generation receipts, generated-snapshot completeness, live Ninja-edge
replay, and verified physical build and project roots. A fixed disposition ledger
shows how the readiness blockers are carried or refined; none disappear implicitly.

ACP is machine-recorded as the first-class candidate producer/operator. Authenticated
ACP session, change, build-artifact, and provenance evidence may enter a later Kotlin
candidate-admission boundary read-only. ACP neither authors this reference capture
input nor gains compiler-action, capture, execution, oracle, reference, policy,
validation, observation, scoring, certification, or release authority, and ACP
lineage is not an input to capture-input v1.

## Resolution boundary

The assessment scans the strict locked TAR/XZ archive and parses C-family
preprocessing directives from every authenticated handwritten/source-only
translation unit and every `.h`, `.hh`, `.hpp`, `.hxx`, `.inc`, and `.def` file in
the source roots represented by the planning inventory. Physical lines are joined
using preprocessing backslash-newline rules; comments, ordinary strings, raw
strings, conditional nesting, NULs, line lengths, and directive populations are
handled by the bounded Kotlin parser.

The output partitions every recognized include-like directive into exactly one of:

- `resolved-local`: a top-level literal quoted include whose lexical path relative
  to the including file's directory targets an authenticated regular archive member;
- `unique-archive-candidate` or `ambiguous-archive-candidate`: a non-local literal
  spelling with one or several header-like archive candidates;
- `unresolved-archive`: a safe literal spelling with no indexed candidate;
- `conditional`: any directive beneath a preprocessing conditional, or every
  directive in a file whose conditional/comment/raw-string structure is not
  balanced;
- `macro`, `nonstandard` (`include_next` / `import`), or `malformed`.

Only `resolved-local` is emitted as direct lexical file-reference evidence. A unique
archive candidate is **not** promoted to an edge: the checked inputs do not bind
compiler include roots, their ordering, sysroot contents, generated overlays,
command-line macro state, or the exact preprocessing result. Conditional directives
are not evaluated, and no transitive closure is attempted.

Per-file occurrence counts and domain-separated, unsigned-big-endian length-framed
SHA-256 commitments preserve duplicate directives. Unique target lists are sorted by
Unicode code point. Non-local candidate lookup is limited to the declared dependency
suffixes and to exact archive/public-include spellings; its 64-candidate ceiling is
charged only when a parsed literal actually queries that spelling. Quoted resolution
relative to the including directory may target any authenticated regular member,
including normalized in-archive `..` targets.

## Compiler-trace and first-class-header checkpoint

The later `FullTreeClangHeaderTraceParser` and
`FullTreeCompilerHeaderPlanProjection` checkpoints narrow the remaining compiler
resolution problem without promoting it to production truth. Both are implemented
in Kotlin/JVM. The parser accepts only raw Clang 22 `direct-per-file` JSON v2 bytes,
two explicit physical-to-logical roots, and the expected canonical main source. It
retains project, generated, external, presumed-location, and module-import facts;
binds both the exact input SHA-256 and canonical-facts SHA-256; treats a zero-byte
payload as an explicitly attributed empty trace; and never executes a compiler or
accepts caller-created parsed facts.

The multi-TU projection accepts exactly one raw trace for each module supplied to
that non-authoritative invocation plus a caller-supplied complete canonical header
manifest. It derives, rather than accepts, two first-class fact types:

- an exact `(observing compilation-unit ID, canonical header path)` observation for
  every reached project header; and
- a contextual `(observing compilation-unit ID, consumer path, dependency header
  path)` edge for each eligible compiler-resolved local include.

The observing translation unit is part of edge identity and canonical output. This
is required because macros and compile flags can make the same physical header pair
an edge in one translation unit but not another. The SCC condensation is therefore
labeled a union/may graph across contextual TU edges. A header's A13 consumer shards
come only from its exact TU observations, never from transitive reachability through
that union graph.

Every manifest header receives its own `header-` ID from a full, domain-separated,
length-framed SHA-256 of the canonical path. Unreferenced headers remain explicit
owners with no consumer shards. Strongly connected header sets remain first-class
members of a deterministic SCC instead of being collapsed into a catch-all owner;
the condensation order is dependency-first and deterministic.

All five parser event channels have an explicit disposition. External includes,
module imports, external consumers, non-header project targets, and consumers
outside the eligible module/header set become digest-bound blockers. A project
header reached through an external consumer still retains its TU observation.
Another module's source encountered inside the current trace is a non-header
blocker, never an edge attributed to that foreign module. The projection also emits
one unavoidable `compiler-trace-unauthenticated` blocker per supplied module. That
blocker commits the raw byte length, raw input SHA-256, canonical-facts SHA-256,
expected source, and sorted root mappings, so the resulting plan is always
`incomplete-accounted-blockers`.

Aggregate admission is fail-closed before trace copying. Current immutable ceilings
include 10,000 traces, 16 GiB total raw trace bytes (still subject to the parser's
16 MiB per-trace ceiling), 100,000 contextual header observations, 100,000 contextual
edges, 50,000 grouped blockers, 100,000 retained evidence facts, 64 MiB retained
evidence text, 100,000,000 projection work units, and the nested plan/parser output
ceilings. Callers may lower every ceiling. Traces are copied and parsed one at a
time; retained observations, edges, blocker keys, fact counts, fact bytes, parser
work, and projection work are checked while accumulating rather than only after the
plan is materialized.

This remains a fixture/planning bridge, not the production #113 control. The
readiness envelope now reconstructs the module universe and authenticated source
candidate subset, but the trace projection still accepts a supplied module/header
universe and no complete source/generated regular-file inventory exists. It does not bind the
recorded Clang executable, command, environment, sysroot, generated overlay, Ninja
depfile/order-only generator provenance, exit status, or exact coverage of all A13
translation units. A production wrapper must derive those identities from the
authenticated registry/inventory, commit explicit present-empty/present-nonempty/
missing coverage for every TU, and authenticate the complete trace batch before any
blocker can be cleared.

## Ownership boundary

Every planning module is retained under its exact compilation-unit ID. Handwritten
module sources have parsed dependency facts; generated module sources absent from
the upstream archive are marked `unavailable-generated-source` and carry `null`
facts rather than a misleading zero count.

Every source-only unit is also retained with its exclusion reason and
`ownershipStatus: excluded-non-owning`. It can contribute direct source evidence but
can never become a module owner. Header/dependency files remain
`unassigned-header-planning-evidence`. `sharedHeaders` is limited to headers directly
referenced by two or more module translation units; it is not transitive ownership
inference and does not create module-to-module edges.

## Authentication and bounds

The planning registry is reconstructed internally from the raw scope, source lock,
artifact manifest, build record, inventory, source inventory, and planning inventory
paths. The source archive must match the locked byte length and SHA-256, strict
single-stream XZ/USTAR profile, archive root, and release commit. Inputs must be
distinct identified regular files without symbolic-link or physical-file aliases.
The retained archive descriptor is rehashed and metadata-checked after scanning, and
the complete planning registry is reconstructed again before acceptance.

As with the existing full-tree control plane, Java NIO cannot prove that a
cooperating same-UID/root writer never transiently changes and perfectly restores a
file. The assessment does not claim that exclusion.

Immutable v1 ceilings include:

- 200,000 indexed regular files, 100,000 parsed files, 1 GiB parsed payload, and
  16 MiB per parsed file;
- 256 KiB per logical line, 1,000,000 include-like directives, and 64 actually
  queried candidates per literal spelling;
- 100,000 emitted records, 2,000,000 charged work units, 64 MiB canonical output,
  and the existing strict archive/control-plane maxima.

Callers may lower every assessment-specific ceiling and the nested planning/control
limits. Output bounds always record the fixed policy maxima, not observed counts.

The locked LLVM population/digest proof is opt-in because it scans the 167 MiB
compressed / 2.16 GiB expanded release archive:

```sh
DECOMP_LLVM_SOURCE_ARCHIVE=/path/to/llvm-project-22.1.6.src.tar.xz \
./gradlew test --tests \
  'decompengine.oracle.fulltree.FullTreeSourceHeaderDependenciesTest.locked LLVM source archive reproduces exact dependency populations'
```

The frozen 22.1.6 run indexes 108,590 relevant regular files and parses 11,053
files / 207,334,974 bytes. Its 87,423 directive occurrences partition into 7,570
resolved-local, 47,391 unique candidates, 59 ambiguous candidates, 7,495
unresolved, 24,831 conditional, 77 nonstandard, and zero macro or malformed
records. Unique local references form 6,040 direct file edges; 300 headers have at
least two direct module consumers. The 14,218,981 canonical bytes have SHA-256
`8650d4c302d9071b6ad1aa08c45a0bb35037ff2951ae63200536a7e9c34e3798` and
report SHA-256
`33abce3226fc60143c5d4586689f2e43db0ab14e10acaf4288c062899ff329bf`.

Remaining #113 work includes authenticated compiler execution and exact all-TU
coverage, generated source/header and Ninja generator provenance, an authenticated
complete header inventory, a production dependency-safe graph, canonical source-tree
construction, clean compilation, and release/CI authority. ACP-produced candidate
changes must carry ACP session/change/build lineage into later host validation, but
ACP cannot clear compiler-trace blockers or author this reference evidence. Related
completeness and alias/template semantics remain dependent on #119, #120, and #123.

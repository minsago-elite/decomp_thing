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

This remains a fixture/planning bridge, not the production #113 control. Its supplied
module IDs and header manifest are not yet reconstructed from the authenticated A13
registry and complete source/generated regular-file inventory. It does not bind the
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

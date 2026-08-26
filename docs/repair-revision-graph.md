# Dependency-indexed crash-consistent repair

Trace-guided repair constructs a sparse dependency index and does not put the complete program into
every repair request. The revision/transaction core has no language, compiler, build-command,
directory-layout, entry-symbol, or output-path convention. Callers inject a `RepairIndexProfile`
which resolves normalized source/editability paths, ownership evidence, dependency edges, shared
inputs, and behavior roots. Profiles return generic, deeply frozen module and entity evidence:
module-owned source paths, read-only dependency context, entity ownership, relevance tokens, and
module/entity/path dependency edges. Source ownership is independent of editability, so a diagnostic
in a read-only input can select its owning module without making that diagnostic input writable.
`DeclarativeRepairIndexProfile` supports arbitrary layouts directly.
The generated-C application injects `GeneratedCRepairIndexProfile`; only that adapter knows about C
suffixes and includes, the generated source tree, Make, generated entry symbols, or build-contract
diagnostics. `RepairValidationStrategy` similarly keeps build commands and rebuilt-program locations
outside the repair loop. GCC is one useful C benchmark, not an architectural dependency.

Production validation is a mandatory capability, not a weak default. Both
`RepairValidationStrategy` and the generated-C `GeneratedCRepairValidationBoundary` expose immutable
`STRICT_CONTAINED` versus `TEST_ONLY_HOST_PROCESS` assurance; the public loop rejects anything but
strict containment before graph creation or agent execution. The strict contract requires an exact
bounded private source snapshot (never the canonical tree mounted read/write), an empty explicit
environment, authenticated executable/runtime inputs rather than sibling-directory mounts, network
denial, and tree-wide pids, memory, writable-file, wall, and output cleanup. Builds and behavior runs
use separate contained scopes. This tree currently provides the program-neutral capability and a
test-only fixture boundary, but no production implementation; the CLI therefore fails closed until
the shared production sandbox authority is adapted and an actual contained C build/behavior flow is
captured as acceptance evidence.

The repair core never discovers or parses a report path or program-model schema. The generated-C
profile alone reads its `reports/module_plan.json` and `reports/program_model.json`, translates C
function/global/call evidence into the generic module/entity contract, adds the transitive local-
include graph, and supplies source-bound build-failure ownership. Other profiles ignore those report
names unless they explicitly choose them. The two generated-C index reports are an all-or-nothing,
exact version-1 evidence pair: when both are absent the profile may use its declared per-path policy,
but a present report with a missing peer, field, array, incompatible field, or wrong type/version is
rejected. Top-level and nested collection cardinalities and string lengths are preflighted before
mapping, sorting, or de-duplication. Likewise, an absent generated-C build contract means that no
profile-authenticated failure ownership is available, while a present contract must be valid version-2
evidence, must attest a stable exact source revision, and must satisfy module/failed-owner bounds; it is
never treated as absent after a parse or validation failure. The profile identity, configuration
fingerprint, complete resolved evidence, and resulting index are canonicalized into the graph binding
through a streaming byte-capped digest. Budget-aware profiles must apply the same index-evidence cap to
configuration fingerprinting. A candidate that
changes dependency evidence is restored and rejected; dependency migrations require a separately
reviewed graph migration.

Immediately before `headId` is persisted, acceptance rebuilds the complete index from the current
profile, source tree, generic resolved evidence, and profile-specific diagnostic evidence and requires
the same profile/layout/index binding plus the installed candidate revision. Evidence changed after
installation therefore cannot be committed using a stale index. Repair-owned canonical/projection
paths (`reports/repair-revisions/**`, `reports/source_revisions.jsonl`, `reports/repair_history.json`,
and `source_tree_manifest.json`) are reserved and cannot be claimed as profile source/editable paths.

For compile failures, profile-authenticated source-bound ownership has first authority; otherwise exact
indexed paths identify seed modules. Raw relevance tokens and module IDs are considered only when
neither stronger source exists, and are accepted only when the complete raw evidence resolves to one
owner. A token shared by multiple owners, or separate raw tokens naming separate owners, fails closed.
Raw tokens therefore cannot widen exact-path or profile-authenticated write authority. Multiple exact
paths are distinct evidence and may intentionally select multiple file owners. Exact path recognition
supports indexed names containing spaces, punctuation, and Unicode; ambiguous unqualified basenames
still fail closed. Unknown profile-supplied IDs and compile diagnostics with no indexed ownership fail
closed; there is no first-module or global-editable fallback. The original and profile-transformed
diagnostic text are independently bounded before indexing.

Every seed's full profile-declared owned corpus remains readable, including a specifically diagnosed
read-only input, while only its editable owned subset is writable. `sharedContextPaths` are read context
only and never imply write authority; only separately declared `sharedInvalidationPaths`, selected by
exact or profile-authenticated shared ownership, can be writable. Profile-declared context paths of
direct dependencies are added read-only. For behavior failures, explicit ownership evidence is treated
the same way. When behavior evidence has no module identity, an explicit profile-declared behavior-root
frontier is required; only those explicit roots are writable seeds. Their transitive dependencies may
be retained as read-only context but do not inherit write authority. Disconnected sinks, cycles, and
lexicographic minima never become implicit authority.

The resolved layout's fallback-module map must exactly cover every otherwise-unowned, non-shared path.
Mappings are injective and cannot collide with explicit IDs. The generic loader never synthesizes,
silently suffixes, or rebinds them. `DeclarativeRepairIndexProfile` applies its explicit zero-module
per-path policy before hashing the resolved layout, using an injective UTF-8 path encoding rather than
lossy name normalization. Declared module/entity roots must resolve exactly. Only each module's
evidence-authorized editable subset is writable.
Selection order and any deferred dependency modules are recorded in the immutable
`dependency-indexed-repair-context` agent input.

Production repair requires an injected `RepairStagingAuthority` with `STRICT_CAPTURED` assurance;
construction fails before an attempt or agent call if it is absent or test-only. The default captured
authority exposes no writable ordinary host directory: a trusted transport adapter emits proposed
file bodies through an authority-owned sink which enforces the allowed paths, patch-file and byte
budgets, complete workspace-byte budget, file-entry budget, and directory-entry budget as each
output is captured. Consequently an agent cannot create a sparse file, FIFO, device, symbolic link,
hostile-permission entry, undeclared directory, or background writer in this authority. A future
broker, quota filesystem, or container implementation can implement the same program-neutral
interface. An ordinary-directory staging implementation is a test seam only and does not satisfy
the public production constructor. Every response is still checked against the writable set,
reported before/after hashes, and accepted source revision.

Project source/evidence reads are descriptor-bound bounded reads of regular files with `NOFOLLOW`;
links, FIFOs, devices, parent-identity changes observed during a read, and oversized inputs fail closed.
The descriptor primitive requires the default filesystem provider on supported Linux architectures
with `/proc/self/fd`: it traverses with pinned `openat` directory descriptors, authorizes the final
entry using `O_PATH | O_NOFOLLOW`, reopens that descriptor rather than its pathname, compares stable
device/inode/mount identity and descriptor metadata, and re-resolves the complete binding after the
read. Unsupported hosts fail closed instead of falling back to a path-based read.

Graph open pins the authenticated project-root directory descriptor before JVM coordination and
retains it until after the graph lock and channel are released. Pre-index recovery, profile/index
reads, source publication, lock/state/blob access, cleanup, and compatibility projections all resolve
from that descriptor's inode. Renaming the root or retargeting an ancestor therefore cannot redirect
an open graph into a replacement tree; a replacement root has a distinct coordinator and lock.
Lexical-binding checks during open are supplemental detection only. The ephemeral
`/proc/self/fd/N` anchor is never written into canonical graph or portable evidence; user-facing
absolute paths are normalized against the originally supplied project path.

Candidate blobs and a pending journal are durably written before replacements are installed. Each
file commit stages an unnamed `O_TMPFILE`, copies the exact POSIX permission mode, verifies ownership,
rejects extended attributes or multiple hard links that cannot be preserved, and only then links the
prepared inode at a journal-owned name. It uses descriptor-relative `renameat2(RENAME_EXCHANGE)`:
the target and prepared inode are
content- and identity-checked, their names are revalidated immediately before the exchange, and both
displaced and installed identities are validated afterward. If the target changes in the final gap,
the exchange is rolled back without discarding the concurrent inode. Rollback publication uses the
same compare/exchange/validate protocol and refuses to overwrite an unrecognized external
replacement. There is no check-then-`REPLACE_EXISTING` or non-atomic fallback. If installation or
validation fails, installed candidate paths are restored to their content-addressed preimages and the
full source-revision digest is checked; failures before candidate installation perform no source
write and preserve file identity and metadata. A process crash can leave a pending journal,
but the next public repair entry acquires the graph lock and restores those same content-addressed
preimages before dependency indexing, compilation, behavior assessment, or another attempt. Before
the first recovery write, startup validates the complete graph topology, accepted-head derivation,
profile binding, pending parent/ordinal/authorization/deltas, blob digests and sizes, and resource
budget. A separately canonical `recovery-binding.json`, written before the first graph journal,
immutably binds profile/configuration, budget, exact source/editable paths, and index digest. A
content-sensitive profile must authorize that persisted layout without reading possibly dirty live
source; only after restoration may normal profile resolution rebuild and verify the live index.
Pending preimage/context and candidate patch cardinality and aggregate-byte limits are checked before
any recovery blob or retained preimage body is read. `beginAttempt` derives preimage sizes and hashes
from the already verified head, applies the aggregate limit, and only then allocates captured file bodies.
The same pending-preimage aggregate validator is used before `beginAttempt`
persists, during every live-state persistence validation, and during startup recovery validation.
The complete selected readable staging context is captured and checked against both context and
staging byte limits before `beginAttempt`, so a valid staging<context configuration cannot create a
durable pending record that startup would reject. Startup also preflights the complete accepted
source set and refuses unknown replacements. Cleanup
removes only exact transaction-derived temporaries whose content matches that journal; arbitrary
`*.repair` files are preserved. Irreversible cleanup first atomically renames an owned entry to a
deterministic quarantine name, validates inode identity and content again at the unlink boundary,
and restores the name on failure; an unrecognized entry observed before the final unlink is never
deleted. Exact transaction/quarantine names are reserved to graph-lock-cooperating repair code. A
same-credential process that mutates those reserved names outside the lock at the final syscall
boundary violates this authority contract; deployments with such adversaries must protect the
project directories with a stronger filesystem boundary.

The project graph lock serializes every repair-owned context selection, publication, build, behavior
assessment, acceptance, and rollback. Each individual exchange is atomic and the journal makes a
multi-file attempt crash-consistent. A general filesystem does not provide an atomic multi-file tree
swap: a non-cooperating external reader can observe a mixed revision between per-file renames. Such
readers must acquire the same graph lock if they require transaction-level visibility.

The full retained regression corpus (IDs, argv, and stdin bytes) and its canonical digest live in
the graph, not merely in `repair_history.json`. Corpus additions acquire the same cross-process graph
lock, merge by ID, reject conflicting bodies, sort deterministically, and persist before assessment.
Each attempt binds the exact corpus digest and complete ID set; a concurrently enlarged corpus makes
a previously constructed request fail and the caller must rebuild/assess against the merged snapshot.
Compatibility history is imported only as migration input and is thereafter an exact graph-derived
projection. This gives independent processes deterministic union-on-retry and restart semantics.

`reports/repair-revisions/graph.json` is the canonical deterministic revision graph. Accepted nodes
advance `headId`; rejected nodes remain attached to their attempted parent without advancing it.
Every node records changed modules and the complete transitive set of downstream modules that must
be invalidated. Source contents live under `reports/repair-revisions/blobs/` by SHA-256. Every
referenced blob is size- and digest-checked on open; transaction persistence accounts
already-validated retained blobs and verifies newly stored blobs instead of rescanning a
multi-gigabyte store on every state transition. The graph has no timestamps, and persisted free-form
evidence replaces the project-root path with `${PROJECT_ROOT}` so equivalent repairs remain
byte-identical across roots.

`repair_history.json`, `source_revisions.jsonl`, and source-manifest updates are derived compatibility
views of the canonical graph. They are reconciled on public entry, and an ordinary projection I/O
failure after durable `headId` persistence cannot turn a committed repair into an ambiguous API
failure. A process kill at any post-commit point is repaired on restart. Thus a crash after `headId`
persistence but before a view is written does not lose or invent canonical repair history. Behavior candidates are compiled and run
against all retained inputs before one-shot acceptance; iterative candidates that regress a case
which previously matched are rejected byte-for-byte.
Any ordinary exception after a candidate has been returned as an executed repair first performs an
idempotent rejection and byte-exact preimage restoration before the public API returns. The original
exception remains primary; rollback and close failures are attached as suppressed detail. This
includes validation strategies that throw after observing the installed candidate.

Generic revisions and compatibility history are byte-neutral: patch bodies are immutable defensive
copies and compatibility JSON stores canonical lowercase `replacementHex`, with its two-times
expansion charged before allocation. Strict UTF-8 is imposed only by the legacy text repair client
and the generated-C text profile. The OpenAI-compatible transport receives the mandatory invocation
budget, deadline, and cancellation token; its actual escaped UTF-8 request body is capped, success
responses are streamed to the smaller of the agent-output and persisted response limits, error
bodies have a small redacted cap, and deadline/cancellation closes and cancels the in-flight exchange.
There is no production overload through which a client can discard those invocation limits.

Compatibility projections are aggregate-accounted before any retained blob is decoded. In-memory
projection budgets have a hard 64 MiB ceiling. `source_revisions.jsonl` contains one record per
revision with one evidence value and a bounded `changes` array, rather than repeating evidence for
every changed file.

## Enforced default resource budget

| Resource | Default limit |
| --- | ---: |
| Indexed modules | 100,000 |
| Indexed entities | 2,000,000 |
| Dependency edges | 20,000,000 |
| Source inputs | 500,000 files / 128 MiB per file / 4 GiB total |
| Profile-specific index evidence | 512 MiB |
| Diagnostic text | 1,000,000 characters |
| Retained regression inputs | 10,000 cases / 100,000 total argv entries / 1 MiB payload |
| Complete agent request | 4 MiB |
| Successful repair response | 16 MiB (also capped by agent output limit) |
| One repair context | 64 modules / 256 files / 2 MiB |
| Strict staging workspace | 512 directories / 2 MiB total captured file data |
| One candidate patch | 32 files / 2 MiB |
| Candidate behavior output/time | 8 MiB stdout / 8 MiB stderr / 16 MiB aggregate / 5 s |
| Generated-C discovery | 1,000,000 entries / 100,000 directories / depth 128 |
| Revision nodes | 10,000 |
| Serialized revision graph | 256 MiB |
| Content-addressed revision blobs | 4 GiB |
| Legacy repair history / revision compatibility log | 64 MiB each |

Callers may supply a smaller `RepairResourceBudget`. The exact budget is persisted in the graph and
must match on restart; changing it requires an explicit new graph rather than silently changing the
meaning of an existing repair history. Required seed context that exceeds a limit fails closed.
Dependency frontiers are deterministically truncated and the omitted module IDs are recorded as
`deferredModules`. Generated-C discovery charges each directory entry before adding it to the list
that will be sorted, so a single huge directory cannot be materialized past the discovery cap. Layout,
profile-configuration, and final-index canonical bytes are fed incrementally into capped digests rather
than accumulated in unbounded strings. Generated-C evidence checks top-level module/entity/type/cycle
counts and aggregate nested-array/reference counts before collection transforms. Diagnostic path
recovery additionally caps a line at 16,384 characters and the number of line-prefix probes at 4,096.

The mechanism is program-agnostic. A large compiler recovery is a useful benchmark, but benchmark-
specific fixtures, compiler names, flags, commands, paths, or expected behavior do not belong in the
revision or transaction API. Real-toolchain benchmark evidence is external acceptance evidence for a
profile/strategy combination, not a prerequisite for the generic graph invariants above.

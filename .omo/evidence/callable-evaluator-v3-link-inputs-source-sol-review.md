# Independent A3 static link-input source review

**Terminal verdict: ITERATE for the exact four-file source checkpoint below.** Three concrete static-resolution/resource findings block source acceptance. The fixed unqualified status remains honest; this review does not claim a current toolchain-authority bypass, actual GCC/linker execution or composed v3 preparation acceptance.

Worktree: `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`. Reviewed source root: `oracle/acp/callable-evaluator-v3/source/`. Root retains source/Git/remote custody. No source, Git/index, remote, Actions, authentication/model, helper/compiler/linker/native/candidate or privileged operation was performed; no descendants were spawned. Only this report and bounded ignored reviewer evidence were written. All fixtures/tmp/cache paths were repository-contained. Other workers' mutable profile/report/graph/coordinator files were not included in a global freeze or composed test claim.

## Exact review binding

Approved plan `.omo/plans/callable-evaluator-v2-automatic-review-corrections.md` hashes to `be68d448f82c15f8d7f525de1f08b29a83407a77c05b05460a265235b504271d`. Its A3 source gate requires finite exact-profile resolution of response/script/default/startup/tool/config/symlink inputs with unknown/missing/ambiguous refusal and complete re-resolution. Real driver dry-run/harmless link inventory and mutation qualification remain a later independently authorized gate.

Author evidence `build/acp-decomp-effectiveness/callable-library-v3/static-link-inputs/freeze.json`:1293bytes, SHA256 `dadc099a26761b2a6a83448ca9e89836341d33d8fbaf9b8023c9aad8120e7835`. All four source sizes/hashes matched before and after the pure checks:

| Source-relative path | Bytes | SHA256 |
| --- | ---: | --- |
| `toolchain-001/link_inputs.py` |22821|`997af85bf6a9c6f81baf8224e54803b2cbf0c8d121bd901c3ecd73ed2afb029f`|
| `toolchain-001/pin_environment.py` |2169|`76fa55e6b42a4b557cfb5450af76810afb8af2cc75ca962834e999ca349e4ff3`|
| `contracts/toolchain-pin-schema.json` |9943|`6edaf7576fcc4f6f7aa55c53074572cd8d10c86a2f286ae180ad59e90aab5d71`|
| `tests/test_link_inputs.py` |9751|`e9f148564fbb38debbf885964207c7da6b480602120fed66d3827fa8e081cbba`|

Author `report.md` SHA256 `0a6fd380d7589b65936614fe0684a6ae569e03284b89b1d94745ea168d295bdc`; `tests.log` SHA256 `03c05bc1d1c99f20c730df3a3de1fab4383d595932c0ad7f3405c29dbc92bfd4`.

## R1 — Lexical normalization removes symlink-sensitive path components

**Anchors:** `link_inputs.py:34–40,60–88,90–94,485–490`; `pin_environment.py:24–32`.

`logical()` calls `posixpath.normpath` before `resolve()` traverses symlinks. Therefore a path such as `/tools/alias/../adjacent` is reduced to `/tools/adjacent` before `/tools/alias` is ever examined. Filesystem `..` after a symlink applies to the resolved target directory, so the actual input can be a different file. The recorded logical/real path and link list lose the dependency; full re-resolution repeats the same incorrect normalization and misses a changed selection.

**Full-pin inert reproduction:** the fixture has `/tools/adjacent`, `/target/adjacent` and `/target2/adjacent` containing distinct inert ELF-magic bytes. `/tools/alias` initially points relatively to `../target/deep`; the recorded linker command includes `/tools/alias/../adjacent`. After collecting the pin, changing alias to `../target2/deep` changes the actual repository-local input bytes, yet `revalidate_pin` returns an equal pin. It records `/tools/adjacent` with no symlinks. Output:

```text
dotdot-symlink changed-real-input True revalidate-accepted-equal True recorded-links []
```

No host path or native linker was used; direct ordinary fixture reads establish that the path's real contents changed.

**Required correction:** preserve input components through symlink traversal and record exact logical selection spelling plus every encountered link and resulting real file. Apply `..` to resolved components, not before the walk. Alternatively explicitly refuse such unsupported ambiguous spellings until a reviewed finite implementation exists. Do not change compiler flags to hide implicit dependencies. Add symlink-plus-dotdot and changed-target revalidation controls, including search directories/response/script paths using the same helper.

## R2 — Linker scripts lose enclosing static/dynamic selection state

**Anchors:** `link_inputs.py:155–160,206–225,265–274,305–311,339–356,389–396`.

`command()` tracks static state and passes it to direct `-l` selections. It calls `input()` without that state for script inputs. `script()` then calls `choose(...,library=True)` with the default `static=False`, including nested AS_NEEDED/INCLUDE recursion. Thus a supported script processed under `-Bstatic` can record a `.so` dependency even when the static `.a` exists. The recorded closure's own selection field incorrectly says static=false.

**Inert reproduction:** existing full fixture gains `/lib/extra.ld` containing `INPUT(-lnested)`, and both `/lib/libnested.so` and `/lib/libnested.a`. Insert `-Bstatic /lib/extra.ld -Bdynamic` into the recorded collect2 command. Collection succeeds but records:

```text
request=-lnested selected=/lib/libnested.so static=false
```

This demonstrates the parser's state loss under syntax it accepts. It does not claim native GCC/linker qualification; the later real exact-command inventory still must establish the supported implementation semantics.

**Required correction:** carry the effective static/dynamic state through script INPUT/GROUP/AS_NEEDED and INCLUDE recursion, respecting the same push/pop ownership as the enclosing command. If a combination is not yet modeled, refuse it explicitly rather than silently using dynamic defaults. Add direct-script and included/nested-script static-versus-dynamic preference controls with both candidate files present. Preserve the exact configured GCC flags and required startup/default inputs.

## R3 — Resource ceilings are checked after unbounded or over-budget materialization

**Anchors:** `link_inputs.py:90–108,121–136,181–204,212–218,239–246`; `pin_environment.py:41`.

Several reported ceilings constrain only eventual output, after the expensive work already happened:

- `file()` reads up to512MiB+1 into one bytes object before charging remaining aggregate bytes or the file-count ceiling. A second file known from stat to exceed remaining budget is still fully opened/read. Response/script1MiB checks happen after that full read.
- `sorted(physical.iterdir())` materializes every directory entry before checking the20000-entry ceiling. A large directory is not bounded by the eventual loop check.
- `response()` extends the parent result with every expanded child, checking the20000-word limit only after finishing the entire parent. Repeated bounded responses can construct a very large intermediate list; repeated script/response parsing and selections also lack a shared cumulative work/expansion budget. Per-file text/depth limits and unique-file byte accounting do not close that repeated expansion work.
- CLI manifest ingestion uses unrestricted `read_bytes()` followed by `json.loads()` before any manifest validation; it has no bounded strict raw-record reader. API collection likewise does not validate complete schema/collection/work limits before filesystem work. The closed output schema is exercised explicitly by tests, not enforced by collection itself.

**Small equivalent-limit probes:** under a16-byte aggregate cap, after admitting8bytes, a12-byte next file is opened and read before refusal (`requested=17 returned=12` with only8remaining). With argument cap4, three four-word response expansions are all read before eventual rejection. With directory cap4, all20fixture entries are yielded to sorting before rejection. Constants were narrowed only inside pure mocked fixtures; no large allocation or real inventory was run.

```text
aggregate-byte remaining8 beforeb [{"requested":17,"returned":12}]
response-expanded4cap callsbeforefailure 3
directory4cap yieldedbeforefailure 20
```

**Required correction:** validate known remaining file/count/byte budgets before opening/reading, stream/hash bounded blocks and distinguish small text reads from large binary hashing; do not allocate the full remaining hard maximum for every file. Boundedly enumerate at most the allowed entry count plus a single refusal probe before sorting. Reserve/check expanded words and shared recursion/work/selection budgets before extending or descending further. Add a bounded strict manifest loader/typed validation path before filesystem resolution, including duplicate/unknown-field refusal. Keep limits explicit and caller-lowerable only if exposed; do not silently widen them. Add observable zero-open/read-after-known-overflow, directory enumeration-stop and repeated expansion/work exact/one-over controls. This is required for the advertised finite resource contract even while all results remain unqualified.

## Pure verification and retained evidence

Independently ran only `python3 -B tests/test_link_inputs.py`:10/10 passed, no skips, with all native subprocess entrypoints mocked by the fixture. Test imports are limited to the owned pin/resolver path and the repository-selected fastjsonschema2.22.2. All11 installed validator Python source files were hashed before/after; unchanged. No dependency was installed/acquired. The additional bounded fixture probe uses the same fixture setup/native mocks and own repository-local files; it does not execute inert ELF/archive bytes.

Reviewer evidence root: `build/acp-decomp-effectiveness/callable-library-v3/static-link-inputs-sol-review/`. Exact four-file source snapshots, validator-input manifest, commands/environment and logs are committed by `review-artifacts.json`, SHA256 `a9eef0dc86fe48ec212474713dd9dc74684a47a91337bd25ae9480ff7022bd7b` (10files,52218bytes, excluding that manifest/report). Key pins:

| Evidence | SHA256 |
| --- | --- |
| `probe.py` | `75e81dc8ac32852705718bf29575860044290abf8cf12956e808732a5e037d8e` |
| `probe-final.log` | `145eb43ae675c4178c1a6d89afad989e95096718b96ae08757d1841db91de0f0` |
| `independent-tests.log` | `a18864c93a0f59aee1004210b5e43af6e481122c1ec085985a0608cde126bfad` |
| `commands.json` | `42b5525afd42c55dfd35c6deeb8024a49dc43e6b8d4019cfdf05a7c0a4f0def7` |

Existing tests establish useful static coverage: startup/default/tool/spec/plugin content changes, preferred selections, config additions, same-content changed symlinks, response/script recursion, missing/unknown forms and closed-schema unknown/v2 refusal. They do not cover R1/R2 or pre-work limits. Their passing result does not qualify actual GCC completeness.

## Authority and remaining integration gates

`collect_pin()` fixes both pin/closure status to `static-recording-unqualified`; schema constants preserve that status. Revalidation compares a fully rebuilt pin rather than merely rehashing an old file list. A changed qualified-status claim fails equality against rebuilt unqualified output. Import and CLI have no subprocess invocation. There is no demonstrated path here that creates an accepted runtime/toolchain/preparation authority from an incomplete receipt. The recording, tool list and config roots are supplied observations, not authenticated proof of actual GCC behavior.

After source corrections and exact refreeze/re-review, actual authorized exact GCC driver dry-run plus harmless link trace/inventory must still establish that the finite resolver covers the real profile. Unsupported forms require a reviewed finite extension or refusal. Full tool/runtime/header/Python/helper/config inventory and actual environment capture remain later integration obligations; replacing the former import-time pin capture with a static supplied recording has not established those inventories. Mutable neighboring A1/A2/A4/A5/profile/report/graph/coordinator files were not globally tested/frozen by this review. The complete matrix/preflight, distinct reviews, source checkpoint versus final seal and post-copy integrity gates in be68 remain necessary. No #1507 closure, native qualification, model/private trial or final preparation acceptance follows.

Root should assign R1–R3 corrections, preserve this exact failed checkpoint/probes, then request an independent source re-review. No source changes are authorized or performed by this report.


---

## Revision 2 independent re-review — CLEAR for the frozen A3 static source checkpoint

**Terminal decision: CLEAR.** The three blocking findings R1–R3 above are resolved in the exact four-file revision reviewed below. No additional blocking defect was found in this held static resolver/API/schema/test scope. This decision does not qualify a supplied recording as an authentic complete toolchain inventory, approve actual GCC/native execution, or approve the mutable composed evaluator.

The original 12463-byte ITERATE report remains the byte-identical prefix with SHA256 `410e1cb8e27f0cb21b8408f4bdcde1c65eb8655834b7f509c08159f1b47c1ab7`. The original author freeze remains `dadc099a26761b2a6a83448ca9e89836341d33d8fbaf9b8023c9aad8120e7835`. Original source snapshots and reviewer probes were retained. Approved correction plan remains `be68d448f82c15f8d7f525de1f08b29a83407a77c05b05460a265235b504271d`, specifically A3 at line39 and later native inventory gate at line64.

### Exact revision binding

Worktree: `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`. Paths in the next table are relative to `oracle/acp/callable-evaluator-v3/source/`. Recomputed source hashes before and after the independent pure suite match the held pins.

| Source | Bytes | SHA256 |
| --- | ---: | --- |
| `toolchain-001/link_inputs.py` | 27689 | `61a2f3a64e327cab74bd1fd16985c97fee8ee7208c3d89512005c7748aba9c31` |
| `toolchain-001/pin_environment.py` | 3820 | `c0080a37f33c02ad41aaadc7e8033fdbdb67ab6c918b528a24dc354b6617b08b` |
| `contracts/toolchain-pin-schema.json` | 10326 | `540bd7fc00cbba495c3e832b1996abc0e7bbaa5bd6a64e58a373fdc4e7051c6c` |
| `tests/test_link_inputs.py` | 16600 | `2242c94f647f739370cedc57cb8c166128930fdec7584005d4c7bf20a023f01a` |

Author evidence under `build/acp-decomp-effectiveness/callable-library-v3/static-link-inputs/revision-2/` was read and rehashed:

| Evidence | SHA256 |
| --- | --- |
| `freeze.json` | `bc11dfceb8f6cba9bdb8a4932338531c49af51c27025cacd04c64a35688db3ed` |
| `tests.log` | `9e2f2dd07f822634246cd6d9c421e00a86b176b8837ce8d6d34da9503472187e` |
| `old-vs-new-confirmed.log` | `425364c9a30c7bddef2d1a7e35ebc7e496f1f2bfd82c83b610f493740c344772` |
| `report.md` | `4a2b8b29fa596738551800fe383122f9cc7a2b6d306b4e66717985f53d514cce` |

### R1 resolved — exact logical spelling through component resolution

`link_inputs.py:39–47` retains dot components and exact selection spelling instead of normalizing before filesystem traversal. `resolve():73–104` walks components in order, records each encountered symlink, follows its absolute/relative target, then applies any subsequent `..` to the resolved components. Non-directory intermediate components, logical-root escape and excessive symlink depth refuse. Files retain both that logical spelling and resulting real path/link list (`106–151`). Search directories, response files and script paths share this path machinery.

The original changed-real-input full-pin failure is now covered by `test_link_inputs.py:84–101`; search, response and script variants are covered at `102–119`. They assert the retained symlink dependency and refusal after alias substitution. Code inspection confirms that relative script-directory construction preserves the same components. Consumers must retain these exact logical spellings; downstream lexical normalization would undo the correction.

### R2 resolved — state reaches direct and recursive script selection

`input(..., static=False)` carries the current command state into `script()` (`link_inputs.py:266–296`). Script INPUT/GROUP/AS_NEEDED selections pass `static` to `choose` and recursive `input` (`327–341`); INCLUDE passes it onward (`372–378`). The command's push/pop and static/dynamic transitions remain owned by its state stack (`415–423`), with script and normal input entry points forwarding the state (`456–463`).

The new test at `test_link_inputs.py:120–134` has both preferred candidates present and checks static archive then dynamic shared-object selection across push/pop for direct INPUT and included nested GROUP/AS_NEEDED scripts. It passes on this revision. The retained old-source log demonstrates the original dynamic-selection error. Its included=True subtest accumulates command insertions after the preceding failing old assertion; that old subtest is not an isolated native comparison. The first direct-script mismatch independently demonstrates state loss, while the corrected revision completes and resets both subtests successfully.

### R3 resolved — bounded admission before identified expensive operations

- `file():106–152` checks regular type, per-file, fresh-file count, remaining unique bytes, cumulative read bytes and explicit small-text size before opening. It reserves the stat size before read, hashes binary blocks of at most64KiB and retains only their first8bytes. Known response text above1MiB refuses before open. Unknown link input needs at most an8-byte format probe to distinguish binary from script; an oversized script refuses before reading its remainder. Growth permits at most one refusal byte and does not append it to retained text. Repeated file reads consume the shared512MiB I/O budget, including repeated identities.
- `directory():154–204` checks directory-record budget before enumeration and shared/per-directory entry admission before metadata/append; only admitted entries are sorted. The cap4 fixture at `test_link_inputs.py:154–168` observes exactly5 yields, the last solely detecting excess, rather than all20 children. Previously admitted entries across directories consume the same shared entry budget.
- `response():235–264` charges expanded leaves before append, checks exhausted expansion before opening the next response and shares the resolution work counter (`68–71`). It processes lexer iterators and bounded children rather than independently expanding all repeated responses first. At cap4 the exact response succeeds, a repeated response refuses after opening only the first file; work cap3 accepts exactly3 leaves then refuses without increasing the count (`test_link_inputs.py:169–187`). Collection expands the recorded command once and passes `expanded=True` (`567–572`).
- Recorded dry-run text/line/word admission (`468–509`), incremental script token admission and depth checks (`291–350`), selection admission (`206–209`) and component/work accounting bound repeated processing. Manifest inventory collections are typed, fixed-key and jointly capped128 before filesystem collection (`512–558`). The input contract retains the exact driver argv/environment rather than changing flags to avoid implicit dependencies.
- `pin_environment.py:37–73` opens the JSON descriptor with NOFOLLOW/NONBLOCK/CLOEXEC, checks regular type and2MiB stat size before read/parse, reads bounded blocks with a single growth refusal byte, closes ownership in finally, rejects duplicate fields/noninteger numbers/invalid JSON and validates the typed manifest before resolution. The CLI uses this loader (`82`). An oversize JSON test forbids both read and parse, and malformed roots/tools/command tests forbid resolver file access (`test_link_inputs.py:188–206`). An initial descriptor open/stat is necessary to learn size; the proven zero-open condition applies to already stat-known resolver file overflow, and zero-read/parse applies to oversized CLI JSON.

### Independent verification and evidence

Independently ran only `python3 -B tests/test_link_inputs.py` in the owned source directory: **17 tests passed in0.393s**, no skips. The original10 controls and7 added controls execute with subprocess entry points mocked by each fixture; no inert ELF/archive bytes execute. All four held source files and all11 previously pinned fastjsonschema2.22.2 Python source files were hashed before/after and unchanged. Temporary/cache settings and created fixture/evidence paths remained under the repository. No compiler, helper, candidate, native tool, acquisition, remote, Git or Actions operation was performed.

New reviewer evidence under `build/acp-decomp-effectiveness/callable-library-v3/static-link-inputs-sol-review/revision-2/`:

| Evidence | SHA256 |
| --- | --- |
| `independent-tests.log` | `4ff458443d42cfc6d7972b33b995de3af4fabe3183650e5c8ec3dc2e5abbc07e` |
| `verification.json` | `74f4553202e9d6666ae6781711f147ecad15bf998e1fba81bd1532ce19fd6153` |

Author old-vs-new evidence retains3 focused test methods rejecting the exact preserved initial source (3 failures and1 error because subtests produce multiple failure records), and the complete corrected17-control suite passes independently. That supports correction of the concrete original failures; it is not a native compiler comparison.

### Authority and remaining gates

`pin_environment.py:19–34` still constructs only `static-recording-unqualified` output and revalidates against a fully rebuilt equal pin. `link_inputs.py:580–590` does the same for the closure; schema constants at lines16/250 reject promotion. Unknown syntax, unresolved input, missing startup/default-library requirements and drift continue to refuse. No receipt-to-qualified-toolchain promotion path was added in these files.

Actual authorized exact GCC dry-run plus controlled harmless link trace/inventory must still bind this finite resolver to the real configured profile and prove complete implicit inputs. Actual full header/tool/runtime/Python/helper/configuration and environment capture, before/after drift controls, native assertions, matrix/preflight, separate reviews and final seal/post-copy checks remain the approved plan's later gates. Supplied tools/recording/roots are observations, not authenticated capture or proof of their own completeness. Filesystem inputs also are not claimed immutable merely because static revalidation succeeds.

Only these four held source files were re-reviewed and independently tested. A4 remains a separate ITERATE and A5/neighboring workers are not covered by this freeze. **CLEAR resolves R1–R3 for revision2 A3 static source only; it does not grant global evaluator qualification, preparation acceptance, issue closure, provider/auth/model permission or native execution authorization.** Root retains all source/Git/remote custody.

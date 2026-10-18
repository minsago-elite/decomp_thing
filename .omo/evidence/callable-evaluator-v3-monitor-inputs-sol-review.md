# Independent A3 monitor/inspection input source review

Verdict: **CLEAR_SCOPED** for the exact five-file static operational byte-closure source checkpoint. No blocking source defect found within this declared-input/parser/API scope. This is not usable-worker/F1 acceptance, actual monitor provenance, actual GCC/header/link/loader qualification, a final composed evaluator/preflight, preparation sealing, full #1507 acceptance or trial authority.

Reviewer: GPT-6.1 Sol, independent of implementation; no descendants. Root retains source/Git/remote custody. Read-only source/artifact/hash/AST/JSON inspection; only this report was written. No compiler/helper/monitor/native/ldd/Bash/target/candidate, model/auth/credential, acquisition, Git/remote/CI action or test replay was executed. Concurrent runtime/C/consumer work was not edited or approved.

## Exact held checkpoint

Worktree: `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`.

| Binding | SHA256 |
| --- | --- |
| `build/acp-decomp-effectiveness/callable-library-v3/static-monitor-inputs/freeze.json` | `1cc25a420ecbfc73c181fdc48c6a4153ac668923b95d1a206d93b7fd69574d45` |
| Adjacent `report.md` | `14d758d8ec9b5d6e53589a76033595ffd504427a73aad808325c51cdc0a2c488` |
| Worker exec plan, root `.omo/plans/callable-evaluator-v3-worker-exec-proof.md` | `b670e2de4fe5fbda4b06872234319f9121887d600b2341473d233d051df34ceb` |
| Explicit ldd ELF recipe addendum | `fd41f6c5b3d8a3bc0967b0933a5fe19f39e6d675b0fd6ea84453072a05e1c010` |
| Prior A3 review including revision2 scoped CLEAR | `09bed49b182468826213c0f760aa543b79d272a7d9149c71a3eedefa32e46d39` |
| Guarded31-test log | `e673f7fe7684dfc18a9e09fa7475a352de462be43937aa1986385a04b5e2e554` |
| Guard result | `23fbcf1dd02c2a49d069b559c59a5bd89f1a130539ba142e1d18069285461432` |

All five current sources and their five source-snapshot copies, all six frozen evidence records, the readonly freeze gate input and all three authority digests match. Source AST/JSON parsing succeeded during inspection. No old review/provisional snapshot was promoted to current native evidence. The prior A3 review's original ITERATE prefix remains historical; its revision2 CLEAR was read as a scoped static source decision, not machine qualification.

## Input closure and finite ELF metadata

`monitor_inputs.py:34–69` validates exact monitor/inspection records before resolver filesystem collection: nonempty bounded inventories, canonical absolute paths, unique SONAME selections and required five recorded build roles. A provisioning dependency array may be empty, but it is never treated as runtime closure/completeness. Monitor and inspection runtime inventories must independently be nonempty.

`elf():89–151` accepts a finite ELF64 little-endian x86-64 profile and bounded program/dynamic/string metadata. It validates file ranges and PT_LOAD-backed PT_DYNAMIC/DT_STRTAB mapping through exactly one matching mapping, requires dynamic string-table identity/termination, checks bounded SONAME strings, and derives PT_INTERP/DT_NEEDED edges. RPATH/RUNPATH and unsupported selection/audit/filter tags or flags refuse; duplicate metadata/needed names, bad ranges, ambiguous mappings and malformed terminators refuse. It is a finite metadata parser, not a full ELF loader or proof every other ELF field would be accepted by the kernel.

`graph():154–182` requires a dynamic root with interpreter/nonempty needed list, refuses a self-interpreter, rejects executable-with-interpreter dependencies and non-ET_DYN libraries, follows every transitive declared needed edge, and requires every declared selection be reachable. Missing/extra/wrong-SONAME entries refuse. Graph roots, paths and actual image contents become retained file records; caller-supplied provisioning deps cannot replace the graph. Interpreter and library closure is exact relative to the declared SONAME selection. It does not prove the real loader used that selection or that ld.so.cache encodes it.

Roles/images and libraries are bounded at128, program headers128, dynamic metadata4096bytes, string table1MiB and each admitted ELF image16MiB. Parser slices remain within that already admitted image; this is not a zero-copy/high-water RSS claim. Existing shared resolver ceilings are20000files,512MiB admitted file payload and separately512MiB cumulative read work, plus200000resolution steps. Count/known file-size/role limits are checked before payload descriptor reads/materialization. JSON record size is checked before decoding; a descriptor open/stat is necessarily used to discover recording size. No parser/runtime performance qualification is inferred from constants or small fixtures.

## Descriptor reads, identity and revalidation

`link_inputs.py:106–175` performs size/type/remaining file and IO admission before final payload open, then walks resolved components relative to retained directory descriptors with O_NOFOLLOW and opens the final regular file NONBLOCK/NOFOLLOW/CLOEXEC. Known input size is reserved before reads; fixed64KiB chunks plus a growth-refusal byte prevent an expanding input from consuming unadmitted payload. Before/after FD and named-path checks compare device/inode/mode/UID/GID/link count/size/time metadata and exact bytes/hash. Output retains logical spelling, resolved realpath, symlink selections and typed identity. Equal-byte inode replacement therefore changes the reconstructed pin.

Owned intermediate directory and final file descriptors close through finally/context-manager paths, including tested partial open and identity replacement failures. Directory/configuration resolution is rebuilt as bounded sorted entry/selection records; it is not represented as a claim that every directory inode was authenticated for runtime. Prior symlink-sensitive dotdot, static/dynamic script state, response/script recursion and preallocation protections remain in the actual code/tests rather than being assumed from the old review alone.

`collect_pin` uses one resolver shared by implicit-link, monitor and inspection closure, so new roles cannot each reset the aggregate IO budget. `revalidate_pin` reconstructs from the manifest against the supplied root and compares canonical complete pin contents. It does not trust an incoming top-level dependency dictionary or rehash only old known paths. Added/removed selections/configuration/runtime/build/source/cache changes must still reconstruct equally to be accepted.

## Fixed monitor/build/inspection inputs

`collect_monitor():185–217` binds source/parser/protocol/builder/provision-manifest, nonempty role inventory, binary and runtime graph. It requires the fixed recorded GCC argv, provisioning-only-unqualified status and exact source/parser/protocol/binary digest agreement. The recorded execution dictionary/build-role inventory does not prove the compiler ran or that actual compiler/header/link inputs were complete. Its explicit buildInputStatus remains recorded-build-inputs-unqualified.

`collect_inspection():221–231` accepts only the fixed /bin/bash, /usr/bin/ldd and /etc/ld.so.cache logical recipe. Script bytes must start with the exact single Bash shebang and newline; env dispatch, other/argumented/CRLF/missing-newline shebangs refuse. Bash has its own nonempty declared ELF runtime graph. The exact loader cache is bounded to1MiB, nonempty, non-symlink and canonical; no whole /etc or private ancestor tree is admitted. Byte changes in script/Bash/cache/dependencies fail revalidation.

This follows fd41's explicit interpreter-argv decision, not an implicit generic script permission or a claim of kernel-shebang/AT_EXECFN equivalence. A1/runtime still own actual canonical Bash argv, separate logical request recording, exact readonly mount recipes, unprivileged executable checks and consumer pre/post input checks. Neither source-only closure nor this review qualifies actual Bash/ldd behavior/selection or grants host-direct execution.

## Profile-bound APIs and qualification boundary

`pin_environment.py:87–104` accepts only a valid profile pin digest and the fixed BASE/toolchain-001/environment-pin.json. The bounded descriptor read's raw hash must match before revalidation. It fully rebuilds against root `/`, then enforces fixed public monitor source/parser/protocol/builder/provision paths. Absent, malformed, mismatched or drifted recordings refuse before worker admission.

`load_monitor_binding():119–128` returns canonical binary/source/parser/protocol/manifest and environment pin hashes plus a nonempty canonical runtime dependency list excluding the separately returned binary. `load_inspection_binding():131–138` includes canonical Bash/script/cache and all its declared graph inputs. Conflicting hashes for one canonical runtime path refuse. These return bytes/metadata only; they are not accepted native capability tokens. The positive formatting test mocks an already loaded value and is honestly limited to normalization; separate tests require actual fixed path/hash/rebuild behavior.

Top-level/closure statuses are fixed static-recording-unqualified; loader selection remains declared-selection-native-unqualified. The schema requires both new closed closures and typed identity rows and rejects native status promotion. `freeze_v3.py:383–388`, unchanged SHA256 `2f1b7735bf57ab9f13c12e55166e67864610e8be90ae46bacf563256bc762505`, rejects static pins and every other invented qualification status because no reviewed typed qualified machine closure is available. A Markdown claim or provisioning execution dictionary cannot pass this gate.

Root-approved fixed public primitive controls may later consume these operational bytes only through the separately reviewed same contained route. This scoped source CLEAR does not authorize that execution, approve concurrent F1 monitor/channel semantics, or weaken actual GCC/header/link/loader machine qualification and final seal gates.

## Retained pure verification and disposition

The guarded source runner installs permanent process/network audit denial before import, then runs the authored inert suite with subprocess entry points additionally mocked. The final retained output records31tests,0failures/skips in1.129seconds; guard result records no forbidden action attempts and the exact current test digest. Initial17/expanded29logs are intermediate history, not additional current qualification. Python3.14.8 and fastjsonschema2.22.2 are recorded; syntax/schema and pure fixture success do not attest native binaries.

Inspected controls cover nonempty/role/graph closure, missing/extra/transitive/wrong SONAME/interpreter, malformed ELF/selection/flags/ranges/strings, pre-open byte/count caps, all input-class mutations, deterministic equal-byte replacement, descriptor recovery, shebang/cache drift, fixed API refusal/rebuild and schema promotion rejection. No actual operational environment pin, provisioned monitor/binary, GCC/header/linktrace, loader selection, candidate/native matrix or final preparation was created by this checkpoint. This review did not rerun the suite because retained source/evidence and specific controls were sufficient for the static source questions.

**CLEAR_SCOPED** supports this five-file source checkpoint for integration review. Compose and freeze all final source/support inputs after other owners stop; include monitor_inputs.py. Later actual native qualification, consumer/isolation/worker proof, all24scenario matrix, independent full acceptance, sealing/post-copy checks and required CI remain mandatory. No broader evaluator acceptance or model/auth/trial authority follows.

## Exact source pins

| Path | SHA256 |
| --- | --- |
| `oracle/acp/callable-evaluator-v3/source/contracts/toolchain-pin-schema.json` | `b7b4962da411b7b0810706bd2964b4762ad0b6ee5a3db6d88c9c822ffb4849c4` |
| `oracle/acp/callable-evaluator-v3/source/tests/test_link_inputs.py` | `2ee1ed81c72b27fe3a47dcb34bfdf6bce22fb34c40817b4885ef45abb244db0f` |
| `oracle/acp/callable-evaluator-v3/source/toolchain-001/link_inputs.py` | `a1fb0950e2500747a5f01c6319d45a522323ecbcc33b535e7ef262241f338f1e` |
| `oracle/acp/callable-evaluator-v3/source/toolchain-001/monitor_inputs.py` | `812586a70c2eecaccde6f94238ffd1f5aa3d7a4bbaa20aecbd6ad104584ccaf6` |
| `oracle/acp/callable-evaluator-v3/source/toolchain-001/pin_environment.py` | `fb650456d802e5dd5195668a1efc8a88ef914cb59582c8b58ea54b7aa6181e82` |

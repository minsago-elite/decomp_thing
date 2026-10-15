# Independent Sol review: PT_INTERP graph roles

**Verdict: CLEAR for the exact held two-file source correction.** No blocking finding in this scoped graph-role change. This is a static source review, not operational closure or native qualification.

## Pins and method

Worktree: `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`.

| Artifact | SHA256 |
|---|---|
| `build/monitor-dso-interpreter-role-correction/freeze.json` | `7aa693dffe8d783f1f50544359255b520c99d30dced8633c33a64dda665c20c6` |
| `source/toolchain-001/monitor_inputs.py` | `0cab347a7874162840bdda8b0dc138782657ddaf592b8e3a51b3c59c731838d1` |
| `source/tests/test_link_inputs.py` | `08e1083786da646f9c4214a093cef2a81b6c3ec5ddcfcd0512b6c3e18b39f471` |
| Retained investigation `build/monitor-dso-interpreter-role-investigation/report.md` | `9df54bd15869137a28ed50f4555da157a5adaf2367035066edb304effd3ab24f` |
| Unchanged underlying `link_inputs.py` | `a1fb0950e2500747a5f01c6319d45a522323ecbcc33b535e7ef262241f338f1e` |

Source prefixes above are `oracle/acp/callable-evaluator-v3/`. Freeze, all listed source/artifact hashes and the investigation hash were independently rechecked. Production before/after snapshots, exact diffs, retained37-test results and old-parser negative control were read. AST comparison confirms `elf()` is unchanged and the test main guard remains last; the final file contains37 test methods. No tests or native processes were executed during review. No source/tests, pin/profile, candidate/auth/model, Git or remote state was mutated. Only this additive review is written.

## Primary-source support

The root/non-root distinction is supported by the cited release-tagged code, independently inspected read-only: Linux's exec path opens the root object's interpreter; interpreter mapping handles LOAD segments without recursive interpreter loading. See `load_elf_binary`801–859 and `load_elf_interp`590–662 in [Linux v6.12 binfmt_elf.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/binfmt_elf.c).

For glibc's DSO path, the program-header switch does not follow PT_INTERP, whereas dependency discovery processes DT_NEEDED entries. See `_dl_map_object_from_fd`1039–1148 in [glibc2.42 dl-load.c](https://raw.githubusercontent.com/bminor/glibc/glibc-2.42/elf/dl-load.c) and `_dl_map_object_deps`193–246 in [glibc2.42 dl-deps.c](https://raw.githubusercontent.com/bminor/glibc/glibc-2.42/elf/dl-deps.c). These establish the role rationale for the admitted profile, not the installed kernel/loader revision or complete runtime selection. Other dynamic dependency mechanisms remain outside this parser's profile.

## Source checks

- `monitor_inputs.graph:181–190`: root handling is byte-for-byte unchanged. A root still needs a non-self interpreter and nonempty DT_NEEDED list; precisely its interpreter is queued. The root loader remains read/hash-bound. The only widened admission is removing non-root interpreter-presence refusal while preserving the ET_DYN-only guard. ET_EXEC dependencies remain refused with or without PT_INTERP; this is still a stricter supported profile than Linux's interpreter type range.
- `elf()` is unchanged: non-root PT_INTERP still undergoes bounded file-span, unique program-header multiplicity, NUL termination, ASCII and canonical absolute-path checks. A malformed field is never excused because it does not add an edge. Its string remains in returned ELF metadata; complete DSO hashing binds those bytes and revalidation detects changes.
- No queue/open/hash operation is added for a non-root interpreter target. A valid absent target is therefore metadata, not an implicitly requested file. An otherwise unused selection for that target remains extra/unreachable and refused. There is no libc/path-specific exception or fabricated dependency.
- DT_NEEDED recursion, exact declared selections, matching SONAME, unused-selection refusal, graph/file/image/string/work/descriptor bounds and cache/input handling are unchanged. No source/protocol/schema/status/authority upgrade or threshold increase appears.

## Retained controls

`results.json` and `pure-tests.log` record37 passing synthetic tests, zero failures/errors/skips and zero denied audit attempts. The34 previous methods remain; three additional methods cover the scoped behavior:

1. Valid ET_DYN PT_INTERP metadata with an absent target succeeds; a tracked resolver proves that target is never opened, while transitive NEEDED dependencies are processed. Metadata/full-file hash are retained, an extra target selection refuses, and changed interpreter bytes break revalidation.
2. ET_EXEC dependencies refuse with/without PT_INTERP; relative/dotdot, unterminated, oversized and duplicate non-root interpreter metadata refuse.
3. Root missing interpreter refuses, valid root loader is retained in the graph, and changed loader bytes refuse revalidation. Existing self/missing-root-loader, transitive missing/extra/wrong-SONAME and bounds/PLT tests remain.

The separate old-parser control deliberately records one error with the exact previous non-root-interpreter diagnostic; it is expected counterexample evidence, not a passing test. No actual host runtime graph/native execution is claimed by these synthetic observations.

## Limits of this clearance

This removes the identified non-root PT_INTERP role refusal in source. It does not establish that an actual complete monitor/Bash/shared-link composite pin has been collected or successfully revalidated. Preserve the exact compiled pair, unqualified/dependency-empty provisioning manifest and historical receipts. Complete authenticated compiler/header/link/loader selection evidence, a reviewed environment-pin/profile binding, root-authorized native public primitive controls, full24 positives/mutants and later hosted/seal gates remain mandatory. No execution release follows from this review.

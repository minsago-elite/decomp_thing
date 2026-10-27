# Issue97 host-inspection bootstrap002 independent review

Verdict: **ITERATE** — one bounded-output issue prevents release under the stated512KiB per-fetch contract. Static review only: no fetch, host query, tests/syntax subprocess, JVM/native, Git or Actions operation performed. No source edits.

## Blocking finding

**F1 — bootstrap output byte ceiling depends on unqualified curl behavior.** In `.github/workflows/llvm-oracle-model.yml:800–818` (literal retained `bootstrap.sh`), the sole transfer/output-size limiter is `curl --max-filesize524288`. There is no independently enforced file-size limit, bounded pipe writer, or post-fetch size admission before `sha256sum`. Curl's streamed-size enforcement is version-dependent; older implementations can rely on advertised response length, so this option is insufficient as a universal output-byte ceiling for unknown-length/chunked transfers. The selected ubuntu22.04 image's curl version/implementation is not pinned or qualified here; hashing curl after both transfers cannot supply that missing precondition. The18second time bound is not a512KiB byte bound. A bad/unexpected response can consume more disk before hash refusal even though the script is never executed.

Smallest startable correction: impose a fixed OS per-file output-size ceiling in the bounded bootstrap shell (explicitly account for shell ulimit units and fail if unavailable), covering both curl output files before either transfer; add post-fetch regular-file/size checks before hashing/execution and preserve exact script hash/no fallback. A narrowly bounded writer is an alternative, but no new framework or source acquisition route is needed. Keep43+2,18seconds, HTTPS-only/closed environment/anonymous URLs unchanged. Add inert/static controls for actual ceiling placement and byte units; actual network qualification is not necessary to author this correction. Do not remove the byte claim merely to mask this gap.

## Otherwise supported correction

- The actual001 run38590540096 remains a failed bootstrap with zero artifacts/no host facts. Its manifest SHA is `cd8b42d3e68f163c55bc5f97e1fcb7b93f52ac9c11795d7c5fcafb224849705f`; this review does not relabel it. The new route removes checkout and its workspace-clean/global-Git-config behavior, and removes the reserved RUNNER_TEMP assumption.
- Only the new inspection job bootstrap changes. It validates40lowercase-hex GITHUB_SHA, allocates owned state once, uses fixed quoted repo paths, fetches exactly two anonymous public exact-commit URLs with `/usr/bin/env -i` and curl `--disable` first. There is no inherited proxy/token/header/netrc/config environment, retry, branch/mirror fallback or install. HTTPS-only redirects are finite. Script SHA492be8… is checked before the later Python step; the fetched workflow is observational data, not executed. No Git metadata is required by the unchanged main/inspection route.
- The quoted heredoc/shell layout, pipefail/hash-check control flow and fixed paths are coherent on inspection; author's retained bash-n result is exit0 (not rerun). Owned root is no longer followed by checkout deletion.45second bootstrap and90second probe fit the existing3minute job, though scheduling/setup/upload can still time out; no terminal receipt means unknown, never successful host inspection. Bootstrap failure may still produce no artifact if failure precedes source-bootstrap.txt; this is a diagnosable failure, not qualification.
- The existing inspector script/tests retain exact001 bytes492be8…/9cd2f3…. Context remains explicit inspect-only known workflow; default capture context/worker gates are untouched. Old jobs/inputs and probe/upload remain unchanged in the reviewed diff. All host capability/capture/target/profile authority remains false. Tool hashes are observations, not tool provenance/host approval.
- Author retains26guarded pure checks with0forbidden attempts and source-only static/bash syntax evidence. I inspected receipts/source; I did not execute them. No actual curl/CA/network success, image prerequisites or host executor capability is proved.

Root should hold the new probe until F1 is corrected/reviewed, then release one fresh exact-ref observation. Original001 source review remains historical; the real run demonstrated a bootstrap defect despite that earlier scoped source clearance. Issue97/P1 feasibility remains open.

## Exact pins

Freeze SHA-256 `f07d450899ae510101989301a7572fbe6b56496ca6ef15e27ac67acb33cb306e`. All listed source/evidence hashes and sizes independently checked; snapshots equal current source.

| Path | SHA-256 |
|---|---|
| `.github/workflows/llvm-oracle-model.yml` | `5673a2b9474515e97bcbbcbf65f00196bd7f1e12e761e572692cf3caa50bbe32` |
| `oracle/llvm/capture_reference_runtime.py` | `492be8d2db0c65868ee50ca8fc007c4e27b2eedced4a26f6881e563710270a0b` |
| `tests/oracle/test_capture_llvm_reference_runtime.py` | `9cd2f3e24e37894c79e1a250bd01ba6a86cd40a8182521dcf33cb82c1eb37125` |
| `build/issue97-actions-host-inspection-002/bootstrap-syntax.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `build/issue97-actions-host-inspection-002/bootstrap-syntax.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `build/issue97-actions-host-inspection-002/bootstrap.sh` | `7d8e1b4f92a47a1424de87c34d0c6d440f8cd2043debb12e9748c068f31b20c4` |
| `build/issue97-actions-host-inspection-002/pure-tests.json` | `d7af44838b21a95f0f018903c782aebff70b5b68b8d4a11c87439bab443e0c7c` |
| `build/issue97-actions-host-inspection-002/pure-tests.log` | `34d6f1ab800d0f55a3009bc303924260c03f013101cead713d3ec75a04667b36` |
| `build/issue97-actions-host-inspection-002/report.md` | `6633085b8c7ebef20349333fc997e412f46d6b13c4fda964f9ed5fa8b26c1c81` |
| `build/issue97-actions-host-inspection-002/static-checks.json` | `f7c98c0a733b2045932f09c45a6faaee4d0e6536ae782d3d96b42624fe6b6e01` |
| `build/issue97-actions-host-inspection-002/workflow.diff` | `c12f8743ab461157accc0c773edf0191c98ca02bb1944215956f46c10a408a80` |

## Addendum — corrective003

Terminal verdict: **CLEAR_SCOPED** for the exact003 source bootstrap and subsequent root-released single read-only host observation. Original002 ITERATE and original001 failed-run facts above remain unchanged. This addendum resolves F1 for the stated bootstrap source scope; it does not establish actual host support, capture/profile approval, native qualification or issue97 closure.

Reviewed003 freeze `b881e8f803cedfe7309a868c4d1a129c177daa899ba681f9ebfa4a65827647d7`; workflow `b1d07e5aa1f6e902a61437ac3a7b5c0f9e5ffb4fca06d0fab1e8e156f053b4f6`. The diff adds exactly two `/usr/bin/prlimit --fsize=524288:524288 --` prefixes, each directly enclosing the existing env-i/curl command before transfer. Thus the output file ceiling no longer relies on advertised Content-Length or curl's version-specific streamed-size behavior. Both soft and hard limits are set to524288bytes and survive env/curl exec. The retained primary Linux resource-limit documentation specifies RLIMIT_FSIZE bytes, SIGXFSZ/EFBIG on attempted extension and exec preservation; util-linux documents soft:hard and command execution. GNU stat documents `%s` as byte size. These manual semantics support this source choice; they are not a claim that the actual Actions utility/image has been dynamically qualified.

Before either source is hashed, `bounded_source_file` checks regular, non-symlink, nonempty and numeric GNU-stat size<=524288. The script then must match the unchanged492be8… SHA before the later Python step. Both required new utilities are checked for executability and missing utility emits a typed refusal/exit78. Failure to apply a limit, curl write failure/oversize, failed stat/hash or any nonzero utility result stops the set-e/pipefail bootstrap; no unverified script can reach execution. Fixed sources reside in the fresh hosted workspace; these shell checks are not a hostile concurrent-filesystem authority claim.

Exactly two fixed anonymous public exact-GITHUB_SHA source URLs remain, with the original closed env/curl argv, HTTPS-only redirects,18seconds each, no retry/config/auth/fallback.43+2second bootstrap cap,90second probe cap and3minute job are unchanged. Helper492be8… and tests9cd2f3… remain byte-identical; prior capture context and all-false inspection authority are unchanged. Root separately verified public-repository accessibility; I performed no network check and do not predict hosted fetch success. Missing tools/network/host facts remain refusal/unknown; the prior actual failed run remains a failure with zero host facts.

All003 freeze source/evidence hashes+sizes and current/snapshot equality were independently checked. The three retained compressed primary manuals and decompressed-text hashes were checked and relevant text read. Author's26 guarded pure controls and bash syntax receipts were inspected, not rerun. No reviewer test/native-limit/fetch/query/Actions/Git operation or source edit occurred. Only this report was appended. Root may now commit the exact reviewed source and separately release the single fresh read-only observation; full capture remains outside this verdict.

###003 exact pins

| Path | SHA-256 |
|---|---|
| `.github/workflows/llvm-oracle-model.yml` | `b1d07e5aa1f6e902a61437ac3a7b5c0f9e5ffb4fca06d0fab1e8e156f053b4f6` |
| `oracle/llvm/capture_reference_runtime.py` | `492be8d2db0c65868ee50ca8fc007c4e27b2eedced4a26f6881e563710270a0b` |
| `tests/oracle/test_capture_llvm_reference_runtime.py` | `9cd2f3e24e37894c79e1a250bd01ba6a86cd40a8182521dcf33cb82c1eb37125` |
| `build/issue97-actions-host-inspection-003/bootstrap-syntax.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `build/issue97-actions-host-inspection-003/bootstrap-syntax.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `build/issue97-actions-host-inspection-003/bootstrap.sh` | `d8bed102bd44c469cc578569cb8f14d4e2784e9bda048c77e82f2b53a77f67e0` |
| `build/issue97-actions-host-inspection-003/primary-doc-pins.json` | `1ecfd2784eb6a9da48d876b1c470108ee3f463a573236b75cb92d9084737f2cf` |
| `build/issue97-actions-host-inspection-003/pure-tests.json` | `bf8a6ada96d4c59b7e1eadc2336fd4a0613eb6c7c9bc7fc9d89c5771c1426ec3` |
| `build/issue97-actions-host-inspection-003/pure-tests.log` | `8dd2e2590a4f038a461708d339d283c51a12beb9e2f4d5ab7d7129e9a8f0de9b` |
| `build/issue97-actions-host-inspection-003/report.md` | `e507c2464c2f32e357cd7d28410c9e6da5ffebfb5ecace0eb3b97671ad9985f1` |
| `build/issue97-actions-host-inspection-003/static-checks.json` | `81e88f2e85047fa4ba13878b7bc2a8f91c422870c9c491406e83bbb20bb7af32` |
| `build/issue97-actions-host-inspection-003/workflow.diff` | `c669fe8bdb2d37333895e7a80009b319200be962075baff3811ee35c6e1eedb9` |
| `build/issue97-actions-host-inspection-003/primary-docs/prlimit.1.bz2` | `85fa8585e141374943e67b86133694380786d56b502ed5fff8e86bc6c2425c51` |
| `build/issue97-actions-host-inspection-003/primary-docs/getrlimit.2.bz2` | `3e2a460b3180cc2b310ff769e64d076b54965b491535a39b08c9342e2a59fdf7` |
| `build/issue97-actions-host-inspection-003/primary-docs/stat.1.bz2` | `e90fa62572b166ccd3daf0842a4fc6eea2fa334caa5bccbd56d897d2e5850a9b` |

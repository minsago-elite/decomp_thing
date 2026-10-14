# Clang schema/runtime/network Stage 1

Issue1480 remains open. Acquisition, native and production qualification remain paused.

## stage1-summary.md

SHA256 `d97a93eb37be1f866acf4085d2d3f5b05719ffedd6233c0557b77904be4d3c64`

# Stage 1 exact source freeze

Finite schema validation now checks the complete checked-in vocabulary and meta-validates every schema branch, including unselected conditionals. References are local-only, cycle/depth/node bounded; schema capture is capped at 1 MiB; regex support is restricted to reviewed common Python/ECMA patterns. Numeric 1 and 1.0 compare equally, true remains distinct and integral floats satisfy integer. Final records require reproducibility; only compare-runs explicitly permits its provisional fragments to omit that final evidence. Canonical normalization command schema and registered exact schema digest are updated.

Runtime discovery roots now include both fixed drivers, retained probe and direct API libraries. Package-time discovery executes through the existing fail-closed bounded sandbox interface and rejects unresolved dependencies. Real discovery/parser control uses inert ldd output with a dependency reachable only from the probe: matching packaging succeeds, then a self-consistently rehashed record/loader omission rejects. Both fixed C/C++ driver identities replay complete byte/path/link/mode/version rows. Seven independent C-driver row mutations reject despite rehashed valid loader evidence. Replay strips raw --version output exactly as provisioning does; explicit producer-shaped newline regression passes.

Network normalization uses fixed loaded helper bytes, a held rootfs descriptor, root/etcfds authority checks and exclusive descriptor-relative temporary creation. It replaces hostname with clang1813 plus newline and resolv.conf with an empty regular file, owned root:root mode 0644, before deterministic archive generation. It never follows leaf links or symlinked etc. Real-FD controls simulate only root ownership/chown and demonstrate leaf-link canary preservation, equal canonical tars across differing network bytes, refusal of linked etc and failure cleanup. They are inert controls, not privileged/native qualification.

Verification:
- Full offline suite: 191 tests passed in 8.846 seconds (stage1-all-tests.log).
- Independent cached optimumcode JVM JSON Schema validator 0.5.5: 31 numeric/conditional/full-document cases passed (schema-crosscheck/results.log; runnable Java source and corpus alongside it).
- All 79 schema inventory hashes match exact repository bytes (schema-inventory-check.log).
- git diff --check passed.
- Independent review found raw version-newline mismatch in first candidate; replay and producer-shaped fixtures/regression are corrected. Concurrent fixed test-root teardown also caused an environmental suite failure; all three classes now use independent repo-local per-run roots and the full rerun passed.

Frozen SHA256:
- scripts/oracle/provision_clang_18_1_3.py: 5b7c7aaccf7c9a283fda0bbc7538eb526f2d70ce5f282f03fe6161bc92bd4125
- oracle/clang/18.1.3/test_provisioning.py: a4a2d293afbbf8a637cb4e79d0c29e9cac51785a9d3c40299f5a5cb8839ac78b
- oracle/clang/18.1.3/build-record.schema.json: edfc5cd7570377714d3483720e96d6ed203a9590f89fe31830484291eace52ff
- oracle/kotlin-schema-inventory-v1.json: ed1fe96494b373c970d0202650c1dbc932f149748312cd61dee1fe7d9c84586c

No privileged action, acquisition, archive/package download, native compiler qualification or Git/GitHub mutation was performed. Acquisition pause and key expiry refusal are unchanged. Production sandbox remains unavailable and fails closed. Host-tool, authenticated package payload and immutable loader checkpoints remain future work; inert packaging success is never native acceptance.

## stage1-sol-review.md

SHA256 `0295da76fa8a6e39c75552d1fb36e17f5289191951b1462d11bdb548b439db0d`

# Stage 1 independent code/evidence review

Verdict: CLEAR for the scoped schema, fragment gate, fixed driver replay, complete fixed runtime roots/discovery, and deterministic network normalization changes at this exact freeze:

- scripts/oracle/provision_clang_18_1_3.py: `5b7c7aaccf7c9a283fda0bbc7538eb526f2d70ce5f282f03fe6161bc92bd4125`
- oracle/clang/18.1.3/test_provisioning.py: `a4a2d293afbbf8a637cb4e79d0c29e9cac51785a9d3c40299f5a5cb8839ac78b`
- oracle/clang/18.1.3/build-record.schema.json: `edfc5cd7570377714d3483720e96d6ed203a9590f89fe31830484291eace52ff`
- oracle/kotlin-schema-inventory-v1.json: `ed1fe96494b373c970d0202650c1dbc932f149748312cd61dee1fe7d9c84586c`

No remaining scoped findings. Read-only source/Git/GitHub review; evidence only written under build/clang-remaining-review. No privileged command, acquisition or actual Clang/bootstrap execution performed.

## Corrected finding

The initial script950555cf... replayed raw --version stdout while provisioning stored stdout.strip(), rejecting unchanged real drivers with normal trailing newlines. Independent producer-shaped inert control reproduced rejection (`stage1-sol-version-control.log`). Final script strips replay stdout consistently. New test_driver_replay_canonicalizes_raw_version_stdout_like_provisioning independently passes and exercises this exact producer/replay boundary. The earlier failure log is retained as historical evidence, not a claim against this freeze.

## Scope and evidence

Finite schema validator meta-walks every branch/definition, rejects unknown vocabulary and unreviewed regex, restricts references to root local definitions, rejects cycles, and applies byte/depth/node limits. It handles ref siblings, boolean schemas, conditionals, required/properties/additionalProperties, JSON numerical equality/uniqueness, types and bounds. Boolean true remains distinct from1; integral1.0 is accepted as integer. Only compare_build_runs opts into omission of final reproducibility; verify/package paths retain full schema requirements. Schema command addition and inventory digest agree. No remote schema retrieval path is introduced.

Runtime fixed roots now include both drivers, retained probe and both API libraries. Discovery goes through the fail-closed reviewed sandbox boundary; there is no new rootfs_run/chroot fallback. Real parser over inert library files and controlled sandbox ldd output accepts a matching fixture, then rejects a self-consistent record/loader omission of a probe-only dependency. Existing symlink/target identity controls remain. This is meaningful offline closure evidence, not actual authenticated/native ldd qualification; production sandbox remains unavailable and rejects.

Driver replay chooses both fixed roles/paths and compares complete rows after sandbox version execution. It rejects rewritten C-driver path, chain, resolution, mode, bytes, digest and version even with syntactically valid record/loader identities. Producer-shaped canonical version handling now agrees. Existing sandbox-unavailable control rejects before unbounded child execution.

Network helper pins root identity, checks root-owned protected root/etc directories, opens etc no-follow, creates root-owned0644 temporary regular files and replaces hostname/resolv.conf leaf entries with fixed bytes. It never opens resolver link targets. Actual descriptor/link replacement and failed-replace cleanup tests preserve canaries; only ownership operations are modeled. Pair of differing host-derived inputs produces identical inert tar bytes after normalization. No native cross-host reproducibility follows.

Independent tests: nine focused schema/meta/fragment/network/runtime/isolation cases passed0.745s (`stage1-sol-focused-tests.log`); corrected version regression plus both-driver mutation test passed2.709s (`stage1-sol-driver-tests.log`). Reviewer inspected worker full log:191 tests pass8.846s, independent JVM schema corpus31 cases passes, schema inventory reports79 entries. JVM corpus/full suite were not rerun by this reviewer. git diff --check independently passes. Test classes now allocate unique repo-local temporary roots, preventing concurrent-run teardown collisions.

Other approved-plan stages—immutable host environment/approval authority, authenticated payload comparison and immutable loader worker—remain unimplemented. This approval neither closes their threads nor qualifies native provenance. Acquisition pause and strict key-expiry refusal remain unchanged.


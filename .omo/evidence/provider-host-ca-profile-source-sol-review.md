# Independent Sol review: explicit trusted-host CA JDK profile

**Verdict: CLEAR for the exact source/test/workflow checkpoint.** No blocking finding in the explicit one-slot input contract. This is source and synthetic-filesystem evidence, not qualification of the real Actions host, JDK, CA authority or provider/native behavior.

## Exact pins and review method

Worktree: `/home/june/decomp_thing/.claude/worktrees/wf_ce026d1b-c24-68`.

| Input | SHA256 |
|---|---|
| `build/provider-host-ca-profile/freeze.json` | `42572dd8e085edb8cc0d9dfa5140a6933fbaa73938caff1d003663f169a5862b` |
| `scripts/ci-owned-jdk.py` | `3787c8e14a0c8c1b8440f9b83a0e496b481d2608cd38f27175450a4c460bdd42` |
| `scripts/ci-jdk/test_owned_jdk.py` | `ee0c70684a847f7d69c1098ec816a01e42e60bf4ce53bf84f2733a85482ce15b` |
| `.github/workflows/ci.yml` | `f70852da97769162b4413279a9765711ef13f9ad2483630be027d19c3eba8c71` |
| `.github/workflows/acp-contract.yml` | `16cdcd9758964537fc5a4fd7c061b1f7dc1385e3f14f09f7c44b60f387de84c6` |

Independently rehashed every freeze-listed artifact/current file and inspected full affected reader/copy/verifier/receipt/CLI flow, exact deltas and retained logs. AST comparisons confirm all29 prior test bodies/assertions remain identical and the generic closed-link validator is unchanged. No tests, host certificate or host/etc reads, JDK/native/compiler/provider/namespace, privileges, auth/model, Git or remote operations were run. Only this additive review is written.

## Authority and descriptor checks

- `source_link_graph:153–163` / `inventory_links:224–260`: default strict behavior remains. Only explicit `actions-host-ca-v1`, source key `lib/security/cacerts`, kind link, exact target `/etc/ssl/certs/adoptium/cacerts` and exact declared marker admit a projected file leaf. Other absolute/external links still refuse. Ordinary regular/internal CA layouts require no host input. The projection does not mutate physical source entries or widen the generic validator.
- `read_host_ca_input:170–221`: starts at a held nofollow directory FD for `/`, then opens each fixed component relative to its retained parent FD. Named entries are checked without following symlinks; opened types are independently checked. Root, ancestors and final regular file must have UID0 and no group/world write. Initial named/opened identities must agree; after reading, every held and parent-named component is revalidated against device/inode/owner/group/type/mode. Root and final pathname are checked separately. Parent-directory mtimes are deliberately not treated as stable authority.
- Final payload is admitted before reading at1..16MiB, read in bounded64KiB chunks with an EOF sentinel, SHA256 and stable before/after file identity/size/mtime. Parent/final symlink, FIFO/special, zero/oversize, replacement and observed authority drift cannot silently become captured data. No host chmod/chown/write or ambient realpath follow is introduced. The caller-authorized trusted-host/root-owned input contract is explicit; it is not vendor-signature authentication or proof of what the installed host currently contains.

## Closed clone, budget and postchecks

Capture happens after source-link admission and before any JDK file copy. `copy_tree:311–329` checks capture/profile/slot/target/size/hash binding, charges the CA payload to the existing4GiB sum, and exclusively creates a nofollow single-link clone-device regular file owned by the caller, then normalizes only that copy to0444. The selected source symlink and external CA bytes remain unmodified.

Only this slot may differ from physical source link to clone file (`421–428`). The clone is inventoried under strict closed-link rules and its expected hash is the captured CA hash. `verify_source:459–517` rechecks the full physical source and exact symlink, freshly recaptures the fixed external authority chain/file and compares the complete JSON-stable record, then verifies the entire clone independently. The final clone walk checks identities, regular-file/single-link status, aggregate byte budget, full hashes, directory inventory and nofollow path state. Existing20,000-entry/depth64/4GiB limits are unchanged; the new external reader has its separate16MiB ceiling, not an expanded JDK budget.

Provision runs full verification before returning. `run:660–668` starts all unchanged facts false/null, executes only the requested command with the owned fixture, and sets source/clone/host facts true only after complete post-command verification. External changes cannot be hidden by an unchanged selected-JDK tree or identical clone bytes. If no external input is needed, hostCaInput/hostCaUnchanged remain null. Rehydrated receipt comparisons normalize tuple/list representation through JSON and retain physical source versus materialized clone roles.

## CLI/workflow and retained controls

`parse_command_arguments:673–679` accepts existing `run -- command...` as strict or an explicit closed profile before the separator; unknown/missing profile/command forms refuse. Independent text normalization of both workflow snapshots proves the only workflow changes are exactly five `--source-profile actions-host-ca-v1` insertions, with no job, command, endpoint, permission or qualification-policy change.

Retained42 pure filesystem/FSMock tests pass, including all29 unchanged prior controls and13 additions. Inspected cases cover wrong UID/writable ancestors/file, symlink/special/size refusal, in-read mutation and ancestor replacement, regular0444 materialization/source preservation, strict/default/other-slot/target rejection, ordinary/internal layouts without host reads, pre-copy capture refusal, aggregate charge, independent source/external/clone changes, same-byte replacement/mode drift, closed projection, post-command false facts, receipt rehydration and five explicit callers. Host-reader mocks redirect every root/relative lookup into repository-owned synthetic trees and reject unknown absolute operations; fake UID metadata models root ownership. No new test was rerun or treated as real-host proof.

## Remaining qualification

This wrapper observes and clones the Actions-selected trusted build JDK; it does not authenticate a vendor distribution or confer oracle/provider authority. The real selected JDK's CA target/chain ownership/type/content may still fail the declared profile. Actual Actions verification must establish those facts and exercise the relevant owned JVM/provider suites before hosted qualification. Existing credentials, JVM selection, full-clone tamper checks and unrelated Kotlin/provider/production source remain outside this delta; no source clearance here substitutes for their gates.

# Independent owned-JDK link closure source review

## Terminal verdict: CLEAR — exact source correction only

No blocking defect found in the two frozen files for the reported P2 escaping-JDK-link correction (thread PRRT_kwDOTCeevs6sSKSm / comment4269982321). The new inventory/graph admission refuses external link targets without following them, and copy/revalidation remains tied to the admitted inventory. This does not qualify an actual JDK/runtime, production isolation, a hosted run, or the rest of PR1502.

## Exact reviewed bindings

Worktree `/home/june/decomp_thing/.claude/worktrees/wf_ce026d1b-c24-68`:

| Input | SHA256 |
|---|---|
| build/provider-86a-owned-jdk-links-correction/freeze.json |6521c252f88a58196cb230442ebd04e3c50ba89559f2dec558ed9e4cc66fe473|
| scripts/ci-owned-jdk.py (25,586B) |acc48d4f153c0228f176f4becfd51bc271d8cb58136fb058f9fd7219d14c824b|
| scripts/ci-jdk/test_owned_jdk.py (12,406B) |e5c4b1646736f7b3b3f1e0308e72d12bbe2c783fb39990fa26d4557ea7e582d3|
| retained run_pure.py |53af3e84f7eaa6073c1a7f81b308f1f1a3a82493112fdb3cffcb7e591dfe70e3|
| retained pure.log |0c68ed4b87585cf74beb8696e760c59fce592f30d71b443631c311aaab3eb30a|
| retained pure-results.json |9850b6a3a707a9e5a87c5aa855a97c4715f9086564e5bddabef21ab13be913d8|
| author report.md |02e15a7324d11948fabb5926a86d5d4ad8f318ccceff38a46f6b116d1b5f2b10|

Both snapshot copies match their live frozen source. Every freeze-listed evidence hash matches. Compared the correction against the retained actual86a CI source blob3b0cde08b88b7e195d613d4c9dfa42812ea7401d from provider-86a-hosted-diagnosis/actual-ci-owned-jdk-blob.json, and the corresponding original JDK test blob3a0fd2ec9f842eb8c7a9454b69e0549ca2b1645a. This is an independent source/data read; no test/module import or execution was performed by this reviewer.

## Mechanism and bypass checks

- **Closed inventory, no target traversal:** ci-owned-jdk.py128–161 inventories descriptor-relative entries with stat(...follow_symlinks=False), readlink, and O_DIRECTORY|O_NOFOLLOW directory opens151. It accepts only regular files/directories/links, checks opened directory identity153 and entry/directory identities157–158. Symlink targets are treated as text; they are not opened/stat-followed by this pass. Resolving the explicitly selected source root at167 is existing selection behavior, not new per-link authority.
- **Component semantics, including link then dotdot:** graph92–125 starts each target at its actual inventory parent. An encountered link expands its target into the pending deque while retaining that link's parent122; it does not lexically collapse away preceding components. Stack directory validation105–106 runs before processing even dot, dotdot or an empty trailing component. Thus regular-file/.., regular-file/., regular-file/child and trailing slash on a file refuse. Directory symlink chains resolve inside the same admitted inventory. A target such as alias/../../outside must resolve alias first, then can only pop an existing stack; it cannot pass a path-prefix string check because none is used.
- **External/unknown paths refuse:** both initial and transitive absolute targets98/121 refuse, including absolute paths back into the original source. Root pop111 refuses before escape, so same-prefix sibling paths and escape-then-reenter spellings are rejected. Each named component must exist115; dangling/transitive dangling targets do not borrow ambient host files. A final relative link to the inventory root is intentionally supported125; copied equivalent remains within the clone.
- **Finite work:** inventory reserves global entry count before inserting138–144; directory names are capped at20,001 before sorting, accepted at most20,000; recursion depth64 and link bytes4096 are fixed. Graph component work is shared across all links and checked before processing104 (20,000*64=1,280,000); link-chain count includes the initial link and refuses above64 before expanding119. Every cycle necessarily reaches that finite chain refusal. Pending expansion reads only already byte-bounded link text. Existing4GiB copy byte limit remains unchanged; this review does not reinterpret it as a newly tested disk quota.
- **Admission before copying/publishing:** graph admission261 precedes copy262, source file reads/hashes, recreated links and all provision receipts/command execution. Precisely, provision170–184 first creates private build/ci-jdk-UUID/jdk staging directories and opens source/target roots; invalid graph admission can leave these empty private directories. Neither source nor author evidence establishes zero filesystem writes on rejection. This bounded staging is not a copied/admitted runtime or published qualification receipt; the implemented promise is validation before payload/link copy and use.
- **Race/revalidation binding:** copy205 refuses an unknown or identity-changed source entry before its copy; link209 also checks exact admitted target text before recreating it. NOFOLLOW directory/file opens and existing open/final identity checks remain. Exact copied-vs-admitted membership263 rejects added/missing inventory; root264 remains bound. verify_source321–322 reapplies the graph rule to the internally produced receipt, then retains prior source identity/content/link-text/membership and owned launcher checks. It does not accept an adjacent digest or externally supplied JSON as new authority. Directory/file replacement failures close owned descriptors through existing/new finally scopes; no fallthrough host fallback exists.

## Retained controls and unchanged policy

Retained20 filesystem fixture methods pass,0 failures/errors/skips; pure-results records identical before/after source hashes and an empty forbiddenAttempts list. The harness AST-parses/imports the test module and denies its listed subprocess/exec/spawn/fork/system/pty events. These are author-retained controls, not a reviewer rerun or a universal sandbox proof. Source inspection of the selected test methods shows fake inert launcher bytes are copied/hashed, never executed; no native/JVM test invocation is present.

New test methods41–89 cover absolute external/absolute internal/same-prefix escape refusal before link copy; internal relative file/directory/root links; transitive escape, cycles, dangling and non-directory components;65-link rejection then64-link acceptance; reduced aggregate work ceiling; post-admission link replacement with FD-count recovery. The unsafe prior ambient-link positive is replaced by a supported internal relative positive; the missing/external target is now an explicit refusal. Existing source-mode777→owned-launcher755, source unchanged/no source chmod, independent inode, partial-open FD recovery, source/launcher substitution, unsupported launcher type, exact worker proof and scratch identity controls remain.

Diff inspection found no changes to credential parsing, independently owned regular-file copy checks, launcher normalization, source regular-file hash validation, actual JVM receipt checks, Gradle selector/environment policy, subprocess command, or final proof requirements. Exact textual comparison also confirms verify_jvms and run (including the remainder of the script) are byte-identical to actual86a source. The existing JAVA_TOOL_OPTIONS behavior is unchanged; this review neither endorses a new policy nor attributes hosted TLS/native failures to it.

## Remaining gate and scope limit

Root must still qualify the selected actual JDK's accepted closure and hosted worker receipts. Strict refusal may reject an installed JDK containing absolute, dangling or otherwise unsupported links; this review authorizes no exception/fallback or target copying from the host. Actual JDK compatibility, filesystem races beyond the retained injection, clone runtime payload behavior, native execution, CI and whole-PR readiness remain unproved here. Other provider failures and the separate P1 DNS checker correction are outside these two files. No Git/remote/review-resolution action was taken.

Reviewer performed only repository-contained reads, hashing and textual/data comparisons. No tests, imported task modules, JVM/native/process execution, process inspection, network, Git, remote or source edits. The only new write is this review report. Source was rehashed against the exact freeze immediately before report creation; CLEAR applies only to those hashes.

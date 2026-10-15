# Owned JDK complete-clone correction: independent source review

Verdict: **CLEAR for this exact correction.** This is read-only source/evidence review, not a rerun of controls or hosted/native JDK qualification.

## Exact authority

Worktree: `.claude/worktrees/wf_ce026d1b-c24-68`.

- Freeze: `build/provider-fc52-owned-jdk-correction/freeze.json`, SHA256 `333a703683ed1454b5da0b6dd6e4af6f372b856d9d17c77ac4b526d374eeeadc`.
- Wrapper: `scripts/ci-owned-jdk.py`, SHA256 `70be96a9712638370bef4940e8dd1e2af262640521a045fe2de04f12ff89d678`.
- Controls: `scripts/ci-jdk/test_owned_jdk.py`, SHA256 `2ca15aac30f85a663165e8af5248bb9fe98f6cf5441290c536fd3730fadf77a7`.

All13 freeze path hashes/sizes matched independently at review start and completion, including exact before/source/test copies, diffs, receipts and logs. Wrapper/control source parsed with Python AST only; no import or execution. AST inventory confirms29 control methods, retaining all20 prior controls.

## Findings

No blocking defect found in the scoped delta.

| Requirement | Inspected implementation/evidence |
| --- | --- |
| Complete clone identity after normalization | Provision records `cloneRoot` and every clone entry after launcher/directory mode normalization (:314–341). A fresh canonical descriptor inventories the clone; names, kinds and link targets must match the admitted source inventory. File expected hashes come from the independently read/copied selected-source bytes, rather than trusting a later changed clone. |
| Verify every file, not merely launcher | `verify_clone` (:410–469) checks root/path identity, exact extra/missing inventory, entry kind and dev/inode/uid/gid/mode/size/mtime identity. Each regular file must retain one link; nofollow descriptor identity is checked before and after bounded SHA256 reads, followed by pathname identity. Equal-length content changes with restored mtime therefore fail by content hash. Directories and symlink targets are checked independently. |
| Bounded traversal/read work | Existing20,000 entry,64 depth and4GiB ceilings are unchanged. Directory listing uses one bounded lookahead; file size is admitted against remaining aggregate bytes before reads. Reads consume at most recorded size plus one EOF sentinel in64KiB chunks. Missing, extra, shortened or growing files refuse. Recursive descriptors and regular-file descriptors close in finally paths. |
| Before and after command | Existing `verify_source` now finishes with `verify_clone` (:407). Provision calls it before returning the fixture (:347); normal command completion calls it before setting either unchanged flag or admitting actual Test JVM receipts (:551–555). A clone failure leaves both flags false and actualTestJvms0, rather than publishing a successful source-only verification as a complete closure fact. |
| Strict link closure | `validate_link_graph` resolves the bounded nofollow inventory only. Absolute, empty, root-escaping, dangling, non-directory and cyclic/over-budget links remain refused; no external-target allowlist or guessed hosted exception was added. Copying still requires the admitted graph and identical link target before writing the private clone. Post-run link comparison does not follow a substituted external target. |
| Bounded rejection diagnostic | Absolute/root-escape refusal identifies the selected relative link and target; chained absolute rejection names the actual offending link. JSON ASCII escaping removes raw control characters, each prefix is bounded and truncated values receive SHA256 commitments (:92–104). For fixed internal reason strings, the complete diagnostic is bounded; no target contents are opened. This does not claim every existing generic link error now carries a path. |
| Original source/no host writes | Existing source root/inventory/identity/mode/content checks remain before clone verification. All copy outputs are fresh repository-local files; fchmod targets owned clone descriptors, never selected-source inodes. No source repair, external link dereference/copy, JDK installation or host permission workaround is introduced. |
| Meaningful retained controls | New cases cover normalized inventory, restored-mtime modules tamper, configuration tamper, extra/missing/replaced entries, modes, regular-file hardlink, altered symlink with unchanged external canary, descriptor recovery and bounded absolute/chained diagnostics. Mocked post-command tamper proves flags stay false and JVM qualification is not reached. All existing strict link/source/launcher/scratch/credential/receipt controls remain. |

## Test evidence and limits

Retained `receipt.json` SHA256 `90c9d80c249cd66eb70b35c10862dc9f7060cb8a3ed06db695caa42fa6881e4f` binds the exact command/source/log. `tests.log` SHA256 `363c1156a680de7812c7bee52f0adaa19d0588fab4b628931e5e1dd09d2130ab` records29 tests,0.096s,OK. Those results were read and hashed, not reproduced by this review. Source inspection confirms inert fake JDK bytes and a mocked command; own-process status/FD metadata reads do not invoke the launcher.

The preserved old-predicate control loads the exact prior wrapper, alters only fake clone modules with size/mtime restored, confirms the old verifier accepts and the corrected verifier refuses `owned JDK content changed`. Result SHA256 `68b6458ef8133342ed357bcbda405ef494b90bbbacb740b30f15ab510ad79693` binds both wrapper generations and confirms unchanged selected-source modules. This demonstrates the concrete prior false acceptance without an external JDK or JVM call.

Remaining gates: the actual hosted selected JDK may contain a forbidden link and must still fail closed with the new diagnostic; its identity/compatibility and real Test JVM receipts have not been qualified here. This review does not clear other provider lifecycle/cleanup findings, authorize R9 execution, relax frozen production files, or supply auth/model/native/Actions authority.

Only this new review was written. No tests, external JDK, native/JVM/compiler, Git/remote, model/auth or network action occurred. All reviewed sources and other pinned production files were left unchanged.

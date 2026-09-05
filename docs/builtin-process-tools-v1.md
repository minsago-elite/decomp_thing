# Built-in process tools v1

`BuiltinTerminalDispatcher` translates `run_process` calls into the existing ACP terminal broker.
A provider chooses a profile-defined operation ID. The profile supplies its build/test/behavior
purpose, exact command rule, arguments, environment, working directory and authenticated runtime
mounts. Extra arguments and unknown IDs are rejected before launch. Each operation must reference
an exact rule instance from the immutable terminal execution policy.

The dispatcher opens `LinuxBubblewrapBoundary`, then obtains its production `AcpTerminalBroker`.
It uses the enclosing built-in deadline during boundary preparation, command admission, waiting,
and cancellation. Every terminal is bound to its stable built-in tool-call ID, observed and released
through the same broker callbacks used by ACP. Closing the dispatcher closes both broker and boundary;
cleanup failure cannot be converted into a successful result. The shared metadata audit and sandbox
evidence remain available to the caller for later archive integration.

Successful process invocation returns bounded JSON with operation ID, purpose, exit code/signal,
output, truncation and a provisional `passed` flag. Nonzero compiler/test exits are model feedback,
so the loop can repair them. Truncated output sets `passed=false` even when the exit code is zero.
This flag describes one process result; it cannot certify source, behavior, oracle truth or release
acceptance. The surrounding workflow remains the validator. `BuiltinProcessToolSession` composes
process tools with an existing workspace session and retains independent completion validation.

## Qualification

Local selection:

```bash
./gradlew --offline test --tests 'decompengine.builtin.*' --tests 'decompengine.agent.*' --console=plain
```

Required configured-host selection:

```bash
python3 scripts/validate-builtin-contract.py
```

The `Built-in core contract` workflow provisions the existing ACP sandbox host and runs the second
command. The v2 inventory freezes 65 cases across six suites: 23 provider, 14 loop, 7 filesystem,
6 captured-context, 7 terminal and 8 shared-agent cases. It forces fresh Gradle execution, requires a clean source
worktree, checks XML cases as well as suite totals, and rejects missing/changed suites, failures,
errors or skips. `build/builtin-contract-qualification/summary.json` records the commit and XML
hashes. It explicitly does not qualify real-provider workflows or a release.

Terminal cases compare direct ACP and built-in results/audit reasons, reject operation injection,
enforce workflow execution denial, retain nonzero/truncated feedback, cancel a sandboxed fixture
with a detached descendant, and pass structured results through the real loop while preserving
validation-required status. These fixtures use a static repository-authored probe, never external
provider credentials or arbitrary commands.

The initial local run passed 53 cases and skipped six terminal cases because `bwrap` was unavailable.
That result is not positive terminal containment evidence. The required-host flag must instead fail
for missing prerequisites. Positive hosted execution and retained evidence remain required before
claiming this tool boundary qualified.

The first hosted run (`33950189165`, `e54313a`) ran every required case with no skips and correctly
failed qualification: all six live cases rejected the fixture's default CPU allowance because it
exceeded their 10-second wall limit. The fixture now explicitly uses a 2-second CPU allowance;
its limit construction is also checked by the host-independent metadata test. This corrects fixture
configuration and does not weaken production limits. A new positive hosted result is still required.

#74 remains open. This checkpoint does not supply production compiler profiles, writable quota-backed
build stages or general host directory inspection. Captured directory and immutable request evidence
tools are documented in [the filesystem contract](builtin-filesystem-tools-v1.md). Full terminal permissions,
environment/credential equivalence, durable transcript/receipt archive wiring and the C1/C2 workflow
and real-provider release gates still need requirement-by-requirement evidence.

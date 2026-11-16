# Contained module file-descriptor policy

The closed `MODULE_COMPILATION` selection declares a finite soft/hard pair of
7678:7678. Other contained-command, BOOT and observation routes retain 512:512.
There is no caller-supplied numeric allowance, environment override or input-count
reduction. The module route preserves all authenticated input leases and its
complete read-only state tree. It does not use the smaller retained-file
visibility selector for its input population.

The policy identity is the canonical JSON object with `schemaVersion: 1`,
`provider: "contained-module-compilation-file-descriptor-policy-v1"`,
`scope: "module-object"`, `softLimit: 7678` and `hardLimit: 7678`. Its digest is
`b75fa01e0ae402ab7db53e24ede656d0bec06748e27b758296b9f436d1e24d4b`.
The trusted launcher separately owns its maximum of 7678. Admission observes
the launching process's actual finite inherited limits and PID/start identity,
requires sufficient hard capacity, and rechecks the same observation immediately
before spawning. It does not change the parent limits or clamp the request.

## Versioned declarations

Request v5 requires the existing terminal policy, the fixed FD policy digest and
`maximumOpenFiles: 7678`, and an explicit Boolean `allowInterruption`. It may
add the existing visibility digest only through the explicit new mode. The
configured module route requires interruption false and visibility absent.
Request versions 1–4 retain their exact field sets and canonical bytes, including
v3's omitted false interruption and v4's explicit Boolean. Their legacy runtime
field helper still rejects combined terminal and visibility policies.

The bootstrap remains `contained-command-v1`; terminal/FD requests retain HMAC
wire `kotlin-contained-command-protocol-v2`. A decoded request is a declaration,
not authorization to launch or accept a revision.

Runtime v5 retains its canonical preimage and includes the exact request SHA,
complete serial resource record, independently admitted FD policy and launcher
observation. Existing configuration, deployment, ordered mount/input, deadline
and directory commitments retain their meanings. The passive result accessor
returns defensive preimage copies. The limiter and bounded descriptor census
consume the same selected value; enumeration count, descriptor-number range and
forbidden socket/session authority remain distinct checks.

## Actual observations and retained proof

Both existing START attachment captures observe the keeper's finite limits
between retained-process, generation and stable-attachment checks. Attachment
v5 adds `fileDescriptorLimits` with provider
`linux-proc-nofile-observation-v1`, host PID, start ticks and the actual soft/hard
pair. The pair must equal 7678:7678 and identify the authenticated supervisor JVM.
The existing comparison rejects any changed attachment across `beforeStart`.
No timestamp or sampled descriptor peak is substituted for this observation.

Successful and interrupted execution records use their corresponding v5
providers. Strict terminal verification explicitly handles versions 3 and 5;
interrupted execution cannot qualify as successful module compilation. Proof v2
adds the runtime preimage to the existing module proof and checks its hash and
semantic joins to the configuration, inputs, resources, process observation,
attachment, output and cleanup. The overall module policy ID is unchanged.
Proof v1 remains historical evidence under its original meaning. Parsing either
proof grants no live permit; private admission still follows complete snapshot
revalidation, deadline and cancellation checks.

## Qualification boundary

Pure constructor, parser, HMAC, resource, observation, preimage and proof tests
exercise authored controls. They do not establish actual namespace visibility,
keeper-to-worker-to-compiler limit inheritance, configured acceptance, rollback,
cancellation, cleanup or retry. Those require retained hosted qualification,
including an unchanged generic 512 route and both configured build profiles.
The finite policy is not a universal-fit or peak-use claim. Unsupported host
capacity or runtime pressure must fail with owned cleanup, without retries at
progressively larger limits. Issue #1786 and its broader parent requirements
remain open until their full applicable evidence is available.

### Qualification staging and freshness

The qualifier invokes Gradle more than once: preparation freezes the installed
worker deployment before the hosted child manifest and compiled inventory consume
it. Each invocation must revalidate the same exact deployment; unchanged re-entry
is not permission to overwrite it. The descriptor-relative staging verifier rejects
changed sources, incomplete/extra/substituted members, links, and altered published
permissions or ownership. Every member's UID and GID must match the frozen stage's
owner, which is itself checked against the read-only manifest owner. Matching bytes,
mode and link count alone do not authenticate member ownership. Consistent modeled
foreign-UID and foreign-GID controls must refuse without repairing published state.
Resource generation uses the reproducible native-helper
records described in [web-packaging.md](web-packaging.md#reproducible-application-jar),
so rebuilding identical inputs does not silently change that frozen application JAR.
These are the focused #1808/#1789 prerequisites, reused from PR #1813 rather than
merging the rest of that child branch.

Report freshness is checked in a separate Gradle prerequisite before `Test` prepares
its outputs. Both that guard and the earlier shell admission reject dangling report
links; the shell also rejects dangling inventory/case links before invoking Gradle
or acquiring owned runtime state. Existing evidence is preserved, not cleaned or
reinterpreted as a new attempt. Isolated staging/freshness/routing fixtures do not
replace the required exact-source, configured Make/Ninja hosted qualification.

The qualification at `8a714d3522358fdb80b7904f0934b649daa149f5` failed:
104 tests, 91 failures, zero skips. All 91 failures contain the pinned compiler's
foreign non-root owner lease refusal. Five Make cells failed at initial/baseline
compilation and all five Ninja cells were not started; reconciled coverage is null,
not success. Issue #1827 owns the authenticated host-to-user-namespace compiler
ownership handoff. A host-root compiler can appear as an unmapped owner in the
contained namespace; accepting UID 65534, removing the lease guard, or merely
checking a read-only mount is not a safe correction. The staged-member owner fix
alone does not solve this compiler admission failure. Parent #1727's host-side owned
compiler snapshot and read-only same-path executable alias are integrated separately;
the intermediate output-tree copy is superseded because leased scratch stays noexec.
The owned-executable runtime provider retains `baseRuntimeProvider` v5 and all FD
request/resource/admission fields. Proof v2 checks the exact three ordered inputs
(private request, configured compiler, private `compiler` snapshot), identical compiler
pins, the 64 MiB snapshot bound and the single exact alias. Old no-alias v5 bytes and
historical replay semantics remain unchanged. Rehashed alias/path/pin/population/provider
substitutions must refuse. This candidate handoff still needs complete current-source
hosted qualification; local worker positives do not close #1827. Parent #1727's separate
off-snapshot compiler-read integrity finding also remains a blocker; FD controls cannot
clear it.

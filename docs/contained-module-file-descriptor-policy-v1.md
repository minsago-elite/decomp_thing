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

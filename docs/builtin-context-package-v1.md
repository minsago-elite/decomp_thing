# Built-in context package v1

The built-in loop now assembles a deterministic initial context package before requesting a model.
Mandatory context contains the objective, sorted transport-neutral root/path/operation authority,
tool schemas, and a manifest of every immutable context input. It does not expose absolute host
root paths. Manifest entries retain each input's ID, media type, UTF-8 byte count, SHA-256 and an
explicit included/omitted decision; the receipt retains an immutable copy of these entries.

Whole input bodies are selected in stable ID order. The assembler charges actual serialized JSON
bytes, including escaping, and bounds both mandatory metadata and aggregate source-evidence bytes.
The default evidence ceiling is 32 MiB. Inputs that do not fit are omitted only if the trusted tool
session advertises context retrieval and registers both `list_evidence` and `read_evidence`. Every
omission remains visible and retrievable; it does not waive a workflow acceptance requirement.
Without that capability the call exhausts explicitly before invoking the provider.

The initial package leaves one quarter of the context ceiling for later model/tool history by
default. The reserve is configurable and every later context is still checked against the full
limit. The selection algorithm reserves the full manifest, encodes each candidate message once,
and then verifies the final package size and hash. It does not summarize or silently truncate source,
diagnostic, regression or prior-summary inputs. Their semantic relevance and dependency priority
remain the responsibility of the caller and the later #78 context index.

Five tests cover order-independent selection and authority, exact omitted hashes, unsupported
omission and mandatory/evidence ceilings, escaped/Unicode byte accounting, and a real captured
loop retrieving a page of a 40,000-character omitted input within its reserved history allowance.
The new required core inventory is v3 (70 cases); local execution passes 64 cases with six live
terminal skips on the host without bwrap. The previously qualified v2 hosted corpus remains dated
evidence for its own 65 cases and commit.

#75 remains open. Context packaging and read-only retrieval are implemented; durable redacted
request/response/tool/policy transcripts, source/checkpoint/provider identity bindings, validated
restart, indeterminate-side-effect reconciliation and archive integration are still required.
The current package is in-memory evidence and must not be represented as durable recovery.

The subsequent [optional durable journal](builtin-journal-v1.md) records this package and execution
payloads, but does not yet restore a stage or restart a session. Context v3 required-host run
[33950974354](https://github.com/minsago-elite/decomp_thing/actions/runs/33950974354), at
`79c7f547d9c8d974a06d686014d0f47d72a1a59e`, passed its 70-case inventory with no failures, errors or
skips. Artifact `9964895617` has digest
`sha256:8dbe0fdfcbca72b1f2f9a6c37f20104e5a1789970ea06bef9376f79b1f2e617b`.
This dated result does not substitute for the later journal v4 qualification.

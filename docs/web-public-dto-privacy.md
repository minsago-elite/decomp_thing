# Public web DTO privacy boundary

Public web projections are allowlists, not persistence serializers. This boundary applies to
legacy JSON/HTML presentation and the v1 JSON contract. It does not change stored records and it
does not classify downloaded report, source, or artifact bodies as DTO metadata.

| Surface | Public projection | Private input handling |
| --- | --- | --- |
| Legacy and v1 jobs | Identity, display filename, typed status, timestamps, size, and validated ELF metadata | `binary_path`, persisted `status_message`, host roots, environment values, and exception prose are never selected. The five ELF category strings must match exact reader output vocabulary before either DTO or legacy HTML is built. |
| Service and storage diagnostics | Fixed, allowlisted code and fixed message | Persisted/exception messages are ignored. Unknown codes collapse to `JOB_STORAGE_UNAVAILABLE`; the unknown code text is not copied. |
| Legacy and v1 progress | Typed categories, bounded measurements, counts, flags, application-issued identifiers, and explicit SHA-256 commitments | Raw task/workflow/revision labels, paths, prose, and plan entries are counted and omitted regardless of their retained representation. Unknown optional categories are counted and omitted. Unknown workflow/kind values map to the fixed `unknown` state. |
| Other v1 metadata DTOs | Explicit constructors for bootstrap, sessions, scheduler state, attempts, reports, artifacts, uploads, recovery, and Git state | No persistence object or exception is serialized wholesale. Content endpoints remain separately bounded and authorized. |

Opaque identifiers intentionally retained by a DTO are application-issued correlation values:
job, attempt, writer, turn, request, cursor, upload, and artifact identifiers. SHA-256 fields are
explicit commitments, not the committed private labels. Typed enums, timestamps, exact numeric
strings, counts, and booleans are retained because they express public state rather than prose.
Uploaded display filenames remain an intentional job field and are length-bounded by the v1
projection; they are not host paths.

`format` accepts `ELF32`/`ELF64`; `endianness` accepts `little`/`big`. The OS ABI, object type,
and machine categories accept only the reader's named values or canonical `unknown(n)` for an
unassigned numeric producer value: 0–255 for OS ABI, 0–65535 for object type and machine.
Malformed or private historical category text makes the job unavailable with a fixed public
diagnostic, leaving persisted bytes unchanged.

For jobs without a durable attempt, the v1 job version hashes only projected public fields;
changing private legacy path/message bytes does not change it. Once durable attempts exist, the
version is the store's opaque `version_` plus 32 lowercase hex digits, checked before release.
This preserves compare-and-set changes such as progress pin/lifecycle updates that do not alter
the job DTO's other fields. Unvalidated stored version text is never emitted.

Compatibility is fail-safe. Older progress records may omit writer/workflow/time metadata; the
legacy projection leaves those fields absent instead of fabricating them. V1 requires them.
Forward category values do not make historical reads fail merely because the server does not yet
recognize them, while malformed values for fields actually promoted to the DTO still fail strict
validation. Negative durations are rejected.

Focused regression canaries cover both job shapes, public-only legacy version changes, durable
pin version changes, exact ELF category vocabulary, fixed
diagnostics, both progress shapes, metadata-sparse legacy records, forward values, host roots,
environment-like values, exception prose, raw identifiers, paths, and plan text. Contract
fixtures reject raw progress fields, and generated frontend types follow that narrowed schema.
Rendering/content hardening beyond this semantic projection remains separate work.

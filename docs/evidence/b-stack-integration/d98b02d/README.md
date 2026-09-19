# Production upload uncertainty HTTP evidence

Source d98b02d: 28 selected tests passed with zero failures, errors or skips on the
identical source immediately before commit. Gradle ran offline with pinned Node
24.20.0 and the existing native/temp-directory setup. Original JUnit reports and
SHA-256 digests are retained here.

UploadPublicationServiceHttpTest exercises three real-server scenarios: legacy JSON,
legacy HTML and authenticated SPA under /workbench/. Its existing publisher fault
checkpoint throws after directory rename; the test asserts 409, canonical identity
and Location, non-cacheable responses, no retry hint, no private exception content,
retained input bytes, rejected workflow admission and rejected second upload without
a second job. Fault injection uses reflection confined to the test and adds no
production fault-control endpoint. The ELF header fixture is never executed.

Other selected suites cover the original JobStore uncertainty helper, streaming
service admission, shared service lifetime and the SPA API. No agent or vulnerability
reproduction was selected. Full CI remains omitted because its patch lane executes
vulnerability reproduction. This does not qualify the later B stack or release gates.

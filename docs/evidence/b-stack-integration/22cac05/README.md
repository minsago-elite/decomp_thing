# Shared-service staging compatibility evidence

Source: 22cac05. The selected tests ran on the identical source immediately before
its commit: 33 tests, zero failures, errors or skips. Gradle ran offline with the
pinned Node 24.20.0 frontend toolchain and the existing native/temp-directory setup.
The JUnit reports and their SHA-256 digests are retained beside this file.

The suites cover shared-service staging publication and restart cleanup, preservation
of ambiguous historical `.upload-N` files across repeated startup, inventory counts,
streaming upload service behavior and shared-service lifetime. Publisher crash
fixtures use inert ELF headers which are never executed. No agent workflow or
vulnerability reproduction was selected. Full CI was omitted because its patch
lane executes vulnerability reproduction.

This verifies the staging namespace change; it does not qualify the later B stack,
production uncertainty HTTP responses, remaining review findings or release readiness.

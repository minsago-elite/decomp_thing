# L1.1: Kotlin JVM Backend

Goal: move the L1 decompilation/backend path out of Python and into Kotlin on the JVM.

Required gates:

- Kotlin/JVM project builds with Gradle.
- Ghidra integration uses an in-process JVM call boundary instead of shelling out to Python backend code.
- L1 generated project and build-log behavior remain covered by Kotlin tests.

Acceptance evidence should include Gradle test output from the Kotlin L1 pipeline and a test fixture that invokes a Ghidra-compatible JVM `main` entrypoint through the same adapter used for real Ghidra classes.

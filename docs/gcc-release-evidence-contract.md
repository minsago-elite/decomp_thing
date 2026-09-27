# GCC fidelity release-evidence contract slice

`oracle/gcc/16.2.0/release-evidence-contract.json` defines the bounded release
record for the checked GCC 16.2.0 inputs. It binds the signed source revision,
build record, toolchain image, ELF manifest, function oracle, and 14-case
behavior corpus by their existing SHA-256 values.

The record is deliberately `releaseEligible: false`. The checked behavior
report's 14 passed cases are reference observations; its preprocessing cases
use staged mock `cc1` tools, and there is no authenticated reconstructed
candidate comparison. The function oracle is an oracle input, not a production
structural score. Therefore the structural thresholds remain `unavailable`.

The production gates still missing are authenticated structural replay, an
accepted candidate source/build archive, every candidate behavior comparison,
and an independent repeated run. Real preprocessing/dependency and
compile/link/produced-program observations are also absent. Any missing,
stale, untrusted, failed, unresolved, or reference-only result blocks
eligibility.

When structural analysis is added, it must run through the application-bundled
Ghidra worker boundary and retain authenticated oracle provenance. This record
does not require `GHIDRA_HOME`, invoke an external `analyzeHeadless`, or allow
candidate observations to author oracle truth.

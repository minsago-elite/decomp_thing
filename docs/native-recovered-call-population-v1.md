# Native recovered call population v1

`NativeRecoveredCallPopulationV1.freeze` derives recovery claims from an exact canonical native observation stream and its paired program model. It takes no boundary projection or independent oracle data. The manifest, stream, model digest, model byte count, input digest, target, collector and exporter bindings must all agree before any result is returned. Native callbacks are speculative until complete stream validation succeeds.

The result is a pure diagnostic object. Its public constructor/parser, hashes and serialized output confer no production capability. `productionVerified`, `scored`, `complete`, `releaseEligible` and `negativeCoverageAvailable` remain false, including when `project` receives an admitted boundary projection. A production owner must authenticate the original native/model capture and replay this derivation before granting any call-domain authority.

## Census and raw evidence

The frozen object retains defensive copies of the complete original manifest and observation bytes. Those bytes retain address-space definitions, raw instruction bytes, prototype/effective flow, override state, typed targets, external program and synthetic coordinates, memory blocks, reference neighborhoods, immediate thunk relationships, zero-site function inventories and complete scan/function counters. The evidence enumerates every original record ordinal and record kind.

The ledger source's `recordIds` enumerate **every native site record**, including prototype calls, analysis call candidates, direct tail candidates, unowned sites and sites outside the paired model. Function and summary records remain bound by the full-stream hash and the separate all-record census; they are not invented call obligations. Each site ordinal has exactly one projected site or explicit owner exclusion. Exceeding byte, site, parser or evidence limits rejects the input without truncation.

## Recovery-only claim selection

Physical-call eligibility requires a real prototype call code (3, 4, 8, 10, 13, 14 or 15), available raw bytes, no listing length override, no flow override and zero delay-slot depth. Native override codes 16 and 18 are not physical-call evidence. Analysis, tail, override and unsupported observations remain typed unresolved records; their projected instruction uses a native namespace so the shared physical-site join cannot give them call credit.

A concrete internal target additionally requires a direct prototype call (3, 4, 10 or 14), exactly one native prototype target, and a unique exact non-thunk function entry in the paired model. Selection does not use model `calls` pairs, names, oracle addresses, expected targets, analysis references or thunk forwarding. A near boundary correspondence does not fill a missing recovered target. Indirect target sets, external imports and thunk implementation targets remain unresolved.

Only unsigned, byte-addressed, non-overlay RAM coordinates in the exact bound image space become image RVAs. Other spaces, below-base offsets and signed/synthetic coordinates retain their original offset bits in a native namespace. Pre-entry instruction RVAs are preserved; there is no caller-local unsigned subtraction. No return address is synthesized from instruction length. The raw prototype fall-through remains a labeled candidate in evidence, while the population fragment leaves `return` null.

## Selected projection

`project` verifies the exact model/input commitments, image base, and complete recovered-plus-ignored model identity/start/status partition. It does not rematch functions. Only an exact ignored recovered owner may exclude a site, and each excluded record references both its selected ignored-recovery row and original oracle exclusion evidence. Unique evidence rows are byte-budgeted and retained once, avoiding repeated expansion of large aliases across sites. An excluded target alone never excludes a call; that target remains unresolved.

The fragment's `source`, `sites` and `exclusions` use the closed shared population vocabulary. Its `binding` commits to the selected boundary observation; `dispositions` preserve the frozen claim classification and source ordinal, and `exclusionEvidence` contains the original uniquely indexed rows. A composer can combine this fragment with independently authenticated oracle sources using the existing population algebra. A source hash alone does not establish complete source coverage, negative evidence or production admission.

External namespace tokens are deliberately unavailable. Native recovery uses the stripped artifact; the independent static import namespace uses authenticated rich-ELF identities. Equal names, ELF section indices or absolute addresses do not prove equivalence. A later authenticated composition must independently verify the claimed physical slot/reference chain and the rich/stripped logical slot and dynamic-symbol relationship, retaining unresolved weak, IFUNC, interposition and runtime-provider states.

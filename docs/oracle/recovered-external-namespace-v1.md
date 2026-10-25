# Recovered external import requests

This component projects an already observed native external claim into the object-local
import-request namespace used by the independent external-call component. It is a
diagnostic component; it does not admit CALLS, identify a runtime provider, establish
negative completeness, or score accuracy.

The native manifest, observations and expected input/model/runtime bindings are
validated and frozen before opening either ELF. Every raw site and its original
record ordinal survives, including unowned, nonphysical, analysis-only and tail
candidates. No oracle call report, canonical function population or selected
boundary mapping is an input. Names never select or supply a target.

Two native claims can be checked:

* A physical computed call already has an INDIRECTION reference to slot S and an
  indexed reference neighborhood from S to an explicit EXTERNAL node E. Byte
  decoding must confirm that the call actually reads S.
* A physical direct call already targets P, and the native function inventory
  explicitly claims that P is a thunk with immediate EXTERNAL target E. The call
  bytes must confirm P. One byte-decoded indirect jump at P must read a static
  slot S. This verifies the existing P-to-E claim; it never creates a missing E.

The original instruction, physical target, EXTERNAL node, function and reference
indices remain in the frozen native evidence. A resolved import request does not
replace those observations, normalize a bare physical PLT edge, or create another
call for credit. Recursive, conflicting, missing, non-thunk and name-only claims
remain unresolved.

One synthetic EXTERNAL node is one recovered identity. If multiple retained
claims for that node reach different authenticated import requests, all affected
projections are marked `unresolved-external-node-conflict`. Their physical edges
and candidate slot proofs remain available; the component does not split that
conflated node into multiple verified semantic targets.

The pair proof authenticates both ELF files against the same explicitly pinned
artifact manifest. It checks the supported ELF profile, active dynamic tables,
symbol ordinals and full encoded symbol/version identity, relocation coordinates
and form, write coverage, slot storage and bytes. Rich and stripped locators are
retained separately. Unsupported reindexing is refused rather than inferred from
names. Instruction bytes require unique executable ownership and exact agreement
between the two pinned files. The native image base is translated through its
own RVA; a synthetic EXTERNAL address is never treated as an ELF address.

The resulting token identifies a versioned import request in the rich object's
namespace. It does not identify the implementation selected by a dynamic linker.
Weak/null, IFUNC, unsupported memory transfers and uncertain relocation writes
remain explicit unresolved outcomes. Raw native labels and library names remain
claims in the original observations and are not rewritten from the ELF.

The standalone worker authenticates the bundled Ghidra decoder and holds the
input descriptors through publication. It uses the byte-only Java decoder APIs;
it does not load a Program or run recovery analysis. Its owner must separately
provide process containment, resource limits, immutable capture and a guarded
production operation. A parsed report alone supplies none of that authority.
